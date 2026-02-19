"""
Tracer Terminal - Client Hub
Manages unique client identities derived from ICMP fingerprinting.
Handles multiple simultaneous clients, session persistence, and
client correlation across DNS and ICMP interactions.
"""
import hashlib
import time
import threading
from dataclasses import dataclass, field

from server.config import STATE_IDLE


@dataclass
class ICMPFingerprint:
    """Fingerprint derived from a client's ICMP Echo Request packets."""
    initial_ttl: int = 0       # OS signature: 128=Windows, 64=Linux/macOS, 255=Solaris/etc
    icmp_payload_hash: str = "" # hash of the ICMP payload pattern (OS-specific)
    os_hint: str = "unknown"


@dataclass
class ClientSession:
    """Per-client session managed by the hub."""
    client_id: str
    source_ip: str
    fingerprint: ICMPFingerprint = field(default_factory=ICMPFingerprint)
    state: str = STATE_IDLE
    outbox: list = field(default_factory=list)
    inbox: list = field(default_factory=list)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)

    @property
    def display_name(self) -> str:
        return f"{self.client_id[:8]}({self.source_ip})"


class ClientHub:
    """
    Central registry for client sessions. Generates stable IDs from
    ICMP fingerprints so clients can be uniquely tracked even when
    multiple clients share the same NAT IP.

    Identity is derived from: source_ip + OS fingerprint (TTL + payload hash).
    This means two different machines behind the same NAT get different IDs
    if they run different OSes or tracert implementations.
    """

    def __init__(self):
        self._sessions: dict[str, ClientSession] = {}  # client_id -> session
        self._ip_index: dict[str, list[str]] = {}       # source_ip -> [client_ids]
        self._lock = threading.Lock()

    def _generate_id(self, source_ip: str, fingerprint: ICMPFingerprint) -> str:
        """
        Deterministic client ID from source IP + ICMP fingerprint.
        Same client produces the same ID across sessions as long as
        the source IP and OS don't change.
        """
        material = f"{source_ip}:{fingerprint.initial_ttl}:{fingerprint.icmp_payload_hash}"
        return hashlib.sha256(material.encode()).hexdigest()[:16]

    @staticmethod
    def fingerprint_packet(pkt) -> ICMPFingerprint:
        """
        Extract an ICMP fingerprint from a Scapy packet.
        Called by the ICMP tunnel on first contact from a new source.
        """
        from scapy.all import IP, ICMP, Raw

        fp = ICMPFingerprint()

        if pkt.haslayer(IP):
            observed_ttl = pkt[IP].ttl
            # Reconstruct initial TTL from common OS defaults
            if observed_ttl <= 64:
                fp.initial_ttl = 64
                fp.os_hint = "Linux/macOS"
            elif observed_ttl <= 128:
                fp.initial_ttl = 128
                fp.os_hint = "Windows"
            else:
                fp.initial_ttl = 255
                fp.os_hint = "Solaris/Other"

        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw])
            fp.icmp_payload_hash = hashlib.sha256(payload).hexdigest()[:16]
        elif pkt.haslayer(ICMP):
            # Some tracert implementations send minimal payloads
            icmp_bytes = bytes(pkt[ICMP])[8:]  # skip ICMP header
            fp.icmp_payload_hash = hashlib.sha256(icmp_bytes).hexdigest()[:16]

        return fp

    def get_or_create(self, source_ip: str,
                      fingerprint: ICMPFingerprint | None = None) -> ClientSession:
        """
        Look up or create a session. If only source_ip is provided (DNS path),
        returns the most recent session for that IP. If fingerprint is also
        provided (ICMP path), uses the full composite key.
        """
        with self._lock:
            if fingerprint:
                client_id = self._generate_id(source_ip, fingerprint)
                if client_id in self._sessions:
                    sess = self._sessions[client_id]
                    sess.last_seen = time.time()
                    sess.source_ip = source_ip  # update in case IP drifted
                    return sess

                sess = ClientSession(
                    client_id=client_id,
                    source_ip=source_ip,
                    fingerprint=fingerprint,
                )
                self._sessions[client_id] = sess
                self._ip_index.setdefault(source_ip, [])
                if client_id not in self._ip_index[source_ip]:
                    self._ip_index[source_ip].append(client_id)
                return sess
            else:
                # DNS-only path: match by source IP, return most recent session
                ids = self._ip_index.get(source_ip, [])
                if ids:
                    best = max(ids, key=lambda cid: self._sessions[cid].last_seen)
                    sess = self._sessions[best]
                    sess.last_seen = time.time()
                    return sess

                # No ICMP fingerprint yet -- create a temporary IP-only session
                temp_id = hashlib.sha256(source_ip.encode()).hexdigest()[:16]
                if temp_id in self._sessions:
                    sess = self._sessions[temp_id]
                    sess.last_seen = time.time()
                    return sess

                sess = ClientSession(client_id=temp_id, source_ip=source_ip)
                self._sessions[temp_id] = sess
                self._ip_index.setdefault(source_ip, [])
                if temp_id not in self._ip_index[source_ip]:
                    self._ip_index[source_ip].append(temp_id)
                return sess

    def upgrade_session(self, source_ip: str, fingerprint: ICMPFingerprint):
        """
        Called when ICMP packets arrive for a client that was previously
        only known by IP (from DNS). Merges the temporary session into
        a properly fingerprinted one.
        """
        with self._lock:
            new_id = self._generate_id(source_ip, fingerprint)
            if new_id in self._sessions:
                return self._sessions[new_id]

            temp_id = hashlib.sha256(source_ip.encode()).hexdigest()[:16]
            if temp_id in self._sessions:
                old_sess = self._sessions.pop(temp_id)
                if source_ip in self._ip_index:
                    self._ip_index[source_ip] = [
                        cid for cid in self._ip_index[source_ip] if cid != temp_id
                    ]

                old_sess.client_id = new_id
                old_sess.fingerprint = fingerprint
                self._sessions[new_id] = old_sess
                self._ip_index.setdefault(source_ip, [])
                if new_id not in self._ip_index[source_ip]:
                    self._ip_index[source_ip].append(new_id)
                return old_sess

        return self.get_or_create(source_ip, fingerprint)

    def remove(self, client_id: str):
        """Remove a session entirely."""
        with self._lock:
            sess = self._sessions.pop(client_id, None)
            if sess and sess.source_ip in self._ip_index:
                self._ip_index[sess.source_ip] = [
                    cid for cid in self._ip_index[sess.source_ip] if cid != client_id
                ]

    def get_by_id(self, client_id: str) -> ClientSession | None:
        with self._lock:
            return self._sessions.get(client_id)

    def get_by_ip(self, source_ip: str) -> ClientSession | None:
        """Get the most recent session for an IP."""
        with self._lock:
            ids = self._ip_index.get(source_ip, [])
            if not ids:
                return None
            best = max(ids, key=lambda cid: self._sessions[cid].last_seen)
            return self._sessions.get(best)

    def all_sessions(self) -> list[ClientSession]:
        with self._lock:
            return list(self._sessions.values())

    def resolve_selector(self, selector: str) -> ClientSession | None:
        """
        Resolve a user-typed selector to a session.
        Accepts: full client_id, partial client_id prefix, or IP address.
        """
        with self._lock:
            if selector in self._sessions:
                return self._sessions[selector]

            # Partial ID match
            matches = [s for cid, s in self._sessions.items()
                       if cid.startswith(selector)]
            if len(matches) == 1:
                return matches[0]

            # IP match
            ids = self._ip_index.get(selector, [])
            if ids:
                best = max(ids, key=lambda cid: self._sessions[cid].last_seen)
                return self._sessions.get(best)

            return None
