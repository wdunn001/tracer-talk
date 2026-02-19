"""
Tracer Terminal - ICMP Tunnel (Fake Hop Factory)
Uses Scapy to intercept ICMP Echo Requests and respond with Time Exceeded
messages from spoofed IPs, creating fake hops that carry payload shards.
"""
import threading
import time
from collections import defaultdict

from scapy.all import (
    sniff, send, IP, ICMP, Raw, conf,
)

import random

from server.config import (
    SERVER_IP, FAKE_HOP_BASE_IP, ICMP_HOP_DELAY_MS, ICMP_TTL_MIN, ICMP_TTL_MAX,
)
from server.client_hub import ClientHub


class ICMPTunnel:
    """
    Listens for incoming ICMP Echo Requests (tracert probes).
    For each client with queued shards, responds with ICMP Time Exceeded
    from sequential spoofed IPs. When the shard queue is empty, responds
    with Echo Reply (final destination reached).
    """

    def __init__(self, hub: ClientHub):
        self._hub = hub
        self._shard_queues: dict[str, list[str]] = {}  # client_id -> [shard_fqdn, ...]
        self._hop_counters: dict[str, int] = defaultdict(int)
        self._fingerprinted: set[str] = set()  # source IPs already fingerprinted
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def queue_shards(self, client_id: str, shards: list[str]):
        """Load shard hostnames for a client. Called by orchestrator."""
        with self._lock:
            self._shard_queues[client_id] = list(shards)
            self._hop_counters[client_id] = 0

    def get_ptr_hostname(self, client_id: str, hop_ip: str) -> str | None:
        """Return the PTR hostname for a given fake hop IP and client."""
        with self._lock:
            if client_id not in self._shard_queues:
                return None
            try:
                hop_num = int(hop_ip.split(".")[-1]) - 1
            except (ValueError, IndexError):
                return None
            shards = self._shard_queues[client_id]
            if 0 <= hop_num < len(shards):
                return shards[hop_num]
            return None

    def clear_client(self, client_id: str):
        """Remove all state for a client."""
        with self._lock:
            self._shard_queues.pop(client_id, None)
            self._hop_counters.pop(client_id, None)

    def start(self):
        """Start the ICMP listener in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _listen(self):
        """Sniff ICMP Echo Requests and handle them."""
        conf.verb = 0
        sniff(
            filter=f"icmp and dst host {SERVER_IP}",
            prn=self._handle_packet,
            stop_filter=lambda _: not self._running,
            store=False,
        )

    def _handle_packet(self, pkt):
        """Process a single ICMP packet."""
        if not pkt.haslayer(ICMP):
            return
        if pkt[ICMP].type != 8:  # Echo Request only
            return

        source_ip = pkt[IP].src

        # Fingerprint on first contact from this IP
        if source_ip not in self._fingerprinted:
            fp = ClientHub.fingerprint_packet(pkt)
            self._hub.upgrade_session(source_ip, fp)
            self._fingerprinted.add(source_ip)

        session = self._hub.get_by_ip(source_ip)
        if not session:
            return

        client_id = session.client_id

        with self._lock:
            shards = self._shard_queues.get(client_id, [])
            hop_idx = self._hop_counters.get(client_id, 0)

        if hop_idx < len(shards):
            self._send_time_exceeded(pkt, hop_idx)
            with self._lock:
                self._hop_counters[client_id] = hop_idx + 1
        else:
            self._send_echo_reply(pkt)

    def _send_time_exceeded(self, original_pkt, hop_idx: int):
        """
        Send ICMP Time Exceeded (type 11, code 0) with a spoofed source IP.
        """
        spoofed_ip = f"{FAKE_HOP_BASE_IP}{hop_idx + 1}"

        orig_ip_bytes = bytes(original_pkt[IP])
        ip_hdr_len = (original_pkt[IP].ihl or 5) * 4
        enclosed = orig_ip_bytes[:ip_hdr_len + 8]

        time_exceeded = (
            IP(src=spoofed_ip, dst=original_pkt[IP].src, ttl=random.randint(ICMP_TTL_MIN, ICMP_TTL_MAX))
            / ICMP(type=11, code=0)
            / Raw(load=enclosed)
        )

        if ICMP_HOP_DELAY_MS > 0:
            time.sleep(ICMP_HOP_DELAY_MS / 1000.0)

        send(time_exceeded, verbose=False)

    def _send_echo_reply(self, original_pkt):
        """Send a standard ICMP Echo Reply (final destination)."""
        echo_reply = (
            IP(src=SERVER_IP, dst=original_pkt[IP].src, ttl=random.randint(ICMP_TTL_MIN, ICMP_TTL_MAX))
            / ICMP(
                type=0,
                id=original_pkt[ICMP].id,
                seq=original_pkt[ICMP].seq,
            )
            / Raw(load=bytes(original_pkt[Raw]) if original_pkt.haslayer(Raw) else b"")
        )
        send(echo_reply, verbose=False)
