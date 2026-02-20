"""
Tracer Terminal - ICMP Tunnel (Fake Hop Factory)
Uses Scapy to intercept ICMP Echo Requests and respond with Time Exceeded
messages from spoofed IPs, creating fake hops that carry payload shards.

Fake hop IPs are randomized from realistic public ranges to avoid the
fingerprint of sequential private IPs.
"""
import random
import threading
import time
from collections import defaultdict

from scapy.all import (
    sniff, send, IP, ICMP, Raw, conf,
)

from server.config import (
    SERVER_IP, ICMP_DELAY_MIN_MS, ICMP_DELAY_MAX_MS, ICMP_TTL_MIN, ICMP_TTL_MAX,
)
from server.client_hub import ClientHub

# Realistic public IP ranges to draw fake hop IPs from.
# These are large transit/infrastructure provider ranges where
# real tracert hops commonly appear.
_REALISTIC_RANGES = [
    (4, 0, 0, 0,     4, 255, 255, 255),     # Level3/Lumen
    (8, 0, 0, 0,     8, 255, 255, 255),      # APNIC / various
    (63, 0, 0, 0,    63, 255, 255, 255),     # various US ISPs
    (72, 14, 192, 0, 72, 14, 255, 255),      # Google infra
    (104, 0, 0, 0,   104, 255, 255, 255),    # Cloudflare/Fastly/CDN range
    (142, 250, 0, 0, 142, 251, 255, 255),    # Google
    (157, 240, 0, 0, 157, 240, 255, 255),    # Meta
    (172, 64, 0, 0,  172, 71, 255, 255),     # Cloudflare
    (198, 32, 0, 0,  198, 51, 255, 255),     # various transit
    (209, 85, 128, 0, 209, 85, 255, 255),    # Google
]


def _random_realistic_ip() -> str:
    """Generate a single random IP from realistic transit ranges."""
    lo = random.choice(_REALISTIC_RANGES)
    a0, a1, a2, a3, b0, b1, b2, b3 = lo
    return (
        f"{random.randint(a0, b0)}."
        f"{random.randint(a1, b1)}."
        f"{random.randint(a2, b2)}."
        f"{random.randint(a3, b3)}"
    )


def generate_hop_ips(count: int) -> list[str]:
    """
    Generate a list of unique, realistic-looking fake hop IPs.
    IPs are sorted by first octet to simulate a plausible geographic path.
    """
    ips = set()
    while len(ips) < count:
        ips.add(_random_realistic_ip())
    return sorted(ips, key=lambda ip: tuple(int(o) for o in ip.split(".")))


class ICMPTunnel:
    """
    Listens for incoming ICMP Echo Requests (tracert probes).
    For each client with queued shards, responds with ICMP Time Exceeded
    from randomized spoofed IPs. When the shard queue is empty, responds
    with Echo Reply (final destination reached).
    """

    def __init__(self, hub: ClientHub):
        self._hub = hub
        self._shard_queues: dict[str, list[str]] = {}
        self._hop_ips: dict[str, list[str]] = {}       # client_id -> [random IPs]
        self._ip_to_shard: dict[str, tuple[str, int]] = {}  # fake_ip -> (client_id, shard_index)
        self._hop_counters: dict[str, int] = defaultdict(int)
        self._fingerprinted: set[str] = set()
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def queue_shards(self, client_id: str, shards: list[str]):
        """Load shard hostnames for a client with randomized hop IPs."""
        hop_ips = generate_hop_ips(len(shards))
        with self._lock:
            # Clean up old IP mappings for this client
            self._clear_ip_mappings(client_id)

            self._shard_queues[client_id] = list(shards)
            self._hop_ips[client_id] = hop_ips
            self._hop_counters[client_id] = 0

            for idx, ip in enumerate(hop_ips):
                self._ip_to_shard[ip] = (client_id, idx)

    def get_ptr_hostname(self, hop_ip: str) -> str | None:
        """Return the PTR hostname for a fake hop IP (any client)."""
        with self._lock:
            entry = self._ip_to_shard.get(hop_ip)
            if not entry:
                return None
            client_id, idx = entry
            shards = self._shard_queues.get(client_id, [])
            if 0 <= idx < len(shards):
                return shards[idx]
            return None

    def is_fake_hop(self, ip: str) -> bool:
        """Check if an IP is one of our fake hops."""
        with self._lock:
            return ip in self._ip_to_shard

    def clear_client(self, client_id: str):
        """Remove all state for a client."""
        with self._lock:
            self._clear_ip_mappings(client_id)
            self._shard_queues.pop(client_id, None)
            self._hop_ips.pop(client_id, None)
            self._hop_counters.pop(client_id, None)

    def _clear_ip_mappings(self, client_id: str):
        """Remove IP-to-shard mappings for a client. Must hold _lock."""
        old_ips = self._hop_ips.get(client_id, [])
        for ip in old_ips:
            self._ip_to_shard.pop(ip, None)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _listen(self):
        conf.verb = 0
        sniff(
            filter=f"icmp and dst host {SERVER_IP}",
            prn=self._handle_packet,
            stop_filter=lambda _: not self._running,
            store=False,
        )

    def _handle_packet(self, pkt):
        if not pkt.haslayer(ICMP):
            return
        if pkt[ICMP].type != 8:
            return

        source_ip = pkt[IP].src

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
            hop_ips = self._hop_ips.get(client_id, [])

        if hop_idx < len(shards) and hop_idx < len(hop_ips):
            self._send_time_exceeded(pkt, hop_ips[hop_idx], hop_idx)
            with self._lock:
                self._hop_counters[client_id] = hop_idx + 1
        else:
            self._send_echo_reply(pkt)

    def _send_time_exceeded(self, original_pkt, spoofed_ip: str, hop_idx: int):
        """Send Time Exceeded with TTL that decreases with hop index (plus jitter) to mimic real path."""
        orig_ip_bytes = bytes(original_pkt[IP])
        ip_hdr_len = (original_pkt[IP].ihl or 5) * 4
        enclosed = orig_ip_bytes[:ip_hdr_len + 8]

        # Real routers: TTL in Time Exceeded typically decreases with hop distance. Replicate that.
        ttl = ICMP_TTL_MAX - hop_idx + random.randint(-2, 2)
        ttl = max(ICMP_TTL_MIN, min(ICMP_TTL_MAX, ttl))

        time_exceeded = (
            IP(src=spoofed_ip, dst=original_pkt[IP].src, ttl=ttl)
            / ICMP(type=11, code=0)
            / Raw(load=enclosed)
        )

        delay = random.randint(ICMP_DELAY_MIN_MS, ICMP_DELAY_MAX_MS) / 1000.0
        time.sleep(delay)

        send(time_exceeded, verbose=False)

    def _send_echo_reply(self, original_pkt):
        echo_reply = (
            IP(src=SERVER_IP, dst=original_pkt[IP].src,
               ttl=random.randint(ICMP_TTL_MIN, ICMP_TTL_MAX))
            / ICMP(
                type=0,
                id=original_pkt[ICMP].id,
                seq=original_pkt[ICMP].seq,
            )
            / Raw(load=bytes(original_pkt[Raw]) if original_pkt.haslayer(Raw) else b"")
        )
        send(echo_reply, verbose=False)
