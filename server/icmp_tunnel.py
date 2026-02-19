"""
Tracer Terminal - ICMP Tunnel (Fake Hop Factory)
Uses Scapy to intercept ICMP Echo Requests and respond with Time Exceeded
messages from spoofed IPs, creating fake hops that carry payload shards.
"""
import threading
import struct
import time
from collections import defaultdict

from scapy.all import (
    sniff, send, IP, ICMP, Raw, conf,
)

from server.config import (
    SERVER_IP, FAKE_HOP_BASE_IP, ICMP_HOP_DELAY_MS,
)


class ICMPTunnel:
    """
    Listens for incoming ICMP Echo Requests (tracert probes).
    For each client with queued shards, responds with ICMP Time Exceeded
    from sequential spoofed IPs. When the shard queue is empty, responds
    with Echo Reply (final destination reached).
    """

    def __init__(self):
        self._shard_queues: dict[str, list[str]] = {}  # client_ip -> [shard_fqdn, ...]
        self._hop_counters: dict[str, int] = defaultdict(int)  # client_ip -> next hop index
        self._lock = threading.Lock()
        self._running = False
        self._thread = None

    def queue_shards(self, client_ip: str, shards: list[str]):
        """Load shard hostnames for a client. Called by orchestrator."""
        with self._lock:
            self._shard_queues[client_ip] = list(shards)
            self._hop_counters[client_ip] = 0

    def get_ptr_hostname(self, client_ip: str, hop_ip: str) -> str | None:
        """Return the PTR hostname for a given fake hop IP and client."""
        with self._lock:
            if client_ip not in self._shard_queues:
                return None
            try:
                hop_num = int(hop_ip.split(".")[-1]) - 1  # 10.200.0.1 -> index 0
            except (ValueError, IndexError):
                return None
            shards = self._shard_queues[client_ip]
            if 0 <= hop_num < len(shards):
                return shards[hop_num]
            return None

    def clear_client(self, client_ip: str):
        """Remove all state for a client."""
        with self._lock:
            self._shard_queues.pop(client_ip, None)
            self._hop_counters.pop(client_ip, None)

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

        client_ip = pkt[IP].src
        icmp_id = pkt[ICMP].id
        icmp_seq = pkt[ICMP].seq

        with self._lock:
            shards = self._shard_queues.get(client_ip, [])
            hop_idx = self._hop_counters.get(client_ip, 0)

        if hop_idx < len(shards):
            # Still have shards to deliver -> send ICMP Time Exceeded
            self._send_time_exceeded(pkt, client_ip, hop_idx)
            with self._lock:
                self._hop_counters[client_ip] = hop_idx + 1
        else:
            # All shards delivered -> send Echo Reply (final destination)
            self._send_echo_reply(pkt)

    def _send_time_exceeded(self, original_pkt, client_ip: str, hop_idx: int):
        """
        Send ICMP Time Exceeded (type 11, code 0) with a spoofed source IP.
        The spoofed IP is FAKE_HOP_BASE_IP + (hop_idx + 1), which the client
        will do a PTR lookup for, getting our shard hostname.
        """
        spoofed_ip = f"{FAKE_HOP_BASE_IP}{hop_idx + 1}"

        # Time Exceeded must include the original IP header + first 8 bytes of payload
        orig_ip_bytes = bytes(original_pkt[IP])
        # Truncate to IP header + 8 bytes of ICMP
        ip_hdr_len = (original_pkt[IP].ihl or 5) * 4
        enclosed = orig_ip_bytes[:ip_hdr_len + 8]

        time_exceeded = (
            IP(src=spoofed_ip, dst=original_pkt[IP].src, ttl=255)
            / ICMP(type=11, code=0)
            / Raw(load=enclosed)
        )

        if ICMP_HOP_DELAY_MS > 0:
            time.sleep(ICMP_HOP_DELAY_MS / 1000.0)

        send(time_exceeded, verbose=False)

    def _send_echo_reply(self, original_pkt):
        """Send a standard ICMP Echo Reply (final destination)."""
        echo_reply = (
            IP(src=SERVER_IP, dst=original_pkt[IP].src, ttl=255)
            / ICMP(
                type=0,  # Echo Reply
                id=original_pkt[ICMP].id,
                seq=original_pkt[ICMP].seq,
            )
            / Raw(load=bytes(original_pkt[Raw]) if original_pkt.haslayer(Raw) else b"")
        )
        send(echo_reply, verbose=False)
