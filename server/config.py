"""
Tracer Terminal - Configuration
All tunables for the orchestrator, DNS handler, ICMP tunnel, and shard encoder.
"""

DOMAIN_ZONE = "lab.yourdomain.com"     # CHANGE THIS: must match your NS delegation
SERVER_IP = "0.0.0.0"                  # CHANGE THIS: your server's public IP

DNS_PORT = 53
DNS_LISTEN = "0.0.0.0"

# XOR key derived from SERVER_IP octets
XOR_KEY = bytes(int(o) for o in SERVER_IP.split("."))

# ICMP fake-hop settings
MAX_HOPS = 30          # tracert default on most systems
RESERVED_HOPS = 2      # 1 for end marker, 1 for final destination echo reply
FAKE_HOP_BASE_IP = "10.200.0."  # spoofed source IPs: 10.200.0.1, .2, .3 ...
ICMP_HOP_DELAY_MS = 5  # simulated latency per fake hop
ICMP_TTL_MIN = 50      # Randomize TTL on ICMP responses within this range
ICMP_TTL_MAX = 120     # Real routers arrive at client with varying TTLs depending
                        # on OS and return path distance. A uniform TTL is a red flag.

# Shard capacity (auto-calculated)
FQDN_MAX = 253
LABEL_MAX = 63
_suffix = f".{DOMAIN_ZONE}"
_suffix_len = len(_suffix)
_available = FQDN_MAX - _suffix_len

# Pack as many 63-char labels as fit, separated by dots
_labels = []
_remaining = _available
while _remaining > 0:
    lbl = min(LABEL_MAX, _remaining)
    _labels.append(lbl)
    _remaining -= lbl + 1  # +1 for the dot separator
MAX_HEX_PER_HOP = sum(_labels)
MAX_BYTES_PER_HOP = MAX_HEX_PER_HOP // 2  # 2 hex chars = 1 byte
USABLE_HOPS = MAX_HOPS - RESERVED_HOPS
MAX_PAYLOAD_BYTES = MAX_BYTES_PER_HOP * USABLE_HOPS

# Subdomain command prefixes
CMD_PAYLOAD = "payload"
CMD_KEY = "key"
CMD_TX = "tx"
CMD_RX = "rx"
CMD_ACK = "ack"
CMD_END = "end"

# Session states
STATE_IDLE = "IDLE"
STATE_DELIVERING = "DELIVERING"
STATE_CHATTING = "CHATTING"
