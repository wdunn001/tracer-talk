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
ICMP_DELAY_MIN_MS = 2   # Randomize per-hop response delay within this range (ms)
ICMP_DELAY_MAX_MS = 40  # Real hops vary from <1ms (local) to 30ms+ (cross-continent)
ICMP_TTL_MIN = 50       # Randomize TTL on ICMP responses within this range
ICMP_TTL_MAX = 120     # Real routers arrive at client with varying TTLs depending
                        # on OS and return path distance. A uniform TTL is a red flag.

# Shard capacity (auto-calculated)
FQDN_MAX = 253
LABEL_MAX = 63
STEALTH_RESERVED = 20   # Chars reserved for realistic prefix/suffix labels in PTR hostnames
_suffix = f".{DOMAIN_ZONE}"
_suffix_len = len(_suffix)
_available = FQDN_MAX - _suffix_len - STEALTH_RESERVED

# Pack as many 63-char labels as fit, separated by dots (hex only; prefix/suffix are extra).
# Each label size is even so hex decoding never drops a half-byte.
_labels = []
_remaining = _available
while _remaining > 0:
    lbl = min(LABEL_MAX, _remaining)
    if lbl % 2 != 0:
        lbl -= 1
    if lbl <= 0:
        break
    _labels.append(lbl)
    _remaining -= lbl + 1  # +1 for the dot separator
MAX_HEX_PER_HOP = sum(_labels)
MAX_BYTES_PER_HOP = MAX_HEX_PER_HOP // 2  # 2 hex chars = 1 byte
USABLE_HOPS = MAX_HOPS - RESERVED_HOPS
MAX_PAYLOAD_BYTES = MAX_BYTES_PER_HOP * USABLE_HOPS

# DNS record TTLs (seconds). 0 = don't cache.
DNS_TTL_A = 0              # A record responses for command subdomains
DNS_TTL_PTR = 0            # PTR record responses for fake hop hostnames (shard data)

# Client poll rate (seconds between rx polls in the chat loop)
POLL_RATE = 5  # seconds to wait between downlink polls; lower = more responsive but noisier

# Subdomain command prefixes
CMD_PAYLOAD = "payload"
CMD_KEY = "key"
CMD_TX = "tx"
CMD_RX = "rx"
CMD_END = "end"

# Session states
STATE_IDLE = "IDLE"
STATE_DELIVERING = "DELIVERING"
STATE_CHATTING = "CHATTING"
