"""
Tracer Terminal - Shard Encoder / Decoder
Converts raw bytes <-> encrypted hex shards packed into DNS hostnames.
Optional gzip compression before encode when COMPRESS_PAYLOAD is True;
client decompresses when gzip magic (1f 8b 08) is present after decrypt.
PTR hostnames use realistic-looking transit router labels (prefix/suffix) with
hex payload in the middle so passive DNS sees router-like names, not raw hex.
"""
import gzip
import re
import random
from server.config import (
    DOMAIN_ZONE, XOR_KEY, FQDN_MAX, LABEL_MAX,
    CMD_END, COMPRESS_PAYLOAD, GZIP_MAGIC, STEALTH_RESERVED,
)

# Realistic transit-router / switch style labels (Level3, Google, Cisco, Juniper, etc.)
_PREFIX_LABELS = (
    "ge-0-0-1", "xe-1-2-3", "te-0-1-0", "so-0-0-0", "et-0-0-1",
    "cr1", "cr2", "ar1", "ar2", "edge1", "core1", "gw1", "rtr1",
    "ae1", "ae2", "bundle-ae1", "ge-1-0-0", "xe-0-0-1", "et-1-0-0",
    "peer1", "peer2", "transit1", "uplink1", "backbone1",
)
_SUFFIX_LABELS = (
    "nyc", "lax", "lhr", "fra", "sin", "syd", "dfw", "ord", "sea", "ams", "iad",
)

# Randomized TLDs and common transit/switch provider domains (hostname appearance only)
PTR_DOMAINS = (
    "level3.net", "level3.com", "lumen.com", "cogentco.com", "he.net",
    "google.com", "google.net", "nvidia.com", "cloudflare.com", "akamai.net",
    "ntt.net", "ntt.com", "telia.net", "equinix.com", "amazon.com",
    "fastly.com", "zayo.com", "centurylink.com", "att.net", "verizon.com",
    "coloblx.net", "linode.com", "digitalocean.com", "ovh.net",
)
_PTR_DOMAIN_SUFFIX_LEN = 1 + max(len(d) for d in PTR_DOMAINS)


def _compute_label_sizes(domain_suffix_len: int, reserved: int = 0) -> list[int]:
    """Calculate how many 63-char labels fit in 253-char FQDN minus domain suffix and reserved.
    domain_suffix_len is 1 + len(domain) e.g. for 'level3.net' use 10. Each label size is even."""
    available = FQDN_MAX - domain_suffix_len - reserved
    labels = []
    remaining = available
    while remaining > 0:
        lbl = min(LABEL_MAX, remaining)
        if lbl % 2 != 0:
            lbl -= 1  # hex labels must be even length (pairs of hex chars = one byte)
        if lbl <= 0:
            break
        labels.append(lbl)
        remaining -= lbl + 1  # dot separator
    return labels


LABEL_SIZES = _compute_label_sizes(_PTR_DOMAIN_SUFFIX_LEN, STEALTH_RESERVED)
MAX_HEX_PER_HOP = sum(LABEL_SIZES)

# Regex: label is only hex chars and has even length (valid hex bytes)
_HEX_LABEL_RE = re.compile(r"^[0-9a-fA-F]+$")


def xor_crypt(data: bytes, key: bytes = XOR_KEY) -> bytes:
    """XOR each byte of data with the repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _extract_hex_from_hostname_part(hostname_part: str) -> str:
    """
    From the part of a hostname before the domain zone, extract only hex-carrying labels.
    Labels that are purely [0-9a-fA-F] and have even length are treated as hex; others
    (e.g. ge-0-0-1, nyc) are decorative and skipped. Used by decode_payload and by clients.
    """
    out = []
    for label in hostname_part.split("."):
        label = label.strip()
        if label and len(label) % 2 == 0 and _HEX_LABEL_RE.match(label):
            out.append(label.lower())
    return "".join(out)


def _random_ptr_domain() -> str:
    """Pick a random transit/switch-style domain for PTR hostname (TLD randomized)."""
    return random.choice(PTR_DOMAINS)


def encode_payload(payload: bytes) -> list[str]:
    """
    Encode a payload into a list of PTR hostnames (shards) that look like transit routers.
    Each shard uses a random TLD/domain (level3.net, google.com, etc.) to avoid domain clustering.
    If COMPRESS_PAYLOAD is True, gzips payload first.
    Returns FQDNs like: 'ge-0-0-1.4a6f686e.nyc.level3.net' plus terminator 'end.<random_domain>'.
    """
    if COMPRESS_PAYLOAD:
        payload = gzip.compress(payload)
    encrypted = xor_crypt(payload)
    hex_str = encrypted.hex()

    shards = []
    offset = 0
    while offset < len(hex_str):
        chunk = hex_str[offset:offset + MAX_HEX_PER_HOP]
        offset += MAX_HEX_PER_HOP

        hex_labels = []
        pos = 0
        for size in LABEL_SIZES:
            part = chunk[pos:pos + size]
            if not part:
                break
            hex_labels.append(part)
            pos += size

        prefix = random.choice(_PREFIX_LABELS)
        suffix = random.choice(_SUFFIX_LABELS)
        domain = _random_ptr_domain()
        hostname = ".".join([prefix] + hex_labels + [suffix]) + f".{domain}"
        shards.append(hostname)

    shards.append(f"{CMD_END}.{_random_ptr_domain()}")
    return shards


def decode_payload(hostnames: list[str]) -> bytes:
    """
    Decode PTR hostnames back into the original payload.
    PTR hostnames may use any randomized domain (level3.net, google.com, etc.).
    Stop when a hostname's first label is CMD_END ('end'); otherwise extract hex from full hostname.
    """
    hex_parts = []
    for h in hostnames:
        h = h.rstrip(".").strip()
        if not h:
            continue
        first_label = h.split(".")[0].lower()
        if first_label == CMD_END.lower():
            break
        hex_parts.append(_extract_hex_from_hostname_part(h))

    hex_str = "".join(hex_parts)
    raw = bytes.fromhex(hex_str)
    decrypted = xor_crypt(raw)
    # Server-side decode (e.g. tests): decompress when gzip magic present
    if len(decrypted) >= len(GZIP_MAGIC) and decrypted[: len(GZIP_MAGIC)] == GZIP_MAGIC:
        try:
            return gzip.decompress(decrypted)
        except OSError:
            return decrypted
    return decrypted


def encode_message(message: str) -> str:
    """
    Encode a short chat message for uplink (subdomain encoding).
    Returns the data labels to prepend before .tx.DOMAIN_ZONE.
    """
    encrypted = xor_crypt(message.encode("utf-8"))
    hex_str = encrypted.hex()
    labels = [hex_str[i:i + LABEL_MAX] for i in range(0, len(hex_str), LABEL_MAX)]
    return ".".join(labels)


def decode_message(subdomain_labels: str) -> str:
    """
    Decode an uplink message from subdomain labels.
    Input is the part before .tx.DOMAIN_ZONE with dots between labels.
    """
    hex_str = subdomain_labels.replace(".", "")
    raw = bytes.fromhex(hex_str)
    decrypted = xor_crypt(raw)
    return decrypted.decode("utf-8", errors="replace")
