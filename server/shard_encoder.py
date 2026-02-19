"""
Tracer Terminal - Shard Encoder / Decoder
Converts raw bytes <-> encrypted hex shards packed into DNS hostnames.
Optional gzip compression before encode when COMPRESS_PAYLOAD is True;
client decompresses when gzip magic (1f 8b 08) is present after decrypt.
"""
import gzip
from server.config import (
    DOMAIN_ZONE, XOR_KEY, FQDN_MAX, LABEL_MAX,
    CMD_END, COMPRESS_PAYLOAD, GZIP_MAGIC,
)


def _compute_label_sizes(domain_zone: str) -> list[int]:
    """Calculate how many 63-char labels fit in 253-char FQDN minus the domain suffix."""
    suffix_len = len(f".{domain_zone}")
    available = FQDN_MAX - suffix_len
    labels = []
    remaining = available
    while remaining > 0:
        lbl = min(LABEL_MAX, remaining)
        labels.append(lbl)
        remaining -= lbl + 1  # dot separator
    return labels


LABEL_SIZES = _compute_label_sizes(DOMAIN_ZONE)
MAX_HEX_PER_HOP = sum(LABEL_SIZES)


def xor_crypt(data: bytes, key: bytes = XOR_KEY) -> bytes:
    """XOR each byte of data with the repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encode_payload(payload: bytes) -> list[str]:
    """
    Encode a payload into a list of PTR hostnames (shards).
    If COMPRESS_PAYLOAD is True, gzips payload first so clients that support
    decompression receive fewer shards.
    Returns FQDNs like: '4a6f686e.446f6573.DOMAIN_ZONE' plus terminator 'end.DOMAIN_ZONE'.
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

        labels = []
        pos = 0
        for size in LABEL_SIZES:
            part = chunk[pos:pos + size]
            if not part:
                break
            labels.append(part)
            pos += size

        hostname = ".".join(labels) + f".{DOMAIN_ZONE}"
        shards.append(hostname)

    shards.append(f"{CMD_END}.{DOMAIN_ZONE}")
    return shards


def decode_payload(hostnames: list[str]) -> bytes:
    """
    Decode PTR hostnames back into the original payload.
    Strips the domain suffix, concatenates hex data, XOR decrypts.
    """
    suffix = f".{DOMAIN_ZONE}"
    hex_parts = []
    for h in hostnames:
        h = h.rstrip(".")
        if h.lower() == f"{CMD_END}.{DOMAIN_ZONE}".lower():
            break
        if h.lower().endswith(suffix.lower()):
            data_part = h[: -len(suffix)]
            hex_parts.append(data_part.replace(".", ""))

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
