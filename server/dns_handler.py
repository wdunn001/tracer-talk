"""
Tracer Terminal - DNS Handler
dnslib-based UDP DNS server that routes queries through the subdomain command map.
"""
from dnslib import RR, QTYPE, A, PTR
from dnslib.server import DNSServer, BaseResolver

from server.config import (
    DOMAIN_ZONE, SERVER_IP, DNS_PORT, DNS_LISTEN,
    DNS_TTL_A, DNS_TTL_PTR,
    CMD_PAYLOAD, CMD_KEY, CMD_TX, CMD_RX, CMD_END,
)


def _add_a(reply, qname: str, ip: str = SERVER_IP, ttl: int = DNS_TTL_A):
    """Add an A record answer to a DNS reply."""
    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=ttl))


def _add_ptr(reply, qname: str, hostname: str, ttl: int = DNS_TTL_PTR):
    """Add a PTR record answer to a DNS reply."""
    if not hostname.endswith("."):
        hostname += "."
    reply.add_answer(RR(qname, QTYPE.PTR, rdata=PTR(hostname), ttl=ttl))


class TracerResolver(BaseResolver):
    """
    Routes DNS queries based on subdomain command map.
    The orchestrator registers callbacks for each command.
    """

    def __init__(self):
        self.orchestrator = None

    def set_orchestrator(self, orch):
        self.orchestrator = orch

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        client_ip = handler.client_address[0]

        if qtype == "A":
            self._handle_a_query(reply, qname, client_ip)
        elif qtype == "PTR":
            self._handle_ptr_query(reply, qname, client_ip)

        return reply

    def _handle_a_query(self, reply, qname: str, client_ip: str):
        """Route A-record queries through the command map."""
        qname_lower = qname.lower()
        zone_suffix = f".{DOMAIN_ZONE}".lower()

        if not qname_lower.endswith(zone_suffix):
            return

        subdomain = qname_lower[: -len(zone_suffix)]
        parts = subdomain.split(".")
        cmd = parts[-1] if parts else ""

        _add_a(reply, qname)

        if not self.orchestrator:
            return

        if cmd == CMD_PAYLOAD:
            self.orchestrator.on_payload_request(client_ip)
        elif cmd == CMD_KEY:
            pass
        elif cmd == CMD_TX:
            self.orchestrator.on_tx_message(client_ip, ".".join(parts[:-1]))
        elif cmd == CMD_RX:
            self.orchestrator.on_rx_request(client_ip)
        elif cmd == CMD_END:
            self.orchestrator.on_end(client_ip)

    def _handle_ptr_query(self, reply, qname: str, client_ip: str):
        """
        Serve PTR records for fake hop IPs.
        PTR queries arrive as reversed octets: 1.0.200.10.in-addr.arpa -> 10.200.0.1
        The ICMP tunnel tracks which randomized fake hop IPs map to which shards.
        """
        if not qname.lower().endswith(".in-addr.arpa"):
            return

        arpa_part = qname.lower().replace(".in-addr.arpa", "")
        octets = arpa_part.split(".")
        if len(octets) != 4:
            return

        ip = ".".join(reversed(octets))

        if self.orchestrator:
            hostname = self.orchestrator.get_ptr_for_hop(ip)
            if hostname:
                _add_ptr(reply, qname, hostname)


def create_dns_server(resolver: TracerResolver) -> DNSServer:
    """Create and return a dnslib DNS server (not yet started)."""
    return DNSServer(resolver, port=DNS_PORT, address=DNS_LISTEN, tcp=False)
