"""
Tracer Terminal - DNS Handler
dnslib-based UDP DNS server that routes queries through the subdomain command map.
"""
import threading
import struct
import socket
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, PTR, TXT
from dnslib.server import DNSServer, BaseResolver

from server.config import (
    DOMAIN_ZONE, SERVER_IP, DNS_PORT, DNS_LISTEN, XOR_KEY,
    CMD_PAYLOAD, CMD_KEY, CMD_TX, CMD_RX, CMD_ACK, CMD_END,
    FAKE_HOP_BASE_IP,
)


class TracerResolver(BaseResolver):
    """
    Routes DNS queries based on subdomain command map.
    The orchestrator registers callbacks for each command.
    """

    def __init__(self):
        self.orchestrator = None
        self._ptr_cache: dict[str, list[str]] = {}  # client_ip -> list of PTR FQDNs

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
        else:
            pass  # ignore other query types silently

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

        if cmd == CMD_PAYLOAD:
            self._on_payload_request(reply, qname, client_ip)
        elif cmd == CMD_KEY:
            self._on_key_request(reply, qname, client_ip)
        elif cmd == CMD_TX:
            data_labels = ".".join(parts[:-1])
            self._on_tx_request(reply, qname, client_ip, data_labels)
        elif cmd == CMD_RX:
            self._on_rx_request(reply, qname, client_ip)
        elif cmd == CMD_ACK:
            self._on_ack_request(reply, qname, client_ip)
        elif cmd == CMD_END:
            self._on_end_request(reply, qname, client_ip)
        else:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=60))

    def _handle_ptr_query(self, reply, qname: str, client_ip: str):
        """
        Serve PTR records for fake hop IPs.
        PTR queries arrive as: 1.0.200.10.in-addr.arpa -> 10.200.0.1
        """
        if not qname.lower().endswith(".in-addr.arpa"):
            return

        arpa_part = qname.lower().replace(".in-addr.arpa", "")
        octets = arpa_part.split(".")
        if len(octets) != 4:
            return

        ip = ".".join(reversed(octets))

        if not ip.startswith(FAKE_HOP_BASE_IP):
            return

        if self.orchestrator:
            hostname = self.orchestrator.get_ptr_for_hop(client_ip, ip)
            if hostname:
                if not hostname.endswith("."):
                    hostname += "."
                reply.add_answer(RR(qname, QTYPE.PTR, rdata=PTR(hostname), ttl=0))

    def _on_payload_request(self, reply, qname, client_ip):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=0))
        if self.orchestrator:
            self.orchestrator.on_payload_request(client_ip)

    def _on_key_request(self, reply, qname, client_ip):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=0))

    def _on_tx_request(self, reply, qname, client_ip, data_labels):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=0))
        if self.orchestrator:
            self.orchestrator.on_tx_message(client_ip, data_labels)

    def _on_rx_request(self, reply, qname, client_ip):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=0))
        if self.orchestrator:
            self.orchestrator.on_rx_request(client_ip)

    def _on_ack_request(self, reply, qname, client_ip):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=0))
        if self.orchestrator:
            self.orchestrator.on_ack(client_ip)

    def _on_end_request(self, reply, qname, client_ip):
        reply.add_answer(RR(qname, QTYPE.A, rdata=A(SERVER_IP), ttl=0))
        if self.orchestrator:
            self.orchestrator.on_end(client_ip)


def create_dns_server(resolver: TracerResolver) -> DNSServer:
    """Create and return a dnslib DNS server (not yet started)."""
    return DNSServer(resolver, port=DNS_PORT, address=DNS_LISTEN, tcp=False)
