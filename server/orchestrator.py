"""
Tracer Terminal - Orchestrator (Director)
Central controller that wires DNS + ICMP + session state together.
Manages the per-client state machine and provides the server-side chat CLI.
"""
import os
import sys
import threading
import time
from collections import defaultdict

from server.config import (
    DOMAIN_ZONE, SERVER_IP, XOR_KEY,
    STATE_IDLE, STATE_DELIVERING, STATE_CHATTING,
    MAX_PAYLOAD_BYTES, MAX_HEX_PER_HOP, USABLE_HOPS,
)
from server.shard_encoder import encode_payload, encode_message, decode_message
from server.dns_handler import TracerResolver, create_dns_server
from server.icmp_tunnel import ICMPTunnel


class Session:
    """Per-client session state."""

    def __init__(self, client_ip: str):
        self.client_ip = client_ip
        self.state = STATE_IDLE
        self.outbox: list[str] = []  # messages waiting to be sent to client
        self.inbox: list[str] = []   # messages received from client


class Orchestrator:
    """
    Director that routes DNS commands, manages ICMP tunnels, and
    provides the server-side chat CLI.
    """

    def __init__(self, payload_file: str | None = None):
        self.sessions: dict[str, Session] = {}
        self._lock = threading.Lock()
        self._active_client: str | None = None

        # Load payload (chat client script)
        self._payload_bytes = b""
        if payload_file and os.path.exists(payload_file):
            with open(payload_file, "rb") as f:
                self._payload_bytes = f.read()
            size = len(self._payload_bytes)
            print(f"[*] Payload loaded: {payload_file} ({size} bytes)")
            if size > MAX_PAYLOAD_BYTES:
                print(f"[!] WARNING: payload exceeds max capacity ({MAX_PAYLOAD_BYTES} bytes)")
        else:
            print("[*] No payload file specified - payload delivery disabled")

        # Pre-encode payload into shards
        self._payload_shards: list[str] = []
        if self._payload_bytes:
            self._payload_shards = encode_payload(self._payload_bytes)
            print(f"[*] Payload encoded into {len(self._payload_shards) - 1} data shards + end marker")
            print(f"[*] Capacity: {MAX_HEX_PER_HOP} hex/hop, {USABLE_HOPS} usable hops, {MAX_PAYLOAD_BYTES} bytes max")

        # Components
        self.resolver = TracerResolver()
        self.resolver.set_orchestrator(self)
        self.icmp = ICMPTunnel()
        self.dns_server = create_dns_server(self.resolver)

    def _get_session(self, client_ip: str) -> Session:
        with self._lock:
            if client_ip not in self.sessions:
                self.sessions[client_ip] = Session(client_ip)
                print(f"\n[+] New client: {client_ip}")
            return self.sessions[client_ip]

    # --- Command handlers (called by DNS resolver) ---

    def on_payload_request(self, client_ip: str):
        """Client requested payload delivery."""
        session = self._get_session(client_ip)
        if not self._payload_shards:
            print(f"\n[!] {client_ip} requested payload but none loaded")
            return

        session.state = STATE_DELIVERING
        self.icmp.queue_shards(client_ip, self._payload_shards)
        print(f"\n[>] Delivering payload to {client_ip} ({len(self._payload_shards) - 1} shards)")

    def on_tx_message(self, client_ip: str, data_labels: str):
        """Client sent an uplink message via subdomain."""
        session = self._get_session(client_ip)
        session.state = STATE_CHATTING
        try:
            message = decode_message(data_labels)
            session.inbox.append(message)
            print(f"\n[{client_ip}] {message}")
        except Exception as e:
            print(f"\n[!] Failed to decode message from {client_ip}: {e}")

    def on_rx_request(self, client_ip: str):
        """Client is polling for downlink messages."""
        session = self._get_session(client_ip)
        session.state = STATE_CHATTING

        with self._lock:
            if session.outbox:
                message = session.outbox.pop(0)
                shards = encode_payload(message.encode("utf-8"))
                self.icmp.queue_shards(client_ip, shards)
            else:
                # No message: queue just the end marker so tracert completes quickly
                end_marker = f"empty.{DOMAIN_ZONE}"
                self.icmp.queue_shards(client_ip, [end_marker])

    def on_ack(self, client_ip: str):
        """Client acknowledged receipt of last downlink."""
        session = self._get_session(client_ip)
        self.icmp.clear_client(client_ip)

    def on_end(self, client_ip: str):
        """Client is disconnecting."""
        session = self._get_session(client_ip)
        print(f"\n[-] Client disconnected: {client_ip}")
        self.icmp.clear_client(client_ip)
        with self._lock:
            self.sessions.pop(client_ip, None)

    def get_ptr_for_hop(self, client_ip: str, hop_ip: str) -> str | None:
        """DNS resolver calls this to get PTR hostname for a fake hop."""
        return self.icmp.get_ptr_hostname(client_ip, hop_ip)

    # --- Server lifecycle ---

    def start(self):
        """Start DNS server, ICMP tunnel, and chat CLI."""
        print(f"[*] Tracer Terminal Orchestrator")
        print(f"[*] Domain zone: {DOMAIN_ZONE}")
        print(f"[*] Server IP / XOR key: {SERVER_IP} -> {list(XOR_KEY)}")
        print(f"[*] Starting DNS server on port 53...")

        self.dns_server.start_thread()
        print(f"[*] Starting ICMP tunnel...")
        self.icmp.start()

        print(f"[*] Server ready. Waiting for connections...")
        print(f"[*] Commands: /list  /select <ip>  /quit")
        print()

        self._chat_cli()

    def _chat_cli(self):
        """Interactive chat CLI for the server operator."""
        try:
            while True:
                try:
                    line = input("server> ")
                except EOFError:
                    break

                line = line.strip()
                if not line:
                    continue

                if line.startswith("/"):
                    self._handle_command(line)
                elif self._active_client:
                    self._send_message(self._active_client, line)
                else:
                    print("[*] No client selected. Use /select <ip> or /list")
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        finally:
            self.stop()

    def _handle_command(self, cmd: str):
        parts = cmd.split()
        verb = parts[0].lower()

        if verb == "/list":
            with self._lock:
                if not self.sessions:
                    print("[*] No active sessions")
                else:
                    for ip, sess in self.sessions.items():
                        marker = " <--" if ip == self._active_client else ""
                        print(f"  {ip}  [{sess.state}]  inbox:{len(sess.inbox)}  outbox:{len(sess.outbox)}{marker}")

        elif verb == "/select" and len(parts) > 1:
            target = parts[1]
            with self._lock:
                if target in self.sessions:
                    self._active_client = target
                    print(f"[*] Selected: {target}")
                else:
                    print(f"[!] Unknown client: {target}")

        elif verb == "/quit":
            raise KeyboardInterrupt

        else:
            print(f"[?] Unknown command: {cmd}")

    def _send_message(self, client_ip: str, message: str):
        """Queue a message for the next time the client polls rx."""
        session = self._get_session(client_ip)
        with self._lock:
            session.outbox.append(message)
        print(f"[*] Queued for {client_ip} (will deliver on next rx poll)")

    def stop(self):
        """Shut down all components."""
        self.dns_server.stop()
        self.icmp.stop()
        print("[*] Stopped.")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Tracer Terminal Orchestrator")
    parser.add_argument("--payload", "-p", help="Path to chat client script to deliver")
    parser.add_argument("--domain", "-d", help="Override domain zone")
    parser.add_argument("--ip", "-i", help="Override server IP")
    args = parser.parse_args()

    if args.domain:
        from server import config
        config.DOMAIN_ZONE = args.domain
    if args.ip:
        from server import config
        config.SERVER_IP = args.ip
        config.XOR_KEY = bytes(int(o) for o in args.ip.split("."))

    orch = Orchestrator(payload_file=args.payload)
    orch.start()


if __name__ == "__main__":
    main()
