"""
Tracer Terminal - Orchestrator (Director)
Central controller that wires DNS + ICMP + ClientHub together.
Manages the per-client state machine and provides the server-side chat CLI.
"""
import os
import sys
import threading

from server.config import (
    DOMAIN_ZONE, SERVER_IP, XOR_KEY,
    STATE_IDLE, STATE_DELIVERING, STATE_CHATTING,
    MAX_PAYLOAD_BYTES, MAX_HEX_PER_HOP, USABLE_HOPS,
)
from server.shard_encoder import encode_payload, decode_message
from server.dns_handler import TracerResolver, create_dns_server
from server.icmp_tunnel import ICMPTunnel
from server.client_hub import ClientHub, ClientSession


class Orchestrator:
    """
    Director that routes DNS commands, manages ICMP tunnels via
    the ClientHub, and provides the server-side chat CLI.
    """

    def __init__(self, payload_file: str | None = None):
        self.hub = ClientHub()
        self._lock = threading.Lock()
        self._active_client_id: str | None = None

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

        self._payload_shards: list[str] = []
        if self._payload_bytes:
            self._payload_shards = encode_payload(self._payload_bytes)
            print(f"[*] Payload encoded into {len(self._payload_shards) - 1} data shards + end marker")
            print(f"[*] Capacity: {MAX_HEX_PER_HOP} hex/hop, {USABLE_HOPS} usable hops, {MAX_PAYLOAD_BYTES} bytes max")

        self.resolver = TracerResolver()
        self.resolver.set_orchestrator(self)
        self.icmp = ICMPTunnel(self.hub)
        self.dns_server = create_dns_server(self.resolver)

    def _resolve_client(self, source_ip: str) -> ClientSession:
        """Get or create a session for a source IP (DNS path)."""
        return self.hub.get_or_create(source_ip)

    # --- Command handlers (called by DNS resolver) ---

    def on_payload_request(self, client_ip: str):
        """Client requested payload delivery."""
        session = self._resolve_client(client_ip)
        if not self._payload_shards:
            print(f"\n[!] {session.display_name} requested payload but none loaded")
            return

        session.state = STATE_DELIVERING
        self.icmp.queue_shards(session.client_id, self._payload_shards)
        n = len(self._payload_shards) - 1
        print(f"\n[+] New client: {session.display_name} [{session.fingerprint.os_hint}]")
        print(f"[>] Delivering payload ({n} shards)")

    def on_tx_message(self, client_ip: str, data_labels: str):
        """Client sent an uplink message via subdomain."""
        session = self._resolve_client(client_ip)
        session.state = STATE_CHATTING
        try:
            message = decode_message(data_labels)
            session.inbox.append(message)
            print(f"\n[{session.display_name}] {message}")
        except Exception as e:
            print(f"\n[!] Failed to decode from {session.display_name}: {e}")

    def on_rx_request(self, client_ip: str):
        """Client is polling for downlink messages."""
        session = self._resolve_client(client_ip)
        session.state = STATE_CHATTING

        with self._lock:
            if session.outbox:
                message = session.outbox.pop(0)
                shards = encode_payload(message.encode("utf-8"))
                self.icmp.queue_shards(session.client_id, shards)
            else:
                end_marker = f"empty.{DOMAIN_ZONE}"
                self.icmp.queue_shards(session.client_id, [end_marker])

    def on_end(self, client_ip: str):
        """Client is disconnecting."""
        session = self._resolve_client(client_ip)
        print(f"\n[-] Client disconnected: {session.display_name}")
        self.icmp.clear_client(session.client_id)
        self.hub.remove(session.client_id)
        if self._active_client_id == session.client_id:
            self._active_client_id = None

    def get_ptr_for_hop(self, hop_ip: str) -> str | None:
        """DNS resolver calls this to get PTR hostname for a fake hop IP."""
        return self.icmp.get_ptr_hostname(hop_ip)

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
        print(f"[*] Commands: /list  /select <id|ip>  /info <id|ip>  /quit")
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
                elif self._active_client_id:
                    self._send_message(self._active_client_id, line)
                else:
                    print("[*] No client selected. Use /select <id|ip> or /list")
        except KeyboardInterrupt:
            print("\n[*] Shutting down...")
        finally:
            self.stop()

    def _handle_command(self, cmd: str):
        parts = cmd.split()
        verb = parts[0].lower()

        if verb == "/list":
            sessions = self.hub.all_sessions()
            if not sessions:
                print("[*] No active sessions")
            else:
                for s in sessions:
                    marker = " <--" if s.client_id == self._active_client_id else ""
                    age = _fmt_age(s.last_seen)
                    print(f"  {s.client_id[:8]}  {s.source_ip:>15s}  "
                          f"[{s.state:10s}]  {s.fingerprint.os_hint:12s}  "
                          f"in:{len(s.inbox)} out:{len(s.outbox)}  "
                          f"last:{age}{marker}")

        elif verb == "/select" and len(parts) > 1:
            sess = self.hub.resolve_selector(parts[1])
            if sess:
                self._active_client_id = sess.client_id
                print(f"[*] Selected: {sess.display_name}")
            else:
                print(f"[!] No client matching: {parts[1]}")

        elif verb == "/info" and len(parts) > 1:
            sess = self.hub.resolve_selector(parts[1])
            if sess:
                print(f"  Client ID:    {sess.client_id}")
                print(f"  Source IP:     {sess.source_ip}")
                print(f"  State:         {sess.state}")
                print(f"  OS hint:       {sess.fingerprint.os_hint}")
                print(f"  Initial TTL:   {sess.fingerprint.initial_ttl}")
                print(f"  Payload hash:  {sess.fingerprint.icmp_payload_hash or 'n/a'}")
                print(f"  Inbox:         {len(sess.inbox)} messages")
                print(f"  Outbox:        {len(sess.outbox)} messages")
                print(f"  Last seen:     {_fmt_age(sess.last_seen)} ago")
            else:
                print(f"[!] No client matching: {parts[1]}")

        elif verb == "/quit":
            raise KeyboardInterrupt

        else:
            print(f"[?] Unknown command: {cmd}")
            print(f"[*] Commands: /list  /select <id|ip>  /info <id|ip>  /quit")

    def _send_message(self, client_id: str, message: str):
        """Queue a message for the next time the client polls rx."""
        session = self.hub.get_by_id(client_id)
        if not session:
            print("[!] Selected client no longer connected")
            self._active_client_id = None
            return
        with self._lock:
            session.outbox.append(message)
        print(f"[*] Queued for {session.display_name} (will deliver on next rx poll)")

    def stop(self):
        """Shut down all components."""
        self.dns_server.stop()
        self.icmp.stop()
        print("[*] Stopped.")


def _fmt_age(timestamp: float) -> str:
    """Format a timestamp as a human-readable age string."""
    import time
    delta = int(time.time() - timestamp)
    if delta < 60:
        return f"{delta}s"
    elif delta < 3600:
        return f"{delta // 60}m{delta % 60}s"
    else:
        return f"{delta // 3600}h{(delta % 3600) // 60}m"


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
