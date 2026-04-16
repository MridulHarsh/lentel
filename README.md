# Lentel

**Send any file or folder, any size, to anyone — no server, no port forwarding.**

[![CI](https://github.com/MridulHarsh/lentel/actions/workflows/ci.yml/badge.svg)](https://github.com/MridulHarsh/lentel/actions/workflows/ci.yml)
[![Release](https://github.com/MridulHarsh/lentel/actions/workflows/release.yml/badge.svg)](https://github.com/MridulHarsh/lentel/releases/latest)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

Lentel is a from-scratch file transfer protocol and application. No existing
protocol is used — the wire format, handshake, reliability layer, congestion
controller, NAT traversal, and application framing are all new. The only
runtime dependency is `cryptography` for AEAD and key-exchange primitives.

**No server of any kind is required.** The sender's public address is
discovered automatically via STUN/UPnP and embedded in the ticket. The
receiver connects directly.

## Download

| Platform | Download | Notes |
|----------|----------|-------|
| **macOS** | [Lentel-macOS.dmg](https://github.com/MridulHarsh/lentel/releases/latest/download/Lentel-macOS.dmg) | Open DMG, drag to Applications. Menu-bar app (no dock icon). |
| **Windows** | [Lentel.exe](https://github.com/MridulHarsh/lentel/releases/latest/download/Lentel.exe) | Single file. Run it — appears in the system tray. |
| **Any OS (pip)** | `pip install lentel` | CLI + Python API. Add `[tray]` for the GUI. |

### macOS: "Lentel is damaged and can't be opened"

This is **not** actually a damaged app. Apple's Gatekeeper shows this
error for any app that isn't signed with a paid ($99/year) Apple
Developer certificate — every open-source Mac app distributed outside
the App Store hits this. Two ways to fix it:

1. **Use the included helper**: after opening the DMG, double-click
   **`Fix 'damaged app' error.command`**. It runs a one-line command that
   strips the quarantine attribute. Then launch Lentel normally.

2. **Or run it yourself** in Terminal:
   ```bash
   xattr -cr /Applications/Lentel.app
   ```
   Then launch Lentel normally. You only need to do this once.

## How it works

```
 Sender                                              Receiver
   │                                                     │
   │  1. Discovers own public IP:port                    │
   │     via free STUN servers (Google, Cloudflare)      │
   │     + optional UPnP port mapping                    │
   │                                                     │
   │  2. Generates ticket:                               │
   │     bold-crab-fern-42@203.0.113.5:54321             │
   │                   ─────────────────────▶            │
   │     (share via chat, email, phone, etc.)            │
   │                                                     │
   │                                       3. Parses IP  │
   │                                          from ticket│
   │                                                     │
   │  ◀════════════ direct UDP connection ══════════════▶ │
   │                                                     │
   │  4. X25519 + ChaCha20-Poly1305 handshake            │
   │  5. Parallel encrypted transfer (4 streams)         │
   │  6. BLAKE2b Merkle verification                     │
   │                                                     │
   ✓  Done — no server touched any of your data          ✓
```

**No coordinator, no relay, no account, no signup.** The ticket IS the
connection string.

## Desktop app

The tray app runs in your **macOS menu bar** or **Windows system tray**:

```
  ↑ Send a file…          ← pick a file, get a ticket
  ↑ Send a folder…        ← pick a folder, transferred as a tree (no zipping)
  ↓ Receive…              ← paste a ticket, get the file or folder
  ──────────────────
  Active transfers ▸
    ↑ video.mkv  72%  45.2 MB/s
  Clear finished
  ──────────────────
  Copy last ticket
  Open downloads folder
  ──────────────────
  Settings ▸
    Downloads folder…
    Parallel streams: 4
  ──────────────────
  About
  Quit
```

The icon lights up blue when a transfer is active.

## CLI

```bash
pip install lentel
```

**Send a file:**
```
$ lentel send ./video.mkv
  Discovering public address…
  Public address: 203.0.113.5:54321 (stun)

ticket: bold-crab-fern-42@203.0.113.5:54321
share it with the receiver.
waiting for peer...

 [####################----------] 65.0%  421.3 MB/612.0 MB  52.7 MB/s  eta 3s
```

**Send a folder** (transferred as a tree — no zipping):
```
$ lentel send ./my-project
  preparing folder my-project (42.3 MB)
  Discovering public address…
ticket: bold-crab-fern-42@203.0.113.5:54321
```

**Receive:**
```
$ lentel recv bold-crab-fern-42@203.0.113.5:54321
  Connecting to sender…
  Connected — handshaking…
  Receiving…

 [##############################] 100.0%  612.0 MB/612.0 MB  48.1 MB/s  eta 0s
saved to ./video.mkv
```

That's it. No flags, no config, no server URL.

## Python API

```python
import asyncio
from lentel import send_file, recv_file

# Sender
async def send():
    ticket = await send_file(
        "./video.mkv",
        on_ticket=lambda t: print(f"ticket: {t}"),
    )

# Receiver (on another machine)
async def receive():
    path = await recv_file(
        "bold-crab-fern-42@203.0.113.5:54321",
        dest_dir="./downloads",
    )
    print(f"saved to {path}")

asyncio.run(send())   # or receive()
```

## Why it's fast

| Feature | What it does |
|---------|-------------|
| **BBR-inspired congestion** | Loss-tolerant — keeps probing bandwidth instead of halving on every drop |
| **4 parallel streams** | Shares one UDP socket + one cipher state; no head-of-line blocking |
| **Selective ACK + NACK** | Fast retransmit at 1.5x SRTT; explicit retransmit requests for integrity failures |
| **64 KiB chunks** | Hashed with BLAKE2b, verified on receive, written directly to disk |
| **Resumable** | Reconnect and the sender skips already-verified chunks |

## Why you don't need port forwarding

Lentel discovers the sender's reachable address automatically:

1. **UPnP (tried first)** — asks your router to open a port via IGD SOAP.
   Works on most home routers. If it succeeds, you're reachable from anywhere.

2. **STUN (fallback)** — queries free public STUN servers (`stun.l.google.com`,
   `stun.cloudflare.com`) to learn your NAT's external IP:port. The sender
   keeps the mapping alive with periodic keepalives. Works with cone-type NATs
   (~75%+ of consumer routers).

The discovered address is embedded in the ticket. The receiver connects
directly — no middleman.

## Security

| Layer | Primitive |
|-------|-----------|
| Key exchange | X25519 ephemeral + ticket PSK |
| Encryption | ChaCha20-Poly1305 AEAD (every packet) |
| Integrity | BLAKE2b Merkle tree over 64 KiB chunks |
| Authentication | 3-message Noise-style handshake (ticket = pre-shared key) |
| Nonces | Deterministic from (direction, stream, sequence) — never reused |

- The ticket's word code is hashed into a 32-byte PSK. Without it, an
  attacker cannot complete the handshake or decrypt any packet.
- A passive eavesdropper cannot see the file name, size, or contents.
- Tickets are single-use and ephemeral — a new one is generated per transfer.

Full wire specification: [PROTOCOL.md](PROTOCOL.md)

## Project layout

```
lentel/
├── wire.py            # Packet framing (20-byte header, type codes)
├── crypto.py          # X25519 handshake + ChaCha20-Poly1305 AEAD
├── congestion.py      # BBR-lite controller (STARTUP/DRAIN/PROBE_BW/PROBE_RTT)
├── transport.py       # Reliable UDP: SACK, NACK, pacing, parallel streams
├── nat.py             # STUN client (RFC 5389) + UPnP IGD port mapping
├── chunker.py         # File → 64 KiB chunks + BLAKE2b Merkle tree
├── session.py         # Send/recv state machines + resume
├── rendezvous.py      # Orchestrates: discover → ticket → punch → transfer
├── wordlist.py        # Ticket encoding (words + checksum + @IP:PORT)
├── cli.py             # `lentel send` / `lentel recv`
├── app/               # macOS menu-bar / Windows system-tray GUI
│   ├── tray.py        #   pystray Icon + dynamic Menu
│   ├── dialogs.py     #   osascript (macOS) / tkinter (Windows) prompts
│   ├── state.py       #   Thread-safe transfer registry + config
│   ├── runner.py      #   Asyncio event loop on worker thread
│   └── icon.py        #   Procedurally drawn tray icon
└── server/            # (Optional) coordinator + relay for legacy/fallback
```

## Building from source

**macOS:**
```bash
cd packaging/macos && ./build.sh
open dist/Lentel.app
```

**Windows:**
```powershell
cd packaging\windows
.\build.ps1
.\dist\Lentel.exe
```

**From pip (any OS):**
```bash
pip install 'lentel[tray]'
python -m lentel.app
```

Builds are automated — every version tag pushed to GitHub triggers a
[GitHub Actions workflow](.github/workflows/release.yml) that builds both
platforms and publishes them as release assets.

## Running tests

```bash
pip install -e . && pip install pytest
python -m pytest tests/ -v
```

24 tests: 20 unit (wire, crypto, chunker, congestion, wordlist, STUN) +
4 end-to-end (loopback transfers through the full pipeline).

## How to release a new version

```bash
# Bump version in pyproject.toml and lentel/__init__.py, then:
git add -A && git commit -m "v1.1.0"
git tag v1.1.0
git push origin main v1.1.0
```

GitHub Actions will automatically build `Lentel-macOS.dmg` + `Lentel.exe`
and publish them as a [GitHub Release](https://github.com/MridulHarsh/lentel/releases).

## License

Apache 2.0
