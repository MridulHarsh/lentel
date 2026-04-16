# Lentel

**Send any file or folder, any size, to anyone — no server, no port forwarding.**

[![CI](https://github.com/MridulHarsh/lentel/actions/workflows/ci.yml/badge.svg)](https://github.com/MridulHarsh/lentel/actions/workflows/ci.yml)
[![Release](https://github.com/MridulHarsh/lentel/actions/workflows/release.yml/badge.svg)](https://github.com/MridulHarsh/lentel/releases/latest)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

Lentel is a from-scratch file transfer protocol and application. No
existing protocol is used — the wire format, handshake, reliability
layer, congestion controller, NAT traversal, and application framing are
all new. The only runtime dependency is `cryptography` for AEAD and
key-exchange primitives.

**Receiver-first, consent-based**: the person who *wants* a file opens a
receive session, gets a ticket, and gives it to the sender. The sender
then uses that ticket to push the file. Nothing lands on a device that
hasn't opened itself up for a transfer.

## Download

| Platform | Download | Notes |
|----------|----------|-------|
| **macOS** | [Lentel-macOS.dmg](https://github.com/MridulHarsh/lentel/releases/latest/download/Lentel-macOS.dmg) | Open DMG, drag to Applications. Menu-bar app. |
| **Windows** | [Lentel.exe](https://github.com/MridulHarsh/lentel/releases/latest/download/Lentel.exe) | Single file. Runs in the system tray. |
| **Any OS (pip)** | `pip install lentel` | CLI + Python API. Add `[tray]` for the GUI. |

### macOS: "Lentel is damaged and can't be opened"

This is **not** a broken app. Apple's Gatekeeper shows this for anything
not signed with a $99/year Apple Developer cert. The DMG includes a
helper — **`Fix damaged app error.command`** — that one-shots the fix.
Or run:
```bash
xattr -cr /Applications/Lentel.app
```

## How it works

```
 Receiver                                             Sender
    │                                                    │
    │  1. Click "Receive"                                 │
    │     → discover public IP:port via STUN/UPnP         │
    │     → ticket:                                       │
    │          bold-crab-fern-42@203.0.113.5:54321        │
    │     → wait for a connection                         │
    │                                                     │
    │                       ← shares ticket (any channel) │
    │                                                     │
    │                                      2. Click "Send"│
    │                                         paste ticket│
    │                                         pick file   │
    │                                                     │
    │  ◀═══════════════ direct UDP flow ═════════════════▶│
    │                                                     │
    │  3. X25519 + ChaCha20-Poly1305 handshake            │
    │  4. Parallel encrypted transfer (4 streams)         │
    │  5. BLAKE2b Merkle verification                     │
    │                                                     │
    ✓  File or folder saved                          ✓ Sent
```

**No coordinator, no relay, no account.** The ticket *is* the rendezvous
address.

## Why receiver-first

- **Consent model.** You have to actively open a receive session before
  anyone can push a file to you. No drive-by transfers.
- **Tickets are single-use.** Close the receive dialog and the ticket
  expires — the socket is gone.
- **Easier on NAT.** The receiver is the one maintaining a STUN-warmed
  UDP mapping. The sender just opens an outbound flow, which every NAT
  lets through.

## Desktop app

Click the **L** icon in your menu bar / system tray:

```
  ↓ Receive a file or folder…   ← generates a ticket, waits
  ──────────────────
  ↑ Send a file…                 ← paste ticket, pick file
  ↑ Send a folder…               ← paste ticket, pick folder
  ──────────────────
  Active transfers ▸
    ↑ video.mkv  72%  45 MB/s
  Clear finished
  ──────────────────
  Copy last ticket
  Open downloads folder
  ──────────────────
  Settings ▸
    Downloads folder…
    Parallel streams: 4
  ──────────────────
  About · Quit
```

The icon lights up blue when a transfer is in progress.

## CLI

```bash
pip install lentel
```

**Receiver** (the one who wants a file): generates a ticket and waits.

```
$ lentel recv
  Discovering public address…
  Public address: 203.0.113.5:54321 (stun)

ticket: bold-crab-fern-42@203.0.113.5:54321
give this ticket to the sender.

  Waiting for sender…
  Sender connected from 198.51.100.9:42001 — handshaking…
  Receiving…

 [##############################] 100.0%  612.0 MB  48 MB/s  eta 0s
saved to ./video.mkv
```

**Sender**: takes the ticket as the first argument, file path as the second.

```
$ lentel send bold-crab-fern-42@203.0.113.5:54321 ./video.mkv
sending file video.mkv (612.0 MB)
  Resolving 203.0.113.5…
  Connecting to receiver at 203.0.113.5:54321…
  Handshake complete — transferring…

 [##############################] 100.0%  612.0 MB  48 MB/s  eta 0s
transfer complete.
```

Works the same for folders — `lentel send <ticket> ./my-folder`.

## Python API

```python
import asyncio
from lentel import recv_file, send_file

# Receiver
async def receive():
    path = await recv_file(
        dest_dir="./downloads",
        on_ticket=lambda t: print(f"ticket: {t}"),
    )
    print("saved to", path)

# Sender (on the other machine)
async def send():
    await send_file("./video.mkv", "bold-crab-fern-42@203.0.113.5:54321")

asyncio.run(receive())   # or send()
```

## Security

| Layer | Primitive |
|-------|-----------|
| Key exchange | X25519 ephemeral + ticket PSK |
| Encryption | ChaCha20-Poly1305 AEAD (every packet) |
| Integrity | BLAKE2b Merkle tree, per-file root, 64 KiB chunks |
| Authentication | 3-message Noise-style handshake (ticket = pre-shared key) |
| Nonces | Deterministic from (direction, stream, sequence) — never reused |

- The ticket's word-code is hashed into a 32-byte PSK. Without that PSK
  an attacker cannot complete the handshake, even if they intercept the
  ticket string.
- A passive eavesdropper cannot see file names, sizes, or contents.
- Tickets are ephemeral — a new one is generated each receive session.

Full wire specification: [PROTOCOL.md](PROTOCOL.md)

## Why it's fast

| Feature | What it does |
|---------|-------------|
| **BBR-inspired congestion** | Loss-tolerant; keeps probing bandwidth instead of halving on every drop |
| **4 parallel streams** | Shares one UDP socket + one cipher state; no head-of-line blocking |
| **Selective ACK + NACK** | Fast retransmit at 1.5×SRTT; explicit retransmit requests for integrity failures |
| **64 KiB chunks, multi-file** | Folders transferred as a tree with per-file Merkle roots — no zipping |
| **Resumable** | On reconnect the sender skips already-verified chunks |

## Why no port forwarding

The **receiver** discovers its public address automatically:

1. **UPnP (tried first)** — asks the local router to open a port via
   IGD SOAP. Works on most home routers. If it succeeds, the receiver is
   publicly reachable regardless of NAT type.
2. **STUN (fallback)** — queries free public STUN servers
   (`stun.l.google.com`, `stun.cloudflare.com`) to learn the NAT's
   external IP:port. The receiver sends STUN keepalives while listening
   to hold the mapping open. Works with cone-type NATs (~75 %+ of
   consumer routers).

The discovered address is embedded in the ticket. The sender parses it
and connects directly.

If the receiver's NAT is strict enough that neither UPnP nor STUN
punches a hole (rare — mostly symmetric NATs on mobile carriers), the
sender's HELLO may not reach the receiver. Usual remedies: enable UPnP
on the receiver's router, try from a different network (mobile hotspot,
a friend's Wi-Fi), or use a host with a real public IP.

## Project layout

```
lentel/
├── wire.py            # Packet framing (20-byte header, type codes)
├── crypto.py          # X25519 handshake + ChaCha20-Poly1305 AEAD
├── congestion.py      # BBR-lite controller (STARTUP/DRAIN/PROBE_BW/PROBE_RTT)
├── transport.py       # Reliable UDP: SACK, NACK, pacing, parallel streams
├── nat.py             # STUN + UPnP; responder_wait_for_hello()
├── chunker.py         # File/folder → 64 KiB chunks + Merkle tree
├── session.py         # Send/recv state machines + resume
├── rendezvous.py      # Orchestrates: recv_file generates ticket; send_file uses it
├── wordlist.py        # Ticket encoding (words + checksum + @IP:PORT)
├── cli.py             # `lentel recv` / `lentel send`
└── app/               # macOS menu-bar / Windows system-tray GUI
```

## Building from source

**macOS**
```bash
cd packaging/macos && ./build.sh
open dist/Lentel.app
```

**Windows**
```powershell
cd packaging\windows
.\build.ps1
.\dist\Lentel.exe
```

**Pip (any OS)**
```bash
pip install 'lentel[tray]'
python -m lentel.app
```

Every version tag pushed to GitHub triggers a workflow that builds both
platforms and publishes them as [release assets](https://github.com/MridulHarsh/lentel/releases).

## Running tests

```bash
pip install -e . && pip install pytest
python -m pytest tests/ -v
```

33 tests: 26 unit (wire, crypto, chunker, congestion, wordlist, STUN) + 7
end-to-end (single-file + folder loopback transfers through the full
receiver-first pipeline).

## License

Apache 2.0
