# Lentel

**A new file-transfer protocol for moving any file, of any size, between
any two hosts on the Internet — with no port forwarding.**

Lentel is a from-scratch protocol and reference implementation. It does not
sit on top of QUIC, WebRTC, libp2p, BitTorrent, rsync, KCP, Magic-Wormhole,
or any other existing transfer system. The wire format, handshake,
reliability layer, congestion controller, NAT-traversal, and application
framing live in this repository.

The full wire specification is in [PROTOCOL.md](PROTOCOL.md).

## Why it's fast

- **BBR-inspired congestion control.** Loss-tolerant: Lentel keeps probing
  bandwidth instead of halving on every dropped packet, so transient drops
  on a congested hop don't collapse throughput.
- **Parallel multiplexed streams.** Four streams by default, sharing a
  single UDP socket and a single cipher state, so the aggregate pacer can
  saturate the path.
- **Custom reliability.** Selective ACKs with explicit NACKs and timer-based
  retransmits. No kernel TCP stack, no head-of-line blocking across streams.
- **Zero-copy-friendly chunks.** 64 KiB chunks, hashed with BLAKE2b and
  verified on receive, write directly to disk — the receiver never buffers
  the whole file.
- **Resumable.** If the link breaks, the receiver's already-verified chunks
  are replayed on reconnect and the sender skips them.

## Why you don't need port forwarding

Lentel ships with a tiny rendezvous **coordinator** (~200 lines of Python).
Both peers make an *outbound* TCP connection to the coordinator. The
coordinator observes each peer's reflexive UDP address and tells them to
begin UDP hole-punching simultaneously. Most home and mobile NATs will
accept an inbound datagram on a mapping that was just used outbound — so a
direct peer-to-peer UDP path comes up without either user touching a router.

For the small fraction of symmetric-NAT pairs where hole punching fails,
the coordinator issues a relay token and the same Lentel session runs
end-to-end through a **relay** (also shipped in this repo). The relay
cannot decrypt anything — it only forwards datagrams.

## Architecture

```
 Sender                 Coordinator                 Receiver
  ───┐                  ┌────────────┐                ┌───
     │── register(tkt) ─▶            ◀── redeem(tkt) ─│
     │                  │  matches    │                │
     │◀─ peer addr ─────│ + punch-at  │──── peer addr ─▶
     │                  └────────────┘                │
     │                                                │
     │═════════════ UDP hole punch ═════════════════▶ │
     │◀════════════ UDP hole punch ════════════════════│
     │                                                │
     │ ╔══════════════════════════════════════════╗  │
     │ ║  Lentel session: handshake, N streams,   ║  │
     │ ║  AEAD, BBR-lite, SACK/NACK, Merkle check ║  │
     │ ╚══════════════════════════════════════════╝  │
```

## Install

The reference implementation is pure Python 3.11+ and depends only on the
`cryptography` library for the AEAD and KEX primitives:

```
pip install -e .
```

## Quick start

Run a coordinator somewhere with a public IP (a cheap $5 VPS is plenty —
the coordinator pushes negligible traffic):

```
lentel-coordinator --bind 0.0.0.0:7777
```

Send a file. You get a ticket; share it with the receiver however you like:

```
$ lentel send --coordinator wss://coord.example.com:7777 ./video.mkv
ticket: swift-otter-41
waiting for peer...
```

Receive it:

```
$ lentel recv --coordinator wss://coord.example.com:7777 swift-otter-41
receiving video.mkv (8.4 GiB)
 ███████████████████████████████  100%  612 MB/s  eta 0s
verified. written to ./video.mkv
```

If no `--coordinator` is given, the client uses the default public one
specified in `~/.lentel/config.toml`, or the environment variable
`LENTEL_COORDINATOR`.

## Running your own relay (optional)

```
lentel-relay --bind 0.0.0.0:7778 --coordinator https://coord.example.com:7777
```

The coordinator will advertise the relay automatically.

## Python API

```python
import asyncio
from lentel import send_file, recv_file

async def main():
    ticket = await send_file("./video.mkv", coordinator="wss://coord.example.com:7777")
    print("ticket:", ticket)

asyncio.run(main())
```

```python
import asyncio
from lentel import recv_file

async def main():
    path = await recv_file("swift-otter-41", dest_dir="./downloads",
                           coordinator="wss://coord.example.com:7777")
    print("saved to", path)

asyncio.run(main())
```

## Layout

```
lentel/
├── PROTOCOL.md            # Wire specification
├── README.md              # You are here
├── pyproject.toml
├── lentel/
│   ├── __init__.py        # public API
│   ├── wire.py            # packet framing & types
│   ├── crypto.py          # handshake + AEAD
│   ├── congestion.py      # BBR-lite controller
│   ├── transport.py       # reliable UDP + streams
│   ├── nat.py             # hole punching + relay switch
│   ├── chunker.py         # file → chunks + Merkle
│   ├── session.py         # send/recv session state machines
│   ├── rendezvous.py      # client protocol for coordinator
│   ├── wordlist.py        # ticket wordlist
│   ├── cli.py             # lentel send / lentel recv
│   └── server/
│       ├── coordinator.py # public rendezvous server
│       └── relay.py       # symmetric-NAT fallback
├── examples/
│   ├── send.py
│   └── recv.py
└── tests/
    └── test_wire.py
```

## Status

Reference implementation of v1 of the protocol. The wire format is
frozen for the v1 line; future changes will bump `VER` in the header.
