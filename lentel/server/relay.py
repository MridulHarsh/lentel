"""
Lentel relay.

The relay is a stateless (per-pair) UDP forwarder used when hole-punching
fails. Each peer sends a small registration packet carrying the shared
match cookie (as a token); the relay pairs two peers that present the same
token and then blindly forwards every subsequent packet between them.

The relay never possesses the peers' AEAD keys — it cannot read or tamper
with payloads. Its sole job is to deliver bytes between addresses.

Registration wire format:

    "LNTLRLY\\x00" || token (16 bytes, hex-decoded from the coordinator)

Registration ACK:

    "LNTLRLY\\x00" || token || 0xFF
"""
from __future__ import annotations

import argparse
import asyncio
import time
from typing import Optional

RELAY_MAGIC = b"LNTLRLY\x00"
TOKEN_LEN = 16
PAIR_TTL = 1800.0  # seconds — drop a half-registered pair after 30 min


class _Relay(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None
        # token -> list of peer addresses (at most 2)
        self.pairs: dict[bytes, list[tuple[str, int]]] = {}
        # routes[addr] = counterpart addr
        self.routes: dict[tuple[str, int], tuple[str, int]] = {}
        # bookkeeping for TTL cleanup
        self.first_seen: dict[bytes, float] = {}

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        if self.transport is None:
            return

        # --- registration path -------------------------------------------
        if (
            len(data) >= len(RELAY_MAGIC) + TOKEN_LEN
            and data[: len(RELAY_MAGIC)] == RELAY_MAGIC
        ):
            token = data[len(RELAY_MAGIC) : len(RELAY_MAGIC) + TOKEN_LEN]
            peers = self.pairs.setdefault(token, [])
            if addr not in peers:
                peers.append(addr)
                self.first_seen.setdefault(token, time.monotonic())
            # When we have two distinct peers, wire them up.
            if len(peers) == 2:
                a, b = peers
                self.routes[a] = b
                self.routes[b] = a
                ack = RELAY_MAGIC + token + b"\xff"
                self.transport.sendto(ack, a)
                self.transport.sendto(ack, b)
            else:
                # Ack the lone peer so its registration loop can exit soon.
                ack = RELAY_MAGIC + token + b"\x00"
                self.transport.sendto(ack, addr)
            self._gc()
            return

        # --- data path ---------------------------------------------------
        dst = self.routes.get(addr)
        if dst is not None:
            self.transport.sendto(data, dst)

    def _gc(self) -> None:
        # Evict half-registered pairs that never saw a second peer.
        now = time.monotonic()
        stale = [
            t for t, ts in self.first_seen.items()
            if now - ts > PAIR_TTL and len(self.pairs.get(t, [])) < 2
        ]
        for t in stale:
            peers = self.pairs.pop(t, [])
            for a in peers:
                self.routes.pop(a, None)
            self.first_seen.pop(t, None)


async def run_relay(host: str, port: int) -> None:
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        _Relay, local_addr=(host, port),
    )
    print(f"lentel-relay listening on {host}:{port}")
    try:
        await asyncio.Event().wait()
    finally:
        transport.close()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lentel-relay")
    p.add_argument("--bind", default="0.0.0.0:7778",
                   help="host:port for UDP (default 0.0.0.0:7778)")
    args = p.parse_args(argv)
    host, port_s = args.bind.rsplit(":", 1)
    try:
        asyncio.run(run_relay(host, int(port_s)))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
