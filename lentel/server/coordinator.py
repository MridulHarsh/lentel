"""
Lentel rendezvous coordinator.

Responsibilities:
  - UDP "STUN" echo: reply to probes telling each peer its reflexive address.
  - TCP registration: match sender and receiver by ticket label.
  - On match: send both sides the peer's address, a synchronized punch_at
    time (~2 s in the future), and a shared 128-bit cookie.
  - On `request_relay`: if a relay is configured, hand each peer the relay
    address and reuse the match cookie as the relay token.

Runs in about 200 lines of code. Put this on any VPS with a public IP — it
moves negligible traffic (only metadata) and supports many concurrent
transfers with no per-transfer state beyond the short matchmaking window.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

STUN_MAGIC = b"LNTLSTUN"
STUN_PROBE = 0x01
STUN_REPLY = 0x02
DEFAULT_PUNCH_DELAY = 2.0
MAX_LABEL_LEN = 128
MAX_FRAME = 1 << 20


def _pack_addr(ip: str, port: int) -> bytes:
    return struct.pack("!H", port) + socket.inet_aton(ip)


class _StunEcho(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport) -> None:  # type: ignore[override]
        self.transport = transport

    def datagram_received(self, data, addr) -> None:  # type: ignore[override]
        if self.transport is None:
            return
        if len(data) < len(STUN_MAGIC) + 1 + 8:
            return
        if data[: len(STUN_MAGIC)] != STUN_MAGIC:
            return
        if data[len(STUN_MAGIC)] != STUN_PROBE:
            return
        nonce = data[len(STUN_MAGIC) + 1 : len(STUN_MAGIC) + 9]
        reply = (
            STUN_MAGIC + bytes([STUN_REPLY]) + nonce
            + _pack_addr(addr[0], addr[1])
        )
        self.transport.sendto(reply, addr)


@dataclass
class _Pending:
    role: str                       # "send" or "recv"
    label: str
    reflexive: dict                 # {"ip": str, "port": int}
    writer: asyncio.StreamWriter
    reader: asyncio.StreamReader
    matched: asyncio.Event = field(default_factory=asyncio.Event)
    cookie: str = ""                # filled in on match


class Coordinator:
    def __init__(
        self,
        tcp_port: int,
        udp_port: int,
        relay_addr: Optional[tuple[str, int]] = None,
        punch_delay: float = DEFAULT_PUNCH_DELAY,
    ):
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.relay_addr = relay_addr
        self.punch_delay = punch_delay
        self._pending: dict[str, list[_Pending]] = {}
        self._lock = asyncio.Lock()

    async def run(self) -> None:
        loop = asyncio.get_event_loop()
        udp_transport, _ = await loop.create_datagram_endpoint(
            _StunEcho, local_addr=("0.0.0.0", self.udp_port),
        )
        server = await asyncio.start_server(
            self._handle, host="0.0.0.0", port=self.tcp_port,
        )
        addr = f"tcp=:{self.tcp_port} udp=:{self.udp_port}"
        if self.relay_addr:
            addr += f" relay={self.relay_addr[0]}:{self.relay_addr[1]}"
        print(f"lentel-coordinator listening: {addr}")
        try:
            async with server:
                await server.serve_forever()
        finally:
            udp_transport.close()

    # ------ framing --------------------------------------------------------

    async def _send(self, writer: asyncio.StreamWriter, obj: dict) -> None:
        buf = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        writer.write(struct.pack("!I", len(buf)) + buf)
        await writer.drain()

    async def _recv(self, reader: asyncio.StreamReader,
                    timeout: float = 600.0) -> dict:
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        (length,) = struct.unpack("!I", hdr)
        if length > MAX_FRAME:
            raise ValueError("oversized frame")
        buf = await reader.readexactly(length)
        return json.loads(buf.decode("utf-8"))

    # ------ connection lifecycle ------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        conn: Optional[_Pending] = None
        try:
            msg = await self._recv(reader, timeout=10.0)
            if msg.get("op") != "register":
                await self._send(writer, {"op": "error", "msg": "expected register"})
                return
            role = msg.get("role")
            label = (msg.get("label") or "").strip()
            reflexive = msg.get("reflexive") or {}
            if role not in ("send", "recv") or not label or len(label) > MAX_LABEL_LEN:
                await self._send(writer, {"op": "error", "msg": "bad register"})
                return
            if "ip" not in reflexive or "port" not in reflexive:
                await self._send(writer, {"op": "error", "msg": "missing reflexive"})
                return

            conn = _Pending(role=role, label=label, reflexive=reflexive,
                            writer=writer, reader=reader)

            peer: Optional[_Pending] = None
            async with self._lock:
                entries = self._pending.setdefault(label, [])
                for e in entries:
                    if e.role != role:
                        peer = e
                        break
                if peer is not None:
                    entries.remove(peer)
                else:
                    entries.append(conn)
                if not entries and label in self._pending and peer is not None:
                    del self._pending[label]

            await self._send(writer, {"op": "registered"})

            if peer is not None:
                await self._match(conn, peer)
            else:
                try:
                    await asyncio.wait_for(conn.matched.wait(), timeout=600.0)
                except asyncio.TimeoutError:
                    async with self._lock:
                        entries = self._pending.get(label, [])
                        if conn in entries:
                            entries.remove(conn)
                            if not entries:
                                self._pending.pop(label, None)
                    await self._send(writer, {"op": "error",
                                              "msg": "timed out waiting for peer"})
                    return

            # Matched: shuttle relay requests / punch confirmations.
            await self._post_match(conn)

        except asyncio.IncompleteReadError:
            pass
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            try:
                await self._send(writer, {"op": "error", "msg": str(e)})
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _match(self, conn: _Pending, peer: _Pending) -> None:
        sender, receiver = (conn, peer) if conn.role == "send" else (peer, conn)
        punch_at = time.time() + self.punch_delay
        cookie = secrets.token_hex(16)
        sender.cookie = cookie
        receiver.cookie = cookie

        await self._send(sender.writer, {
            "op": "match",
            "peer": receiver.reflexive,
            "punch_at": punch_at,
            "cookie": cookie,
            "session_role": "initiator",
        })
        await self._send(receiver.writer, {
            "op": "match",
            "peer": sender.reflexive,
            "punch_at": punch_at,
            "cookie": cookie,
            "session_role": "responder",
        })
        peer.matched.set()
        conn.matched.set()

    async def _post_match(self, conn: _Pending) -> None:
        try:
            while True:
                msg = await self._recv(conn.reader, timeout=120.0)
                op = msg.get("op")
                if op == "request_relay":
                    if self.relay_addr is None:
                        await self._send(conn.writer, {
                            "op": "error", "msg": "relay not configured"
                        })
                    else:
                        await self._send(conn.writer, {
                            "op": "relay",
                            "relay": {"ip": self.relay_addr[0],
                                      "port": self.relay_addr[1]},
                            "token": conn.cookie,
                        })
                elif op == "punched":
                    return
                else:
                    # Unknown op; ignore to keep forward compat.
                    continue
        except Exception:
            return


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="lentel-coordinator")
    p.add_argument("--bind", default="0.0.0.0:7777",
                   help="host:port for TCP (UDP uses the same port by default)")
    p.add_argument("--udp-port", type=int, default=None,
                   help="override the UDP port (default: same as TCP port)")
    p.add_argument("--relay", default=None, metavar="HOST:PORT",
                   help="advertise a relay for symmetric-NAT fallback")
    p.add_argument("--punch-delay", type=float, default=DEFAULT_PUNCH_DELAY,
                   help="seconds into the future to schedule hole-punch")
    args = p.parse_args(argv)

    host, tcp_port_s = args.bind.rsplit(":", 1)
    tcp_port = int(tcp_port_s)
    udp_port = args.udp_port or tcp_port
    relay_addr: Optional[tuple[str, int]] = None
    if args.relay:
        rh, rp = args.relay.rsplit(":", 1)
        relay_addr = (rh, int(rp))
    coord = Coordinator(tcp_port, udp_port, relay_addr,
                        punch_delay=args.punch_delay)
    try:
        asyncio.run(coord.run())
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
