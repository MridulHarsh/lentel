"""
Lentel reliable UDP transport.

Built on top of the wire format and crypto modules, this layer provides:
  - Per-stream reliable in-order delivery of discrete messages.
  - Selective-ACK with fast retransmit (fires on gap older than 1.5×SRTT).
  - Pacing driven by the BBR-lite congestion controller.
  - Parallel streams sharing one UDP socket, one AEAD state, and one BBR.
  - RTT measurement via ACK timestamp echo (no separate PING required).

The transport does not interpret message content. A `Session.send(stream,
bytes)` call yields exactly one `Session.recv(stream) -> bytes` on the far
side. Framing above that (manifests, chunk headers) is the job of session.py.

**Nonce discipline (important):** AEAD nonces are derived from (direction,
stream_id, sequence). Two disjoint counter spaces are used per direction:

  - stream_id 0 is reserved for handshake (HELLO/HELLO_ACK/HS_DONE) and
    transport-control packets (ACK, NACK, PING, PONG, CLOSE). These share a
    single monotonic counter per direction. The initiator's counter starts
    at 1 because HS_DONE consumed sequence 0; the responder's starts at 0.
  - stream_id >= 1 is reserved for application DATA. Each data stream has
    its own per-direction counter starting at 0.

Because the spaces never overlap, no AEAD nonce is ever reused under the
same key.
"""
from __future__ import annotations

import asyncio
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from .congestion import BBRLite, MSS
from .crypto import AEAD, HandshakeKeys
from .wire import (
    AEAD_TAG_SIZE, Direction, Flag, HEADER_SIZE, Header, MAX_PAYLOAD,
    PacketType, decode_header, derive_nonce, encode_header,
)

RETX_POLL_INTERVAL = 0.01
MIN_RTO = 0.05
MAX_RETRIES = 20
SACK_MAX_RANGES = 16
INITIAL_SRTT = 0.1
ACK_BATCH_DELAY = 0.002

# Reserved stream id: 0 for handshake + transport control. Data streams use >= 1.
CONTROL_STREAM_ID = 0


@dataclass
class _Outstanding:
    stream_id: int
    seq: int
    wire: bytes
    plain_size: int
    sent_at: float
    retries: int = 0


@dataclass
class _RecvStream:
    expect: int = 0
    buffer: dict[int, bytes] = field(default_factory=dict)
    queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    high_seen: int = -1
    sack_dirty: bool = False
    last_ack_sent: float = 0.0
    fin_seen: bool = False


@dataclass
class _SendStream:
    next_seq: int = 0
    pending_fin: bool = False


class _Proto(asyncio.DatagramProtocol):
    def __init__(self, session: Optional["Session"]):
        self.session = session

    def datagram_received(self, data: bytes, addr) -> None:
        if self.session is None:
            return  # handshake not finished attaching the session yet
        self.session._on_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self.session is not None:
            self.session._on_lost(exc)


class Session:
    def __init__(
        self,
        udp_transport: asyncio.DatagramTransport,
        keys: HandshakeKeys,
        is_initiator: bool,
        peer_addr: tuple[str, int],
    ):
        self._udp = udp_transport
        self._keys = keys
        self._peer = peer_addr
        self._is_initiator = is_initiator
        self._dir_out = (
            Direction.INITIATOR_TO_RESPONDER if is_initiator
            else Direction.RESPONDER_TO_INITIATOR
        )
        self._dir_in = (
            Direction.RESPONDER_TO_INITIATOR if is_initiator
            else Direction.INITIATOR_TO_RESPONDER
        )
        self._enc = AEAD(keys.k_i2r if is_initiator else keys.k_r2i)
        self._dec = AEAD(keys.k_r2i if is_initiator else keys.k_i2r)

        self.session_id = keys.session_id
        self.bbr = BBRLite()
        self.srtt = INITIAL_SRTT
        self.rttvar = INITIAL_SRTT / 2

        # Outbound queues/state.
        self._send_q: asyncio.Queue[tuple[int, bytes, bool]] = asyncio.Queue()
        self._send: dict[int, _SendStream] = defaultdict(_SendStream)
        # Control counter: 1 on initiator side (seq 0 was HS_DONE), 0 on responder.
        self._control_seq: int = 1 if is_initiator else 0

        # Inbound state.
        self._recv: dict[int, _RecvStream] = defaultdict(_RecvStream)
        self._inflight: dict[tuple[int, int], _Outstanding] = {}
        self._inflight_bytes = 0

        self._next_send_time = 0.0

        self._closed = False
        self._close_reason: Optional[str] = None
        self._tasks: list[asyncio.Task] = []
        self._ack_pending: set[int] = set()
        self._ack_timer: Optional[asyncio.TimerHandle] = None

    # ----- public API -----------------------------------------------------

    def start(self) -> None:
        loop = asyncio.get_event_loop()
        self._tasks.append(loop.create_task(self._send_loop()))
        self._tasks.append(loop.create_task(self._retx_loop()))

    async def send(self, stream_id: int, payload: bytes, fin: bool = False) -> None:
        if self._closed:
            raise ConnectionError("session closed")
        if stream_id < 1 or stream_id > 0xFFFF:
            raise ValueError("application streams must be 1..65535")
        max_body = MAX_PAYLOAD - 4
        header = struct.pack("!I", len(payload))
        stream = header + payload
        offset = 0
        while offset < len(stream):
            piece = stream[offset : offset + max_body]
            is_last = (offset + len(piece)) >= len(stream) and fin
            await self._send_q.put((stream_id, piece, is_last))
            offset += len(piece)

    async def recv(self, stream_id: int) -> bytes:
        if stream_id < 1 or stream_id > 0xFFFF:
            raise ValueError("application streams must be 1..65535")
        state = self._recv[stream_id]
        accum = bytearray()
        expected: Optional[int] = None
        while True:
            frag = await state.queue.get()
            if frag == b"":
                if not accum:
                    return b""
                break
            accum.extend(frag)
            if expected is None and len(accum) >= 4:
                expected = struct.unpack("!I", bytes(accum[:4]))[0]
            if expected is not None and len(accum) >= 4 + expected:
                return bytes(accum[4 : 4 + expected])
            if state.fin_seen and state.queue.empty():
                break
        if expected is None:
            return bytes(accum)
        return bytes(accum[4 : 4 + (expected or 0)])

    async def drain(self, timeout: float = 10.0) -> None:
        """Wait until every outbound packet has been ACKed (or timeout)."""
        deadline = time.monotonic() + timeout
        while not self._closed and self._inflight and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        # Also drain the send queue.
        deadline = time.monotonic() + max(0.5, timeout)
        while not self._closed and not self._send_q.empty() and time.monotonic() < deadline:
            await asyncio.sleep(0.01)

    async def close(self, reason: int = 0) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            h = Header(
                type=PacketType.CLOSE, flags=0, session_id=self.session_id,
                stream_id=CONTROL_STREAM_ID, sequence=self._next_control_seq(),
                payload_length=0,
            )
            self._raw_send(h, struct.pack("!B", reason))
        except Exception:
            pass
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    def nack(self, stream_id: int, seqs: list[int]) -> None:
        if not seqs:
            return
        body = struct.pack("!HI", stream_id, len(seqs))
        body += b"".join(struct.pack("!I", s) for s in seqs)
        h = Header(
            type=PacketType.NACK, flags=0, session_id=self.session_id,
            stream_id=CONTROL_STREAM_ID, sequence=self._next_control_seq(),
            payload_length=0,
        )
        self._raw_send(h, body)

    def snapshot(self) -> dict:
        return {
            "inflight_packets": len(self._inflight),
            "inflight_bytes": self._inflight_bytes,
            "srtt_ms": int(self.srtt * 1000),
            **self.bbr.snapshot(),
        }

    # ----- control counter ------------------------------------------------

    def _next_control_seq(self) -> int:
        s = self._control_seq
        self._control_seq += 1
        return s

    # ----- inbound --------------------------------------------------------

    def _on_datagram(self, data: bytes, addr) -> None:
        if addr != self._peer:
            return
        try:
            h = decode_header(data)
        except Exception:
            return
        if h.session_id != self.session_id:
            return
        header_bytes = data[:HEADER_SIZE]
        body = data[HEADER_SIZE : HEADER_SIZE + h.payload_length]
        if h.flags & Flag.NOENCRYPT:
            plain = body
        else:
            nonce = derive_nonce(self._dir_in, h.session_id, h.stream_id, h.sequence)
            try:
                plain = self._dec.open(header_bytes, nonce, body)
            except Exception:
                return  # drop forged/corrupt packet

        if h.type is PacketType.DATA:
            self._on_data(h, plain)
        elif h.type is PacketType.ACK:
            self._on_ack(h, plain)
        elif h.type is PacketType.NACK:
            self._on_nack(h, plain)
        elif h.type is PacketType.PING:
            self._on_ping(h, plain)
        elif h.type is PacketType.PONG:
            self._on_pong(h, plain)
        elif h.type is PacketType.CLOSE:
            self._closed = True
            for s in self._recv.values():
                s.queue.put_nowait(b"")
        # Other types (HELLO, HELLO_ACK, HS_DONE, PUNCH) are ignored here —
        # they are consumed during the handshake phase before Session.start().

    def _on_data(self, h: Header, plain: bytes) -> None:
        s = self._recv[h.stream_id]
        if h.sequence > s.high_seen:
            s.high_seen = h.sequence
        if h.sequence < s.expect:
            self._schedule_ack(h.stream_id)
            return
        if h.sequence == s.expect:
            s.queue.put_nowait(plain)
            s.expect += 1
            while s.expect in s.buffer:
                s.queue.put_nowait(s.buffer.pop(s.expect))
                s.expect += 1
        else:
            s.buffer[h.sequence] = plain
            s.sack_dirty = True
        if h.flags & Flag.FIN:
            s.fin_seen = True
            s.queue.put_nowait(b"")
        self._schedule_ack(h.stream_id)

    def _on_ack(self, h: Header, plain: bytes) -> None:
        # body layout: target_stream (u16) || tx_ts (f64) || cumulative (u32)
        #              || sack_count (u8) || [start (u32), length (u32)] * sack_count
        if len(plain) < 2 + 8 + 4 + 1:
            return
        target = struct.unpack_from("!H", plain, 0)[0]
        tx_ts = struct.unpack_from("!d", plain, 2)[0]
        cumulative = struct.unpack_from("!I", plain, 10)[0]
        sack_count = plain[14]
        off = 15

        rtt = max(0.0005, time.monotonic() - tx_ts)
        acked = 0
        to_del = [k for k in self._inflight if k[0] == target and k[1] < cumulative]
        for k in to_del:
            p = self._inflight.pop(k)
            acked += p.plain_size
            self._inflight_bytes -= len(p.wire)
        for _ in range(sack_count):
            if off + 8 > len(plain):
                break
            start, length = struct.unpack_from("!II", plain, off)
            off += 8
            for seq in range(start, start + length):
                p = self._inflight.pop((target, seq), None)
                if p:
                    acked += p.plain_size
                    self._inflight_bytes -= len(p.wire)

        if acked > 0:
            err = rtt - self.srtt
            self.srtt = self.srtt + err / 8
            self.rttvar = self.rttvar + (abs(err) - self.rttvar) / 4
            self.bbr.on_ack(acked, rtt)

    def _on_nack(self, h: Header, plain: bytes) -> None:
        if len(plain) < 2 + 4:
            return
        target = struct.unpack_from("!H", plain, 0)[0]
        count = struct.unpack_from("!I", plain, 2)[0]
        off = 6
        now = time.monotonic()
        for _ in range(count):
            if off + 4 > len(plain):
                break
            (seq,) = struct.unpack_from("!I", plain, off)
            off += 4
            p = self._inflight.get((target, seq))
            if p:
                self._udp.sendto(p.wire, self._peer)
                p.sent_at = now
                p.retries += 1

    def _on_ping(self, h: Header, plain: bytes) -> None:
        out = Header(
            type=PacketType.PONG, flags=0, session_id=self.session_id,
            stream_id=CONTROL_STREAM_ID, sequence=self._next_control_seq(),
            payload_length=0,
        )
        self._raw_send(out, plain)

    def _on_pong(self, h: Header, plain: bytes) -> None:
        if len(plain) >= 8:
            tx_ts = struct.unpack_from("!d", plain, 0)[0]
            rtt = max(0.0005, time.monotonic() - tx_ts)
            self.bbr.on_ack(0, rtt)

    def _on_lost(self, exc: Optional[Exception]) -> None:
        self._closed = True

    # ----- outbound -------------------------------------------------------

    async def _send_loop(self) -> None:
        while not self._closed:
            try:
                stream_id, piece, fin = await asyncio.wait_for(
                    self._send_q.get(), timeout=0.5,
                )
            except asyncio.TimeoutError:
                continue

            while not self._closed and self._inflight_bytes >= self.bbr.cwnd:
                await asyncio.sleep(0.001)

            now = time.monotonic()
            if now < self._next_send_time:
                await asyncio.sleep(self._next_send_time - now)

            s = self._send[stream_id]
            seq = s.next_seq
            s.next_seq += 1

            flags = Flag.FIN if fin else 0
            h = Header(
                type=PacketType.DATA, flags=flags, session_id=self.session_id,
                stream_id=stream_id, sequence=seq, payload_length=0,
            )
            wire = self._seal(h, piece)
            self._udp.sendto(wire, self._peer)
            self._inflight[(stream_id, seq)] = _Outstanding(
                stream_id=stream_id, seq=seq, wire=wire,
                plain_size=len(piece), sent_at=time.monotonic(),
            )
            self._inflight_bytes += len(wire)

            pacing = max(self.bbr.pacing_rate, 10_000.0)
            self._next_send_time = time.monotonic() + len(wire) / pacing

    async def _retx_loop(self) -> None:
        while not self._closed:
            await asyncio.sleep(RETX_POLL_INTERVAL)
            now = time.monotonic()
            rto = max(MIN_RTO, self.srtt + 4 * self.rttvar)
            fast_thresh = max(1.5 * self.srtt, MIN_RTO)
            for key, pkt in list(self._inflight.items()):
                if now - pkt.sent_at > fast_thresh:
                    if pkt.retries >= MAX_RETRIES:
                        self._closed = True
                        self._close_reason = "max retries"
                        return
                    self._udp.sendto(pkt.wire, self._peer)
                    pkt.sent_at = now + min(rto, 1.0) * pkt.retries
                    pkt.retries += 1

    # ----- ACK batching ---------------------------------------------------

    def _schedule_ack(self, stream_id: int) -> None:
        self._ack_pending.add(stream_id)
        if self._ack_timer is None:
            loop = asyncio.get_event_loop()
            self._ack_timer = loop.call_later(ACK_BATCH_DELAY, self._flush_acks)

    def _flush_acks(self) -> None:
        self._ack_timer = None
        pending = list(self._ack_pending)
        self._ack_pending.clear()
        for stream_id in pending:
            self._send_ack(stream_id)

    def _send_ack(self, target_stream: int) -> None:
        s = self._recv[target_stream]
        now = time.monotonic()
        buffered = sorted(s.buffer.keys())
        ranges: list[tuple[int, int]] = []
        i = 0
        while i < len(buffered) and len(ranges) < SACK_MAX_RANGES:
            start = buffered[i]
            j = i
            while j + 1 < len(buffered) and buffered[j + 1] == buffered[j] + 1:
                j += 1
            ranges.append((start, buffered[j] - start + 1))
            i = j + 1

        body = struct.pack("!HdIB", target_stream, now, s.expect, len(ranges))
        for start, length in ranges:
            body += struct.pack("!II", start, length)

        h = Header(
            type=PacketType.ACK, flags=0, session_id=self.session_id,
            stream_id=CONTROL_STREAM_ID, sequence=self._next_control_seq(),
            payload_length=0,
        )
        self._raw_send(h, body)
        s.last_ack_sent = now
        s.sack_dirty = False

    # ----- sealing --------------------------------------------------------

    def _seal(self, h: Header, plain: bytes) -> bytes:
        h.payload_length = len(plain) + AEAD_TAG_SIZE
        hdr_bytes = encode_header(h)
        nonce = derive_nonce(self._dir_out, h.session_id, h.stream_id, h.sequence)
        ct = self._enc.seal(hdr_bytes, nonce, plain)
        return hdr_bytes + ct

    def _raw_send(self, h: Header, plain: bytes) -> None:
        self._udp.sendto(self._seal(h, plain), self._peer)
