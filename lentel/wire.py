"""
Lentel wire format: packet header encoding/decoding, type codes, flags.

See PROTOCOL.md §2 for the full specification. This module is pure; it has
no knowledge of crypto or I/O.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

MAGIC = 0x4C4E544C  # "LNTL"
VERSION = 1
HEADER_SIZE = 20
AEAD_TAG_SIZE = 16
MAX_PAYLOAD = 1200
MAX_PACKET = HEADER_SIZE + MAX_PAYLOAD + AEAD_TAG_SIZE


class PacketType(IntEnum):
    HELLO = 0x01
    HELLO_ACK = 0x02
    HS_DONE = 0x03
    PUNCH = 0x04
    PING = 0x05
    PONG = 0x06
    DATA = 0x07
    ACK = 0x08
    NACK = 0x09
    WINDOW = 0x0A
    CONTROL = 0x0B
    CLOSE = 0x0F


class Flag:
    """Packet flags (16 bits wide in the header)."""
    FIN = 1 << 0          # last packet of a stream
    SYN = 1 << 1          # first packet of a new stream
    NOENCRYPT = 1 << 2    # payload is not AEAD-protected (PUNCH, HELLO)
    RESUME = 1 << 3       # receiver wants to resume a prior transfer
    RESPONDER = 1 << 4    # sender identifies as responder (vs initiator)


class Direction:
    INITIATOR_TO_RESPONDER = 0x01
    RESPONDER_TO_INITIATOR = 0x02


# Header layout:
#   !   network byte order, no padding
#   I   magic                u32   (4)
#   B   version              u8    (1)
#   B   type                 u8    (1)
#   H   flags                u16   (2)
#   I   session_id           u32   (4)
#   H   stream_id            u16   (2)
#   I   sequence             u32   (4)
#   H   payload_length       u16   (2)
# total: 20 bytes
_HEADER = struct.Struct("!IBBHIHIH")
assert _HEADER.size == HEADER_SIZE


@dataclass(slots=True)
class Header:
    type: PacketType
    flags: int
    session_id: int
    stream_id: int
    sequence: int
    payload_length: int


class WireError(ValueError):
    """Raised when a packet fails framing validation."""


def encode_header(h: Header) -> bytes:
    if h.payload_length > MAX_PAYLOAD + AEAD_TAG_SIZE:
        raise WireError(f"payload too large: {h.payload_length}")
    return _HEADER.pack(
        MAGIC,
        VERSION,
        int(h.type),
        h.flags & 0xFFFF,
        h.session_id & 0xFFFFFFFF,
        h.stream_id & 0xFFFF,
        h.sequence & 0xFFFFFFFF,
        h.payload_length & 0xFFFF,
    )


def decode_header(buf: bytes) -> Header:
    if len(buf) < HEADER_SIZE:
        raise WireError(f"short packet: {len(buf)} bytes")
    magic, ver, typ, flags, sid, stream, seq, plen = _HEADER.unpack_from(buf)
    if magic != MAGIC:
        raise WireError(f"bad magic: 0x{magic:08x}")
    if ver != VERSION:
        raise WireError(f"unsupported version: {ver}")
    try:
        ptype = PacketType(typ)
    except ValueError as e:
        raise WireError(f"unknown packet type: 0x{typ:02x}") from e
    expected_len = HEADER_SIZE + plen
    if len(buf) < expected_len:
        raise WireError(f"truncated packet: have {len(buf)} need {expected_len}")
    return Header(ptype, flags, sid, stream, seq, plen)


def derive_nonce(direction: int, session_id: int, stream_id: int, sequence: int) -> bytes:
    """
    Compose a 12-byte AEAD nonce from packet fields.

    Nonces are never sent on the wire — both peers recompute them from the
    header. The direction byte (initiator->responder vs. the reverse) ensures
    the two directions use disjoint nonce spaces even with identical headers.

    Layout: dir(1) || session(4) || stream(2) || sequence(4) || 0x00(1) = 12
    """
    return struct.pack(
        "!BIHIB",
        direction & 0xFF,
        session_id & 0xFFFFFFFF,
        stream_id & 0xFFFF,
        sequence & 0xFFFFFFFF,
        0,
    )


def encode_packet(h: Header, body: bytes) -> bytes:
    """Assemble a full packet (header + body). AEAD is applied by the caller."""
    h.payload_length = len(body)
    return encode_header(h) + body


def split_packet(buf: bytes) -> tuple[Header, bytes]:
    """Parse and return (header, body). Body includes ciphertext + tag."""
    h = decode_header(buf)
    body = buf[HEADER_SIZE : HEADER_SIZE + h.payload_length]
    return h, body
