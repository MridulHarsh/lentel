"""Unit tests for wire, chunker, crypto, congestion, wordlist, and STUN."""
from __future__ import annotations

import os
import struct
import tempfile
import time

import pytest

from lentel.chunker import (
    Manifest, hash_chunk, merkle_root, scan_file, ChunkWriter,
)
from lentel.congestion import BBRLite, Phase
from lentel.crypto import (
    InitiatorHandshake, ResponderHandshake, AEAD, psk_from_ticket,
)
from lentel.wire import (
    HEADER_SIZE, Direction, Flag, Header, PacketType, WireError,
    decode_header, derive_nonce, encode_header,
)
from lentel.wordlist import new_ticket, parse_ticket, new_code


# ---------- wire ----------------------------------------------------------

def test_header_roundtrip():
    h = Header(type=PacketType.DATA, flags=Flag.FIN, session_id=0xDEADBEEF,
               stream_id=7, sequence=42, payload_length=128)
    b = encode_header(h)
    assert len(b) == HEADER_SIZE
    h2 = decode_header(b + b"\x00" * 128)
    assert h2.type is PacketType.DATA
    assert h2.flags == Flag.FIN
    assert h2.session_id == 0xDEADBEEF
    assert h2.stream_id == 7
    assert h2.sequence == 42
    assert h2.payload_length == 128


def test_header_bad_magic():
    with pytest.raises(WireError):
        decode_header(b"\x00" * 20)


def test_nonce_derivation_distinct_directions():
    a = derive_nonce(Direction.INITIATOR_TO_RESPONDER, 1, 2, 3)
    b = derive_nonce(Direction.RESPONDER_TO_INITIATOR, 1, 2, 3)
    assert a != b and len(a) == 12


def test_nonce_derivation_distinct_sequences():
    a = derive_nonce(Direction.INITIATOR_TO_RESPONDER, 1, 2, 3)
    b = derive_nonce(Direction.INITIATOR_TO_RESPONDER, 1, 2, 4)
    assert a != b


# ---------- chunker -------------------------------------------------------

def test_merkle_empty():
    assert len(merkle_root([])) == 32

def test_merkle_single():
    leaf = hash_chunk(b"hello")
    assert merkle_root([leaf]) == leaf

def test_merkle_stable():
    leaves = [hash_chunk(str(i).encode()) for i in range(7)]
    assert merkle_root(leaves) == merkle_root(leaves)

def test_scan_file_and_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "data.bin")
        with open(p, "wb") as f:
            f.write(os.urandom(200_000))
        manifest, leaves = scan_file(p, chunk_size=65536)
        assert manifest.file_size == 200_000
        assert manifest.chunk_count == 4
        assert manifest.root_hash == merkle_root(leaves)
        wire = manifest.to_wire()
        m2 = Manifest.from_wire(wire)
        assert m2.root_hash == manifest.root_hash

def test_chunk_writer_sparse():
    with tempfile.TemporaryDirectory() as d:
        src = os.path.join(d, "src.bin")
        dst = os.path.join(d, "dst.bin")
        data = os.urandom(130_000)
        with open(src, "wb") as f:
            f.write(data)
        manifest, _ = scan_file(src, chunk_size=65536)
        w = ChunkWriter(dst, manifest)
        with open(src, "rb") as f:
            c0, c1, c2 = f.read(65536), f.read(65536), f.read(65536)
        w.write(2, c2)
        w.write(0, c0)
        w.write(1, c1)
        w.close()
        assert open(dst, "rb").read() == data


# ---------- crypto --------------------------------------------------------

def test_ticket_psk_stability():
    assert psk_from_ticket("swift-otter-41") == psk_from_ticket("swift-otter-41")
    assert psk_from_ticket("swift-otter-41") != psk_from_ticket("swift-otter-42")

def test_handshake_round_trip():
    psk = psk_from_ticket("fable-crab-arena-17")
    i = InitiatorHandshake(psk)
    r = ResponderHandshake(psk)
    hello = i.hello()
    ack = r.on_hello(hello)
    hs_done = i.on_hello_ack(ack)
    r.on_hs_done(hs_done)
    assert i.keys is not None and r.keys is not None
    assert i.keys.k_i2r == r.keys.k_i2r
    assert i.keys.k_r2i == r.keys.k_r2i

def test_handshake_wrong_psk():
    i = InitiatorHandshake(psk_from_ticket("a-b-00"))
    r = ResponderHandshake(psk_from_ticket("c-d-00"))
    hello = i.hello()
    ack = r.on_hello(hello)
    with pytest.raises(Exception):
        i.on_hello_ack(ack)

def test_aead_roundtrip():
    key = os.urandom(32)
    aead = AEAD(key)
    nonce = os.urandom(12)
    aad = os.urandom(20)
    ct = aead.seal(aad, nonce, b"hello, world")
    assert aead.open(aad, nonce, ct) == b"hello, world"


# ---------- congestion ----------------------------------------------------

def test_bbr_startup_to_drain():
    bbr = BBRLite()
    assert bbr.phase is Phase.STARTUP
    now = time.monotonic()
    for i in range(30):
        bbr.on_ack(1200, 0.05, now + i * 0.1)
    assert bbr.phase is not Phase.STARTUP

def test_bbr_increases_pacing_on_better_bw():
    bbr = BBRLite()
    bbr.on_ack(10_000, 0.01)
    r1 = bbr.pacing_rate
    bbr.on_ack(100_000, 0.01)
    assert bbr.pacing_rate >= r1


# ---------- wordlist (new format with address) ----------------------------

def test_ticket_roundtrip():
    for _ in range(50):
        t = new_ticket(("127.0.0.1", 9999))
        code, addr = parse_ticket(t)
        assert "@" in t
        assert addr == ("127.0.0.1", 9999)
        assert len(code.split("-")) == 4  # 3 words + checksum

def test_ticket_bad_checksum():
    t = new_ticket(("1.2.3.4", 5555))
    code, addr_s = t.split("@")
    parts = code.split("-")
    parts[-1] = f"{(int(parts[-1]) + 1) % 100:02d}"
    bad = "-".join(parts) + "@" + addr_s
    with pytest.raises(ValueError):
        parse_ticket(bad)

def test_ticket_no_address():
    with pytest.raises(ValueError, match="@"):
        parse_ticket("bold-crab-fern-42")

def test_code_only():
    c = new_code()
    assert "@" not in c
    assert len(c.split("-")) == 4


# ---------- STUN ----------------------------------------------------------

def test_stun_request_format():
    from lentel.nat import _build_stun_request, _STUN_MAGIC, _BINDING_REQUEST
    pkt, txn_id = _build_stun_request()
    assert len(pkt) == 20
    assert len(txn_id) == 12
    msg_type, msg_len, magic = struct.unpack_from("!HHI", pkt, 0)
    assert msg_type == _BINDING_REQUEST
    assert magic == _STUN_MAGIC
    assert msg_len == 0
