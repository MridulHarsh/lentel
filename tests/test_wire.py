"""Unit tests for wire, chunker, crypto, congestion, wordlist, and STUN."""
from __future__ import annotations

import os
import struct
import tempfile
import time

import pytest

from lentel.chunker import (
    Manifest, FileEntry, MultiFileWriter, UnsafePathError,
    hash_chunk, merkle_root, sanitize_relpath, scan_file, scan_folder,
    scan_path, verify_manifest,
)
from lentel.congestion import BBRLite, Phase
from lentel.crypto import (
    InitiatorHandshake, ResponderHandshake, AEAD, psk_from_ticket,
)
from lentel.wire import (
    HEADER_SIZE, Direction, Flag, Header, PacketType, WireError,
    decode_header, derive_nonce, encode_header,
)
from lentel.wordlist import new_code, new_ticket, parse_ticket


# ---------- wire ----------------------------------------------------------

def test_header_roundtrip():
    h = Header(type=PacketType.DATA, flags=Flag.FIN, session_id=0xDEADBEEF,
               stream_id=7, sequence=42, payload_length=128)
    b = encode_header(h)
    assert len(b) == HEADER_SIZE
    h2 = decode_header(b + b"\x00" * 128)
    assert h2.type is PacketType.DATA
    assert h2.session_id == 0xDEADBEEF
    assert h2.stream_id == 7

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


# ---------- chunker: Merkle -----------------------------------------------

def test_merkle_empty():
    assert len(merkle_root([])) == 32

def test_merkle_single():
    leaf = hash_chunk(b"hello")
    assert merkle_root([leaf]) == leaf

def test_merkle_stable():
    leaves = [hash_chunk(str(i).encode()) for i in range(7)]
    assert merkle_root(leaves) == merkle_root(leaves)


# ---------- chunker: single-file + folder manifests ----------------------

def test_scan_file_single_manifest():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "data.bin")
        with open(p, "wb") as f:
            f.write(os.urandom(200_000))
        m, all_hashes = scan_file(p, chunk_size=65536)
        assert not m.is_folder
        assert len(m.files) == 1
        assert m.files[0].size == 200_000
        assert m.total_chunks == 4
        assert m.total_size == 200_000
        assert m.files[0].root_hash == merkle_root(all_hashes[0])

def test_manifest_wire_roundtrip():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "data.bin")
        with open(p, "wb") as f:
            f.write(os.urandom(50_000))
        m, _ = scan_file(p)
        m2 = Manifest.from_wire(m.to_wire())
        assert m2.is_folder == m.is_folder
        assert m2.total_chunks == m.total_chunks
        assert m2.files[0].root_hash == m.files[0].root_hash

def test_scan_folder_nested():
    with tempfile.TemporaryDirectory() as d:
        folder = os.path.join(d, "my-folder")
        os.makedirs(os.path.join(folder, "sub1", "sub2"))
        with open(os.path.join(folder, "a.txt"), "wb") as f:
            f.write(b"hello world\n")
        with open(os.path.join(folder, "sub1", "b.bin"), "wb") as f:
            f.write(os.urandom(100_000))
        with open(os.path.join(folder, "sub1", "sub2", "c.log"), "wb") as f:
            f.write(b"deeply nested\n")
        m, _ = scan_folder(folder)
        assert m.is_folder
        paths = {e.path for e in m.files}
        assert paths == {"a.txt", "sub1/b.bin", "sub1/sub2/c.log"}

def test_scan_path_autodetect():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "a.bin")
        with open(p, "wb") as f:
            f.write(b"x")
        m, _ = scan_path(p)
        assert not m.is_folder
        folder = os.path.join(d, "dir")
        os.makedirs(folder)
        with open(os.path.join(folder, "x"), "wb") as f:
            f.write(b"y")
        m2, _ = scan_path(folder)
        assert m2.is_folder


# ---------- chunker: path safety ------------------------------------------

def test_sanitize_rejects_absolute():
    with pytest.raises(UnsafePathError):
        sanitize_relpath("/etc/passwd")

def test_sanitize_rejects_dotdot():
    with pytest.raises(UnsafePathError):
        sanitize_relpath("../secret")
    with pytest.raises(UnsafePathError):
        sanitize_relpath("ok/../bad")

def test_sanitize_rejects_drive_letter():
    with pytest.raises(UnsafePathError):
        sanitize_relpath("C:/Windows")

def test_sanitize_accepts_good():
    assert sanitize_relpath("sub/file.txt") == "sub/file.txt"
    assert sanitize_relpath("sub\\file.txt") == "sub/file.txt"


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


# ---------- wordlist ------------------------------------------------------

def test_ticket_roundtrip():
    for _ in range(50):
        t = new_ticket(("127.0.0.1", 9999))
        code, addr = parse_ticket(t)
        assert addr == ("127.0.0.1", 9999)
        assert len(code.split("-")) == 4

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


# ---------- STUN request framing ------------------------------------------

def test_stun_request_format():
    from lentel.nat import _build_stun_request, _STUN_MAGIC, _BINDING_REQUEST
    pkt, txn_id = _build_stun_request()
    assert len(pkt) == 20
    assert len(txn_id) == 12
    msg_type, msg_len, magic = struct.unpack_from("!HHI", pkt, 0)
    assert msg_type == _BINDING_REQUEST
    assert magic == _STUN_MAGIC


# ---------- discover_public_address LAN fallback --------------------------

def test_discover_lan_fallback_when_stun_fails():
    """If STUN can't reach any server, we must fall back to the LAN IP
    so same-network transfers still work."""
    import asyncio
    import socket

    import lentel.nat as nat

    async def run():
        # Use a throwaway UDP socket; we won't actually send anything.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind(("127.0.0.1", 0))
        try:
            # Force STUN to fail by pointing at an unroutable address.
            saved_servers = nat.STUN_SERVERS
            nat.STUN_SERVERS = [("240.0.0.1", 19302)]  # reserved, unroutable
            try:
                ip, port, method = await nat.discover_public_address(
                    sock, allow_lan_fallback=True,
                )
                assert method == "lan"
                assert port == sock.getsockname()[1]
                assert ip not in ("0.0.0.0", "127.0.0.1")
            finally:
                nat.STUN_SERVERS = saved_servers
        finally:
            sock.close()

    asyncio.run(run())
