"""
End-to-end integration test — coordinator-free.

Both sender and receiver run on localhost. The sender uses STUN to discover
its reflexive address (which for loopback will be the LAN IP or fail; we
override with a direct loopback address). Then the receiver connects
directly.

This tests the full pipeline: STUN fallback → ticket with address →
direct punch → handshake → parallel transfer → Merkle verification.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile

from lentel import send_file, recv_file
from lentel.wordlist import new_ticket


def _h(path: str) -> bytes:
    h = hashlib.blake2b(digest_size=32)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


async def _run(file_size: int, parallel: int = 4) -> None:
    """Run a full loopback transfer without any server."""
    with tempfile.TemporaryDirectory() as tdir:
        src_path = os.path.join(tdir, "source.bin")
        dst_dir = os.path.join(tdir, "dst")
        os.makedirs(dst_dir, exist_ok=True)
        with open(src_path, "wb") as f:
            f.write(os.urandom(file_size))

        # Pre-build a ticket pointing at localhost (bypass STUN for tests).
        # In production, send_file discovers the address via STUN/UPnP
        # automatically. For unit tests we hard-code 127.0.0.1 and a
        # fixed port so no real NAT/STUN is involved.
        import socket
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        sender_port = probe.getsockname()[1]
        probe.close()

        ticket = new_ticket(("127.0.0.1", sender_port))

        sender = asyncio.create_task(
            send_file(
                src_path,
                ticket=ticket,
                parallel=parallel,
                wait_timeout=30.0,
            ),
        )
        # Small delay so sender socket is listening before receiver starts.
        await asyncio.sleep(0.3)

        receiver = asyncio.create_task(
            recv_file(
                ticket,
                dest_dir=dst_dir,
                parallel=parallel,
            ),
        )

        try:
            out_path = await asyncio.wait_for(receiver, timeout=60.0)
            await asyncio.wait_for(sender, timeout=60.0)
        except Exception:
            sender.cancel()
            receiver.cancel()
            raise

        assert os.path.exists(out_path), out_path
        assert _h(src_path) == _h(out_path), "file contents differ"
        assert os.path.getsize(out_path) == file_size


def test_small_file():
    asyncio.run(_run(file_size=1024))


def test_medium_file():
    asyncio.run(_run(file_size=2 * 1024 * 1024))


def test_empty_file():
    asyncio.run(_run(file_size=0))


def test_boundary_aligned():
    asyncio.run(_run(file_size=64 * 1024))
