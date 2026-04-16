"""
End-to-end tests for the receiver-first flow.

The receiver starts first (and generates the ticket); the sender reads
that ticket and pushes the payload.  In these tests STUN is skipped by
passing ``advertise_host="127.0.0.1"`` to ``recv_file`` — this makes the
receiver advertise its loopback address so the sender can reach it.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import tempfile

from lentel import recv_file, send_file


def _file_hash(path: str) -> bytes:
    h = hashlib.blake2b(digest_size=32)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def _tree_fingerprint(root: str) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for dp, _, fn in os.walk(root, followlinks=False):
        for f in sorted(fn):
            abs_f = os.path.join(dp, f)
            rel = os.path.relpath(abs_f, root).replace(os.sep, "/")
            out[rel] = _file_hash(abs_f)
    return out


async def _loopback_transfer(src_path: str, dst_dir: str, parallel: int = 4) -> str:
    """Run a full loopback transfer (receiver-first) and return the output path."""
    ticket_holder: dict[str, str] = {}

    def on_ticket(t: str) -> None:
        ticket_holder["t"] = t

    # Start the receiver first — it generates the ticket.
    receiver = asyncio.create_task(
        recv_file(
            dest_dir=dst_dir,
            parallel=parallel,
            on_ticket=on_ticket,
            advertise_host="127.0.0.1",  # bypass STUN for loopback tests
            wait_timeout=30.0,
        ),
    )

    # Wait for the ticket to be generated.
    for _ in range(100):
        if "t" in ticket_holder:
            break
        await asyncio.sleep(0.02)
    assert "t" in ticket_holder, "receiver never produced a ticket"

    # Now the sender connects with that ticket.
    sender = asyncio.create_task(
        send_file(src_path, ticket_holder["t"], parallel=parallel),
    )

    try:
        out = await asyncio.wait_for(receiver, timeout=60.0)
        await asyncio.wait_for(sender, timeout=60.0)
        return out
    except Exception:
        sender.cancel()
        receiver.cancel()
        raise


# ---------- single-file transfers -----------------------------------------

async def _run_file(file_size: int) -> None:
    with tempfile.TemporaryDirectory() as tdir:
        src = os.path.join(tdir, "source.bin")
        dst = os.path.join(tdir, "dst")
        os.makedirs(dst, exist_ok=True)
        with open(src, "wb") as f:
            f.write(os.urandom(file_size))
        out = await _loopback_transfer(src, dst)
        assert os.path.isfile(out)
        assert _file_hash(src) == _file_hash(out)
        assert os.path.getsize(out) == file_size


def test_file_small():
    asyncio.run(_run_file(1024))


def test_file_medium():
    asyncio.run(_run_file(2 * 1024 * 1024))


def test_file_empty():
    asyncio.run(_run_file(0))


def test_file_boundary_aligned():
    asyncio.run(_run_file(64 * 1024))


# ---------- folder transfers ----------------------------------------------

async def _run_folder_simple() -> None:
    with tempfile.TemporaryDirectory() as tdir:
        src_folder = os.path.join(tdir, "letters")
        dst = os.path.join(tdir, "dst")
        os.makedirs(src_folder)
        os.makedirs(dst, exist_ok=True)
        for name, body in [("a.txt", b"alpha\n"),
                            ("b.txt", b"bravo\n"),
                            ("c.txt", b"charlie\n")]:
            with open(os.path.join(src_folder, name), "wb") as f:
                f.write(body)
        out = await _loopback_transfer(src_folder, dst)
        assert os.path.isdir(out)
        assert os.path.basename(out) == "letters"
        assert _tree_fingerprint(src_folder) == _tree_fingerprint(out)


def test_folder_simple():
    asyncio.run(_run_folder_simple())


async def _run_folder_nested() -> None:
    with tempfile.TemporaryDirectory() as tdir:
        src_folder = os.path.join(tdir, "project")
        dst = os.path.join(tdir, "dst")
        os.makedirs(os.path.join(src_folder, "src", "lib"))
        os.makedirs(os.path.join(src_folder, "docs"))
        os.makedirs(dst, exist_ok=True)
        payloads = {
            "README.md":       b"# README\n",
            "src/main.py":     os.urandom(1_000),
            "src/lib/util.py": os.urandom(200_000),
            "docs/guide.txt":  os.urandom(65_536),
        }
        for rel, data in payloads.items():
            full = os.path.join(src_folder, rel)
            with open(full, "wb") as f:
                f.write(data)
        out = await _loopback_transfer(src_folder, dst)
        assert _tree_fingerprint(src_folder) == _tree_fingerprint(out)


def test_folder_nested():
    asyncio.run(_run_folder_nested())


async def _run_folder_with_empty_file() -> None:
    with tempfile.TemporaryDirectory() as tdir:
        src_folder = os.path.join(tdir, "mixed")
        dst = os.path.join(tdir, "dst")
        os.makedirs(src_folder)
        os.makedirs(dst, exist_ok=True)
        with open(os.path.join(src_folder, "data.bin"), "wb") as f:
            f.write(os.urandom(5_000))
        open(os.path.join(src_folder, "empty"), "wb").close()
        out = await _loopback_transfer(src_folder, dst)
        assert _tree_fingerprint(src_folder) == _tree_fingerprint(out)
        assert os.path.getsize(os.path.join(out, "empty")) == 0


def test_folder_with_empty_file():
    asyncio.run(_run_folder_with_empty_file())
