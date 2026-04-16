"""
End-to-end integration tests — coordinator-free, file AND folder transfers.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import tempfile

from lentel import send_file, recv_file
from lentel.wordlist import new_ticket


def _file_hash(path: str) -> bytes:
    h = hashlib.blake2b(digest_size=32)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def _tree_fingerprint(root: str) -> dict[str, bytes]:
    """Map every file's relative path -> hash, for tree comparisons."""
    out: dict[str, bytes] = {}
    for dp, _, fn in os.walk(root, followlinks=False):
        for f in sorted(fn):
            abs_f = os.path.join(dp, f)
            rel = os.path.relpath(abs_f, root).replace(os.sep, "/")
            out[rel] = _file_hash(abs_f)
    return out


def _reserve_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


async def _loopback_transfer(src: str, dst_dir: str, parallel: int = 4) -> str:
    """Run a full loopback transfer and return the output path."""
    sender_port = _reserve_port()
    ticket = new_ticket(("127.0.0.1", sender_port))

    sender = asyncio.create_task(
        send_file(src, ticket=ticket, parallel=parallel, wait_timeout=30.0),
    )
    await asyncio.sleep(0.3)

    receiver = asyncio.create_task(
        recv_file(ticket, dest_dir=dst_dir, parallel=parallel),
    )
    try:
        out_path = await asyncio.wait_for(receiver, timeout=60.0)
        await asyncio.wait_for(sender, timeout=60.0)
        return out_path
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
    """Flat folder with three small files."""
    with tempfile.TemporaryDirectory() as tdir:
        src_folder = os.path.join(tdir, "letters")
        dst = os.path.join(tdir, "dst")
        os.makedirs(src_folder)
        os.makedirs(dst, exist_ok=True)
        with open(os.path.join(src_folder, "a.txt"), "wb") as f:
            f.write(b"alpha\n")
        with open(os.path.join(src_folder, "b.txt"), "wb") as f:
            f.write(b"bravo\n")
        with open(os.path.join(src_folder, "c.txt"), "wb") as f:
            f.write(b"charlie\n")

        out = await _loopback_transfer(src_folder, dst)
        assert os.path.isdir(out)
        assert os.path.basename(out) == "letters"
        assert _tree_fingerprint(src_folder) == _tree_fingerprint(out)


def test_folder_simple():
    asyncio.run(_run_folder_simple())


async def _run_folder_nested() -> None:
    """Deeply nested folder with files of varying sizes."""
    with tempfile.TemporaryDirectory() as tdir:
        src_folder = os.path.join(tdir, "project")
        dst = os.path.join(tdir, "dst")
        os.makedirs(os.path.join(src_folder, "src", "lib"))
        os.makedirs(os.path.join(src_folder, "docs"))
        os.makedirs(dst, exist_ok=True)

        # File sizes chosen to exercise chunk boundaries
        payloads = {
            "README.md":       b"# README\n",
            "src/main.py":     os.urandom(1_000),
            "src/lib/util.py": os.urandom(200_000),      # multi-chunk
            "docs/guide.txt":  os.urandom(65_536),       # exactly one chunk
        }
        for rel, data in payloads.items():
            full = os.path.join(src_folder, rel)
            with open(full, "wb") as f:
                f.write(data)

        out = await _loopback_transfer(src_folder, dst)
        assert os.path.isdir(out)
        fp_src = _tree_fingerprint(src_folder)
        fp_dst = _tree_fingerprint(out)
        assert fp_src == fp_dst, (
            f"tree mismatch: only-in-src={fp_src.keys() - fp_dst.keys()}, "
            f"only-in-dst={fp_dst.keys() - fp_src.keys()}"
        )


def test_folder_nested():
    asyncio.run(_run_folder_nested())


async def _run_folder_with_empty_file() -> None:
    """Folder containing a zero-byte file."""
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
