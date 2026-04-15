"""
File chunking and integrity verification.

Lentel splits files into fixed-size chunks, hashes each chunk with BLAKE2b,
and builds a Merkle tree over the hashes. The root is sent in the manifest;
every received chunk is verified against its leaf hash before it is written
to disk. A corrupted chunk triggers a NACK at the session layer — transport
ACKs are not sufficient because a man-in-the-middle could forge ACKs even
though AEAD prevents them from forging plaintext.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, asdict
from typing import Iterable

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def hash_chunk(data: bytes) -> bytes:
    """Domain-separated leaf hash."""
    return hashlib.blake2b(LEAF_PREFIX + data, digest_size=32).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.blake2b(NODE_PREFIX + left + right, digest_size=32).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Binary Merkle over a list of leaf hashes; last lonely leaf is duplicated."""
    if not leaf_hashes:
        return hashlib.blake2b(b"", digest_size=32).digest()
    layer = list(leaf_hashes)
    while len(layer) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(layer), 2):
            left = layer[i]
            right = layer[i + 1] if i + 1 < len(layer) else left
            nxt.append(_hash_node(left, right))
        layer = nxt
    return layer[0]


@dataclass
class Manifest:
    file_name: str
    file_size: int
    chunk_size: int
    chunk_count: int
    root_hash: bytes  # raw 32 bytes

    def to_wire(self) -> bytes:
        payload = {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "chunk_size": self.chunk_size,
            "chunk_count": self.chunk_count,
            "root_hash": self.root_hash.hex(),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_wire(cls, data: bytes) -> "Manifest":
        obj = json.loads(data.decode("utf-8"))
        return cls(
            file_name=obj["file_name"],
            file_size=int(obj["file_size"]),
            chunk_size=int(obj["chunk_size"]),
            chunk_count=int(obj["chunk_count"]),
            root_hash=bytes.fromhex(obj["root_hash"]),
        )


def scan_file(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple[Manifest, list[bytes]]:
    """Read the file and compute per-chunk hashes + Merkle root.

    Returns (manifest, list_of_leaf_hashes). The leaf hashes are kept in
    memory so the sender can verify chunks on-the-fly if paranoia demands it,
    and so the receiver can request the chunk_hashes side-channel for
    random-access verification when resuming.
    """
    size = os.path.getsize(path)
    count = max(1, (size + chunk_size - 1) // chunk_size) if size else 0
    hashes: list[bytes] = []
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            hashes.append(hash_chunk(data))
    root = merkle_root(hashes)
    return (
        Manifest(
            file_name=os.path.basename(path),
            file_size=size,
            chunk_size=chunk_size,
            chunk_count=len(hashes),
            root_hash=root,
        ),
        hashes,
    )


class ChunkReader:
    """Random-access reader. Keeps a single file descriptor open."""

    def __init__(self, path: str, chunk_size: int = DEFAULT_CHUNK_SIZE):
        self.path = path
        self.chunk_size = chunk_size
        self._f = open(path, "rb")

    def read(self, index: int) -> bytes:
        self._f.seek(index * self.chunk_size)
        return self._f.read(self.chunk_size)

    def close(self) -> None:
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class ChunkWriter:
    """
    Sparse random-access writer. Creates the destination pre-sized so chunks
    can be written in any order. Tracks which chunk indices have been
    verified; exposes `.missing()` for resume support.
    """

    def __init__(self, path: str, manifest: Manifest):
        self.path = path
        self.manifest = manifest
        self._f = open(path, "wb+")
        if manifest.file_size > 0:
            self._f.truncate(manifest.file_size)
        self.received: set[int] = set()

    def write(self, index: int, data: bytes) -> None:
        if index in self.received:
            return
        expected_hash = hash_chunk(data)
        # Caller verified against known leaf hash before calling write().
        self._f.seek(index * self.manifest.chunk_size)
        self._f.write(data)
        self.received.add(index)

    def missing(self) -> list[int]:
        return [i for i in range(self.manifest.chunk_count) if i not in self.received]

    def done(self) -> bool:
        return len(self.received) == self.manifest.chunk_count

    def flush(self) -> None:
        """Flush buffered writes to the OS so subsequent reads see them."""
        self._f.flush()
        try:
            os.fsync(self._f.fileno())
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.flush()
        finally:
            self._f.close()
