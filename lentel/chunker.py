"""
File / folder chunking and integrity verification.

A Lentel transfer ships either a single file or an entire folder tree.
Either way the payload is described by a **multi-file manifest** of the form:

    Manifest {
        root_name:    str           # "video.mkv" or "my-folder"
        is_folder:    bool
        chunk_size:   int           # 65536
        files:        [FileEntry]   # list, always >= 1 entry
        total_size:   int
        total_chunks: int
    }
    FileEntry {
        path:      str              # relative path ("a.txt", "sub/b.txt")
        size:      int
        root_hash: bytes            # per-file BLAKE2b Merkle root (32 B)
    }

Chunks are numbered per-file: on the wire every DATA message carries
(file_index, chunk_index, length, data). 64 KiB chunks are hashed with
BLAKE2b and verified against the per-file Merkle root. A corrupted chunk
triggers a NACK at the session layer — integrity is end-to-end independent
of the transport.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from typing import Iterable

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KiB
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


# ---------- hashing / Merkle ---------------------------------------------

def hash_chunk(data: bytes) -> bytes:
    return hashlib.blake2b(LEAF_PREFIX + data, digest_size=32).digest()


def _hash_node(left: bytes, right: bytes) -> bytes:
    return hashlib.blake2b(NODE_PREFIX + left + right, digest_size=32).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
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


# ---------- data classes --------------------------------------------------

@dataclass
class FileEntry:
    path: str           # relative path from root (forward slashes on the wire)
    size: int
    root_hash: bytes    # 32 bytes

    def chunk_count(self, chunk_size: int) -> int:
        if self.size == 0:
            return 0
        return (self.size + chunk_size - 1) // chunk_size


@dataclass
class Manifest:
    root_name: str                # top-level name (folder or file)
    is_folder: bool
    chunk_size: int
    files: list[FileEntry]
    total_size: int
    total_chunks: int

    def to_wire(self) -> bytes:
        obj = {
            "root_name": self.root_name,
            "is_folder": self.is_folder,
            "chunk_size": self.chunk_size,
            "total_size": self.total_size,
            "total_chunks": self.total_chunks,
            "files": [
                {"path": f.path, "size": f.size, "root_hash": f.root_hash.hex()}
                for f in self.files
            ],
        }
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_wire(cls, data: bytes) -> "Manifest":
        obj = json.loads(data.decode("utf-8"))
        files = [
            FileEntry(
                path=e["path"],
                size=int(e["size"]),
                root_hash=bytes.fromhex(e["root_hash"]),
            )
            for e in obj["files"]
        ]
        return cls(
            root_name=obj["root_name"],
            is_folder=bool(obj.get("is_folder", False)),
            chunk_size=int(obj["chunk_size"]),
            files=files,
            total_size=int(obj["total_size"]),
            total_chunks=int(obj["total_chunks"]),
        )


# ---------- safe path handling --------------------------------------------

class UnsafePathError(ValueError):
    pass


def sanitize_relpath(rel: str) -> str:
    """Reject absolute paths and path-traversal attempts.

    Accepts forward- or back-slash separators (we normalise to forward
    slashes on the wire). Rejects anything that would escape the root
    dir, plus reserved Windows-only absolute forms like ``C:\\foo``.
    """
    if not rel:
        raise UnsafePathError("empty path in manifest")
    norm = rel.replace("\\", "/")
    if norm.startswith("/"):
        raise UnsafePathError(f"absolute path in manifest: {rel!r}")
    if len(norm) >= 2 and norm[1] == ":":  # drive-letter
        raise UnsafePathError(f"drive-letter path in manifest: {rel!r}")
    parts = norm.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise UnsafePathError(f"unsafe path component in manifest: {rel!r}")
    return "/".join(parts)


def _resolve_under(root: str, rel: str) -> str:
    """Join ``rel`` onto ``root`` and ensure the result stays inside ``root``."""
    safe = sanitize_relpath(rel)
    full = os.path.normpath(os.path.join(root, *safe.split("/")))
    root_abs = os.path.abspath(root)
    full_abs = os.path.abspath(full)
    if not (full_abs == root_abs or full_abs.startswith(root_abs + os.sep)):
        raise UnsafePathError(f"path escapes root: {rel!r}")
    return full


# ---------- scanning (sender side) ---------------------------------------

def _scan_single(abs_path: str, chunk_size: int) -> tuple[FileEntry, list[bytes]]:
    size = os.path.getsize(abs_path)
    hashes: list[bytes] = []
    with open(abs_path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            hashes.append(hash_chunk(data))
    return (
        FileEntry(
            path=os.path.basename(abs_path),
            size=size,
            root_hash=merkle_root(hashes),
        ),
        hashes,
    )


def scan_file(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple[Manifest, list[list[bytes]]]:
    """Build a single-file manifest.

    Returns (manifest, list_of_leaf_hashes_per_file) — the second element
    is always a length-1 list here, kept for parity with ``scan_folder``.
    """
    entry, hashes = _scan_single(path, chunk_size)
    total_chunks = entry.chunk_count(chunk_size)
    manifest = Manifest(
        root_name=entry.path,
        is_folder=False,
        chunk_size=chunk_size,
        files=[entry],
        total_size=entry.size,
        total_chunks=total_chunks,
    )
    return manifest, [hashes]


def scan_folder(
    path: str, chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> tuple[Manifest, list[list[bytes]]]:
    """Build a multi-file manifest from a directory tree.

    Walks ``path`` recursively, in sorted order for reproducibility.
    Silently skips symlinks that point outside the tree and anything that
    can't be opened for reading.
    """
    root = os.path.abspath(path)
    root_name = os.path.basename(root.rstrip(os.sep)) or "folder"

    files: list[FileEntry] = []
    all_hashes: list[list[bytes]] = []
    total_size = 0
    total_chunks = 0

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for fname in sorted(filenames):
            abs_f = os.path.join(dirpath, fname)
            if not os.path.isfile(abs_f) or os.path.islink(abs_f):
                continue
            rel = os.path.relpath(abs_f, root).replace(os.sep, "/")
            try:
                sanitize_relpath(rel)
            except UnsafePathError:
                continue

            try:
                _, hashes = _scan_single(abs_f, chunk_size)
            except OSError:
                continue

            size = os.path.getsize(abs_f)
            entry = FileEntry(path=rel, size=size, root_hash=merkle_root(hashes))
            files.append(entry)
            all_hashes.append(hashes)
            total_size += size
            total_chunks += entry.chunk_count(chunk_size)

    manifest = Manifest(
        root_name=root_name,
        is_folder=True,
        chunk_size=chunk_size,
        files=files,
        total_size=total_size,
        total_chunks=total_chunks,
    )
    return manifest, all_hashes


def scan_path(path: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple[Manifest, list[list[bytes]]]:
    """Auto-detect file vs folder and build the appropriate manifest."""
    if os.path.isdir(path):
        return scan_folder(path, chunk_size)
    if os.path.isfile(path):
        return scan_file(path, chunk_size)
    raise FileNotFoundError(path)


# ---------- multi-file reader (sender side) ------------------------------

class MultiFileReader:
    """Random-access reader over all files in a manifest.

    Keeps file handles open in a small LRU cache so we don't open/close on
    every chunk read.
    """

    def __init__(self, root_path: str, manifest: Manifest, cache_size: int = 8):
        self.root = root_path
        self.manifest = manifest
        self._cache: dict[int, object] = {}
        self._order: list[int] = []
        self._cache_size = max(1, cache_size)

    def _abs_path(self, file_index: int) -> str:
        entry = self.manifest.files[file_index]
        if self.manifest.is_folder:
            # Receiver side: root_path already includes the folder name.
            # Sender side: root_path is the folder itself.
            return os.path.join(self.root, *entry.path.split("/"))
        return self.root  # single-file case: root_path IS the file

    def _get(self, file_index: int):
        f = self._cache.get(file_index)
        if f is not None:
            self._order.remove(file_index)
            self._order.append(file_index)
            return f
        f = open(self._abs_path(file_index), "rb")
        self._cache[file_index] = f
        self._order.append(file_index)
        while len(self._order) > self._cache_size:
            evict = self._order.pop(0)
            self._cache.pop(evict).close()
        return f

    def read(self, file_index: int, chunk_index: int) -> bytes:
        f = self._get(file_index)
        f.seek(chunk_index * self.manifest.chunk_size)
        return f.read(self.manifest.chunk_size)

    def close(self) -> None:
        for f in self._cache.values():
            try:
                f.close()
            except Exception:
                pass
        self._cache.clear()
        self._order.clear()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# ---------- multi-file writer (receiver side) ----------------------------

class MultiFileWriter:
    """Sparse random-access writer over all files in a manifest.

    For a folder manifest: creates ``<dest_dir>/<root_name>/`` and every
    subdirectory, pre-sizes each file, and accepts out-of-order writes.

    For a single-file manifest: writes directly into ``dest_dir``.
    """

    def __init__(self, dest_dir: str, manifest: Manifest):
        self.manifest = manifest
        self.received: set[tuple[int, int]] = set()  # (file_idx, chunk_idx)

        if manifest.is_folder:
            self.root_path = os.path.join(dest_dir, manifest.root_name)
        else:
            self.root_path = dest_dir

        self._handles: dict[int, object] = {}
        self._paths: dict[int, str] = {}

        os.makedirs(self.root_path, exist_ok=True)

        for i, entry in enumerate(manifest.files):
            if manifest.is_folder:
                full = _resolve_under(self.root_path, entry.path)
            else:
                # Single-file manifest: entry.path IS the file name.
                full = _resolve_under(self.root_path, entry.path)

            os.makedirs(os.path.dirname(full) or self.root_path, exist_ok=True)
            f = open(full, "wb+")
            if entry.size > 0:
                f.truncate(entry.size)
            self._handles[i] = f
            self._paths[i] = full

    @property
    def output_path(self) -> str:
        """For single-file manifests this is the written file; for folders,
        the directory we created."""
        if self.manifest.is_folder:
            return self.root_path
        return self._paths[0]

    def write(self, file_index: int, chunk_index: int, data: bytes) -> None:
        key = (file_index, chunk_index)
        if key in self.received:
            return
        f = self._handles[file_index]
        f.seek(chunk_index * self.manifest.chunk_size)
        f.write(data)
        self.received.add(key)

    def missing(self) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for i, entry in enumerate(self.manifest.files):
            n = entry.chunk_count(self.manifest.chunk_size)
            for c in range(n):
                if (i, c) not in self.received:
                    out.append((i, c))
        return out

    def done(self) -> bool:
        return len(self.received) == self.manifest.total_chunks

    def flush(self) -> None:
        for f in self._handles.values():
            try:
                f.flush()
                os.fsync(f.fileno())
            except OSError:
                pass

    def close(self) -> None:
        try:
            self.flush()
        finally:
            for f in self._handles.values():
                try:
                    f.close()
                except Exception:
                    pass
            self._handles.clear()


# ---------- final verification (receiver side) ---------------------------

def verify_manifest(root_path: str, manifest: Manifest) -> bool:
    """Recompute every file's Merkle root and compare to the manifest."""
    for entry in manifest.files:
        if manifest.is_folder:
            abs_f = _resolve_under(root_path, entry.path)
        else:
            abs_f = _resolve_under(os.path.dirname(root_path) or root_path, entry.path)
            if not os.path.isfile(abs_f):
                abs_f = root_path  # fall back for single-file writers
        try:
            with open(abs_f, "rb") as f:
                leaves: list[bytes] = []
                while True:
                    data = f.read(manifest.chunk_size)
                    if not data:
                        break
                    leaves.append(hash_chunk(data))
                if os.path.getsize(abs_f) != entry.size:
                    return False
                if merkle_root(leaves) != entry.root_hash:
                    return False
        except OSError:
            return False
    return True
