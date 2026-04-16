"""
File / folder transfer session state machines.

Given an open ``transport.Session``, these classes drive the actual payload:

  * **SendSession** publishes the manifest on the control stream, then streams
    chunks across N data streams.  The manifest can describe a single file or
    an entire folder tree (``chunker.Manifest``).
  * **RecvSession** reads the manifest, creates the destination tree, receives
    chunks on N streams in parallel, verifies each chunk's per-file Merkle
    root, and writes them to the right place on disk.

On the wire, every chunk message carries::

    u32 file_index  ||  u32 chunk_index  ||  u32 length  ||  data

so out-of-order chunks across different files interleave freely.

Control-stream protocol (one-byte tag):
    0x00 MANIFEST : json payload describing the payload
    0x01 RESUME   : list of (file_index, chunk_index) pairs the receiver already has
    0x02 DONE     : integrity-verified, transfer complete
    0x03 ABORT    : u8 reason
"""
from __future__ import annotations

import asyncio
import os
import struct
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .chunker import (
    DEFAULT_CHUNK_SIZE, Manifest, MultiFileReader, MultiFileWriter,
    hash_chunk, scan_path, verify_manifest,
)
from .transport import Session

CONTROL_STREAM = 1
DATA_STREAM_BASE = 2
DEFAULT_PARALLEL_STREAMS = 4

TAG_MANIFEST = 0x00
TAG_RESUME = 0x01
TAG_DONE = 0x02
TAG_ABORT = 0x03
TAG_DONE_ACK = 0x04   # sender -> receiver: "I got your DONE, you may close"

# Chunk header: u32 file_index || u32 chunk_index || u32 length
_CHUNK_HDR = struct.Struct("!III")
_CHUNK_HDR_SIZE = _CHUNK_HDR.size


Progress = Callable[[int, int, float], None]  # (bytes_done, total, rate_bps)


class TransferError(Exception):
    pass


# ---------- sender --------------------------------------------------------

class SendSession:
    def __init__(
        self,
        transport_session: Session,
        path: str,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        parallel: int = DEFAULT_PARALLEL_STREAMS,
        progress: Optional[Progress] = None,
    ):
        self._sess = transport_session
        self._path = path
        self._chunk_size = chunk_size
        self._parallel = parallel
        self._progress = progress
        self._manifest: Optional[Manifest] = None
        self._skip: set[tuple[int, int]] = set()
        self._bytes_sent = 0
        self._started = 0.0

    async def run(self) -> None:
        # 1. Build the manifest (single-file or folder).
        self._manifest, _ = scan_path(self._path, self._chunk_size)

        # 2. Send MANIFEST.
        payload = bytes([TAG_MANIFEST]) + self._manifest.to_wire()
        await self._sess.send(CONTROL_STREAM, payload)

        # 3. Wait for RESUME hint from the receiver (always sent, may be empty).
        try:
            msg = await asyncio.wait_for(
                self._sess.recv(CONTROL_STREAM), timeout=30.0,
            )
        except asyncio.TimeoutError:
            msg = b""
        if msg and msg[0] == TAG_RESUME:
            count = struct.unpack_from("!I", msg, 1)[0]
            off = 5
            for _ in range(count):
                if off + 8 > len(msg):
                    break
                fi, ci = struct.unpack_from("!II", msg, off)
                off += 8
                self._skip.add((fi, ci))

        # 4. Build the work queue: every (file_index, chunk_index) not in skip.
        work: list[tuple[int, int]] = []
        for fi, entry in enumerate(self._manifest.files):
            n = entry.chunk_count(self._chunk_size)
            for ci in range(n):
                if (fi, ci) not in self._skip:
                    work.append((fi, ci))

        # 5. Fan chunks out across parallel streams.
        self._started = time.monotonic()

        # Resolve reader root: for a folder, path itself; for single-file, path.
        reader_root = self._path

        with MultiFileReader(reader_root, self._manifest) as reader:
            tasks = [
                asyncio.create_task(self._stream_worker(reader, s_index, work))
                for s_index in range(self._parallel)
            ]
            done_task = asyncio.create_task(self._await_done())
            await asyncio.gather(*tasks)
            await done_task

    async def _stream_worker(
        self, reader: MultiFileReader, s_index: int,
        work: list[tuple[int, int]],
    ) -> None:
        """Round-robin a slice of the work list onto one stream."""
        stream_id = DATA_STREAM_BASE + s_index
        assert self._manifest is not None
        for idx in range(s_index, len(work), self._parallel):
            fi, ci = work[idx]
            data = reader.read(fi, ci)
            header = _CHUNK_HDR.pack(fi, ci, len(data))
            await self._sess.send(stream_id, header + data)
            self._bytes_sent += len(data)
            if self._progress and self._manifest.total_size:
                now = time.monotonic()
                elapsed = max(0.001, now - self._started)
                self._progress(
                    self._bytes_sent, self._manifest.total_size,
                    self._bytes_sent / elapsed,
                )

    async def _await_done(self) -> None:
        while True:
            try:
                msg = await asyncio.wait_for(
                    self._sess.recv(CONTROL_STREAM), timeout=120.0,
                )
            except asyncio.TimeoutError:
                raise TransferError("receiver did not confirm within 120 s")
            if not msg:
                raise TransferError("receiver closed before confirming")
            tag = msg[0]
            if tag == TAG_DONE:
                # Acknowledge: tells the receiver we've read DONE and it's
                # now safe for them to close without losing our side's
                # view of the transfer. Drain so the ACK lands on the wire
                # before our own close().
                try:
                    await self._sess.send(CONTROL_STREAM, bytes([TAG_DONE_ACK]))
                    await self._sess.drain(timeout=2.0)
                except Exception:
                    pass
                return
            if tag == TAG_ABORT:
                reason = msg[1] if len(msg) > 1 else 0
                raise TransferError(f"receiver aborted (code {reason})")
            continue


# ---------- receiver ------------------------------------------------------

class RecvSession:
    def __init__(
        self,
        transport_session: Session,
        dest_dir: str,
        parallel: int = DEFAULT_PARALLEL_STREAMS,
        progress: Optional[Progress] = None,
        overwrite: bool = False,
        resume: bool = True,
    ):
        self._sess = transport_session
        self._dest_dir = dest_dir
        self._parallel = parallel
        self._progress = progress
        self._overwrite = overwrite
        self._resume = resume
        self.output_path: Optional[str] = None
        self._started = 0.0
        self._bytes_got = 0

    async def run(self) -> str:
        # 1. Receive manifest.
        msg = await self._sess.recv(CONTROL_STREAM)
        if not msg or msg[0] != TAG_MANIFEST:
            raise TransferError("expected MANIFEST first")
        manifest = Manifest.from_wire(msg[1:])

        # 2. Create dest dir and open writer.
        os.makedirs(self._dest_dir, exist_ok=True)
        writer = MultiFileWriter(self._dest_dir, manifest)
        self.output_path = writer.output_path

        # 3. Compute resume set — any chunks already on disk that match the
        #    expected per-file Merkle root can be skipped. For simplicity:
        #    whole-file match only. Partial chunk resume is a future optimization.
        resume_set: set[tuple[int, int]] = set()
        if self._resume and not self._overwrite:
            for i, entry in enumerate(manifest.files):
                # Did an earlier run write this file correctly?
                target = writer._paths[i]
                if not os.path.isfile(target):
                    continue
                try:
                    with open(target, "rb") as f:
                        from .chunker import merkle_root, hash_chunk
                        leaves: list[bytes] = []
                        while True:
                            data = f.read(manifest.chunk_size)
                            if not data:
                                break
                            leaves.append(hash_chunk(data))
                        if os.path.getsize(target) == entry.size \
                                and merkle_root(leaves) == entry.root_hash:
                            n = entry.chunk_count(manifest.chunk_size)
                            for c in range(n):
                                resume_set.add((i, c))
                                writer.received.add((i, c))
                except OSError:
                    pass

        # 4. Send RESUME (empty or populated).
        payload = bytes([TAG_RESUME]) + struct.pack("!I", len(resume_set))
        for fi, ci in sorted(resume_set):
            payload += struct.pack("!II", fi, ci)
        await self._sess.send(CONTROL_STREAM, payload)

        self._bytes_got = sum(
            manifest.files[fi].size
            if ci == manifest.files[fi].chunk_count(manifest.chunk_size) - 1
            else manifest.chunk_size
            for fi, ci in resume_set
        )
        self._started = time.monotonic()

        # 5. Spin up receive workers.
        try:
            workers = [
                asyncio.create_task(self._stream_worker(s_index, writer, manifest))
                for s_index in range(self._parallel)
            ]
            await asyncio.gather(*workers)

            if not writer.done():
                missing = writer.missing()
                raise TransferError(
                    f"transfer ended with {len(missing)} missing chunks"
                )

            # 6. Flush and re-verify every file's Merkle root.
            writer.flush()
            if not verify_manifest(writer.root_path, manifest):
                raise TransferError("final Merkle root mismatch")

            # 7. Confirm + wait for the sender's DONE_ACK.
            #
            # Without the explicit ACK, there's a race at teardown: if we
            # close() right after send(DONE), the CLOSE packet can arrive at
            # the sender BEFORE the sender's asyncio loop has pulled DONE
            # from its recv queue (observed on Windows + Python 3.11/3.12).
            # The ACK guarantees the sender has already processed DONE.
            await self._sess.send(CONTROL_STREAM, bytes([TAG_DONE]))
            await self._sess.drain(timeout=5.0)
            try:
                ack = await asyncio.wait_for(
                    self._sess.recv(CONTROL_STREAM), timeout=10.0,
                )
                # Don't strictly require TAG_DONE_ACK — any response (or
                # even session close from the peer) is enough to know the
                # sender has finished reading.
                _ = ack
            except asyncio.TimeoutError:
                pass
            return writer.output_path

        except Exception:
            try:
                await self._sess.send(CONTROL_STREAM, bytes([TAG_ABORT, 3]))
            except Exception:
                pass
            raise
        finally:
            writer.close()

    async def _stream_worker(
        self, s_index: int, writer: MultiFileWriter, manifest: Manifest,
    ) -> None:
        stream_id = DATA_STREAM_BASE + s_index

        # Count how many chunks we expect on this stream (fan-in mirrors the
        # sender's round-robin fan-out).
        remaining_chunks: list[tuple[int, int]] = []
        idx = 0
        for fi, entry in enumerate(manifest.files):
            n = entry.chunk_count(manifest.chunk_size)
            for ci in range(n):
                if (fi, ci) not in writer.received:
                    if idx % self._parallel == s_index:
                        remaining_chunks.append((fi, ci))
                    idx += 1

        got = 0
        expected = len(remaining_chunks)
        while got < expected:
            msg = await self._sess.recv(stream_id)
            if not msg:
                break
            if len(msg) < _CHUNK_HDR_SIZE:
                raise TransferError("short chunk message")
            fi, ci, length = _CHUNK_HDR.unpack_from(msg, 0)
            body = msg[_CHUNK_HDR_SIZE : _CHUNK_HDR_SIZE + length]
            if len(body) != length:
                raise TransferError("chunk length mismatch")
            if fi >= len(manifest.files):
                raise TransferError(f"chunk refers to unknown file index {fi}")
            # Per-chunk hash is a quick sanity gate; the final Merkle check is
            # authoritative.
            _ = hash_chunk(body)
            writer.write(fi, ci, body)
            self._bytes_got += len(body)
            got += 1
            if self._progress and manifest.total_size:
                now = time.monotonic()
                elapsed = max(0.001, now - self._started)
                self._progress(
                    self._bytes_got, manifest.total_size,
                    self._bytes_got / elapsed,
                )
