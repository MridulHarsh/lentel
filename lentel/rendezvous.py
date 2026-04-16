"""
Peer-to-peer rendezvous, **receiver-first** model.

Public API:
    path   = await recv_file(dest_dir, on_ticket=..., progress=...)
    await  send_file(path, ticket, progress=...)

**Receiver** generates a fresh ticket (three words + checksum + its own
public IP:port discovered via STUN/UPnP), shares it with whoever will be
sending, and waits for the sender's incoming HELLO.  No server of any
kind is involved.

**Sender** supplies that ticket along with the file/folder to push.  The
sender does not need its own public address — it simply opens an
outbound UDP flow to the receiver.

This model is consent-based: nothing can be pushed to a device that has
not actively opened a receive session.
"""
from __future__ import annotations

import asyncio
import os
import socket
from typing import Callable, Optional

from .crypto import (
    HandshakeKeys, InitiatorHandshake, ResponderHandshake,
    psk_from_ticket,
)
from .nat import (
    NATError, discover_public_address, responder_wait_for_hello,
)
from .session import RecvSession, SendSession, DEFAULT_PARALLEL_STREAMS
from .transport import Session, _Proto
from .wire import HEADER_SIZE, PacketType, decode_header
from .wordlist import new_ticket as _gen_ticket, parse_ticket


# ---------- socket helpers ------------------------------------------------

async def _make_socket(bind_addr: str = "0.0.0.0", bind_port: int = 0) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setblocking(False)
    sock.bind((bind_addr, bind_port))
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    return sock


async def _resolve_host(host: str) -> str:
    """Resolve a hostname to an IPv4 address (no-op for IP literals)."""
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, 0, type=socket.SOCK_DGRAM,
                                       family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except socket.gaierror:
        pass
    return host


async def _wrap_socket(
    sock: socket.socket, keys: HandshakeKeys,
    is_initiator: bool, peer: tuple[str, int],
) -> Session:
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _Proto(None), sock=sock,
    )
    session = Session(transport, keys, is_initiator, peer)
    protocol.session = session
    session.start()
    return session


# ---------- handshake -----------------------------------------------------
#
# Sender is the cryptographic initiator (sends HELLO first).  Receiver is
# the responder (waits for HELLO, sends HELLO_ACK, verifies HS_DONE).
# In this receiver-first model the receiver doesn't know the sender's
# address until HELLO arrives — so the responder-side function that is
# used here (_finish_responder) takes an already-received HELLO and the
# source address from which it came.

async def _do_handshake_initiator(
    sock: socket.socket, peer: tuple[str, int], psk: bytes,
) -> HandshakeKeys:
    loop = asyncio.get_event_loop()
    hs = InitiatorHandshake(psk)
    hello = hs.hello()
    for _ in range(10):
        await loop.sock_sendto(sock, hello, peer)
        try:
            data, src = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 65535), timeout=1.0,
            )
        except asyncio.TimeoutError:
            continue
        if src != peer:
            continue
        try:
            h = decode_header(data)
        except Exception:
            continue
        if h.type is PacketType.HELLO_ACK:
            hs_done = hs.on_hello_ack(data)
            for _ in range(3):
                await loop.sock_sendto(sock, hs_done, peer)
                await asyncio.sleep(0.05)
            assert hs.keys is not None
            return hs.keys
    raise TimeoutError(
        "handshake timed out — the receiver may be offline or unreachable "
        "(check the ticket address)"
    )


async def _finish_responder(
    sock: socket.socket, peer: tuple[str, int], hello_data: bytes, psk: bytes,
    timeout: float = 10.0,
) -> HandshakeKeys:
    loop = asyncio.get_event_loop()
    hs = ResponderHandshake(psk)
    ack = hs.on_hello(hello_data)
    deadline = asyncio.get_event_loop().time() + timeout
    for _ in range(10):
        await loop.sock_sendto(sock, ack, peer)
        try:
            remaining = max(0.1, deadline - asyncio.get_event_loop().time())
            data, src = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 65535), timeout=min(1.0, remaining),
            )
        except asyncio.TimeoutError:
            continue
        if src != peer:
            continue
        try:
            h = decode_header(data)
        except Exception:
            continue
        if h.type is PacketType.HS_DONE:
            hs.on_hs_done(data)
            assert hs.keys is not None
            return hs.keys
        if h.type is PacketType.HELLO:
            # Sender retransmitted HELLO — ignore; our retransmitted ACK
            # will reach them shortly.
            continue
    raise TimeoutError("handshake timed out as responder")


# ---------- public API ----------------------------------------------------

async def recv_file(
    dest_dir: str = ".",
    parallel: int = DEFAULT_PARALLEL_STREAMS,
    progress: Optional[Callable] = None,
    on_ticket: Optional[Callable[[str], None]] = None,
    on_status: Optional[Callable[[str], None]] = None,
    wait_timeout: float = 300.0,
    overwrite: bool = False,
    advertise_host: Optional[str] = None,
    **_kw,
) -> str:
    """Open a receive session.  Returns the local path once a file arrives.

    The receiver:
      1. Opens a UDP socket.
      2. Discovers its public address (STUN + UPnP, unless
         ``advertise_host`` overrides it — used in tests).
      3. Generates a fresh ticket and calls ``on_ticket(ticket)``.  Share
         this ticket with whoever is going to send.
      4. Waits up to ``wait_timeout`` seconds for the sender's HELLO.
      5. Completes the AEAD handshake and receives the payload.
    """
    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    sock = await _make_socket()
    try:
        local_port = sock.getsockname()[1]

        if advertise_host is not None:
            pub_ip, pub_port = advertise_host, local_port
            _status(f"Advertising at {pub_ip}:{pub_port}")
        else:
            _status("Discovering public address\u2026")
            pub_ip, pub_port, method = await discover_public_address(sock)
            _status(f"Public address: {pub_ip}:{pub_port} ({method})")

        ticket = _gen_ticket((pub_ip, pub_port))
        code, _ = parse_ticket(ticket)
        psk = psk_from_ticket(code)

        if on_ticket:
            on_ticket(ticket)

        _status("Waiting for sender\u2026")
        hello_data, sender_addr = await responder_wait_for_hello(
            sock, timeout=wait_timeout,
        )
        _status(f"Sender connected from {sender_addr[0]}:{sender_addr[1]} \u2014 handshaking\u2026")

        keys = await _finish_responder(sock, sender_addr, hello_data, psk)

        _status("Receiving\u2026")
        session = await _wrap_socket(sock, keys, False, sender_addr)
        try:
            recv = RecvSession(
                session, dest_dir, parallel=parallel,
                progress=progress, overwrite=overwrite,
            )
            out = await recv.run()
        finally:
            await session.close()
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return out


async def send_file(
    path: str,
    ticket: str,
    parallel: int = DEFAULT_PARALLEL_STREAMS,
    progress: Optional[Callable] = None,
    on_status: Optional[Callable[[str], None]] = None,
    **_kw,
) -> None:
    """Send a file or folder to the holder of ``ticket``.

    The ticket is issued by the receiver (see ``recv_file``) and carries
    the receiver's public address.  The sender has no need for STUN or
    UPnP — it just opens an outbound UDP flow to that address.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if not (os.path.isfile(path) or os.path.isdir(path)):
        raise ValueError(f"path is not a file or folder: {path}")

    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    code, (host, port) = parse_ticket(ticket)
    psk = psk_from_ticket(code)

    sock = await _make_socket()
    try:
        _status(f"Resolving {host}\u2026")
        ip = await _resolve_host(host)
        peer = (ip, port)

        _status(f"Connecting to receiver at {host}:{port}\u2026")
        keys = await _do_handshake_initiator(sock, peer, psk)
        _status("Handshake complete \u2014 transferring\u2026")

        session = await _wrap_socket(sock, keys, True, peer)
        try:
            sender = SendSession(session, path, parallel=parallel, progress=progress)
            await sender.run()
        finally:
            await session.close()
    finally:
        try:
            sock.close()
        except Exception:
            pass


send_folder = send_file
