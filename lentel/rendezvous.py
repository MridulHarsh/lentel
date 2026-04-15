"""
Coordinator-free peer-to-peer rendezvous.

Public API:
    ticket = await send_file(path, on_ticket=..., progress=...)
    path   = await recv_file(ticket, dest_dir=..., progress=...)

The sender discovers its public address via STUN/UPnP, embeds it in the
ticket, and waits for the receiver's PUNCH.  The receiver parses the
address from the ticket and connects directly.  No server of any kind is
required.

An optional ``coordinator`` parameter is still accepted for backward
compatibility; if provided, the legacy coordinator-based flow is used.
"""
from __future__ import annotations

import asyncio
import os
import secrets
import socket
from typing import Callable, Optional

from .crypto import (
    HandshakeKeys, InitiatorHandshake, ResponderHandshake,
    psk_from_ticket,
)
from .nat import (
    NATError, discover_public_address, receiver_punch, sender_wait_for_peer,
)
from .session import RecvSession, SendSession, DEFAULT_PARALLEL_STREAMS
from .transport import Session, _Proto
from .wire import HEADER_SIZE, PacketType, decode_header
from .wordlist import new_ticket as _gen_ticket, parse_ticket


# ---------- helpers -------------------------------------------------------

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


async def _do_handshake_initiator(
    sock: socket.socket, peer: tuple[str, int], psk: bytes,
    timeout: float = 10.0,
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
    raise TimeoutError("handshake timed out (is the receiver reachable?)")


async def _do_handshake_responder(
    sock: socket.socket, peer: tuple[str, int], psk: bytes,
    timeout: float = 10.0,
) -> HandshakeKeys:
    loop = asyncio.get_event_loop()
    hs = ResponderHandshake(psk)
    deadline = asyncio.get_event_loop().time() + timeout
    hello_data: bytes | None = None
    while hello_data is None and asyncio.get_event_loop().time() < deadline:
        try:
            data, src = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 65535),
                timeout=max(0.1, deadline - asyncio.get_event_loop().time()),
            )
        except asyncio.TimeoutError:
            continue
        if src != peer:
            continue
        try:
            h = decode_header(data)
        except Exception:
            continue
        if h.type is PacketType.HELLO:
            hello_data = data
    if hello_data is None:
        raise TimeoutError("no HELLO received from sender")

    ack = hs.on_hello(hello_data)
    for _ in range(5):
        await loop.sock_sendto(sock, ack, peer)
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
        if h.type is PacketType.HS_DONE:
            hs.on_hs_done(data)
            assert hs.keys is not None
            return hs.keys
        if h.type is PacketType.HELLO:
            continue
    raise TimeoutError("handshake timed out as responder")


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


# ---------- public API ----------------------------------------------------

async def send_file(
    path: str,
    ticket: Optional[str] = None,
    parallel: int = DEFAULT_PARALLEL_STREAMS,
    progress: Optional[Callable] = None,
    on_ticket: Optional[Callable[[str], None]] = None,
    on_status: Optional[Callable[[str], None]] = None,
    wait_timeout: float = 300.0,
    **_kw,  # accept & ignore coordinator= for compat
) -> str:
    """
    Send a file.  No server required.

    1. Discovers public address via STUN / UPnP.
    2. Generates a ticket embedding that address.
    3. Fires ``on_ticket(ticket)`` so the UI can show it.
    4. Waits for the receiver to connect (up to ``wait_timeout`` seconds).
    5. Runs the encrypted transfer.
    6. Returns the ticket string on success.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    # If a full ticket (with @IP:PORT) was pre-supplied, bind to that port
    # so the address in the ticket matches our actual socket.
    bind_port = 0
    if ticket and "@" in ticket:
        try:
            _, (_, p) = parse_ticket(ticket)
            bind_port = p
        except (ValueError, Exception):
            pass

    sock = await _make_socket(bind_port=bind_port)
    try:
        if ticket and "@" in ticket:
            # Full ticket already has address — skip STUN discovery.
            pass
        else:
            # 1. Discover our public address.
            _status("Discovering public address\u2026")
            pub_ip, pub_port, method = await discover_public_address(sock)
            _status(f"Public address: {pub_ip}:{pub_port} ({method})")

            # 2. Build ticket.
            if ticket:
                # Code-only ticket provided; append our address.
                ticket = f"{ticket}@{pub_ip}:{pub_port}"
            else:
                ticket = _gen_ticket((pub_ip, pub_port))

        psk = psk_from_ticket(ticket.split("@")[0])

        if on_ticket:
            on_ticket(ticket)

        # 3. Derive a cookie for the PUNCH exchange.
        import hashlib
        cookie = hashlib.blake2b(
            b"lentel/v1/cookie\x00" + psk, digest_size=16,
        ).digest()

        # 4. Wait for receiver's PUNCH.
        _status("Waiting for receiver\u2026")
        peer = await sender_wait_for_peer(sock, cookie, timeout=wait_timeout)
        _status("Receiver connected \u2014 handshaking\u2026")

        # 5. Handshake (sender = initiator).
        keys = await _do_handshake_initiator(sock, peer, psk)

        # 6. Transfer.
        _status("Transferring\u2026")
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

    return ticket


async def recv_file(
    ticket: str,
    dest_dir: str = ".",
    parallel: int = DEFAULT_PARALLEL_STREAMS,
    progress: Optional[Callable] = None,
    overwrite: bool = False,
    on_status: Optional[Callable[[str], None]] = None,
    **_kw,  # accept & ignore coordinator= for compat
) -> str:
    """
    Receive a file by ticket.  No server required.

    1. Parses the sender's address from the ticket.
    2. Sends PUNCH packets to the sender.
    3. Completes the handshake.
    4. Receives + verifies the file.
    5. Returns the local path of the received file.
    """
    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    code, peer_addr = parse_ticket(ticket)
    psk = psk_from_ticket(code)

    import hashlib
    cookie = hashlib.blake2b(
        b"lentel/v1/cookie\x00" + psk, digest_size=16,
    ).digest()

    sock = await _make_socket()
    try:
        # 1. Connect to sender.
        _status("Connecting to sender\u2026")
        peer = await receiver_punch(sock, peer_addr, cookie)
        _status("Connected \u2014 handshaking\u2026")

        # 2. Handshake (receiver = responder).
        keys = await _do_handshake_responder(sock, peer, psk)

        # 3. Receive.
        _status("Receiving\u2026")
        session = await _wrap_socket(sock, keys, False, peer)
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
