"""
Peer-to-peer rendezvous.

Public API:
    ticket = await send_file(path, on_ticket=..., progress=..., relay=None)
    path   = await recv_file(ticket, dest_dir=..., progress=..., relay=None)

**Default (direct) mode**: the sender discovers its public address via
STUN/UPnP, embeds it in the ticket, and waits for the receiver's PUNCH.
The receiver parses the address from the ticket and connects directly.
No server is involved.  Works when at least one side's NAT is cone-type.

**Relay mode**: if the sender passes ``relay="host:port"``, the ticket
encodes the relay's address instead of the sender's.  Both peers connect
to the relay, which forwards opaque UDP datagrams between them.  The
relay never sees plaintext (the AEAD keys are derived from the ticket
PSK and never leave either peer).  This works on any NAT type.  Run
your own relay with ``lentel-relay --bind 0.0.0.0:7778``.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import socket
from typing import Callable, Optional

from .crypto import (
    HandshakeKeys, InitiatorHandshake, ResponderHandshake,
    psk_from_ticket,
)
from .nat import (
    NATError, RELAY_MAGIC, RELAY_TOKEN_LEN, discover_public_address,
    parse_relay_url, receiver_punch, relay_register, sender_wait_for_peer,
)
from .session import RecvSession, SendSession, DEFAULT_PARALLEL_STREAMS
from .transport import Session, _Proto
from .wire import HEADER_SIZE, PacketType, decode_header
from .wordlist import (
    new_code, new_ticket as _gen_ticket, parse_ticket, psk_to_relay_token,
)


# ---------- socket + handshake helpers ------------------------------------

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


def _is_relay_stray(data: bytes) -> bool:
    """A stray relay registration-ACK packet arriving during handshake."""
    return data.startswith(RELAY_MAGIC)


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
        if _is_relay_stray(data):
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
        if _is_relay_stray(data):
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
        if _is_relay_stray(data):
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


async def _resolve_host(host: str) -> str:
    """Best-effort DNS resolution to an IPv4 address."""
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.getaddrinfo(host, 0, type=socket.SOCK_DGRAM,
                                       family=socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except socket.gaierror:
        pass
    return host  # may already be an IP literal


# ---------- public API ----------------------------------------------------

async def send_file(
    path: str,
    ticket: Optional[str] = None,
    parallel: int = DEFAULT_PARALLEL_STREAMS,
    progress: Optional[Callable] = None,
    on_ticket: Optional[Callable[[str], None]] = None,
    on_status: Optional[Callable[[str], None]] = None,
    wait_timeout: float = 300.0,
    relay: Optional[str] = None,
    **_kw,
) -> str:
    """Send a file or folder.  Returns the ticket on success.

    If ``relay`` is a ``host:port`` string, the transfer goes through that
    relay (required when your NAT blocks incoming connections).  The relay
    never sees plaintext.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if not (os.path.isfile(path) or os.path.isdir(path)):
        raise ValueError(f"path is not a file or folder: {path}")

    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    # ---- relay mode -----------------------------------------------------
    if relay:
        return await _send_via_relay(
            path, relay, ticket, parallel, progress,
            on_ticket, _status, wait_timeout,
        )

    # ---- direct mode ----------------------------------------------------
    bind_port = 0
    if ticket and "@" in ticket:
        try:
            _, (_, p), _ = parse_ticket(ticket)
            bind_port = p
        except Exception:
            pass

    sock = await _make_socket(bind_port=bind_port)
    try:
        if ticket and "@" in ticket:
            pass
        else:
            _status("Discovering public address\u2026")
            pub_ip, pub_port, method = await discover_public_address(sock)
            _status(f"Public address: {pub_ip}:{pub_port} ({method})")
            if ticket:
                ticket = f"{ticket}@{pub_ip}:{pub_port}"
            else:
                ticket = _gen_ticket((pub_ip, pub_port))

        code, _addr, _relay_flag = parse_ticket(ticket)
        psk = psk_from_ticket(code)

        if on_ticket:
            on_ticket(ticket)

        cookie = hashlib.blake2b(
            b"lentel/v1/cookie\x00" + psk, digest_size=16,
        ).digest()

        _status("Waiting for receiver\u2026")
        peer = await sender_wait_for_peer(sock, cookie, timeout=wait_timeout)
        _status("Receiver connected \u2014 handshaking\u2026")

        keys = await _do_handshake_initiator(sock, peer, psk)

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


async def _send_via_relay(
    path: str,
    relay_url: str,
    ticket: Optional[str],
    parallel: int,
    progress: Optional[Callable],
    on_ticket: Optional[Callable[[str], None]],
    _status: Callable[[str], None],
    wait_timeout: float,
) -> str:
    relay_host, relay_port = parse_relay_url(relay_url)
    _status(f"Resolving relay {relay_host}\u2026")
    relay_ip = await _resolve_host(relay_host)
    relay_addr = (relay_ip, relay_port)

    code = ticket.split("@")[0] if (ticket and "@" in ticket) else (ticket or new_code())
    # Build ticket with relay address baked in.
    ticket = f"{code}@r:{relay_host}:{relay_port}"
    psk = psk_from_ticket(code)
    token = psk_to_relay_token(psk)

    if on_ticket:
        on_ticket(ticket)

    sock = await _make_socket()
    try:
        _status(f"Registering with relay at {relay_host}:{relay_port}\u2026")
        await relay_register(sock, relay_addr, token, paired_timeout=wait_timeout)
        _status("Receiver connected via relay \u2014 handshaking\u2026")

        keys = await _do_handshake_initiator(sock, relay_addr, psk)

        _status("Transferring (via relay)\u2026")
        session = await _wrap_socket(sock, keys, True, relay_addr)
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
    **_kw,
) -> str:
    """Receive a file or folder by ticket.

    Relay mode is auto-detected from the ticket — no extra flag needed.
    """
    def _status(msg: str) -> None:
        if on_status:
            on_status(msg)

    code, peer_host_port, via_relay = parse_ticket(ticket)
    psk = psk_from_ticket(code)

    _status(f"Resolving {peer_host_port[0]}\u2026")
    peer_ip = await _resolve_host(peer_host_port[0])
    peer_addr = (peer_ip, peer_host_port[1])

    sock = await _make_socket()
    try:
        if via_relay:
            token = psk_to_relay_token(psk)
            _status(f"Registering with relay at {peer_host_port[0]}:{peer_host_port[1]}\u2026")
            await relay_register(sock, peer_addr, token, paired_timeout=60.0)
            _status("Paired via relay \u2014 handshaking\u2026")
        else:
            cookie = hashlib.blake2b(
                b"lentel/v1/cookie\x00" + psk, digest_size=16,
            ).digest()
            _status("Connecting to sender\u2026")
            peer_addr = await receiver_punch(sock, peer_addr, cookie)
            _status("Connected \u2014 handshaking\u2026")

        keys = await _do_handshake_responder(sock, peer_addr, psk)

        _status("Receiving\u2026")
        session = await _wrap_socket(sock, keys, False, peer_addr)
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


# Convenience alias.
send_folder = send_file
