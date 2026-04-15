"""
Coordinator-free NAT traversal.

Lentel no longer requires a rendezvous server. Instead:

  1. The SENDER discovers its own public IP:port via public STUN servers
     (Google, Cloudflare — free, stateless, no account needed) and,
     optionally, opens a port mapping via UPnP/NAT-PMP on the local router.
  2. The public address is embedded directly in the ticket:
         bold-crab-fern-42@203.0.113.5:54321
  3. The sender keeps its NAT mapping alive by sending periodic STUN
     keepalives.
  4. The RECEIVER parses the address from the ticket and sends a PUNCH
     packet directly to the sender. On most home/mobile NATs (full cone,
     address-restricted, port-restricted) the sender's mapping is still
     alive so the packet gets through.
  5. The Lentel handshake then proceeds directly over the punched path.

If UPnP succeeds the sender has a truly reachable port (works with every
NAT type). If only STUN works, the success depends on the sender's NAT
being cone-type (covers ~75 %+ of consumer NATs).

Public STUN servers used (UDP, stateless, free, no signup):
  - stun.l.google.com:19302
  - stun.cloudflare.com:3478
"""
from __future__ import annotations

import asyncio
import secrets
import socket
import struct
import time
from typing import Optional

# ---------- STUN (RFC 5389, minimal binding-request client) ---------------

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
    ("stun.stunprotocol.org", 3478),
]

_STUN_MAGIC = 0x2112A442
_BINDING_REQUEST = 0x0001
_BINDING_RESPONSE = 0x0101
_ATTR_MAPPED_ADDRESS = 0x0001
_ATTR_XOR_MAPPED_ADDRESS = 0x0020


class NATError(Exception):
    pass


def _build_stun_request() -> tuple[bytes, bytes]:
    txn_id = secrets.token_bytes(12)
    hdr = struct.pack("!HHI", _BINDING_REQUEST, 0, _STUN_MAGIC) + txn_id
    return hdr, txn_id


def _parse_stun_response(data: bytes, txn_id: bytes) -> Optional[tuple[str, int]]:
    if len(data) < 20:
        return None
    msg_type, msg_len, magic = struct.unpack_from("!HHI", data, 0)
    if msg_type != _BINDING_RESPONSE or magic != _STUN_MAGIC:
        return None
    if data[8:20] != txn_id:
        return None
    off = 20
    end = 20 + msg_len
    while off + 4 <= end:
        attr_type, attr_len = struct.unpack_from("!HH", data, off)
        off += 4
        if attr_type == _ATTR_XOR_MAPPED_ADDRESS and attr_len >= 8:
            family = data[off + 1]
            if family == 0x01:
                xport = struct.unpack_from("!H", data, off + 2)[0] ^ (_STUN_MAGIC >> 16)
                xip = struct.unpack_from("!I", data, off + 4)[0] ^ _STUN_MAGIC
                return socket.inet_ntoa(struct.pack("!I", xip)), xport
        elif attr_type == _ATTR_MAPPED_ADDRESS and attr_len >= 8:
            family = data[off + 1]
            if family == 0x01:
                port = struct.unpack_from("!H", data, off + 2)[0]
                ip = socket.inet_ntoa(data[off + 4 : off + 8])
                return ip, port
        off += attr_len
        if attr_len % 4:
            off += 4 - (attr_len % 4)
    return None


async def stun_discover(
    sock: socket.socket,
    servers: list[tuple[str, int]] | None = None,
    retries: int = 3,
    timeout: float = 2.0,
) -> tuple[str, int]:
    """Query public STUN servers to learn this socket's reflexive address."""
    loop = asyncio.get_event_loop()
    servers = servers or list(STUN_SERVERS)
    last_err: Optional[Exception] = None
    for server in servers:
        pkt, txn_id = _build_stun_request()
        for _ in range(retries):
            try:
                await loop.sock_sendto(sock, pkt, server)
                data, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 1024), timeout=timeout,
                )
                result = _parse_stun_response(data, txn_id)
                if result:
                    return result
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                last_err = e
                break
    raise NATError(
        f"Could not reach any STUN server ({last_err or 'all timed out'}). "
        "Check your internet connection."
    )


async def stun_keepalive(
    sock: socket.socket,
    interval: float = 15.0,
    stop: asyncio.Event | None = None,
) -> None:
    """Send periodic STUN binding requests to keep the NAT mapping alive."""
    loop = asyncio.get_event_loop()
    stop = stop or asyncio.Event()
    server = STUN_SERVERS[0]
    while not stop.is_set():
        try:
            pkt, _ = _build_stun_request()
            await loop.sock_sendto(sock, pkt, server)
        except Exception:
            pass
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass


# ---------- UPnP IGD (best-effort port mapping) --------------------------

_SSDP_ADDR = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {_SSDP_ADDR}:{_SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)


def _ssdp_discover(timeout: float = 3.0) -> Optional[str]:
    """Discover the IGD's description URL via SSDP multicast."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)
    try:
        sock.sendto(_SSDP_SEARCH.encode(), (_SSDP_ADDR, _SSDP_PORT))
        while True:
            try:
                data, _ = sock.recvfrom(4096)
                text = data.decode(errors="replace")
                for line in text.splitlines():
                    if line.lower().startswith("location:"):
                        return line.split(":", 1)[1].strip()
            except socket.timeout:
                return None
    except Exception:
        return None
    finally:
        sock.close()


def _upnp_get_control_url(desc_url: str) -> Optional[tuple[str, str]]:
    """Fetch the IGD XML description and extract the WANIPConnection control URL."""
    import urllib.request
    import xml.etree.ElementTree as ET
    try:
        with urllib.request.urlopen(desc_url, timeout=5) as resp:
            tree = ET.parse(resp)
        ns = {"u": "urn:schemas-upnp-org:device-1-0"}
        root = tree.getroot()
        base = desc_url.rsplit("/", 1)[0]
        for svc in root.iter():
            if "serviceType" in svc.tag:
                continue
            st = svc.findtext("u:serviceType", "", ns)
            if not st:
                st = svc.findtext("serviceType", "")
            if "WANIPConnection" in st or "WANPPPConnection" in st:
                ctrl = svc.findtext("u:controlURL", "", ns)
                if not ctrl:
                    ctrl = svc.findtext("controlURL", "")
                if ctrl:
                    if ctrl.startswith("http"):
                        return ctrl, st
                    return base + ctrl, st
    except Exception:
        pass
    return None


def _upnp_add_mapping(
    control_url: str,
    service_type: str,
    external_port: int,
    local_ip: str,
    local_port: int,
    protocol: str = "UDP",
    description: str = "Lentel",
    lease: int = 3600,
) -> bool:
    """Send a SOAP AddPortMapping request to the IGD."""
    import urllib.request
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:AddPortMapping xmlns:u="{service_type}">'
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{external_port}</NewExternalPort>"
        f"<NewProtocol>{protocol}</NewProtocol>"
        f"<NewInternalPort>{local_port}</NewInternalPort>"
        f"<NewInternalClient>{local_ip}</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        f"<NewPortMappingDescription>{description}</NewPortMappingDescription>"
        f"<NewLeaseDuration>{lease}</NewLeaseDuration>"
        "</u:AddPortMapping>"
        "</s:Body>"
        "</s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#AddPortMapping"',
    }
    req = urllib.request.Request(control_url, body.encode(), headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def _upnp_delete_mapping(
    control_url: str, service_type: str,
    external_port: int, protocol: str = "UDP",
) -> None:
    import urllib.request
    body = (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"'
        ' s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:DeletePortMapping xmlns:u="{service_type}">'
        "<NewRemoteHost></NewRemoteHost>"
        f"<NewExternalPort>{external_port}</NewExternalPort>"
        f"<NewProtocol>{protocol}</NewProtocol>"
        "</u:DeletePortMapping>"
        "</s:Body>"
        "</s:Envelope>"
    )
    headers = {
        "Content-Type": 'text/xml; charset="utf-8"',
        "SOAPAction": f'"{service_type}#DeletePortMapping"',
    }
    req = urllib.request.Request(control_url, body.encode(), headers)
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _get_local_ip() -> str:
    """Best-effort guess at the LAN IP used to reach the internet."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


class UPnPMapping:
    """RAII wrapper: opens a UPnP mapping on enter, deletes on exit."""

    def __init__(self):
        self._ctrl: Optional[str] = None
        self._svc: Optional[str] = None
        self._port: int = 0
        self.public_ip: Optional[str] = None
        self.public_port: int = 0

    def try_map(self, local_port: int) -> bool:
        desc = _ssdp_discover()
        if not desc:
            return False
        info = _upnp_get_control_url(desc)
        if not info:
            return False
        self._ctrl, self._svc = info
        local_ip = _get_local_ip()
        ext_port = local_port  # try the same port first
        if _upnp_add_mapping(self._ctrl, self._svc, ext_port, local_ip, local_port):
            self._port = ext_port
            self.public_port = ext_port
            return True
        return False

    def close(self) -> None:
        if self._ctrl and self._port:
            _upnp_delete_mapping(self._ctrl, self._svc, self._port)
            self._ctrl = None


# ---------- Sender: discover address + wait for peer ----------------------

PUNCH_MAGIC = b"LNTLPUNCH"


async def discover_public_address(
    sock: socket.socket,
) -> tuple[str, int, str]:
    """
    Discover this socket's public address. Returns (ip, port, method).
    method is "upnp" or "stun".
    """
    local_port = sock.getsockname()[1]

    # 1. Try UPnP (gives a real public port — works with all NAT types).
    mapping = UPnPMapping()
    try:
        upnp_ok = await asyncio.get_event_loop().run_in_executor(
            None, mapping.try_map, local_port,
        )
    except Exception:
        upnp_ok = False

    if upnp_ok and mapping.public_port:
        # Still need our public IP — get it via STUN.
        try:
            ip, _ = await stun_discover(sock)
            return ip, mapping.public_port, "upnp"
        except NATError:
            pass

    # 2. Fall back to STUN (learns reflexive address for cone NATs).
    ip, port = await stun_discover(sock)
    return ip, port, "stun"


async def sender_wait_for_peer(
    sock: socket.socket,
    cookie: bytes,
    timeout: float = 300.0,
) -> tuple[str, int]:
    """
    Sender: keep the NAT mapping alive and wait for the receiver's PUNCH.

    Returns the receiver's (ip, port) once a valid punch is received.
    """
    loop = asyncio.get_event_loop()
    stop_keepalive = asyncio.Event()
    keepalive_task = asyncio.create_task(stun_keepalive(sock, 15.0, stop_keepalive))

    try:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 2048), timeout=min(remaining, 2.0),
                )
            except asyncio.TimeoutError:
                continue

            # Accept PUNCH packets with the matching cookie.
            if (
                len(data) >= len(PUNCH_MAGIC) + len(cookie)
                and data[: len(PUNCH_MAGIC)] == PUNCH_MAGIC
                and data[len(PUNCH_MAGIC) : len(PUNCH_MAGIC) + len(cookie)] == cookie
            ):
                # Reply so the receiver knows we're alive.
                try:
                    reply = PUNCH_MAGIC + cookie + b"\x01"
                    await loop.sock_sendto(sock, reply, addr)
                except Exception:
                    pass
                return addr

        raise NATError("No receiver connected within the timeout.")
    finally:
        stop_keepalive.set()
        keepalive_task.cancel()
        try:
            await keepalive_task
        except (asyncio.CancelledError, Exception):
            pass


# ---------- Receiver: connect to sender -----------------------------------

async def receiver_punch(
    sock: socket.socket,
    peer: tuple[str, int],
    cookie: bytes,
    timeout: float = 30.0,
    interval: float = 0.2,
) -> tuple[str, int]:
    """
    Receiver: send PUNCH packets to the sender's public address and wait
    for an acknowledgement. Returns the confirmed peer address.
    """
    loop = asyncio.get_event_loop()
    punch_pkt = PUNCH_MAGIC + cookie
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        # Send a punch.
        try:
            await loop.sock_sendto(sock, punch_pkt, peer)
        except Exception:
            pass

        # Wait briefly for a reply.
        try:
            data, addr = await asyncio.wait_for(
                loop.sock_recvfrom(sock, 2048), timeout=interval,
            )
            if (
                data.startswith(PUNCH_MAGIC)
                and len(data) >= len(PUNCH_MAGIC) + len(cookie)
                and data[len(PUNCH_MAGIC) : len(PUNCH_MAGIC) + len(cookie)] == cookie
            ):
                return addr
        except asyncio.TimeoutError:
            continue

    raise NATError(
        "Could not reach the sender.\n"
        "Their NAT may have blocked the connection.\n"
        "Ask the sender to try again — if it keeps failing, one of you\n"
        "may need to use a network without a strict/symmetric NAT."
    )
