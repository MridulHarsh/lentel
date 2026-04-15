"""
Lentel cryptographic layer.

Implements:
  - The 3-message authenticated handshake described in PROTOCOL.md §5.
  - Per-packet ChaCha20-Poly1305 AEAD with header-bound associated data.
  - Deterministic nonce derivation (see wire.derive_nonce).

The only external crypto dependency is `cryptography` (a primitive library).
The *protocol* built on top of those primitives is defined here and nowhere
else.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives import hashes

from .wire import (
    HEADER_SIZE, Flag, Header, PacketType, Direction,
    derive_nonce, encode_header,
)

HANDSHAKE_NONCE_LEN = 16
X25519_KEY_LEN = 32
AEAD_KEY_LEN = 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract with SHA-256."""
    import hmac
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    ).derive(prk)


def psk_from_ticket(ticket: str) -> bytes:
    """Derive the 32-byte PSK from the textual ticket form.

    The ticket string includes the pronounceable word label and the 2-digit
    checksum. We bind the ticket literally so copy/paste errors cannot collide.
    """
    return hashlib.blake2b(
        b"lentel/v1/psk\x00" + ticket.encode("utf-8"),
        digest_size=AEAD_KEY_LEN,
    ).digest()


def ticket_label(psk: bytes) -> str:
    """A short public label derived from the PSK (for coordinator lookup).

    This is safe to transmit to the coordinator in the clear — it does not
    leak the PSK because BLAKE2b-64 is one-way.
    """
    return hashlib.blake2b(b"lentel/v1/label\x00" + psk, digest_size=8).hexdigest()


@dataclass
class HandshakeKeys:
    """Output of a completed handshake: per-direction AEAD keys + session id."""
    session_id: int
    k_i2r: bytes  # initiator -> responder
    k_r2i: bytes  # responder -> initiator
    peer_pub: bytes


class AEAD:
    """Stateful ChaCha20-Poly1305 with header-bound AAD."""

    def __init__(self, key: bytes):
        if len(key) != AEAD_KEY_LEN:
            raise ValueError(f"bad key length {len(key)}")
        self._aead = ChaCha20Poly1305(key)

    def seal(self, header_bytes: bytes, nonce: bytes, plaintext: bytes) -> bytes:
        """Return ciphertext||tag. Authenticates the wire header as AAD."""
        return self._aead.encrypt(nonce, plaintext, header_bytes)

    def open(self, header_bytes: bytes, nonce: bytes, ct_with_tag: bytes) -> bytes:
        """Decrypt. Raises InvalidTag on failure."""
        return self._aead.decrypt(nonce, ct_with_tag, header_bytes)


class HandshakeError(Exception):
    pass


class InitiatorHandshake:
    """Drive the three handshake messages from the initiator side."""

    def __init__(self, psk: bytes):
        self.psk = psk
        self.sk = X25519PrivateKey.generate()
        self.ek = self.sk.public_key().public_bytes_raw()
        self.i_nonce = secrets.token_bytes(HANDSHAKE_NONCE_LEN)
        self.session_id = int.from_bytes(secrets.token_bytes(4), "big") | 1
        self.peer_pub: bytes | None = None
        self.r_nonce: bytes | None = None
        self.keys: HandshakeKeys | None = None

    def hello(self) -> bytes:
        """Build the first packet (HELLO). Unencrypted."""
        body = self.ek + self.i_nonce
        h = Header(
            type=PacketType.HELLO,
            flags=Flag.NOENCRYPT,
            session_id=self.session_id,
            stream_id=0,
            sequence=0,
            payload_length=len(body),
        )
        return encode_header(h) + body

    def on_hello_ack(self, pkt: bytes) -> bytes:
        """Consume HELLO_ACK, return HS_DONE."""
        if len(pkt) < HEADER_SIZE + X25519_KEY_LEN + HANDSHAKE_NONCE_LEN + 16:
            raise HandshakeError("short HELLO_ACK")
        body = pkt[HEADER_SIZE:]
        self.peer_pub = body[:X25519_KEY_LEN]
        self.r_nonce = body[X25519_KEY_LEN : X25519_KEY_LEN + HANDSHAKE_NONCE_LEN]
        tag_ct = body[X25519_KEY_LEN + HANDSHAKE_NONCE_LEN :]

        peer = X25519PublicKey.from_public_bytes(self.peer_pub)
        shared = self.sk.exchange(peer)

        k0 = hkdf_expand(
            hkdf_extract(self.psk, self.ek + self.peer_pub),
            b"lentel/v1/ack",
            AEAD_KEY_LEN,
        )
        try:
            ChaCha20Poly1305(k0).decrypt(b"\x00" * 12, tag_ct, self.ek + self.peer_pub)
        except Exception as e:
            raise HandshakeError("bad HELLO_ACK tag (wrong ticket?)") from e

        prk = hkdf_extract(
            self.psk + self.i_nonce + self.r_nonce,
            shared,
        )
        k_i2r = hkdf_expand(prk, b"lentel/v1/i2r", AEAD_KEY_LEN)
        k_r2i = hkdf_expand(prk, b"lentel/v1/r2i", AEAD_KEY_LEN)

        self.keys = HandshakeKeys(
            session_id=self.session_id,
            k_i2r=k_i2r,
            k_r2i=k_r2i,
            peer_pub=self.peer_pub,
        )

        # Build HS_DONE: AEAD seal of empty string with i2r key
        h = Header(
            type=PacketType.HS_DONE,
            flags=0,
            session_id=self.session_id,
            stream_id=0,
            sequence=0,
            payload_length=16,
        )
        hdr = encode_header(h)
        nonce = derive_nonce(Direction.INITIATOR_TO_RESPONDER, self.session_id, 0, 0)
        tag = ChaCha20Poly1305(k_i2r).encrypt(nonce, b"", hdr)
        return hdr + tag


class ResponderHandshake:
    """Drive the handshake from the responder side."""

    def __init__(self, psk: bytes):
        self.psk = psk
        self.sk = X25519PrivateKey.generate()
        self.ek = self.sk.public_key().public_bytes_raw()
        self.r_nonce = secrets.token_bytes(HANDSHAKE_NONCE_LEN)
        self.session_id: int | None = None
        self.peer_pub: bytes | None = None
        self.i_nonce: bytes | None = None
        self.keys: HandshakeKeys | None = None

    def on_hello(self, pkt: bytes) -> bytes:
        """Consume HELLO, return HELLO_ACK."""
        if len(pkt) < HEADER_SIZE + X25519_KEY_LEN + HANDSHAKE_NONCE_LEN:
            raise HandshakeError("short HELLO")
        from .wire import decode_header
        hdr = decode_header(pkt)
        if hdr.type != PacketType.HELLO:
            raise HandshakeError(f"expected HELLO, got {hdr.type}")
        self.session_id = hdr.session_id

        body = pkt[HEADER_SIZE : HEADER_SIZE + hdr.payload_length]
        self.peer_pub = body[:X25519_KEY_LEN]
        self.i_nonce = body[X25519_KEY_LEN : X25519_KEY_LEN + HANDSHAKE_NONCE_LEN]

        k0 = hkdf_expand(
            hkdf_extract(self.psk, self.peer_pub + self.ek),
            b"lentel/v1/ack",
            AEAD_KEY_LEN,
        )
        tag = ChaCha20Poly1305(k0).encrypt(b"\x00" * 12, b"", self.peer_pub + self.ek)

        body_out = self.ek + self.r_nonce + tag
        h = Header(
            type=PacketType.HELLO_ACK,
            flags=Flag.NOENCRYPT,
            session_id=self.session_id,
            stream_id=0,
            sequence=0,
            payload_length=len(body_out),
        )

        peer = X25519PublicKey.from_public_bytes(self.peer_pub)
        shared = self.sk.exchange(peer)
        prk = hkdf_extract(
            self.psk + self.i_nonce + self.r_nonce,
            shared,
        )
        self.keys = HandshakeKeys(
            session_id=self.session_id,
            k_i2r=hkdf_expand(prk, b"lentel/v1/i2r", AEAD_KEY_LEN),
            k_r2i=hkdf_expand(prk, b"lentel/v1/r2i", AEAD_KEY_LEN),
            peer_pub=self.peer_pub,
        )
        return encode_header(h) + body_out

    def on_hs_done(self, pkt: bytes) -> None:
        """Verify the initiator's completion message. Raises on tamper."""
        if self.keys is None:
            raise HandshakeError("HS_DONE before HELLO")
        from .wire import decode_header
        hdr = decode_header(pkt)
        if hdr.type != PacketType.HS_DONE:
            raise HandshakeError(f"expected HS_DONE, got {hdr.type}")
        header_bytes = pkt[:HEADER_SIZE]
        body = pkt[HEADER_SIZE : HEADER_SIZE + hdr.payload_length]
        nonce = derive_nonce(Direction.INITIATOR_TO_RESPONDER, self.session_id, 0, 0)
        try:
            ChaCha20Poly1305(self.keys.k_i2r).decrypt(nonce, body, header_bytes)
        except Exception as e:
            raise HandshakeError("HS_DONE authentication failed") from e
