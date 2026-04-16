"""
Ticket encoding.

A Lentel ticket encodes either:

  * a **direct** peer-to-peer address
        bold-crab-fern-42@203.0.113.5:54321

  * or a **relay** address (for networks where NAT hole-punching fails)
        bold-crab-fern-42@r:relay.example.com:7778

Both forms begin with a three-word code + two-digit checksum.  The word
code is hashed into the 32-byte PSK used for the AEAD handshake.  The
``@`` delimiter separates the code from the address.  A leading ``r:``
on the address marks relay mode — in that case the address is the relay's
own endpoint, and both peers connect there.  The relay pairs peers by a
token derived from the ticket's PSK; it forwards opaque UDP datagrams and
never sees plaintext.
"""
from __future__ import annotations

import hashlib
import secrets
from typing import Optional

WORDLIST: tuple[str, ...] = (
    "able", "acid", "acorn", "agent", "air", "alien", "alpha", "amber",
    "angel", "ankle", "anvil", "apple", "april", "arbor", "arch", "arena",
    "arm", "armor", "art", "ash", "asset", "atlas", "atom", "aunt",
    "axis", "axle", "badge", "bagel", "bake", "ball", "balm", "band",
    "bank", "barn", "bark", "basin", "batch", "beach", "beam", "bean",
    "bear", "beast", "bee", "bell", "belt", "bench", "berry", "beta",
    "bike", "bin", "bird", "bison", "blade", "blend", "block", "blond",
    "blue", "boar", "boat", "bold", "bolt", "bond", "bone", "book",
    "boot", "brake", "brand", "brave", "bread", "brew", "brick", "bride",
    "bridge", "brink", "brisk", "broth", "brown", "brush", "bunny", "burst",
    "cable", "cactus", "cage", "cake", "calm", "camel", "camp", "canal",
    "candy", "cape", "car", "card", "care", "cargo", "carp", "carry",
    "cash", "castle", "cat", "cave", "cedar", "cell", "chair", "chalk",
    "champ", "chef", "chess", "child", "chime", "chin", "chip", "choir",
    "chord", "chrome", "cider", "city", "civil", "clam", "clap", "clay",
    "clean", "clear", "clerk", "cliff", "climb", "clock", "cloud", "clove",
    "clown", "clue", "coach", "coal", "coast", "cobra", "coin", "comet",
    "cook", "cool", "copy", "coral", "cord", "core", "corn", "couch",
    "cove", "cow", "crab", "craft", "crane", "crash", "crate", "cream",
    "creek", "crest", "crib", "cross", "crown", "crust", "cube", "cup",
    "curl", "curve", "daisy", "dark", "dart", "dash", "data", "dawn",
    "deer", "delta", "desk", "dew", "dice", "diet", "dime", "dip",
    "disk", "ditch", "dock", "dodge", "dog", "dome", "door", "dorm",
    "dose", "dot", "dough", "dove", "draft", "dragon", "drake", "drama",
    "dream", "dress", "drift", "drill", "drink", "drive", "drop", "drum",
    "duck", "duet", "duke", "dune", "dust", "eagle", "earth", "east",
    "echo", "edge", "egg", "elbow", "elder", "elk", "elm", "ember",
    "emu", "engine", "ether", "fable", "face", "fairy", "falcon", "fancy",
    "fang", "farm", "fawn", "feast", "fence", "fern", "ferry", "fiber",
    "field", "fig", "finch", "fir", "fire", "fish", "fist", "flag",
    "flame", "flask", "flint", "floor", "flour", "flow", "foam", "fog",
    "forest", "fork", "fort", "fox", "frog", "fruit", "fudge", "fury",
)

assert len(WORDLIST) == 256
_INDEX = {w: i for i, w in enumerate(WORDLIST)}

RELAY_MARKER = "r:"


def _checksum(words: list[str]) -> int:
    data = "-".join(words).encode("utf-8")
    return int.from_bytes(hashlib.blake2b(data, digest_size=1).digest(), "big") % 100


def new_code(n_words: int = 3) -> str:
    """Generate just the word code (no address)."""
    if n_words < 2:
        raise ValueError("ticket needs at least 2 words")
    words = [secrets.choice(WORDLIST) for _ in range(n_words)]
    chk = _checksum(words)
    return "-".join(words) + f"-{chk:02d}"


def new_ticket(
    addr: tuple[str, int],
    via_relay: bool = False,
    n_words: int = 3,
) -> str:
    """Generate a ticket with an embedded address.

    ``addr`` is the direct sender address, or the relay address when
    ``via_relay=True``.
    """
    code = new_code(n_words)
    prefix = RELAY_MARKER if via_relay else ""
    return f"{code}@{prefix}{addr[0]}:{addr[1]}"


def parse_ticket(ticket: str) -> tuple[str, tuple[str, int], bool]:
    """Validate and return (code, (ip_or_host, port), via_relay).

    Raises ValueError on bad format/checksum.
    """
    ticket = ticket.strip()
    if "@" not in ticket:
        raise ValueError(
            "ticket must contain '@' followed by the sender's address "
            "(e.g. bold-crab-fern-42@203.0.113.5:54321)"
        )
    code, addr_str = ticket.rsplit("@", 1)

    via_relay = False
    if addr_str.startswith(RELAY_MARKER):
        via_relay = True
        addr_str = addr_str[len(RELAY_MARKER):]

    # Validate code.
    parts = code.split("-")
    if len(parts) < 3:
        raise ValueError("ticket code too short")
    body, chk_str = parts[:-1], parts[-1]
    if not chk_str.isdigit() or len(chk_str) != 2:
        raise ValueError("ticket checksum must be two digits")
    for w in body:
        if w not in _INDEX:
            raise ValueError(f"unknown word in ticket: {w!r}")
    expected = _checksum(body)
    if int(chk_str) != expected:
        raise ValueError("ticket checksum mismatch (typo?)")

    # Validate address.
    if ":" not in addr_str:
        raise ValueError("ticket address must be HOST:PORT")
    host_str, port_str = addr_str.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"bad port in ticket: {port_str!r}")
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")

    return code, (host_str, port), via_relay


def psk_to_relay_token(psk: bytes) -> bytes:
    """Derive the 16-byte relay pairing token from the ticket PSK.

    The relay uses this as an opaque key to match two peers.  Deriving it
    from the PSK means the relay operator never sees the PSK itself.
    """
    return hashlib.blake2b(b"lentel/v1/relay-token\x00" + psk, digest_size=16).digest()
