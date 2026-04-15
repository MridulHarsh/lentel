"""
Lentel — a new UDP-based protocol for moving files of any size between any
two hosts, without port forwarding and without any server.

Public API:
    from lentel import send_file, recv_file

The wire protocol is documented in PROTOCOL.md at the repository root.
"""
from __future__ import annotations

__version__ = "1.0.0"
__all__ = [
    "__version__",
    "send_file",
    "recv_file",
]

from .rendezvous import recv_file, send_file
