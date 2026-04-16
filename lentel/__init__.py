"""
Lentel — send any file or folder to anyone, no server, no port forwarding.

Receiver-first: the recipient opens a session, generates a ticket, and
shares it.  The sender uses that ticket to push a file or folder.

Public API:
    from lentel import recv_file, send_file
"""
from __future__ import annotations

__version__ = "1.0.6"
__all__ = [
    "__version__",
    "recv_file",
    "send_file",
    "send_folder",
]

from .rendezvous import recv_file, send_file, send_folder
