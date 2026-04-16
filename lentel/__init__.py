"""
Lentel — a new UDP-based protocol for moving files and folders of any size
between any two hosts, without port forwarding and without any server.

Public API:
    from lentel import send_file, send_folder, recv_file

``send_file`` and ``send_folder`` are aliases — both accept either a file
path or a directory path.  ``recv_file`` likewise handles both automatically.
"""
from __future__ import annotations

__version__ = "1.0.2"
__all__ = [
    "__version__",
    "send_file",
    "send_folder",
    "recv_file",
]

from .rendezvous import recv_file, send_file, send_folder
