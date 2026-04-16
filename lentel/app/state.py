"""
App-wide state: persistent config and transfer registry.
"""
from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Optional

CONFIG_DIR = Path.home() / ".lentel"
CONFIG_PATH = CONFIG_DIR / "config.json"


@dataclass
class Config:
    parallel: int = 4
    download_dir: str = str(Path.home() / "Downloads")
    # Optional relay URL (host:port). When set, sends go through this relay
    # instead of direct P2P — needed when your NAT blocks incoming connections.
    # The relay only forwards opaque UDP packets; it never sees plaintext.
    relay_url: str = ""


def load_config() -> Config:
    if not CONFIG_PATH.exists():
        return Config()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, json.JSONDecodeError):
        return Config()
    base = asdict(Config())
    base.update({k: v for k, v in raw.items() if k in base})
    return Config(**base)


def save_config(cfg: Config) -> None:
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(asdict(cfg), f, indent=2)


@dataclass
class Transfer:
    id: int
    kind: str
    file_name: str
    size: int = 0
    bytes_done: int = 0
    rate_bps: float = 0.0
    status: str = "starting"
    ticket: Optional[str] = None
    error: Optional[str] = None
    output_path: Optional[str] = None


class AppState:
    def __init__(self) -> None:
        self.config: Config = load_config()
        self.transfers: dict[int, Transfer] = {}
        self._next_id: int = 1
        self._lock = threading.Lock()
        self.last_ticket: Optional[str] = None
        self.on_change: Callable[[], None] = lambda: None

    def new_transfer(self, kind: str, file_name: str) -> Transfer:
        with self._lock:
            t = Transfer(id=self._next_id, kind=kind, file_name=file_name)
            self._next_id += 1
            self.transfers[t.id] = t
        self.on_change()
        return t

    def update(self, t: Transfer, **fields) -> None:
        with self._lock:
            for k, v in fields.items():
                setattr(t, k, v)
        self.on_change()

    def remove(self, transfer_id: int) -> None:
        with self._lock:
            self.transfers.pop(transfer_id, None)
        self.on_change()

    def snapshot(self) -> list[Transfer]:
        with self._lock:
            return list(self.transfers.values())

    def set_download_dir(self, path: str) -> None:
        with self._lock:
            self.config.download_dir = path
            save_config(self.config)
        self.on_change()

    def set_parallel(self, n: int) -> None:
        with self._lock:
            self.config.parallel = max(1, min(16, int(n)))
            save_config(self.config)
        self.on_change()

    def set_relay_url(self, url: str) -> None:
        with self._lock:
            self.config.relay_url = url.strip()
            save_config(self.config)
        self.on_change()

    def remember_ticket(self, ticket: str) -> None:
        with self._lock:
            self.last_ticket = ticket
        self.on_change()
