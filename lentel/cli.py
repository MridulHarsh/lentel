"""
``lentel send`` and ``lentel recv`` — no server needed.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import sys
import time

from . import __version__
from .rendezvous import recv_file, send_file
from .wordlist import parse_ticket


def _humanbytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


class ProgressBar:
    def __init__(self):
        self._last_render = 0.0

    def __call__(self, done: int, total: int, rate_bps: float) -> None:
        now = time.monotonic()
        if now - self._last_render < 0.1 and done < total:
            return
        self._last_render = now
        cols = max(20, shutil.get_terminal_size((80, 20)).columns - 40)
        frac = min(1.0, done / total) if total > 0 else 1.0
        filled = int(frac * cols)
        bar = "#" * filled + "-" * (cols - filled)
        pct = frac * 100
        rate = _humanbytes(rate_bps) + "/s"
        eta = ((total - done) / rate_bps) if rate_bps > 0 else 0
        sys.stdout.write(
            f"\r [{bar}] {pct:5.1f}%  {_humanbytes(done)}/{_humanbytes(total)}  {rate}  eta {int(eta)}s"
        )
        sys.stdout.flush()
        if done >= total:
            sys.stdout.write("\n")


async def _cmd_send(args: argparse.Namespace) -> int:
    path = args.path
    if not os.path.exists(path):
        print(f"error: {path} does not exist", file=sys.stderr)
        return 1
    if os.path.isdir(path):
        # Sum up all files in the tree for the progress total.
        size = 0
        for dp, _, fn in os.walk(path, followlinks=False):
            for f in fn:
                fp = os.path.join(dp, f)
                if os.path.isfile(fp) and not os.path.islink(fp):
                    size += os.path.getsize(fp)
        kind = "folder"
    elif os.path.isfile(path):
        size = os.path.getsize(path)
        kind = "file"
    else:
        print(f"error: {path} is not a file or folder", file=sys.stderr)
        return 1
    print(f"preparing {kind} {os.path.basename(path.rstrip(os.sep)) or path} "
          f"({_humanbytes(size)})")

    def on_ticket(t: str) -> None:
        print(f"\nticket: {t}")
        print("share it with the receiver.")
        print("waiting for peer...\n")

    def on_status(msg: str) -> None:
        print(f"  {msg}")

    pb = ProgressBar()
    try:
        await send_file(
            path,
            parallel=args.parallel,
            progress=pb,
            on_ticket=on_ticket,
            on_status=on_status,
            wait_timeout=args.timeout,
        )
    except Exception as e:
        print(f"\nsend failed: {e}", file=sys.stderr)
        return 2
    print("transfer complete.")
    return 0


async def _cmd_recv(args: argparse.Namespace) -> int:
    try:
        parse_ticket(args.ticket)
    except ValueError as e:
        print(f"bad ticket: {e}", file=sys.stderr)
        return 1
    dest_dir = args.out
    os.makedirs(dest_dir, exist_ok=True)

    def on_status(msg: str) -> None:
        print(f"  {msg}")

    pb = ProgressBar()
    print("connecting to sender...")
    try:
        out = await recv_file(
            args.ticket,
            dest_dir=dest_dir,
            parallel=args.parallel,
            progress=pb,
            overwrite=args.overwrite,
            on_status=on_status,
        )
    except Exception as e:
        print(f"\nreceive failed: {e}", file=sys.stderr)
        return 2
    print(f"saved to {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="lentel",
        description="Lentel — send any file, any size, to anyone. No server needed.",
    )
    p.add_argument("--version", action="version", version=f"lentel {__version__}")
    p.add_argument(
        "--parallel", type=int, default=4,
        help="number of parallel streams (default 4)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("send", help="send a file or folder")
    ps.add_argument("path", help="path to the file or folder to send")
    ps.add_argument("--timeout", type=float, default=300.0,
                    help="seconds to wait for a receiver (default 300)")

    pr = sub.add_parser("recv", help="receive a file or folder by ticket")
    pr.add_argument("ticket", help="ticket from the sender (includes @address)")
    pr.add_argument("--out", default=".", help="destination directory")
    pr.add_argument("--overwrite", action="store_true")

    args = p.parse_args(argv)
    coro = _cmd_send(args) if args.cmd == "send" else _cmd_recv(args)
    return asyncio.run(coro)


if __name__ == "__main__":
    raise SystemExit(main())
