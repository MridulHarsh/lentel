"""
Menu-bar / system-tray UI — coordinator-free edition.

The tray app wraps the Lentel protocol which now works purely peer-to-peer:
the sender discovers its own public address via STUN/UPnP, embeds it in the
ticket, and the receiver connects directly. No server of any kind is needed.

**Threading model**:
  - pystray owns the main thread.
  - Every callback that shows a dialog runs in a worker thread (``_bg()``).
  - On macOS, dialogs use osascript to avoid AppKit conflicts.
  - File transfers run on a dedicated asyncio event loop thread (``runner.py``).
"""
from __future__ import annotations

import os
import sys
import threading
from typing import Optional

try:
    import pystray
    from pystray import Icon, Menu, MenuItem
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "The Lentel tray app requires `pystray` and `Pillow`. Install them "
        "with:  pip install 'lentel[tray]'"
    ) from e

from lentel import recv_file, send_file
from lentel.app.dialogs import (
    ask_parallel, ask_ticket, copy_to_clipboard, error, info,
    pick_directory, pick_file, reveal_in_file_manager,
)
from lentel.app.icon import make_icon
from lentel.app.runner import Runner
from lentel.app.state import AppState, Transfer


def _humanbytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _path_total_size(path: str) -> int:
    """Sum all file sizes at or under ``path``. Folders are walked recursively."""
    if os.path.isfile(path):
        return os.path.getsize(path)
    total = 0
    for dirpath, _, filenames in os.walk(path, followlinks=False):
        for fname in filenames:
            fp = os.path.join(dirpath, fname)
            try:
                if os.path.isfile(fp) and not os.path.islink(fp):
                    total += os.path.getsize(fp)
            except OSError:
                pass
    return total


def _fmt_transfer(t: Transfer) -> str:
    arrow = "\u2191" if t.kind == "send" else "\u2193"
    st = t.status
    if st == "error":
        return f"{arrow} {t.file_name}  \u2717 error"
    if st == "done":
        return f"{arrow} {t.file_name}  \u2713 done"
    if "waiting" in st:
        return f"{arrow} {t.file_name}  waiting for receiver\u2026"
    if "discovering" in st.lower() or "connecting" in st.lower():
        return f"{arrow} {t.file_name}  {st}"
    if t.size > 0 and t.bytes_done > 0:
        pct = 100 * t.bytes_done / t.size
        rate = _humanbytes(t.rate_bps) + "/s"
        return f"{arrow} {t.file_name}  {pct:4.0f}%  {rate}"
    return f"{arrow} {t.file_name}  {st}"


class TrayApp:
    def __init__(self) -> None:
        self.state = AppState()
        self.runner = Runner()
        self.icon: Optional[Icon] = None

    def _bg(self, fn):
        def wrapper(icon, item):
            threading.Thread(target=fn, args=(icon, item), daemon=True).start()
        return wrapper

    # ---- lifecycle -------------------------------------------------------

    def run(self) -> None:
        self.runner.start()
        self.icon = Icon(
            name="lentel",
            icon=make_icon(64, active=False),
            title="Lentel",
            menu=self._build_menu(),
        )
        self.state.on_change = self._refresh
        self.icon.run()

    def _refresh(self) -> None:
        if self.icon is None:
            return
        active = any(
            t.status not in ("done", "error", "cancelled")
            for t in self.state.snapshot()
        )
        try:
            self.icon.icon = make_icon(64, active=active)
            self.icon.menu = self._build_menu()
            self.icon.update_menu()
        except Exception:
            pass

    # ---- menu ------------------------------------------------------------

    def _build_menu(self) -> Menu:
        items: list[MenuItem] = [
            MenuItem("Send a file\u2026",    self._bg(self._on_send_file)),
            MenuItem("Send a folder\u2026",  self._bg(self._on_send_folder)),
            MenuItem("Receive\u2026",        self._bg(self._on_recv)),
            Menu.SEPARATOR,
        ]

        transfers = sorted(self.state.snapshot(), key=lambda x: -x.id)
        if transfers:
            items.append(MenuItem("Active transfers", self._transfers_menu(transfers)))
            items.append(MenuItem("Clear finished", self._on_clear_finished))
            items.append(Menu.SEPARATOR)

        if self.state.last_ticket:
            items.append(MenuItem(
                f"Copy last ticket",
                self._on_copy_last_ticket,
            ))

        items.append(MenuItem("Open downloads folder", self._on_open_downloads))
        items.append(Menu.SEPARATOR)
        items.append(MenuItem("Settings", self._settings_menu()))
        items.append(Menu.SEPARATOR)
        items.append(MenuItem("About",   self._bg(self._on_about)))
        items.append(MenuItem("Quit",    self._on_quit))
        return Menu(*items)

    def _transfers_menu(self, transfers: list[Transfer]) -> Menu:
        if not transfers:
            return Menu(MenuItem("(none)", None, enabled=False))
        items: list[MenuItem] = []
        for t in transfers:
            if t.kind == "recv" and t.status == "done" and t.output_path:
                items.append(MenuItem(
                    _fmt_transfer(t),
                    (lambda tt: lambda icon, item: reveal_in_file_manager(tt.output_path or ""))(t),
                ))
            else:
                items.append(MenuItem(_fmt_transfer(t), None, enabled=False))
        return Menu(*items)

    def _settings_menu(self) -> Menu:
        return Menu(
            MenuItem("Downloads folder\u2026", self._bg(self._on_set_download_dir)),
            MenuItem(
                f"Parallel streams: {self.state.config.parallel}",
                self._bg(self._on_set_parallel),
            ),
        )

    # ---- send flow -------------------------------------------------------
    #
    # 1. _on_send (worker thread):
    #      pick file → submit async task (which discovers address, builds
    #      ticket, shows dialog, waits for receiver, transfers)
    #
    # 2. _run_send (asyncio thread):
    #      STUN/UPnP → ticket → on_ticket callback → show dialog in thread →
    #      wait for peer → handshake → transfer → done/error
    #

    def _on_send_file(self, icon, item) -> None:
        path = pick_file("Send a file with Lentel")
        if not path:
            return
        self._start_send(path)

    def _on_send_folder(self, icon, item) -> None:
        path = pick_directory("Send a folder with Lentel")
        if not path:
            return
        self._start_send(path)

    def _start_send(self, path: str) -> None:
        name = os.path.basename(path.rstrip(os.sep)) or path
        size = _path_total_size(path)

        transfer = self.state.new_transfer("send", name)
        self.state.update(transfer, size=size, status="discovering address\u2026")
        self._refresh()

        self.runner.submit(self._run_send(transfer, path))

    async def _run_send(self, transfer: Transfer, path: str) -> None:
        started_transferring = [False]

        def on_ticket(ticket: str) -> None:
            self.state.update(transfer, ticket=ticket, status="waiting for receiver")
            self.state.remember_ticket(ticket)
            self._refresh()
            # Show the ticket in a dialog (runs in a thread so we don't
            # block the asyncio loop while the user reads it).
            threading.Thread(target=self._show_ticket_dialog,
                             args=(transfer.file_name, transfer.size, ticket),
                             daemon=True).start()

        def on_status(msg: str) -> None:
            self.state.update(transfer, status=msg)
            self._refresh()

        def progress(done: int, total: int, rate: float) -> None:
            if not started_transferring[0]:
                started_transferring[0] = True
                self.state.update(transfer, status="transferring")
            self.state.update(transfer, bytes_done=done, rate_bps=rate)
            if total > 0:
                pct = 100 * done / total
                if int(pct) % 2 == 0:
                    self._refresh()

        try:
            await send_file(
                path,
                parallel=self.state.config.parallel,
                progress=progress,
                on_ticket=on_ticket,
                on_status=on_status,
            )
            self.state.update(transfer, status="done",
                              bytes_done=transfer.size or 0)
            self._notify("Sent", transfer.file_name)
            self._refresh()

        except Exception as e:
            self._friendly_error(transfer, "send", e)

    def _show_ticket_dialog(self, file_name: str, size: int, ticket: str) -> None:
        copy_to_clipboard(ticket)
        info(
            "Lentel \u2014 Ticket Ready",
            f"File:   {file_name} ({_humanbytes(size)})\n"
            f"Ticket: {ticket}\n\n"
            "Copied to clipboard. Share it with the receiver.\n"
            "The transfer starts automatically when they connect.",
        )

    # ---- receive flow ----------------------------------------------------

    def _on_recv(self, icon, item) -> None:
        ticket = ask_ticket()
        if not ticket or not ticket.strip():
            return
        ticket = ticket.strip()

        try:
            from lentel.wordlist import parse_ticket
            parse_ticket(ticket)
        except ValueError as e:
            error("Lentel", f"Bad ticket: {e}\n\nCheck for typos and try again.")
            return

        transfer = self.state.new_transfer("recv", "(connecting\u2026)")
        self.state.update(transfer, status="connecting\u2026")
        self._refresh()
        self.runner.submit(self._run_recv(transfer, ticket))

    async def _run_recv(self, transfer: Transfer, ticket: str) -> None:
        started_transferring = [False]

        def on_status(msg: str) -> None:
            self.state.update(transfer, status=msg)
            self._refresh()

        def progress(done: int, total: int, rate: float) -> None:
            if not started_transferring[0]:
                started_transferring[0] = True
                self.state.update(transfer, status="transferring")
            if transfer.size == 0 and total > 0:
                self.state.update(transfer, size=total)
            self.state.update(transfer, bytes_done=done, rate_bps=rate)
            if total > 0:
                pct = 100 * done / total
                if int(pct) % 2 == 0:
                    self._refresh()

        try:
            out = await recv_file(
                ticket,
                dest_dir=self.state.config.download_dir,
                parallel=self.state.config.parallel,
                progress=progress,
                on_status=on_status,
            )
            self.state.update(
                transfer,
                file_name=os.path.basename(out),
                status="done",
                output_path=out,
            )
            self._notify("Received", os.path.basename(out))
            self._refresh()

        except Exception as e:
            self._friendly_error(transfer, "recv", e)

    # ---- friendly errors -------------------------------------------------

    def _friendly_error(self, transfer: Transfer, direction: str, exc: Exception) -> None:
        msg = str(exc)
        label = "Send" if direction == "send" else "Receive"

        if isinstance(exc, FileNotFoundError):
            friendly = f"File not found: {msg}"
        elif "STUN" in msg or "stun" in msg:
            friendly = (
                "Cannot discover your public address.\n"
                "Check your internet connection."
            )
        elif "No receiver connected" in msg or "timed out waiting" in msg.lower():
            friendly = (
                "No receiver connected within the timeout.\n"
                "Use Send again for a new ticket."
            )
        elif "Could not reach the sender" in msg:
            friendly = (
                "Could not reach the sender.\n"
                "Their NAT may block incoming connections.\n"
                "Ask them to try sending again from a different network."
            )
        elif "timeout" in msg.lower() or isinstance(exc, TimeoutError):
            friendly = "Connection timed out. Try again."
        elif "handshake" in msg.lower():
            friendly = "Handshake failed \u2014 ticket may be wrong or expired."
        elif "Merkle" in msg or "integrity" in msg.lower():
            friendly = "File integrity check failed. Try again."
        else:
            friendly = msg

        self.state.update(transfer, status="error", error=friendly)
        self._notify(f"{label} failed", friendly)
        self._refresh()

    # ---- settings --------------------------------------------------------

    def _on_set_download_dir(self, icon, item) -> None:
        new = pick_directory("Choose Lentel downloads folder")
        if new:
            self.state.set_download_dir(new)

    def _on_set_parallel(self, icon, item) -> None:
        n = ask_parallel(self.state.config.parallel)
        if n:
            self.state.set_parallel(int(n))

    # ---- utility callbacks -----------------------------------------------

    def _on_copy_last_ticket(self, icon, item) -> None:
        if self.state.last_ticket:
            copy_to_clipboard(self.state.last_ticket)
            self._notify("Ticket copied", self.state.last_ticket)

    def _on_open_downloads(self, icon, item) -> None:
        d = self.state.config.download_dir
        os.makedirs(d, exist_ok=True)
        if sys.platform == "darwin":
            import subprocess; subprocess.Popen(["open", d])
        elif sys.platform.startswith("win"):
            os.startfile(d)  # type: ignore[attr-defined]
        else:
            import subprocess; subprocess.Popen(["xdg-open", d])

    def _on_clear_finished(self, icon, item) -> None:
        for t in self.state.snapshot():
            if t.status in ("done", "error", "cancelled"):
                self.state.remove(t.id)

    def _on_about(self, icon, item) -> None:
        info(
            "About Lentel",
            "Lentel 1.0.0\n\n"
            "Send any file, any size, to anyone \u2014\n"
            "no server, no port forwarding.\n\n"
            "Your public address is discovered automatically\n"
            "via STUN/UPnP and embedded in the ticket.\n\n"
            f"Downloads: {self.state.config.download_dir}\n"
            f"Parallel:  {self.state.config.parallel} streams",
        )

    def _on_quit(self, icon, item) -> None:
        try:
            if self.icon is not None:
                self.icon.stop()
        finally:
            self.runner.stop()

    def _notify(self, title: str, message: str) -> None:
        if self.icon is None:
            return
        try:
            self.icon.notify(message, title=title)
        except Exception:
            pass


def run() -> None:
    TrayApp().run()
