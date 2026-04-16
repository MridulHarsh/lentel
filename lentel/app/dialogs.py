"""
Cross-platform GUI dialogs for the Lentel tray app.

**macOS**: pystray owns the AppKit main loop, and tkinter's Tk() tries to
initialise a *second* NSApplication — they deadlock silently, which is why
"Send a file" / "Receive a file" appeared to do nothing. We fix this by
using `osascript` (AppleScript) on macOS: every dialog runs in a child
process, so there is zero conflict with AppKit. The clipboard is handled
via `pbcopy`.

**Windows / Linux**: tkinter works fine since pystray doesn't claim the
Tk event loop on those platforms.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import Optional

_IS_MAC = sys.platform == "darwin"


# -------- macOS (osascript) -----------------------------------------------

def _osa(script: str) -> Optional[str]:
    """Run an AppleScript snippet, return stripped stdout or None on cancel."""
    try:
        r = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            return None
        return r.stdout.strip() or None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def _mac_pick_file(title: str) -> Optional[str]:
    return _osa(
        f'POSIX path of (choose file with prompt "{title}")'
    )


def _mac_pick_directory(title: str) -> Optional[str]:
    return _osa(
        f'POSIX path of (choose folder with prompt "{title}")'
    )


def _mac_ask_string(title: str, prompt: str, default: str = "") -> Optional[str]:
    esc_prompt = prompt.replace('"', '\\"')
    esc_default = default.replace('"', '\\"')
    return _osa(
        f'text returned of (display dialog "{esc_prompt}" '
        f'default answer "{esc_default}" '
        f'with title "{title}")'
    )


def _mac_ask_integer(title: str, prompt: str, default: int = 4) -> Optional[int]:
    raw = _mac_ask_string(title, prompt, str(default))
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _mac_info(title: str, message: str) -> None:
    esc = message.replace('"', '\\"')
    _osa(f'display dialog "{esc}" with title "{title}" buttons {{"OK"}} default button "OK"')


def _mac_error(title: str, message: str) -> None:
    esc = message.replace('"', '\\"')
    _osa(
        f'display dialog "{esc}" with title "{title}" '
        f'buttons {{"OK"}} default button "OK" with icon stop'
    )


def _mac_copy(text: str) -> None:
    try:
        subprocess.run(["pbcopy"], input=text.encode(), check=True, timeout=5)
    except Exception:
        pass


# -------- Windows / Linux (tkinter) ---------------------------------------

def _make_root():
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
    try:
        root.attributes("-topmost", True)
    except Exception:
        pass
    try:
        root.update_idletasks()
    except Exception:
        pass
    return root


def _tk_pick_file(title: str) -> Optional[str]:
    from tkinter import filedialog
    root = _make_root()
    try:
        return filedialog.askopenfilename(parent=root, title=title) or None
    finally:
        root.destroy()


def _tk_pick_directory(title: str) -> Optional[str]:
    from tkinter import filedialog
    root = _make_root()
    try:
        return filedialog.askdirectory(parent=root, title=title) or None
    finally:
        root.destroy()


def _tk_ask_string(title: str, prompt: str, default: str = "") -> Optional[str]:
    from tkinter import simpledialog
    root = _make_root()
    try:
        return simpledialog.askstring(title, prompt, initialvalue=default, parent=root)
    finally:
        root.destroy()


def _tk_ask_integer(title: str, prompt: str, default: int = 4) -> Optional[int]:
    from tkinter import simpledialog
    root = _make_root()
    try:
        return simpledialog.askinteger(title, prompt, initialvalue=default,
                                       minvalue=1, maxvalue=16, parent=root)
    finally:
        root.destroy()


def _tk_info(title: str, message: str) -> None:
    from tkinter import messagebox
    root = _make_root()
    try:
        messagebox.showinfo(title, message, parent=root)
    finally:
        root.destroy()


def _tk_error(title: str, message: str) -> None:
    from tkinter import messagebox
    root = _make_root()
    try:
        messagebox.showerror(title, message, parent=root)
    finally:
        root.destroy()


def _tk_copy(text: str) -> None:
    root = _make_root()
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
    finally:
        root.destroy()


# -------- public API (dispatches by platform) -----------------------------

def pick_file(title: str = "Select a file") -> Optional[str]:
    return _mac_pick_file(title) if _IS_MAC else _tk_pick_file(title)


def pick_directory(title: str = "Select a folder") -> Optional[str]:
    return _mac_pick_directory(title) if _IS_MAC else _tk_pick_directory(title)


def ask_ticket() -> Optional[str]:
    if _IS_MAC:
        return _mac_ask_string("Lentel", "Paste the ticket you received:")
    return _tk_ask_string("Lentel", "Paste the ticket you received:")


def ask_coordinator(default: str) -> Optional[str]:
    prompt = "Coordinator URL  (e.g. tcp://coord.example.com:7777)"
    if _IS_MAC:
        return _mac_ask_string("Lentel Coordinator", prompt, default)
    return _tk_ask_string("Lentel Coordinator", prompt, default)


def ask_relay(default: str) -> Optional[str]:
    prompt = (
        "Relay URL  (host:port)\\n\\n"
        "Leave empty for direct peer-to-peer.\\n"
        "Set to e.g.  relay.example.com:7778  to route through a relay\\n"
        "when your NAT blocks incoming connections.\\n\\n"
        "The relay never sees plaintext."
    )
    if _IS_MAC:
        return _mac_ask_string("Lentel Relay", prompt, default)
    return _tk_ask_string("Lentel Relay", prompt, default)


def ask_parallel(default: int) -> Optional[int]:
    prompt = "How many parallel streams? (1-16)"
    if _IS_MAC:
        return _mac_ask_integer("Parallel streams", prompt, default)
    return _tk_ask_integer("Parallel streams", prompt, default)


def info(title: str, message: str) -> None:
    if _IS_MAC:
        _mac_info(title, message)
    else:
        _tk_info(title, message)


def error(title: str, message: str) -> None:
    if _IS_MAC:
        _mac_error(title, message)
    else:
        _tk_error(title, message)


def copy_to_clipboard(text: str) -> None:
    if _IS_MAC:
        _mac_copy(text)
    else:
        _tk_copy(text)


def reveal_in_file_manager(path: str) -> None:
    if not path or not os.path.exists(path):
        return
    if _IS_MAC:
        subprocess.Popen(["open", "-R", path])
    elif sys.platform.startswith("win"):
        subprocess.Popen(["explorer", "/select,", path])
    else:
        subprocess.Popen(["xdg-open", os.path.dirname(path) or "."])
