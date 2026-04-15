"""Module entry point: ``python -m lentel.app``."""
from __future__ import annotations

from lentel.app.tray import run


def main() -> int:
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
