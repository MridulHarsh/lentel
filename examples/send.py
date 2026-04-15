"""Minimal example: send a file using the Lentel API."""
import asyncio
import sys

from lentel import send_file


async def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: send.py <file>")
    path = sys.argv[1]

    def on_ticket(t: str) -> None:
        print(f"share this ticket with the receiver: {t}")

    def progress(done: int, total: int, rate_bps: float) -> None:
        if total:
            pct = 100 * done / total
            print(f"  {pct:5.1f}%  {rate_bps / 1e6:6.2f} MB/s", end="\r")

    await send_file(
        path,
        coordinator="tcp://localhost:7777",
        on_ticket=on_ticket,
        progress=progress,
    )
    print("\ndone.")


if __name__ == "__main__":
    asyncio.run(main())
