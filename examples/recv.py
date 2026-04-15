"""Minimal example: receive a file using the Lentel API."""
import asyncio
import sys

from lentel import recv_file


async def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("usage: recv.py <ticket>")
    ticket = sys.argv[1]

    def progress(done: int, total: int, rate_bps: float) -> None:
        if total:
            pct = 100 * done / total
            print(f"  {pct:5.1f}%  {rate_bps / 1e6:6.2f} MB/s", end="\r")

    out = await recv_file(
        ticket,
        dest_dir="./downloads",
        coordinator="tcp://localhost:7777",
        progress=progress,
    )
    print(f"\nsaved to {out}")


if __name__ == "__main__":
    asyncio.run(main())
