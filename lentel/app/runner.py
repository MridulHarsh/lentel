"""
Background asyncio event loop.

pystray owns the main thread on every OS it supports. To run Lentel's
asyncio-based transfers, we spin up a dedicated event loop on a worker
thread and funnel coroutines to it with ``run_coroutine_threadsafe``.
"""
from __future__ import annotations

import asyncio
import threading
from concurrent.futures import Future
from typing import Coroutine, TypeVar

T = TypeVar("T")


class Runner:
    def __init__(self) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name="lentel-asyncio", daemon=True,
        )
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.loop = loop
        self._ready.set()
        try:
            loop.run_forever()
        finally:
            # Let outstanding tasks finish briefly.
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(
                    asyncio.gather(*pending, return_exceptions=True),
                )
            loop.close()

    def submit(self, coro: Coroutine[object, object, T]) -> Future[T]:
        """Schedule a coroutine on the worker loop and return a Future."""
        if self.loop is None:
            raise RuntimeError("runner not started")
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def stop(self) -> None:
        if self.loop is None:
            return
        self.loop.call_soon_threadsafe(self.loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)
