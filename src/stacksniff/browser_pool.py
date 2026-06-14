"""Playwright browser instance pool to prevent memory exhaustion."""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from playwright.async_api import Browser, Playwright


class BrowserPool:
    """Singleton pool managing a fixed set of concurrent Playwright browser instances."""

    def __init__(self, max_browsers: int = 3) -> None:
        self._max_browsers = max_browsers
        self._semaphore = asyncio.Semaphore(max_browsers)
        self._playwright: Playwright | None = None
        self._lock = asyncio.Lock()
        self._initialized: bool = False
        self._waiting: int = 0

    async def initialize(self) -> None:
        """Start Playwright once, thread-safely."""
        async with self._lock:
            if self._initialized:
                return
            try:
                from playwright.async_api import async_playwright
            except (ImportError, ModuleNotFoundError):
                import sys
                pw_mod = sys.modules.get("playwright")
                if pw_mod is not None:
                    async_playwright = getattr(pw_mod, "async_api", pw_mod)  # type: ignore[arg-type]
                    if hasattr(async_playwright, "async_playwright"):
                        async_playwright = async_playwright.async_playwright
                else:
                    raise
            import inspect

            apw: Any = async_playwright()
            start_val = apw.start() if hasattr(apw, "start") else None
            if inspect.isawaitable(start_val):
                self._playwright = await start_val
            elif hasattr(apw, "__aenter__"):
                aenter_val = apw.__aenter__()
                if inspect.isawaitable(aenter_val):
                    self._playwright = await aenter_val
                else:
                    self._playwright = aenter_val
            else:
                self._playwright = apw

            self._initialized = True

    async def shutdown(self) -> None:
        """Close Playwright cleanly."""
        async with self._lock:
            if not self._initialized:
                return
            if self._playwright is not None:
                import inspect
                if hasattr(self._playwright, "stop"):
                    stop_val = self._playwright.stop()
                    if inspect.isawaitable(stop_val):
                        await stop_val
                self._playwright = None
            self._initialized = False

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[Browser]:
        """Acquire a browser instance, waiting if the pool is full."""
        if not self._initialized:
            await self.initialize()

        self._waiting += 1
        acquired = False
        try:
            async with self._semaphore:
                self._waiting -= 1
                acquired = True
                if self._playwright is None:
                    raise RuntimeError("Browser pool has not been initialized.")

                browser = await self._playwright.chromium.launch(headless=True)
                try:
                    yield browser
                finally:
                    await browser.close()
        finally:
            if not acquired:
                self._waiting -= 1

    @property
    def queue_depth(self) -> int:
        """Return the number of scans currently waiting for a browser slot."""
        return self._waiting


_pool: BrowserPool | None = None


def get_pool() -> BrowserPool:
    """Return the process-wide BrowserPool instance."""
    global _pool
    if _pool is None:
        max_b = int(os.environ.get("STACKSNIFF_MAX_BROWSERS", "3"))
        _pool = BrowserPool(max_browsers=max_b)
    return _pool


async def initialize_pool() -> None:
    """Initialize the browser pool."""
    await get_pool().initialize()


async def shutdown_pool() -> None:
    """Shut down the browser pool."""
    global _pool
    if _pool is not None:
        await _pool.shutdown()
