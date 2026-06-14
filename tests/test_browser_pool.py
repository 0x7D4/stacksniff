"""Unit tests for the Playwright BrowserPool."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from stacksniff.browser_pool import BrowserPool, get_pool, shutdown_pool


@pytest.fixture(autouse=True)
def clean_global_pool() -> None:
    """Ensure global pool singleton is reset before and after each test."""
    import stacksniff.browser_pool
    stacksniff.browser_pool._pool = None
    yield
    stacksniff.browser_pool._pool = None


def test_get_pool_singleton() -> None:
    """Verify get_pool() returns the same singleton instance."""
    pool1 = get_pool()
    pool2 = get_pool()
    assert pool1 is pool2
    assert isinstance(pool1, BrowserPool)


@pytest.mark.asyncio
async def test_browser_pool_initialization_double_check() -> None:
    """Test double-check lock pattern in initialize()."""
    pool = BrowserPool(max_browsers=2)
    mock_playwright = MagicMock()
    mock_start = AsyncMock(return_value=mock_playwright)

    with patch("playwright.async_api.async_playwright", return_value=MagicMock(start=mock_start)):
        # Run initialize twice concurrently
        await asyncio.gather(pool.initialize(), pool.initialize())
        # The underlying start should be called exactly once
        mock_start.assert_called_once()
        assert pool._initialized is True
        assert pool._playwright is mock_playwright


@pytest.mark.asyncio
async def test_browser_pool_concurrency_limiting() -> None:
    """Test that BrowserPool limits concurrent browsers and tracks queue depth."""
    pool = BrowserPool(max_browsers=2)

    mock_browser = MagicMock(close=AsyncMock())
    mock_playwright = MagicMock()
    mock_playwright.chromium.launch = AsyncMock(return_value=mock_browser)

    with patch("playwright.async_api.async_playwright", return_value=MagicMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.initialize()

        active_count = 0
        max_active = 0
        results = []

        async def worker(worker_id: int) -> None:
            nonlocal active_count, max_active
            async with pool.acquire() as browser:
                assert browser is mock_browser
                active_count += 1
                max_active = max(max_active, active_count)
                # Sleep to simulate browser work
                await asyncio.sleep(0.05)
                active_count -= 1
                results.append(worker_id)

        # Run 3 workers concurrently
        # Since max_browsers=2, the third worker must wait.
        task1 = asyncio.create_task(worker(1))
        task2 = asyncio.create_task(worker(2))
        await asyncio.sleep(0.01)  # allow task 1 & 2 to acquire

        # Check queue depth before task 3 is started/queued
        assert pool.queue_depth == 0

        task3 = asyncio.create_task(worker(3))
        await asyncio.sleep(0.01)  # allow task 3 to enter acquire and wait

        # Task 3 should be waiting in queue
        assert pool.queue_depth == 1
        assert active_count == 2

        # Wait for all to finish
        await asyncio.gather(task1, task2, task3)

        assert pool.queue_depth == 0
        assert active_count == 0
        assert max_active == 2  # Concurrency limit was respected
        assert len(results) == 3


@pytest.mark.asyncio
async def test_browser_pool_exception_release() -> None:
    """Test that semaphore and queue depth are cleaned up properly on failure."""
    pool = BrowserPool(max_browsers=1)

    mock_playwright = MagicMock()
    # Mock launch to throw exception
    mock_playwright.chromium.launch = AsyncMock(side_effect=RuntimeError("Launch failed"))

    with patch("playwright.async_api.async_playwright", return_value=MagicMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.initialize()

        # Try to acquire, which should fail
        with pytest.raises(RuntimeError, match="Launch failed"):
            async with pool.acquire():
                pass

        # Verify waiting queue and semaphore are released
        assert pool.queue_depth == 0
        # Check that we can acquire again (if launch succeeded)
        mock_browser = MagicMock(close=AsyncMock())
        mock_playwright.chromium.launch = AsyncMock(return_value=mock_browser)

        async with pool.acquire() as browser:
            assert browser is mock_browser
            assert pool.queue_depth == 0


@pytest.mark.asyncio
async def test_browser_pool_cancellation_safety() -> None:
    """Test that cancellation while waiting in queue recovers count and semaphore."""
    pool = BrowserPool(max_browsers=1)

    mock_browser = MagicMock(close=AsyncMock())
    mock_playwright = MagicMock()
    mock_playwright.chromium.launch = AsyncMock(return_value=mock_browser)

    with patch("playwright.async_api.async_playwright", return_value=MagicMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.initialize()

        # Hold the only slot
        async def slot_holder() -> None:
            async with pool.acquire():
                await asyncio.sleep(1.0)

        holder_task = asyncio.create_task(slot_holder())
        await asyncio.sleep(0.01)  # let holder acquire

        # Queue a waiting task
        async def waiting_task() -> None:
            async with pool.acquire():
                pass

        waiter = asyncio.create_task(waiting_task())
        await asyncio.sleep(0.01)  # let waiter enter queue

        assert pool.queue_depth == 1

        # Cancel the waiter
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter

        # The waiter should be removed from the queue depth count
        assert pool.queue_depth == 0

        # Cleanup holder
        holder_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await holder_task


@pytest.mark.asyncio
async def test_browser_pool_shutdown() -> None:
    """Test that shutdown stops playwright and resets state."""
    pool = BrowserPool(max_browsers=2)
    mock_playwright = MagicMock(stop=AsyncMock())

    with patch("playwright.async_api.async_playwright", return_value=MagicMock(start=AsyncMock(return_value=mock_playwright))):
        await pool.initialize()
        assert pool._initialized is True

        await pool.shutdown()
        mock_playwright.stop.assert_called_once()
        assert pool._initialized is False
        assert pool._playwright is None
