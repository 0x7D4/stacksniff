"""Pytest configuration and global fixtures."""

from __future__ import annotations

import pytest

import stacksniff.browser_pool
import stacksniff.cache


@pytest.fixture(autouse=True)
def reset_singletons() -> None:
    """Reset process-wide singletons before and after each test to ensure isolation."""
    stacksniff.browser_pool._pool = None
    stacksniff.cache._cache = None
    yield
    stacksniff.browser_pool._pool = None
    stacksniff.cache._cache = None
