"""Unit tests for the ScanCache component."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest

from stacksniff.cache import ScanCache, get_cache
from stacksniff.models import DetectedEndpoint, Evidence, ScanMeta, ScanResult, TechMatch

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def temp_cache_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory for ScanCache."""
    return tmp_path / "cache_dir"


@pytest.fixture
def dummy_scan_result() -> ScanResult:
    """Provide a standard dummy ScanResult for cache testing."""
    evidence = [
        Evidence(source="header", key="Server", matched="nginx", pattern="nginx"),
    ]
    techs = [
        TechMatch(name="Nginx", category="Web Server", version="1.25", confidence=0.9, evidence=evidence),
    ]
    endpoints = [
        DetectedEndpoint(url="/api/v1/users", method="GET", content_type="application/json", pattern_matched="api", confidence=0.8),
    ]
    meta = ScanMeta(duration_seconds=1.2, phases_completed=["http", "browser"], fingerprints_version="1.0", rules_count=100)

    return ScanResult(
        url="https://example.com",
        scan_time=datetime.now(UTC),
        technologies=techs,
        api_endpoints=endpoints,
        meta=meta,
        openapi_spec_found=True,
        runtime_dependencies=[{"domain": "google.com", "request_count": 2}],
        discovered_subdomains=[{"subdomain": "api.example.com", "status_code": 200}],
    )


def test_get_cache_singleton() -> None:
    """Verify get_cache() singleton behavior."""
    import stacksniff.cache
    stacksniff.cache._cache = None

    c1 = get_cache()
    c2 = get_cache()
    assert c1 is c2
    assert isinstance(c1, ScanCache)


def test_cache_miss(temp_cache_dir: Path) -> None:
    """Test cache get on missing items."""
    cache = ScanCache(directory=temp_cache_dir)
    res = cache.get("https://example.com", {"browser": True})
    assert res is None
    assert cache.stats()["misses"] == 1
    assert cache.stats()["hits"] == 0


def test_cache_set_and_hit(temp_cache_dir: Path, dummy_scan_result: ScanResult) -> None:
    """Test setting a result and retrieving it successfully."""
    cache = ScanCache(directory=temp_cache_dir)
    options = {"browser": True, "crawl_depth": 1}

    cache.set("https://example.com", options, dummy_scan_result)

    # Cache hit
    retrieved = cache.get("https://example.com", options)
    assert retrieved is not None
    assert retrieved.url == dummy_scan_result.url
    # datetime parsing can drop microseconds or timezone formats, verify ISO or date match
    assert retrieved.scan_time.isoformat() == dummy_scan_result.scan_time.isoformat()
    assert retrieved.openapi_spec_found == dummy_scan_result.openapi_spec_found
    assert retrieved.runtime_dependencies == dummy_scan_result.runtime_dependencies
    assert retrieved.discovered_subdomains == dummy_scan_result.discovered_subdomains

    # Validate nested objects
    assert len(retrieved.technologies) == 1
    t = retrieved.technologies[0]
    assert t.name == "Nginx"
    assert t.confidence == 0.9
    assert len(t.evidence) == 1
    assert t.evidence[0].key == "Server"
    assert t.evidence[0].matched == "nginx"

    assert len(retrieved.api_endpoints) == 1
    ae = retrieved.api_endpoints[0]
    assert ae.url == "/api/v1/users"
    assert ae.method == "GET"

    assert retrieved.meta.duration_seconds == 1.2
    assert retrieved.meta.phases_completed == ["http", "browser"]

    stats = cache.stats()
    assert stats["hits"] == 1
    assert stats["total_entries"] == 1


def test_cache_key_excludes_transient_options(temp_cache_dir: Path, dummy_scan_result: ScanResult) -> None:
    """Test that key computation excludes timeout and other transient properties."""
    cache = ScanCache(directory=temp_cache_dir)

    options_a = {"browser": True, "timeout": 30.0, "cache_ttl": 60}
    options_b = {"browser": True, "timeout": 45.5}

    cache.set("https://example.com", options_a, dummy_scan_result)

    # Retrieve with different timeout: should still hit
    retrieved = cache.get("https://example.com", options_b)
    assert retrieved is not None
    assert cache.stats()["hits"] == 1


def test_cache_ttl_expiration(temp_cache_dir: Path, dummy_scan_result: ScanResult) -> None:
    """Test that expired cache items return None and are cleaned up."""
    cache = ScanCache(directory=temp_cache_dir)
    options = {"browser": True}

    # Set with negative TTL so it is immediately expired
    cache.set("https://example.com", options, dummy_scan_result, ttl=-10)

    retrieved = cache.get("https://example.com", options)
    assert retrieved is None
    assert cache.stats()["misses"] == 1
    assert cache.stats()["hits"] == 0

    # The expired file should have been invalidated (removed)
    assert cache.stats()["total_entries"] == 0


def test_cache_invalidate(temp_cache_dir: Path, dummy_scan_result: ScanResult) -> None:
    """Test manual invalidation of specific key."""
    cache = ScanCache(directory=temp_cache_dir)
    options = {"browser": True}

    cache.set("https://example.com", options, dummy_scan_result)
    assert cache.stats()["total_entries"] == 1

    # Invalidate
    removed = cache.invalidate("https://example.com", options)
    assert removed is True
    assert cache.stats()["total_entries"] == 0

    # Invalidate non-existent
    removed_again = cache.invalidate("https://example.com", options)
    assert removed_again is False


def test_cache_clear(temp_cache_dir: Path, dummy_scan_result: ScanResult) -> None:
    """Test clearing all cache entries."""
    cache = ScanCache(directory=temp_cache_dir)
    cache.set("https://a.com", {"b": True}, dummy_scan_result)
    cache.set("https://b.com", {"b": True}, dummy_scan_result)
    assert cache.stats()["total_entries"] == 2

    deleted = cache.clear()
    assert deleted == 2
    assert cache.stats()["total_entries"] == 0


def test_cache_clear_expired(temp_cache_dir: Path, dummy_scan_result: ScanResult) -> None:
    """Test clearing only expired entries."""
    cache = ScanCache(directory=temp_cache_dir)
    # Valid entry
    cache.set("https://valid.com", {"b": True}, dummy_scan_result, ttl=300)
    # Expired entry
    cache.set("https://expired.com", {"b": True}, dummy_scan_result, ttl=-10)

    assert cache.stats()["total_entries"] == 2

    purged = cache.clear_expired()
    assert purged == 1
    assert cache.stats()["total_entries"] == 1


@pytest.mark.asyncio
async def test_scanner_integration_with_caching(temp_cache_dir: Path) -> None:
    """Test Scanner correctly hits cache or saves to cache depending on bypass."""
    from stacksniff.scanner import Scanner

    scanner = Scanner(cache_ttl=60)
    # Patch get_cache to return a cache in our temp directory
    test_cache = ScanCache(directory=temp_cache_dir)

    with (
        patch("stacksniff.cache.get_cache", return_value=test_cache),
        patch("stacksniff.scanner.HeaderCollector") as mock_header,
        patch("stacksniff.scanner.CookieCollector") as mock_cookie,
        patch("stacksniff.scanner.HtmlCollector") as mock_html,
        patch("stacksniff.scanner.JsStaticCollector") as mock_static,
        patch("stacksniff.scanner.FrameworkProber") as mock_prober,
        patch("stacksniff.scanner.DomainMapper") as mock_mapper,
    ):
        # Setup mocks
        from stacksniff.collectors.base import CollectorResult
        mock_header.return_value.collect = AsyncMock(return_value=CollectorResult(data={"headers": {}}))
        mock_cookie.return_value.collect = AsyncMock(return_value=CollectorResult(data={"cookies": {}}))
        mock_html.return_value.collect = AsyncMock(return_value=CollectorResult(data={"raw_html": ""}))
        mock_static.return_value.collect = AsyncMock(return_value=CollectorResult(data={}))
        mock_prober.return_value.collect = AsyncMock(return_value=CollectorResult(data={"framework_endpoints": []}))
        mock_mapper.return_value.collect = AsyncMock(return_value=CollectorResult(data={"external_dependencies": [], "internal_subdomains": []}))

        # 1. First scan should be a miss, and write to cache
        res1 = await scanner.scan("https://test.com", browser=False)
        assert test_cache.stats()["misses"] == 1
        assert test_cache.stats()["hits"] == 0
        assert test_cache.stats()["total_entries"] == 1

        # 2. Second scan should hit the cache (and not call collectors)
        mock_header.return_value.collect.reset_mock()
        res2 = await scanner.scan("https://test.com", browser=False)
        mock_header.return_value.collect.assert_not_called()
        assert res1.url == res2.url
        assert test_cache.stats()["hits"] == 1

        # 3. Scan with bypass should ignore cache (miss/skip), call collectors, and rewrite
        await scanner.scan("https://test.com", browser=False, cache_bypass=True)
        mock_header.return_value.collect.assert_called_once()
        # Hits should remain 1 (no cache lookup performed)
        assert test_cache.stats()["hits"] == 1


def test_cache_key_consistent_with_partial_options(temp_cache_dir: Path) -> None:
    """Verify that partial/implicit options resolve to the same key as full explicit options."""
    cache = ScanCache(directory=temp_cache_dir)
    options1 = {"browser": True}
    options2 = {
        "browser": True,
        "scan_technologies": True,
        "scan_subdomains": True,
        "scan_endpoints": True,
        "fingerprints_path": None,
        "crawl_depth": 1,
    }
    key1 = cache._make_key("https://dnsblocks.in", options1)
    key2 = cache._make_key("https://dnsblocks.in", options2)
    assert key1 == key2


def test_cache_key_differs_for_different_options(temp_cache_dir: Path) -> None:
    """Verify that different configurations produce different keys (e.g. tech-only vs full)."""
    cache = ScanCache(directory=temp_cache_dir)
    tech_options = {
        "browser": True,
        "scan_technologies": True,
        "scan_subdomains": False,
        "scan_endpoints": False,
    }
    full_options = {
        "browser": True,
        "scan_technologies": True,
        "scan_subdomains": True,
        "scan_endpoints": True,
    }
    key_tech = cache._make_key("https://dnsblocks.in", tech_options)
    key_full = cache._make_key("https://dnsblocks.in", full_options)
    assert key_tech != key_full
