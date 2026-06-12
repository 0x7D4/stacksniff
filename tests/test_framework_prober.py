"""Unit tests for the SecLists-based FrameworkProber collector.

Tests use tmp_path for disk isolation and respx/unittest.mock for httpx mocking.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import yaml

from stacksniff.collectors.framework_prober import (
    FrameworkProber,
    _MAX_PROBES,
    _BATCH_SIZE,
    _CANARY_PATH,
    _GENERIC_WORDLISTS,
)
from stacksniff.models import Evidence, TechMatch


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_tech(name: str, confidence: float = 0.9) -> TechMatch:
    """Create a minimal TechMatch for testing."""
    return TechMatch(
        name=name,
        category="web-frameworks",
        version=None,
        confidence=confidence,
        evidence=[],
    )


def _write_manifest(seclists_dir: Path, files_meta: dict[str, Any]) -> Path:
    """Write a manifest.yaml into seclists_dir and return the manifest path."""
    manifest = {
        "version": "2025-01-01T00:00:00+00:00",
        "files": files_meta,
    }
    manifest_path = seclists_dir / "manifest.yaml"
    manifest_path.write_text(yaml.dump(manifest, sort_keys=False), encoding="utf-8")
    return manifest_path


def _write_wordlist(seclists_dir: Path, filename: str, paths: list[str]) -> None:
    """Write a wordlist file into seclists_dir."""
    (seclists_dir / filename).write_text("\n".join(paths), encoding="utf-8")


def _make_response(status: int, *, content_type: str = "text/html", body: str = "") -> httpx.Response:
    """Build a minimal httpx.Response for mocking."""
    headers = {"content-type": content_type}
    if status in (301, 302):
        headers["location"] = "https://example.com/redirect"
    return httpx.Response(
        status,
        headers=headers,
        text=body,
        request=httpx.Request("GET", "https://example.com/test"),
    )


# ---------------------------------------------------------------------------
# Test 1: Missing seclists_dir returns empty result with warning message
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_seclists_dir_returns_warning(tmp_path: Path) -> None:
    """When seclists_dir does not exist, collect() returns empty + error message."""
    nonexistent = tmp_path / "no_such_dir"
    prober = FrameworkProber(
        [_make_tech("Django")],
        "https://example.com",
        seclists_dir=nonexistent,
    )
    result = await prober.collect()

    assert result.data.get("framework_endpoints") == []
    assert len(result.errors) == 1
    assert "update-fingerprints" in result.errors[0]


# ---------------------------------------------------------------------------
# Test 2: Missing manifest.yaml returns empty result with warning
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_manifest_returns_warning(tmp_path: Path) -> None:
    """When the directory exists but manifest.yaml is absent, return empty + error."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()
    # Do NOT write manifest.yaml

    prober = FrameworkProber(
        [_make_tech("Django")],
        "https://example.com",
        seclists_dir=seclists_dir,
    )
    result = await prober.collect()

    assert result.data.get("framework_endpoints") == []
    assert any("update-fingerprints" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Test 3: always_probe paths are always included regardless of tech
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_always_probe_always_included(tmp_path: Path) -> None:
    """Paths from always_probe=True wordlists fire even with no tech match."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    # Only always-probe wordlists; no framework-specific ones
    files_meta = {
        "swagger.txt": {"tech_match": [], "path_count": 2, "always_probe": True},
        "graphql.txt": {"tech_match": [], "path_count": 1, "always_probe": True},
        "django.txt": {"tech_match": ["django", "python"], "path_count": 2, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "swagger.txt", ["/swagger.json", "/swagger-ui.html"])
    _write_wordlist(seclists_dir, "graphql.txt", ["/graphql"])
    _write_wordlist(seclists_dir, "django.txt", ["/admin/", "/django-admin/"])

    # Tech detected is "Spring" — does NOT match django
    prober = FrameworkProber(
        [_make_tech("Spring Boot")],
        "https://example.com",
        seclists_dir=seclists_dir,
    )

    # Intercept HTTP with all 404s
    probed_urls: list[str] = []

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        probed_urls.append(str(url))
        return _make_response(404)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        result = await prober.collect()

    # swagger.txt and graphql.txt paths should be probed, django.txt should NOT
    assert any("swagger" in u for u in probed_urls)
    assert any("graphql" in u for u in probed_urls)
    assert not any("admin" in u for u in probed_urls)
    assert result.data["framework_endpoints"] == []  # all 404s are skipped


# ---------------------------------------------------------------------------
# Test 4: Tech match filtering — Django matches django.txt paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tech_match_django_includes_django_txt(tmp_path: Path) -> None:
    """When Django is detected, django.txt paths are probed."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django", "python"], "path_count": 2, "always_probe": False},
        "spring-boot.txt": {
            "tech_match": ["spring boot", "spring", "java"],
            "path_count": 2,
            "always_probe": False,
        },
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/", "/api/"])
    _write_wordlist(seclists_dir, "spring-boot.txt", ["/actuator/health", "/actuator/info"])

    probed_urls: list[str] = []

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        probed_urls.append(str(url))
        return _make_response(404)

    prober = FrameworkProber(
        [_make_tech("Django")],
        "https://example.com",
        seclists_dir=seclists_dir,
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        await prober.collect()

    assert any("/admin/" in u for u in probed_urls)
    assert any("/api/" in u for u in probed_urls)
    assert not any("actuator" in u for u in probed_urls)


# ---------------------------------------------------------------------------
# Test 5: Tech match filtering — Spring does NOT include django.txt
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tech_match_spring_excludes_django(tmp_path: Path) -> None:
    """When Spring Boot is detected, django.txt paths are NOT probed."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django", "python"], "path_count": 1, "always_probe": False},
        "spring-boot.txt": {
            "tech_match": ["spring boot", "spring", "java"],
            "path_count": 1,
            "always_probe": False,
        },
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])
    _write_wordlist(seclists_dir, "spring-boot.txt", ["/actuator/health"])

    probed_urls: list[str] = []

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        probed_urls.append(str(url))
        return _make_response(404)

    prober = FrameworkProber(
        [_make_tech("Spring Boot")],
        "https://example.com",
        seclists_dir=seclists_dir,
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        await prober.collect()

    assert not any("admin" in u for u in probed_urls)
    assert any("actuator" in u for u in probed_urls)


# ---------------------------------------------------------------------------
# Test 6: 500-path cap is respected
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_probe_limit_500(tmp_path: Path) -> None:
    """Total probes capped at _MAX_PROBES (500) even if wordlists contain more."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    # Create 600 unique paths across two wordlists
    paths_a = [f"/path-a-{i}" for i in range(350)]
    paths_b = [f"/path-b-{i}" for i in range(350)]

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 350, "always_probe": False},
        "rails.txt": {"tech_match": ["rails"], "path_count": 350, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", paths_a)
    _write_wordlist(seclists_dir, "rails.txt", paths_b)

    probed_urls: list[str] = []

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if _CANARY_PATH in url:
            return _make_response(404)
        probed_urls.append(str(url))
        return _make_response(404)

    prober = FrameworkProber(
        [_make_tech("Django"), _make_tech("Rails")],
        "https://example.com",
        seclists_dir=seclists_dir,
    )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        await prober.collect()

    assert len(probed_urls) == _MAX_PROBES


# ---------------------------------------------------------------------------
# Test 7: Batch concurrency — probes run in batches of _BATCH_SIZE (50)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_size_50(tmp_path: Path) -> None:
    """Probes are fired in batches of _BATCH_SIZE (50) using asyncio.gather."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    # 120 paths → should require 3 gather calls (50+50+20)
    paths = [f"/batch-{i}" for i in range(120)]
    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 120, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", paths)

    gather_call_sizes: list[int] = []
    original_gather = asyncio.gather

    async def patched_gather(*coros: Any, **kwargs: Any) -> Any:
        # Track how many coroutines are passed to gather in each call
        # We filter out only the probe-related calls (> 1 coro)
        if len(coros) > 1:
            gather_call_sizes.append(len(coros))
        return await original_gather(*coros, **kwargs)

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(404)

    with (
        patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_http,
        patch("stacksniff.collectors.framework_prober.asyncio.gather", side_effect=patched_gather),
    ):
        mock_http.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        await prober.collect()

    # Should have 3 gather calls: 50 + 50 + 20
    assert len(gather_call_sizes) == 3
    assert gather_call_sizes[0] == _BATCH_SIZE
    assert gather_call_sizes[1] == _BATCH_SIZE
    assert gather_call_sizes[2] == 20


# ---------------------------------------------------------------------------
# Test 8: 200 response → confidence 0.95, status "exposed"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confidence_mapping_200(tmp_path: Path) -> None:
    """HTTP 200 → confidence=0.95, status_label='exposed'."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(200, content_type="text/plain", body="exposed endpoint info")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["confidence"] == 0.95
    assert endpoints[0]["status_label"] == "exposed"
    assert endpoints[0]["status_code"] == 200
    assert endpoints[0]["source_wordlist"] == "django.txt"


# ---------------------------------------------------------------------------
# Test 9: 401 response → confidence 0.85, status "auth-required"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confidence_mapping_401(tmp_path: Path) -> None:
    """HTTP 401 → confidence=0.85, status_label='auth-required'."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(401)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["confidence"] == 0.85
    assert endpoints[0]["status_label"] == "auth-required"


# ---------------------------------------------------------------------------
# Test 10: 403 response → confidence 0.80, status "forbidden"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confidence_mapping_403(tmp_path: Path) -> None:
    """HTTP 403 → confidence=0.80, status_label='forbidden'."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(403)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["confidence"] == 0.80
    assert endpoints[0]["status_label"] == "forbidden"


# ---------------------------------------------------------------------------
# Test 11: 301 response → confidence 0.70, status "redirect"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confidence_mapping_redirect(tmp_path: Path) -> None:
    """HTTP 301 → confidence=0.70, status_label='redirect'."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if _CANARY_PATH in url:
            return _make_response(404)
        return _make_response(301)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["confidence"] == 0.70
    assert endpoints[0]["status_label"] == "redirect"
    assert "redirect_location" in endpoints[0]


# ---------------------------------------------------------------------------
# Test 12 (bonus): Other status codes (404, 500) are skipped
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_other_status_codes_skipped(tmp_path: Path) -> None:
    """HTTP 404 and 500 responses are not recorded in framework_endpoints."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 2, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/missing/", "/server-error/"])

    call_count = 0

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        nonlocal call_count
        if _CANARY_PATH in url:
            return _make_response(404)
        call_count += 1
        if "missing" in url:
            return _make_response(404)
        return _make_response(500)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    assert call_count == 2
    assert result.data["framework_endpoints"] == []


# ---------------------------------------------------------------------------
# Test 13: Content-type filtering
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_html_200_response_discarded(tmp_path: Path) -> None:
    """HTTP 200 with text/html content-type that is not JSON is discarded."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(200, content_type="text/html", body="<html>Not JSON</html>")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    assert result.data["framework_endpoints"] == []


@pytest.mark.asyncio
async def test_html_401_response_kept(tmp_path: Path) -> None:
    """HTTP 401 with text/html is kept because it's an auth wall."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(401, content_type="text/html", body="<html>Auth wall</html>")

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 401


@pytest.mark.asyncio
async def test_json_with_html_content_type_kept(tmp_path: Path) -> None:
    """HTTP 200 with text/html that parses as JSON is kept."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {"tech_match": ["django"], "path_count": 1, "always_probe": False},
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return _make_response(200, content_type="text/html", body='{"status": "ok"}')

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 200
    assert endpoints[0]["top_level_keys"] == ["status"]


# ---------------------------------------------------------------------------
# Test 14: Redirect-noise filter — CMS nav redirects discarded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redirect_to_settings_discarded(tmp_path: Path) -> None:
    """/api/foo/admin 301 → /api/foo/settings is silently discarded.

    GitHub rewrites paths ending in /admin → /settings via 301.
    These are CMS navigation redirects, not real API endpoints.
    """
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "api-endpoints.txt": {
            "tech_match": [],
            "path_count": 2,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(
        seclists_dir, "api-endpoints.txt", ["/api/user/admin", "/api/v1/health"]
    )

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if "admin" in url:
            # Simulate GitHub's /admin → /settings CMS rewrite
            return httpx.Response(
                301,
                headers={
                    "content-type": "text/html; charset=utf-8",
                    "location": url.replace("/admin", "/settings"),
                },
                text="",
                request=httpx.Request("GET", url),
            )
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            text='{"status": "ok"}',
            request=httpx.Request("GET", url),
        )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],  # no techs — always_probe fires
            "https://github.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    urls = [ep["url"] for ep in endpoints]
    # The /admin redirect must be absent; the /health JSON must be present
    assert not any("admin" in u for u in urls), f"Nav redirect leaked: {urls}"
    assert any("health" in u for u in urls), f"Health endpoint missing: {urls}"


@pytest.mark.asyncio
async def test_redirect_same_domain_non_nav_kept(tmp_path: Path) -> None:
    """301 redirect to a non-nav path on the same domain is kept as a real redirect endpoint."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "api-endpoints.txt": {
            "tech_match": [],
            "path_count": 1,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "api-endpoints.txt", ["/api/v1"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if _CANARY_PATH in url:
            return httpx.Response(404, request=httpx.Request("GET", url))
        # A versioned redirect: /api/v1 → /api/v1.0  (same domain, non-nav)
        return httpx.Response(
            301,
            headers={
                "content-type": "text/html; charset=utf-8",
                "location": "https://example.com/api/v1.0",
            },
            text="",
            request=httpx.Request("GET", url),
        )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 301
    assert endpoints[0]["status_label"] == "redirect"
    assert endpoints[0]["redirect_location"] == "https://example.com/api/v1.0"


@pytest.mark.asyncio
async def test_actions_txt_html_200_always_discarded(tmp_path: Path) -> None:
    """Verify that any 200 text/html response from generic wordlists (actions.txt) is discarded."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "actions.txt": {
            "tech_match": [],
            "path_count": 1,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "actions.txt", ["/admin"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text='{"status": "exposed"}',
            request=httpx.Request("GET", url),
        )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 0


@pytest.mark.asyncio
async def test_framework_specific_html_200_json_body_kept(tmp_path: Path) -> None:
    """Verify that a 200 text/html response from framework-specific lists is kept if body is valid JSON."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {
            "tech_match": ["django"],
            "path_count": 1,
            "always_probe": False,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text='{"valid": "json"}',
            request=httpx.Request("GET", url),
        )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 200
    assert endpoints[0]["top_level_keys"] == ["valid"]


@pytest.mark.asyncio
async def test_trailing_slash_redirect_resolved(tmp_path: Path) -> None:
    """Verify that a 301 redirect to the same path with a trailing slash is resolved,
    and if it then redirects to a login page, it is discarded.
    """
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "actions.txt": {
            "tech_match": [],
            "path_count": 1,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "actions.txt", ["/admin"])

    calls = []

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        calls.append(url)
        if url == "https://example.com/admin":
            return httpx.Response(
                301,
                headers={"Location": "/admin/"},
                request=httpx.Request("GET", url),
            )
        elif url == "https://example.com/admin/":
            return httpx.Response(
                302,
                headers={"Location": "/admin/login/?next=/admin/"},
                request=httpx.Request("GET", url),
            )
        return httpx.Response(404, request=httpx.Request("GET", url))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 0
    assert "https://example.com/admin" in calls
    assert "https://example.com/admin/" in calls


@pytest.mark.asyncio
async def test_trailing_slash_redirect_to_valid_json_kept(tmp_path: Path) -> None:
    """Verify that a 301 redirect to the same path with a trailing slash is resolved,
    and if it then returns a 200 with valid JSON, it is kept.
    """
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "actions.txt": {
            "tech_match": [],
            "path_count": 1,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "actions.txt", ["/admin"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if url == "https://example.com/admin":
            return httpx.Response(
                301,
                headers={"Location": "/admin/"},
                request=httpx.Request("GET", url),
            )
        elif url == "https://example.com/admin/":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                text='{"status": "ok"}',
                request=httpx.Request("GET", url),
            )
        return httpx.Response(404, request=httpx.Request("GET", url))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 200
    assert endpoints[0]["top_level_keys"] == ["status"]


# ---------------------------------------------------------------------------
# Test: WordPress canonical-redirect baseline — canary detects redirect target
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wordpress_canonical_redirect_baseline(tmp_path: Path) -> None:
    """WordPress redirects nonsense paths to the homepage.  The canary detects
    this and subsequent probes that redirect to the same target are discarded.

    Scenario (iifon.org-style):
      - Canary → 302 → /
      - /Com    → 302 → /community/  (fuzzy slug — different from baseline, but
                                       still a fuzzy rewrite for generic lists)
      - /admin  → 302 → /            (matches baseline)
      - /robots.txt → 200 text/plain (legitimate — kept)
    """
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "actions.txt": {
            "tech_match": [],
            "path_count": 3,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(
        seclists_dir,
        "actions.txt",
        ["/Com", "/admin", "/robots.txt"],
    )

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if _CANARY_PATH in url:
            # WordPress redirects unknown → homepage
            return httpx.Response(
                302,
                headers={"location": "/", "content-type": "text/html"},
                text="",
                request=httpx.Request("GET", url),
            )
        if "/Com" in url:
            # Fuzzy slug rewrite: /Com → /community/
            return httpx.Response(
                302,
                headers={"location": "/community/", "content-type": "text/html"},
                text="",
                request=httpx.Request("GET", url),
            )
        if "/admin" in url:
            # Canonical redirect to homepage (matches baseline)
            return httpx.Response(
                302,
                headers={"location": "/", "content-type": "text/html"},
                text="",
                request=httpx.Request("GET", url),
            )
        if "/robots.txt" in url:
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                text="User-agent: *\nDisallow:",
                request=httpx.Request("GET", url),
            )
        return httpx.Response(404, request=httpx.Request("GET", url))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    urls = [ep["url"] for ep in endpoints]
    # /Com and /admin should be filtered out; /robots.txt should be kept
    assert not any("/Com" in u for u in urls), f"Fuzzy slug rewrite leaked: {urls}"
    assert not any("/admin" in u for u in urls), f"Baseline redirect leaked: {urls}"
    assert any("/robots.txt" in u for u in urls), f"Legitimate endpoint missing: {urls}"


# ---------------------------------------------------------------------------
# Test: Fuzzy-slug rewrite on generic wordlists discarded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fuzzy_slug_rewrite_generic_wordlist_discarded(tmp_path: Path) -> None:
    """For generic wordlists (api-endpoints.txt), a 301 redirect where the
    probed path is structurally unrelated to the target is discarded.

    /v1/data → /video-data/ is a CMS fuzzy-slug guess, not a real endpoint.
    """
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "api-endpoints.txt": {
            "tech_match": [],
            "path_count": 2,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "api-endpoints.txt", ["/v1/data", "/api/auth"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if _CANARY_PATH in url:
            # Server returns 404 for canary (no baseline redirect)
            return httpx.Response(404, request=httpx.Request("GET", url))
        if "/v1/data" in url:
            # WordPress fuzzy slug: /v1/data → /video-data/
            return httpx.Response(
                301,
                headers={"location": "/video-data/", "content-type": "text/html"},
                text="",
                request=httpx.Request("GET", url),
            )
        if "/api/auth" in url:
            # WordPress fuzzy slug: /api/auth → /about-us/
            return httpx.Response(
                301,
                headers={"location": "/about-us/", "content-type": "text/html"},
                text="",
                request=httpx.Request("GET", url),
            )
        return httpx.Response(404, request=httpx.Request("GET", url))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    # Both fuzzy-slug redirects should be discarded
    assert len(endpoints) == 0, f"Fuzzy slug redirects leaked: {endpoints}"


# ---------------------------------------------------------------------------
# Test: Framework-specific wordlist redirect NOT filtered by fuzzy-slug rule
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_framework_wordlist_redirect_not_filtered_by_fuzzy_slug(tmp_path: Path) -> None:
    """Framework-specific wordlists (e.g. django.txt) are NOT subject to the
    fuzzy-slug filter — only the baseline filter and nav-redirect filter apply.

    /admin/ → /dashboard/ is a legitimate redirect for framework-specific probes.
    """
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "django.txt": {
            "tech_match": ["django"],
            "path_count": 1,
            "always_probe": False,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "django.txt", ["/admin/"])

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if _CANARY_PATH in url:
            return httpx.Response(404, request=httpx.Request("GET", url))
        if "/admin/" in url:
            # Redirect to /dashboard/ — different path, but framework-specific
            return httpx.Response(
                301,
                headers={"location": "/dashboard/", "content-type": "text/html"},
                text="",
                request=httpx.Request("GET", url),
            )
        return httpx.Response(404, request=httpx.Request("GET", url))

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [_make_tech("Django")],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    # Framework-specific redirect should NOT be filtered by fuzzy-slug rule
    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 301
    assert endpoints[0]["redirect_location"] == "/dashboard/"


# ---------------------------------------------------------------------------
# Test: _is_canonical_redirect unit tests
# ---------------------------------------------------------------------------


class TestIsCanonicalRedirect:
    """Unit tests for the static _is_canonical_redirect method."""

    def test_baseline_match(self) -> None:
        """Redirect matching the baseline path should be flagged canonical."""
        assert FrameworkProber._is_canonical_redirect(
            probed_path="/Com",
            redirect_location="/",
            probe_url="https://example.com/Com",
            baseline="/",
            source_wordlist="actions.txt",
        )

    def test_no_baseline_no_match(self) -> None:
        """Without a baseline, the baseline rule does not fire."""
        assert not FrameworkProber._is_canonical_redirect(
            probed_path="/admin",
            redirect_location="/admin/",
            probe_url="https://example.com/admin",
            baseline=None,
            source_wordlist="django.txt",
        )

    def test_fuzzy_slug_generic_wordlist(self) -> None:
        """Generic wordlist with unrelated redirect path → canonical."""
        assert FrameworkProber._is_canonical_redirect(
            probed_path="/v1/data",
            redirect_location="/video-data/",
            probe_url="https://example.com/v1/data",
            baseline=None,
            source_wordlist="api-endpoints.txt",
        )

    def test_prefix_match_generic_wordlist_kept(self) -> None:
        """Generic wordlist where redirect IS a prefix match → NOT canonical."""
        assert not FrameworkProber._is_canonical_redirect(
            probed_path="/api/v1",
            redirect_location="/api/v1/",
            probe_url="https://example.com/api/v1",
            baseline=None,
            source_wordlist="api-endpoints.txt",
        )

    def test_fuzzy_slug_framework_wordlist_not_flagged(self) -> None:
        """Framework-specific wordlists skip the fuzzy-slug check."""
        assert not FrameworkProber._is_canonical_redirect(
            probed_path="/admin",
            redirect_location="/dashboard/",
            probe_url="https://example.com/admin",
            baseline=None,
            source_wordlist="django.txt",
        )


# ---------------------------------------------------------------------------
# Test: Canary timeout does not break probing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_canary_timeout_does_not_break_probing(tmp_path: Path) -> None:
    """If the canary request times out, probing should still proceed normally."""
    seclists_dir = tmp_path / "seclists"
    seclists_dir.mkdir()

    files_meta = {
        "actions.txt": {
            "tech_match": [],
            "path_count": 1,
            "always_probe": True,
        }
    }
    _write_manifest(seclists_dir, files_meta)
    _write_wordlist(seclists_dir, "actions.txt", ["/robots.txt"])

    call_count = 0

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if _CANARY_PATH in url:
            raise httpx.TimeoutException("canary timed out")
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            text="User-agent: *",
            request=httpx.Request("GET", url),
        )

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock:
        mock.side_effect = mock_get
        prober = FrameworkProber(
            [],
            "https://example.com",
            seclists_dir=seclists_dir,
        )
        result = await prober.collect()

    endpoints = result.data["framework_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["url"] == "https://example.com/robots.txt"

