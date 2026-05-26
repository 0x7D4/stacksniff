"""Unit tests for the JsStaticCollector class."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from stacksniff.collectors.js_static_collector import JsStaticCollector


@pytest.mark.asyncio
async def test_js_static_collector_cdn_filtering() -> None:
    """Test that known CDN and analytics domains are filtered out and not requested."""
    script_srcs = [
        "https://googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js",
        "https://cdn.jsdelivr.net/npm/react@17/umd/react.production.min.js",
        "https://unpkg.com/vue@3/dist/vue.global.js",
        "https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js",
        "https://example.com/assets/custom-app.js",  # Only this should be fetched
    ]

    collector = JsStaticCollector(script_srcs)

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = 'console.log("hello");'
    mock_response.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await collector.collect("https://example.com")

        # Verify only custom-app.js is fetched
        assert mock_get.call_count == 1
        mock_get.assert_called_once_with("https://example.com/assets/custom-app.js")

        assert result.data == {"static_endpoints": []}


@pytest.mark.asyncio
async def test_js_static_collector_regex_extraction() -> None:
    """Test regex patterns on a minified JS string."""
    script_srcs = ["/assets/main.js"]
    collector = JsStaticCollector(script_srcs)

    # JS code containing matches for all 4 patterns
    js_content = """
    // Pattern 1: '/api' quotes/backticks (2 to 80 chars)
    const url1 = "/api/v1/auth/login";
    const url2 = `/api/v2/user-profile`;
    // Pattern 2: fetch('/api...')
    fetch("/api/posts/query");
    fetch(`/api/v3/comments`);
    // Pattern 3: axios.get/post etc.
    axios.get("/api/v1/billing");
    axios.post(`/api/v1/payment`);
    // Pattern 4: absolute target URL containing /api
    const remote = "https://example.com/api/v4/metrics";
    const external = "https://api.stripe.com/v1/charges"; // Doesn't match (no /api suffix)
    """

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = js_content
    mock_response.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await collector.collect("https://example.com")

        endpoints = result.data.get("static_endpoints", [])

        # Verify extracted endpoints
        assert "/api/v1/auth/login" in endpoints
        assert "/api/v2/user-profile" in endpoints
        assert "/api/posts/query" in endpoints
        assert "/api/v3/comments" in endpoints
        assert "/api/v1/billing" in endpoints
        assert "/api/v1/payment" in endpoints
        # Normalized absolute same-origin to root-relative path
        assert "/api/v4/metrics" in endpoints

        # external should not be here since stripe doesn't match the patterns
        assert "https://api.stripe.com/v1/charges" not in endpoints


@pytest.mark.asyncio
async def test_js_static_collector_source_map_comment() -> None:
    """Test that source maps are probed and parsed when sourceMappingURL comment is present."""
    script_srcs = ["/assets/app.js"]
    collector = JsStaticCollector(script_srcs)

    js_content = """
    console.log("hello");
    //# sourceMappingURL=app.js.map
    """

    # Parallel sources list. One sourceContent is null, one has code.
    map_json = {
        "version": 3,
        "sources": ["foo.js", "bar.js"],
        "sourcesContent": [
            None,  # Null check should not crash the collector
            'const endpoint = "/api/v1/from-sourcemap";',
        ],
    }

    async def mock_get(url: str, *args, **kwargs) -> httpx.Response:
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.headers = {}
        if url == "https://example.com/assets/app.js":
            resp.text = js_content
        elif url == "https://example.com/assets/app.js.map":
            resp.text = json.dumps(map_json)
        else:
            resp.status_code = 404
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        result = await collector.collect("https://example.com")
        endpoints = result.data.get("static_endpoints", [])
        assert "/api/v1/from-sourcemap" in endpoints


@pytest.mark.asyncio
async def test_js_static_collector_source_map_header() -> None:
    """Test that source maps are probed and parsed when SourceMap/X-SourceMap header is present."""
    script_srcs = ["/assets/app.js"]
    collector = JsStaticCollector(script_srcs)

    map_json = {
        "version": 3,
        "sources": ["main.ts"],
        "sourcesContent": ['fetch("/api/v1/via-header-map");'],
    }

    async def mock_get(url: str, *args, **kwargs) -> httpx.Response:
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        if url == "https://example.com/assets/app.js":
            resp.text = 'console.log("hello");'
            resp.headers = {"X-SourceMap": "app.js.map"}
        elif url == "https://example.com/assets/app.js.map":
            resp.text = json.dumps(map_json)
            resp.headers = {}
        else:
            resp.status_code = 404
        return resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get):
        result = await collector.collect("https://example.com")
        endpoints = result.data.get("static_endpoints", [])
        assert "/api/v1/via-header-map" in endpoints


@pytest.mark.asyncio
async def test_js_static_collector_deduplication_normalization() -> None:
    """Test that endpoints are normalized correctly and duplicates are removed.

    When no base_url is provided (no domain filter), absolute URLs are always
    stripped to their root-relative path component.
    """
    script_srcs = ["/assets/app.js"]
    # No base_url -> no domain filter; all absolute URLs are stripped to paths
    collector = JsStaticCollector(script_srcs)

    js_content = """
    // Multiple duplicates
    fetch("/api/v1/users");
    fetch("/api/v1/users");

    // Absolute same-origin URL -> should be normalized to root-relative path
    fetch("https://example.com/api/v1/normalized");

    // Absolute external URL -> no base_url filter, so also stripped to its path
    fetch("https://api.external-service.com/api/v2/items");
    """

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = js_content
    mock_response.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await collector.collect("https://example.com")
        endpoints = result.data.get("static_endpoints", [])

        # Without base_url, all absolute URLs are converted to root-relative paths
        assert endpoints == [
            "/api/v1/normalized",
            "/api/v1/users",
            "/api/v2/items",
        ]


@pytest.mark.asyncio
async def test_absolute_url_different_domain_filtered() -> None:
    """Absolute URLs pointing to a different domain must be discarded when base_url is set.

    A JS bundle may contain hardcoded absolute URLs to third-party services
    (e.g. https://analytics.googleapis.com/...).  When base_url is provided,
    only same-domain absolute URLs should survive; cross-domain ones are dropped.
    """
    script_srcs = ["/assets/app.js"]
    # base_url is set -> domain filter is active
    collector = JsStaticCollector(script_srcs, base_url="https://example.com")

    js_content = """
    // Same-domain absolute URL -> keep, convert to relative path
    const url1 = "https://example.com/api/v1/users";

    // Different-domain absolute URL -> discard entirely
    const url2 = "https://analytics.googleapis.com/api/collect";
    const url3 = "https://cdn.external.com/api/v2/items";
    """

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = js_content
    mock_response.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await collector.collect("https://example.com")
        endpoints = result.data.get("static_endpoints", [])

        # Same-domain endpoint should appear as a relative path
        assert "/api/v1/users" in endpoints, f"Expected /api/v1/users in {endpoints}"

        # Cross-domain endpoints must be absent
        assert not any("googleapis" in ep for ep in endpoints), (
            f"googleapis URL leaked into static_endpoints: {endpoints}"
        )
        assert not any("external.com" in ep for ep in endpoints), (
            f"external.com URL leaked into static_endpoints: {endpoints}"
        )


@pytest.mark.asyncio
async def test_absolute_url_same_domain_kept() -> None:
    """Absolute URLs matching the target domain are kept and converted to a relative path.

    When base_url is set to https://example.com and the JS bundle contains
    https://example.com/api/v2/orders, the collector should output /api/v2/orders.
    """
    script_srcs = ["/assets/app.js"]
    collector = JsStaticCollector(script_srcs, base_url="https://example.com")

    js_content = """
    // Absolute same-origin URL with query string
    const endpoint = "https://example.com/api/v2/orders";
    fetch("https://example.com/api/v1/auth/login");
    """

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = js_content
    mock_response.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await collector.collect("https://example.com")
        endpoints = result.data.get("static_endpoints", [])

        # Both same-origin absolute URLs must appear as root-relative paths
        assert "/api/v2/orders" in endpoints, f"Expected /api/v2/orders in {endpoints}"
        assert "/api/v1/auth/login" in endpoints, f"Expected /api/v1/auth/login in {endpoints}"

        # No absolute URLs should remain in the output
        assert not any(ep.startswith("http") for ep in endpoints), (
            f"Absolute URL not stripped to relative path: {endpoints}"
        )




@pytest.mark.asyncio
async def test_absolute_url_subdomain_kept() -> None:
    """Absolute URLs targeting subdomains of the target domain are kept and converted to relative paths.

    When base_url is set to https://example.com and the JS bundle contains
    https://api.example.com/api/v2/orders or https://v2.example.com/api/v1/auth/login,
    the collector should output their paths.
    """
    script_srcs = ["/assets/app.js"]
    collector = JsStaticCollector(script_srcs, base_url="https://example.com")

    js_content = """
    const endpoint = "https://api.example.com/api/v2/orders";
    fetch("https://v2.example.com/api/v1/auth/login");
    """

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.text = js_content
    mock_response.headers = {}

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_response
        result = await collector.collect("https://example.com")
        endpoints = result.data.get("static_endpoints", [])

        # Subdomain absolute URLs must appear as root-relative paths
        assert "/api/v2/orders" in endpoints
        assert "/api/v1/auth/login" in endpoints

        # No absolute URLs should remain in the output
        assert not any(ep.startswith("http") for ep in endpoints)
