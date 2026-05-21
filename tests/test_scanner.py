"""Unit tests for the Scanner orchestrator."""

from __future__ import annotations

import sys
from collections.abc import Generator  # noqa: TC003
from pathlib import Path  # noqa: TC003
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from stacksniff.collectors.base import CollectorResult
from stacksniff.models import ScanResult
from stacksniff.scanner import Scanner, scan_sync


@pytest.fixture
def mock_collectors() -> Generator[dict[str, AsyncMock], None, None]:
    """Mock all 5 collectors to return standard mock CollectorResults."""
    with (
        patch("stacksniff.scanner.HeaderCollector") as mock_header,
        patch("stacksniff.scanner.CookieCollector") as mock_cookie,
        patch("stacksniff.scanner.HtmlCollector") as mock_html,
        patch("stacksniff.scanner.JsCollector") as mock_js,
        patch("stacksniff.scanner.NetworkCollector") as mock_net,
        patch("stacksniff.scanner.JsStaticCollector") as mock_static,
    ):
        # Header
        hc_instance = mock_header.return_value
        hc_instance.collect = AsyncMock(
            return_value=CollectorResult(data={"headers": {"Server": "nginx/1.25.3"}})
        )

        # Cookie
        cc_instance = mock_cookie.return_value
        cc_instance.collect = AsyncMock(
            return_value=CollectorResult(data={"cookies": {"session": "xyz"}})
        )

        # Html
        html_instance = mock_html.return_value
        html_instance.collect = AsyncMock(
            return_value=CollectorResult(
                data={
                    "raw_html": "<html></html>",
                    "meta_tags": {"generator": "WordPress 6.4"},
                    "script_srcs": [],
                    "link_hrefs": [],
                }
            )
        )

        # Js
        js_instance = mock_js.return_value
        js_instance.collect = AsyncMock(
            return_value=CollectorResult(data={"js_globals": {"window.jQuery": "3.7.1"}})
        )

        # Network
        net_instance = mock_net.return_value
        net_instance.collect = AsyncMock(
            return_value=CollectorResult(
                data={
                    "network_requests": [
                        {
                            "url": "https://example.com/api/v1/users",
                            "method": "GET",
                            "resource_type": "xhr",
                            "status": 200,
                            "content_type": "application/json",
                        }
                    ],
                    "probed_paths": [
                        {
                            "url": "https://example.com/robots.txt",
                            "method": "GET",
                            "resource_type": "probe",
                            "status": 200,
                            "content_type": "text/plain",
                        }
                    ],
                }
            )
        )

        # Static JS endpoints
        static_instance = mock_static.return_value
        static_instance.collect = AsyncMock(
            return_value=CollectorResult(data={"static_endpoints": []})
        )

        yield {
            "header": hc_instance,
            "cookie": cc_instance,
            "html": html_instance,
            "js": js_instance,
            "net": net_instance,
            "static": static_instance,
        }


@pytest.mark.asyncio
async def test_scanner_http_only(mock_collectors: dict[str, AsyncMock]) -> None:
    """Test scan with browser=False, verifying that browser collectors are not called."""
    # Ensure custom tech.yaml location for test environment
    test_yaml = Path(__file__).parents[1] / "fingerprints" / "tech.yaml"

    scanner = Scanner(fingerprints_path=test_yaml)
    result = await scanner.scan("https://example.com", browser=False)

    assert isinstance(result, ScanResult)
    assert result.url == "https://example.com"
    assert result.meta.phases_completed == ["http"]

    # Check collector calls
    mock_collectors["header"].collect.assert_called_once_with("https://example.com")
    mock_collectors["cookie"].collect.assert_called_once_with("https://example.com")
    mock_collectors["html"].collect.assert_called_once_with("https://example.com")

    mock_collectors["js"].collect.assert_not_called()
    mock_collectors["net"].collect.assert_not_called()

    # Check that Nginx was detected (via headers Server)
    nginx_match = next((t for t in result.technologies if t.name == "Nginx"), None)
    assert nginx_match is not None
    assert nginx_match.version == "1.25.3"


@pytest.mark.asyncio
async def test_scanner_with_browser_success(mock_collectors: dict[str, AsyncMock]) -> None:
    """Test scanner running with browser enabled and playwright installed."""
    test_yaml = Path(__file__).parents[1] / "fingerprints" / "tech.yaml"

    # Mock playwright import using sys.modules dictionary
    mock_playwright = MagicMock()
    with patch.dict(sys.modules, {"playwright": mock_playwright}):
        scanner = Scanner(fingerprints_path=test_yaml)
        result = await scanner.scan("https://example.com", browser=True)

        assert isinstance(result, ScanResult)
        assert "http" in result.meta.phases_completed
        assert "browser" in result.meta.phases_completed

        mock_collectors["header"].collect.assert_called_once_with("https://example.com")
        mock_collectors["js"].collect.assert_called_once_with("https://example.com")
        mock_collectors["net"].collect.assert_called_once_with("https://example.com")

        # Verify that API endpoints are detected from browser traffic
        api_ep = next((e for e in result.api_endpoints if e.url == "/api/v1/users"), None)
        assert api_ep is not None
        assert api_ep.confidence == 0.8  # 0.7 base + 0.1 ct json

        # Verify robots.txt probe was detected
        robots_ep = next((e for e in result.api_endpoints if e.url == "/robots.txt"), None)
        assert robots_ep is not None
        assert robots_ep.confidence == 0.8  # Probed API confidence


@pytest.mark.asyncio
async def test_scanner_with_browser_missing_playwright(
    mock_collectors: dict[str, AsyncMock],
) -> None:
    """Test browser=True but playwright not installed triggers silent skip of browser phase."""
    test_yaml = Path(__file__).parents[1] / "fingerprints" / "tech.yaml"

    with patch.dict(sys.modules, {"playwright": None}):
        scanner = Scanner(fingerprints_path=test_yaml)
        result = await scanner.scan("https://example.com", browser=True)

        assert "http" in result.meta.phases_completed
        assert "browser" not in result.meta.phases_completed

        mock_collectors["js"].collect.assert_not_called()
        mock_collectors["net"].collect.assert_not_called()


@pytest.mark.asyncio
async def test_scanner_progress_callback(mock_collectors: dict[str, AsyncMock]) -> None:
    """Test progress callback invocations."""
    test_yaml = Path(__file__).parents[1] / "fingerprints" / "tech.yaml"

    callback_calls = []

    def progress_cb(phase: str, status: str) -> None:
        callback_calls.append((phase, status))

    mock_playwright = MagicMock()
    with patch.dict(sys.modules, {"playwright": mock_playwright}):
        scanner = Scanner(fingerprints_path=test_yaml)
        await scanner.scan("https://example.com", browser=True, progress_callback=progress_cb)

        assert ("http", "started") in callback_calls
        assert ("http", "completed") in callback_calls
        assert ("browser", "started") in callback_calls
        assert ("browser", "completed") in callback_calls


def test_scan_sync_wrapper(mock_collectors: dict[str, AsyncMock]) -> None:
    """Test synchronous scan_sync wrapper."""
    test_yaml = Path(__file__).parents[1] / "fingerprints" / "tech.yaml"

    # We patch run_scan / Scanner.scan inside scan_sync to ensure it is called
    with patch("stacksniff.scanner.Scanner.scan", new_callable=AsyncMock) as mock_scan:
        mock_scan.return_value = ScanResult(
            url="https://example.com",
            scan_time=None,
            technologies=[],
            api_endpoints=[],
            meta=None,
        )
        res = scan_sync("https://example.com", browser=False, fingerprints_path=test_yaml)
        assert res.url == "https://example.com"
        mock_scan.assert_called_once_with(
            "https://example.com",
            browser=False,
            timeout=30.0,
            fingerprints_path=test_yaml,
        )
