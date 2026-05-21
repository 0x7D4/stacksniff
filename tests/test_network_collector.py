"""Unit tests for the NetworkCollector class."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from stacksniff.collectors.network_collector import NetworkCollector


class MockRequest:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        rtype: str = "xhr",
        headers: dict | None = None,
        timing: dict | None = None,
    ):
        self.url = url
        self.method = method
        self.resource_type = rtype
        self.headers = headers or {}
        self.timing = timing or {"startTime": 100.0, "responseEnd": 120.0}


class MockResponse:
    def __init__(self, request: MockRequest, status: int = 200, headers: dict | None = None):
        self.request = request
        self.status = status
        self.headers = headers or {}


@pytest.fixture
def mock_playwright():
    """Fixture to mock playwright and page methods."""
    with patch("playwright.async_api.async_playwright") as mock_apw:
        pw = AsyncMock()
        browser = AsyncMock()
        context = AsyncMock()
        page = AsyncMock()

        mock_apw.return_value.__aenter__.return_value = pw
        pw.chromium.launch.return_value = browser
        browser.new_context.return_value = context
        context.new_page.return_value = page

        # Page mock methods
        page.on = MagicMock()
        page.goto = AsyncMock()
        page.eval_on_selector_all = AsyncMock(return_value=[])
        page.set_default_timeout = MagicMock()
        browser.close = AsyncMock()

        yield {
            "pw": pw,
            "browser": browser,
            "context": context,
            "page": page,
        }


@pytest.mark.asyncio
async def test_network_collector_same_origin_filtering(mock_playwright) -> None:
    """Test same-origin filtering excludes external domain links."""
    page = mock_playwright["page"]

    # Mock link extraction: returns one same-origin link and one external link
    page.eval_on_selector_all.return_value = [
        "https://example.com/about",
        "https://external.com/blog",
        "https://example.com/contact",
    ]

    collector = NetworkCollector(timeout=10.0, max_crawl_depth=1)

    # We patch _probe_paths to speed up the test
    with patch.object(collector, "_probe_paths", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = ([], [], None, [])
        await collector.collect("https://example.com")

    # Assert navigation occurred only for the initial URL and same-origin links
    assert page.goto.call_count == 3
    visited = [call[0][0] for call in page.goto.call_args_list]
    assert "https://example.com" in visited
    assert "https://example.com/about" in visited
    assert "https://example.com/contact" in visited
    assert "https://external.com/blog" not in visited


@pytest.mark.asyncio
async def test_network_collector_max_crawl_depth_zero(mock_playwright) -> None:
    """Test max_crawl_depth=0 skips the crawl phase entirely."""
    page = mock_playwright["page"]

    # Even if links are found on page
    page.eval_on_selector_all.return_value = ["https://example.com/about"]

    collector = NetworkCollector(timeout=10.0, max_crawl_depth=0)
    with patch.object(collector, "_probe_paths", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = ([], [], None, [])
        await collector.collect("https://example.com")

    # Only the initial URL should be visited, and eval_on_selector_all shouldn't be called
    assert page.goto.call_count == 1
    assert page.goto.call_args[0][0] == "https://example.com"
    assert page.eval_on_selector_all.call_count == 0


@pytest.mark.asyncio
async def test_network_collector_visited_tracking_loop_prevention(mock_playwright) -> None:
    """Test visited tracking prevents infinite/looping navigations."""
    page = mock_playwright["page"]

    # Mock a loop where / links to /about and /about links back to / and /about
    def mock_eval_on_selector_all(selector: str, expression: str) -> list[str]:
        current_url = page.goto.call_args[0][0]
        if current_url == "https://example.com":
            return ["https://example.com/about"]
        elif current_url == "https://example.com/about":
            return ["https://example.com", "https://example.com/about"]
        return []

    page.eval_on_selector_all.side_effect = mock_eval_on_selector_all

    collector = NetworkCollector(timeout=10.0, max_crawl_depth=2)
    with patch.object(collector, "_probe_paths", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = ([], [], None, [])
        await collector.collect("https://example.com")

    # Should visit / and /about exactly once
    assert page.goto.call_count == 2
    visited = [call[0][0] for call in page.goto.call_args_list]
    assert visited == ["https://example.com", "https://example.com/about"]


@pytest.mark.asyncio
async def test_network_collector_timeout_budget(mock_playwright) -> None:
    """Test that timeout budget cuts the crawl short when elapsed time exceeds the limit."""
    page = mock_playwright["page"]
    page.eval_on_selector_all.return_value = ["https://example.com/about"]

    collector = NetworkCollector(timeout=10.0, max_crawl_depth=2)

    # Mock time.monotonic to simulate elapsed time
    with (
        patch("time.monotonic") as mock_time,
        patch.object(collector, "_probe_paths", new_callable=AsyncMock) as mock_probe,
    ):
        mock_probe.return_value = ([], [], None, [])

        # 1. start_time = time.monotonic() (returns 100.0)
        # 2. elapsed check at loop start (returns 101.0 -> elapsed=1.0, remaining=9.0)
        # 3. elapsed check at next loop start (returns 112.0 -> elapsed=12.0, remaining=-2.0 <= 0)
        mock_time.side_effect = [100.0, 101.0, 112.0]

        result = await collector.collect("https://example.com")

    assert "Crawl timed out." in result.errors
    # Should only run the first page.goto and stop before navigating the second link
    assert page.goto.call_count == 1
    assert page.goto.call_args[0][0] == "https://example.com"


@pytest.mark.asyncio
async def test_network_collector_har_timing_capture(mock_playwright) -> None:
    """Test that HAR entries are populated with response and timing metadata."""
    page = mock_playwright["page"]

    collector = NetworkCollector(timeout=10.0, max_crawl_depth=0)
    with patch.object(collector, "_probe_paths", new_callable=AsyncMock) as mock_probe:
        mock_probe.return_value = ([], [], None, [])

        # Collect starts, page.on gets called to register request/response handlers
        # We need to simulate those handlers during the navigation
        async def mock_goto(*args, **kwargs):
            # Retrieve handlers
            request_cb = None
            response_cb = None
            for call_arg in page.on.call_args_list:
                call_args, _ = call_arg
                if call_args[0] == "request":
                    request_cb = call_args[1]
                elif call_args[0] == "response":
                    response_cb = call_args[1]

            if request_cb and response_cb:
                # Trigger a request and response
                req = MockRequest(
                    url="https://example.com/api/v1/data",
                    method="POST",
                    rtype="xhr",
                    headers={"X-Test": "req-val"},
                    timing={"startTime": 200.0, "responseEnd": 250.0},
                )
                resp = MockResponse(
                    request=req,
                    status=201,
                    headers={"Content-Type": "application/json", "X-Custom": "resp-val"},
                )
                request_cb(req)
                response_cb(resp)

        page.goto.side_effect = mock_goto
        result = await collector.collect("https://example.com")

    assert not result.errors
    har_entries = result.data.get("har_entries", [])
    assert len(har_entries) == 1

    entry = har_entries[0]
    assert entry["url"] == "https://example.com/api/v1/data"
    assert entry["method"] == "POST"
    assert entry["status"] == 201
    assert entry["content_type"] == "application/json"
    assert entry["request_headers"] == {"X-Test": "req-val"}
    assert entry["response_headers"] == {"Content-Type": "application/json", "X-Custom": "resp-val"}
    assert entry["timing"] == {"startTime": 200.0, "responseEnd": 250.0}
