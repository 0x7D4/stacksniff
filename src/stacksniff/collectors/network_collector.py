"""Collect network requests made by a page and probe known API paths.

Uses Playwright to intercept all XHR/fetch requests fired during page
load, then probes a curated list of well-known API/config paths with
:mod:`httpx`.

Returned ``data`` dict shape::

    {
        "network_requests": [<NetworkRequest>, ...],
        "probed_paths":     [<NetworkRequest>, ...],
    }

Both lists contain :class:`~stacksniff.collectors.base.NetworkRequest`
dataclass instances serialised as dicts (for JSON compatibility inside
:class:`CollectorResult`).

If Playwright is not installed the browser phase is skipped and only
the httpx path-probe phase runs.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from stacksniff.collectors.base import CollectorResult, NetworkRequest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known paths to probe (appended to the target's base URL).
# ---------------------------------------------------------------------------

_PROBE_PATHS: tuple[str, ...] = (
    "/robots.txt",
    "/sitemap.xml",
    "/api-docs",
    "/openapi.json",
    "/swagger.json",
    "/graphql",
    "/.well-known/security.txt",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/v1/swagger.yaml",
    "/api/v2/swagger.yaml",
    "/__docs__/openapi.json",
    "/_swagger-ui/",
    "/api-docs/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi/v3/openapi.json",
)

_DEFAULT_TIMEOUT: float = 30.0


class NetworkCollector:
    """Async collector that captures browser network traffic and probes API paths.

    Parameters
    ----------
    timeout:
        Total timeout in seconds shared between the browser phase and
        the httpx probe phase.
    max_crawl_depth:
        Maximum link depth to crawl on same-origin pages.
    """

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_crawl_depth: int = 1,
    ) -> None:
        self._timeout = timeout
        self._max_crawl_depth = max_crawl_depth

    # ------------------------------------------------------------------
    # Collector protocol
    # ------------------------------------------------------------------

    async def collect(self, url: str) -> CollectorResult:
        """Intercept XHR/fetch requests from *url* and probe known paths.

        Returns partial results on any error.  Returns only probe results
        (no browser traffic) if Playwright is not installed.
        """
        result = CollectorResult()
        browser_requests: list[dict] = []
        har_entries: list[dict] = []
        probed: list[dict] = []

        # ---- Phase 1: Browser network interception --------------------
        browser_requests, har_entries, browser_errors = await self._collect_browser(url)
        for err in browser_errors:
            result.add_error(err)

        # ---- Phase 2: Probe well-known paths --------------------------
        probed, probe_errors, parsed_spec, spec_endpoints = await self._probe_paths(url)
        for err in probe_errors:
            result.add_error(err)

        result.data = {
            "network_requests": browser_requests,
            "probed_paths": probed,
            "har_entries": har_entries,
            "parsed_spec": parsed_spec,
            "spec_endpoints": spec_endpoints,
        }
        return result

    # ------------------------------------------------------------------
    # Phase 1 — Playwright network capture
    # ------------------------------------------------------------------

    async def _collect_browser(self, url: str) -> tuple[list[dict], list[dict], list[str]]:
        """Launch browser, intercept XHR/fetch, crawl same-origin links, return results."""
        captured: list[dict] = []
        har_entries: list[dict] = []
        errors: list[str] = []

        try:
            from playwright.async_api import async_playwright
        except ImportError:
            errors.append(
                "Playwright is not installed - browser network capture skipped. "
                "Install with: pip install playwright && "
                "python -m playwright install chromium"
            )
            return captured, har_entries, errors

        # Mutable stores shared by event handlers
        pending: dict[Any, dict] = {}  # request object -> partial dict
        finished: list[dict] = []

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                try:
                    context = await browser.new_context(
                        user_agent=(
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/125.0.0.0 Safari/537.36"
                        ),
                        java_script_enabled=True,
                        ignore_https_errors=True,
                    )
                    page = await context.new_page()

                    # ---- attach request/response listeners BEFORE nav ----
                    def _on_request(request) -> None:  # type: ignore[no-untyped-def]
                        rtype = request.resource_type
                        if rtype not in ("xhr", "fetch"):
                            return
                        req_headers = {}
                        with contextlib.suppress(Exception):
                            req_headers = dict(request.headers)
                        pending[request] = {
                            "request": request,
                            "url": request.url,
                            "method": request.method,
                            "resource_type": rtype,
                            "request_headers": req_headers,
                            "status": None,
                            "content_type": None,
                            "response_headers": {},
                        }

                    def _on_response(response) -> None:  # type: ignore[no-untyped-def]
                        req = response.request
                        entry = pending.pop(req, None)
                        if entry is None:
                            return
                        resp_headers = {}
                        with contextlib.suppress(Exception):
                            resp_headers = dict(response.headers)
                        entry["status"] = response.status
                        lower_headers = {k.lower(): v for k, v in resp_headers.items()}
                        entry["content_type"] = lower_headers.get("content-type")
                        entry["response_headers"] = resp_headers
                        finished.append(entry)

                    page.on("request", _on_request)
                    page.on("response", _on_response)

                    # ---- navigate & crawl loop ---------------------------
                    queue: list[tuple[str, int]] = [(url, 0)]
                    visited: set[str] = {url}
                    crawled_count = 0
                    start_time = time.monotonic()

                    while queue:
                        elapsed = time.monotonic() - start_time
                        remaining = self._timeout - elapsed
                        if remaining <= 0:
                            errors.append("Crawl timed out.")
                            break

                        current_url, current_depth = queue.pop(0)
                        nav_timeout_ms = max(int(remaining * 1_000), 1000)
                        page.set_default_timeout(nav_timeout_ms)

                        try:
                            await page.goto(
                                current_url,
                                wait_until="networkidle",
                                timeout=nav_timeout_ms,
                            )
                            if current_depth > 0:
                                crawled_count += 1
                        except Exception as nav_exc:
                            errors.append(f"Navigation issue to {current_url}: {nav_exc}")
                            if current_depth == 0:
                                # If initial navigation fails, stop immediately to save time
                                break
                            continue

                        # Link extraction
                        if current_depth < self._max_crawl_depth and crawled_count < 10:
                            extracted_links = []
                            try:
                                extracted_links = await page.eval_on_selector_all(
                                    "a", "elements => elements.map(el => el.href)"
                                )
                            except Exception as eval_exc:
                                logger.debug(
                                    "Failed to extract links on %s: %s",
                                    current_url,
                                    eval_exc,
                                )

                            target_parsed = urlparse(url)
                            target_netloc = target_parsed.netloc.lower()

                            valid_links = []
                            for link in extracted_links:
                                if not link:
                                    continue
                                link_no_frag = link.split("#")[0]
                                if not link_no_frag:
                                    continue
                                try:
                                    link_parsed = urlparse(link_no_frag)
                                except Exception:
                                    continue
                                if (
                                    link_parsed.netloc.lower() == target_netloc
                                    and link_no_frag not in visited
                                ):
                                    visited.add(link_no_frag)
                                    valid_links.append(link_no_frag)

                            remaining_quota = 10 - crawled_count
                            if remaining_quota > 0:
                                for link_to_crawl in valid_links[:remaining_quota]:
                                    queue.append((link_to_crawl, current_depth + 1))
                            else:
                                break

                    # Small grace period for late XHRs
                    await asyncio.sleep(1.0)

                    # Merge any requests that never got a response
                    for entry in pending.values():
                        finished.append(entry)

                    # Convert to serialised NetworkRequest dicts and HAR entries
                    for entry in finished:
                        timing_data = {}
                        with contextlib.suppress(Exception):
                            req_obj = entry.get("request")
                            if req_obj and hasattr(req_obj, "timing"):
                                timing_data = req_obj.timing or {}

                        nr = NetworkRequest(
                            url=entry["url"],
                            method=entry["method"],
                            resource_type=entry["resource_type"],
                            status=entry.get("status"),
                            content_type=entry.get("content_type"),
                            request_headers=entry.get("request_headers", {}),
                            response_headers=entry.get("response_headers", {}),
                        )
                        captured.append(_nr_to_dict(nr))

                        har_entry = {
                            "url": entry["url"],
                            "method": entry["method"],
                            "status": entry.get("status"),
                            "content_type": entry.get("content_type"),
                            "request_headers": entry.get("request_headers", {}),
                            "response_headers": entry.get("response_headers", {}),
                            "timing": timing_data,
                        }
                        har_entries.append(har_entry)

                finally:
                    await browser.close()

        except Exception as exc:  # noqa: BLE001
            logger.exception("Playwright network capture error for %s", url)
            errors.append(f"Browser error: {exc}")

        return captured, har_entries, errors

    # ------------------------------------------------------------------
    # Phase 2 — Probe well-known paths with httpx
    # ------------------------------------------------------------------

    async def _probe_paths(self, url: str) -> tuple[list[dict], list[str], dict | None, list[str]]:
        """HEAD/GET well-known paths and return those that respond usefully."""
        probed: list[dict] = []
        errors: list[str] = []
        parsed_spec: dict | None = None
        spec_endpoints: list[str] = []

        # Derive base URL (scheme + host)
        from urllib.parse import urlparse

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        probe_timeout = max(self._timeout / 3, 5.0)
        transport = httpx.AsyncHTTPTransport(retries=1)

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(probe_timeout),
                follow_redirects=True,
                max_redirects=5,
                transport=transport,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/125.0.0.0 Safari/537.36"
                    ),
                },
                verify=True,
            ) as client:
                tasks = [self._probe_single(client, base_url, path) for path in _PROBE_PATHS]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for r in results:
                    if isinstance(r, Exception):
                        # Don't pollute errors for expected 404s etc.
                        logger.debug("Probe exception: %s", r)
                        continue
                    if r is not None:
                        probed.append(r["request_dict"])

                        # Attempt to parse as OpenAPI if not already found
                        if parsed_spec is None:
                            text = r.get("text", "")
                            spec_candidate = None
                            try:
                                spec_candidate = json.loads(text)
                            except Exception:
                                # Try YAML if JSON fails
                                with contextlib.suppress(Exception):
                                    spec_candidate = yaml.safe_load(text)

                            if isinstance(spec_candidate, dict) and "paths" in spec_candidate:
                                paths_dict = spec_candidate["paths"]
                                if isinstance(paths_dict, dict):
                                    info = spec_candidate.get("info", {})
                                    info_title = None
                                    info_version = None
                                    if isinstance(info, dict):
                                        info_title = info.get("title")
                                        info_version = info.get("version")

                                    paths_methods = {}
                                    for p, path_item in paths_dict.items():
                                        if isinstance(path_item, dict):
                                            methods = [
                                                m.upper()
                                                for m in path_item
                                                if m.lower()
                                                in {
                                                    "get",
                                                    "post",
                                                    "put",
                                                    "delete",
                                                    "options",
                                                    "head",
                                                    "patch",
                                                    "trace",
                                                }
                                            ]
                                            paths_methods[p] = methods
                                        else:
                                            paths_methods[p] = ["GET"]

                                    parsed_spec = {
                                        "info": {
                                            "title": info_title,
                                            "version": info_version,
                                        },
                                        "paths": paths_methods,
                                    }
                                    spec_endpoints = list(paths_methods.keys())

        except httpx.HTTPError as exc:
            logger.warning("Probe client error for %s: %s", url, exc)
            errors.append(f"Probe error: {exc}")
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected probe error for %s", url)
            errors.append(f"Unexpected probe error: {exc}")

        return probed, errors, parsed_spec, spec_endpoints

    @staticmethod
    async def _probe_single(
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
    ) -> dict | None:
        """Probe a single path. Returns dict with request_dict and text, or None."""
        full_url = urljoin(base_url, path)
        try:
            resp = await client.get(full_url)

            # Only keep responses that look "real" (not generic 404 pages)
            if resp.status_code >= 400:
                return None

            content_type = resp.headers.get("content-type", "")
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            nr = NetworkRequest(
                url=full_url,
                method="GET",
                resource_type="probe",
                status=resp.status_code,
                content_type=content_type,
                request_headers={},
                response_headers=resp_headers,
            )
            return {
                "request_dict": _nr_to_dict(nr),
                "text": resp.text,
            }

        except (httpx.TimeoutException, httpx.ConnectError):
            return None
        except httpx.HTTPError:
            return None


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _nr_to_dict(nr: NetworkRequest) -> dict:
    """Serialise a frozen NetworkRequest to a plain dict.

    We store dicts in ``CollectorResult.data`` so the result is
    JSON-serialisable without a custom encoder.
    """
    return {
        "url": nr.url,
        "method": nr.method,
        "resource_type": nr.resource_type,
        "status": nr.status,
        "content_type": nr.content_type,
        "request_headers": nr.request_headers,
        "response_headers": nr.response_headers,
    }
