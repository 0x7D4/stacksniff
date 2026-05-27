"""Collect potential API endpoints from static JavaScript bundles and their source maps.

Downloads JS files discovered on the page, runs patterns to identify endpoints,
and inspects source maps if available.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx

from stacksniff.collectors.base import CollectorResult

logger = logging.getLogger(__name__)

# Regex patterns to search for API endpoints in JS bundles
_REGEX_PATTERNS = [
    re.compile(r'["\`](/api[^\s"\'`\>]{2,80})["\`]'),
    re.compile(r'["\`](/v\d+/[^\s"\'`\>]{2,80})["\`]'),
    re.compile(r'fetch\(["\`]([^"\'`]{5,100})["\`]'),
    re.compile(r'axios\.[a-z]+\(["\`]([^"\'`]{5,100})'),
    re.compile(r'["\`](https?://[^"\'` ]{5,100}/api[^"\'` ]{2,60})["\`]'),
    re.compile(r'(?:url|path|endpoint|route)\s*[:=]\s*["\`](/[a-zA-Z][^\s"\'`\>]{2,80})["\`]'),
]

# Source map mapping comment regex
_SOURCEMAP_REGEX = re.compile(r"(?://#|//@)\s*sourceMappingURL=(\S+)\s*$")

_DEFAULT_TIMEOUT: float = 30.0


class JsStaticCollector:
    """Collector that parses static JS files and their source maps for API endpoints.

    Parameters
    ----------
    script_srcs:
        List of ``<script src>`` values extracted from the page HTML.
    base_url:
        The target page URL.  Used to resolve relative script paths **and** to
        filter out absolute endpoint candidates that point to a different domain.
        Defaults to an empty string (no domain filtering).
    timeout:
        HTTP timeout in seconds for downloading JS files.
    """

    def __init__(
        self,
        script_srcs: list[str],
        *,
        base_url: str = "",
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self._script_srcs = script_srcs
        self._base_url = base_url
        self._timeout = timeout
        # Pre-parse target netloc once; empty string means "don't filter"
        try:
            self._target_netloc: str = urlparse(base_url).netloc.lower() if base_url else ""
        except Exception:
            self._target_netloc = ""

    async def collect(self, url: str) -> CollectorResult:
        """Download scripts, scan for routes, inspect source maps, return findings."""
        result = CollectorResult()
        endpoints: set[str] = set()

        # 1. Resolve relative URLs & Filter CDN domains
        resolved_urls = []
        for src in self._script_srcs:
            if not src:
                continue
            src = src.strip()
            # If already absolute (starts with http:// or https://)
            resolved_url = src if src.startswith(("http://", "https://")) else urljoin(url, src)

            try:
                parsed = urlparse(resolved_url)
                netloc = parsed.netloc.lower()
            except Exception:
                continue

            cdn_domains = [
                "googleapis.com",
                "cdn.jsdelivr.net",
                "unpkg.com",
                "cdnjs.cloudflare.com",
            ]
            if any(cdn in netloc for cdn in cdn_domains):
                continue

            resolved_urls.append(resolved_url)
            logger.debug("JsStaticCollector: queued script %s", resolved_url)

        # Limit to max 15 script files to balance coverage vs. scan time (Fix 3)
        resolved_urls = resolved_urls[:15]

        if not resolved_urls:
            result.data = {"static_endpoints": []}
            return result

        # 2. Download and scan concurrently
        async with httpx.AsyncClient(
            follow_redirects=True,
            verify=False,
            timeout=self._timeout,
        ) as client:
            tasks = [
                self._process_script(client, js_url, url, endpoints) for js_url in resolved_urls
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        # 3. Deduplicate and normalize endpoints
        normalized_endpoints: set[str] = set()
        target_netloc = self._target_netloc

        for ep in endpoints:
            if not ep:
                continue
            ep = ep.strip()

            if ep.startswith(("http://", "https://")):
                # Absolute URL: keep only if it matches the target domain
                # (or if we have no target domain configured).  Convert to
                # a root-relative path by stripping scheme + netloc.
                try:
                    ep_parsed = urlparse(ep)
                    ep_netloc = ep_parsed.netloc.lower()
                except Exception:
                    continue  # malformed — discard

                if target_netloc and not _is_first_party(ep_netloc, target_netloc):
                    # Different domain — discard (Fix 2)
                    logger.debug(
                        "JsStaticCollector: discarding cross-domain endpoint %s", ep
                    )
                    continue

                # Same domain (or no domain filter) → strip to relative path
                path = ep_parsed.path
                if ep_parsed.query:
                    path += f"?{ep_parsed.query}"
                if not path.startswith("/"):
                    path = f"/{path}"
                normalized_endpoints.add(path)

            elif ep.startswith("/") and not ep.startswith("//"):
                # Root-relative path — always keep as-is
                normalized_endpoints.add(ep)

            else:
                # Protocol-relative (//), data:, blob:, bare word, etc. — discard
                logger.debug(
                    "JsStaticCollector: discarding non-relative/non-http candidate %s", ep
                )

        result.data = {"static_endpoints": sorted(list(normalized_endpoints))}
        return result

    async def _process_script(
        self, client: httpx.AsyncClient, js_url: str, base_url: str, endpoints: set[str]
    ) -> None:
        """Download a single JS script, run regexes, and check for source maps."""
        try:
            response = await client.get(js_url)
            if response.status_code != 200:
                return
        except Exception as exc:
            logger.debug("Failed to download JS file from %s: %s", js_url, exc)
            return

        js_content = response.text

        # Run regex patterns over JS bundle content
        for pattern in _REGEX_PATTERNS:
            for match in pattern.findall(js_content):
                endpoints.add(match)

        # Check for source maps (headers first, then comments)
        source_map_url = None
        lower_headers = {k.lower(): v for k, v in response.headers.items()}
        x_sm = lower_headers.get("x-sourcemap")
        sm = lower_headers.get("sourcemap")

        if x_sm:
            source_map_url = x_sm
        elif sm:
            source_map_url = sm

        if not source_map_url:
            match = _SOURCEMAP_REGEX.search(js_content)
            if match:
                source_map_url = match.group(1).strip()

        if source_map_url:
            map_content = None
            if source_map_url.startswith("data:"):
                try:
                    if "base64," in source_map_url:
                        b64_part = source_map_url.split("base64,")[1]
                        map_content = base64.b64decode(b64_part).decode("utf-8", errors="ignore")
                except Exception as b64_exc:
                    logger.debug("Failed to decode inline source map: %s", b64_exc)
            else:
                map_resolved_url = urljoin(js_url, source_map_url)
                try:
                    map_res = await client.get(map_resolved_url)
                    if map_res.status_code == 200:
                        map_content = map_res.text
                except Exception as fetch_exc:
                    logger.debug(
                        "Failed to fetch source map from %s: %s", map_resolved_url, fetch_exc
                    )

            if map_content:
                try:
                    map_json = json.loads(map_content)
                    sources_content = map_json.get("sourcesContent", [])
                    if isinstance(sources_content, list):
                        for src_code in sources_content:
                            if isinstance(src_code, str):
                                for pattern in _REGEX_PATTERNS:
                                    for match in pattern.findall(src_code):
                                        endpoints.add(match)
                except Exception as json_exc:
                    logger.debug("Failed to parse source map JSON: %s", json_exc)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _get_apex_domain(host: str) -> str:
    host = host.lower().split(":")[0]
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return host
    if len(parts) >= 3:
        second_last = parts[-2]
        last = parts[-1]
        if len(second_last) <= 3 and len(last) == 2:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _is_first_party(host1: str, host2: str) -> bool:
    h1 = host1.lower().split(":")[0].removeprefix("www.")
    h2 = host2.lower().split(":")[0].removeprefix("www.")
    if h1 == h2:
        return True
    return _get_apex_domain(h1) == _get_apex_domain(h2)
