"""Collect HTML-level evidence from a target URL.

Uses :mod:`httpx` to fetch the page HTML and :mod:`bs4` (BeautifulSoup4)
to parse it.  Extracts structured evidence that the fingerprint matcher
can test against.

Returned ``data`` dict shape
----------------------------
::

    {
        "meta_tags":       {"generator": "WordPress 6.5", "viewport": "..."},
        "script_srcs":     ["https://cdn.example.com/app.js", ...],
        "link_hrefs":      ["https://example.com/style.css", ...],
        "inline_scripts":  ["var defined = true; ...", ...],
        "html_comments":   ["<!-- powered by Varnish -->", ...],
        "data_attributes": {"theme": "flavor-dark", ...},
        "raw_html":        "<!doctype html>...",
        "final_url":       "https://www.example.com/",
    }
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx
from bs4 import BeautifulSoup, Comment

from stacksniff.collectors.base import DEFAULT_USER_AGENT, CollectorResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT: float = 20.0
_MAX_REDIRECTS: int = 10
# Cap inline script content to avoid storing megabytes of bundled JS.
_INLINE_SCRIPT_MAX_LEN: int = 2_000
# Cap raw HTML stored in result (we only need enough for regex matching).
_RAW_HTML_MAX_LEN: int = 200_000


class HtmlCollector:
    """Async collector that parses HTML for technology fingerprints.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds.
    max_redirects:
        Maximum redirect hops.
    user_agent:
        ``User-Agent`` header value.
    """

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_redirects: int = _MAX_REDIRECTS,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._user_agent = user_agent

    async def collect(self, url: str) -> CollectorResult:
        """Fetch *url*, parse its HTML, and return structured evidence."""
        result = CollectorResult()

        transport = httpx.AsyncHTTPTransport(retries=1)
        client_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(self._timeout),
            "follow_redirects": True,
            "max_redirects": self._max_redirects,
            "transport": transport,
            "headers": {"User-Agent": self._user_agent},
            "verify": True,
        }

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                response = await client.get(url)

                if response.status_code >= 400:
                    result.add_error(f"HTTP {response.status_code} from {response.url}")

                raw_html = response.text
                soup = BeautifulSoup(raw_html, "html.parser")

                # Get the set of DOM selectors we need to check
                try:
                    from stacksniff.fingerprints import FingerprintStore
                    store = FingerprintStore.default()
                    selectors = store.get_all_dom_selectors()
                except Exception:
                    selectors = set()

                result.data = {
                    "meta_tags": _extract_meta_tags(soup),
                    "script_srcs": _extract_script_srcs(soup),
                    "link_hrefs": _extract_link_hrefs(soup),
                    "inline_scripts": _extract_inline_scripts(soup),
                    "html_comments": _extract_comments(soup),
                    "data_attributes": _extract_data_attributes(soup),
                    "dom": _extract_dom_evidence(soup, selectors),
                    "raw_html": raw_html[:_RAW_HTML_MAX_LEN],
                    "final_url": str(response.url),
                    "manifest_url": _extract_manifest_url(soup),
                }

        except httpx.TimeoutException as exc:
            logger.warning("Timeout collecting HTML from %s: %s", url, exc)
            result.add_error(f"Timeout: {exc}")

        except httpx.ConnectError as exc:
            logger.warning("Connection error for %s: %s", url, exc)
            result.add_error(f"Connection error: {exc}")

        except httpx.TooManyRedirects as exc:
            logger.warning("Too many redirects for %s: %s", url, exc)
            result.add_error(f"Too many redirects: {exc}")

        except httpx.HTTPError as exc:
            logger.warning("HTTP error collecting HTML from %s: %s", url, exc)
            result.add_error(f"HTTP error: {exc}")

        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error collecting HTML from %s", url)
            result.add_error(f"Unexpected error: {exc}")

        return result


# ------------------------------------------------------------------
# Extraction helpers
# ------------------------------------------------------------------


def _extract_meta_tags(soup: BeautifulSoup) -> dict[str, str]:
    """Extract ``<meta>`` tags into a ``{name_or_property: content}`` dict.

    Handles both ``<meta name="..." content="...">`` and
    ``<meta property="og:..." content="...">``.
    """
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        content = tag.get("content")
        if key and content:
            meta[key.lower()] = content
    return meta


def _extract_script_srcs(soup: BeautifulSoup) -> list[str]:
    """Return a list of ``src`` URLs from all ``<script>`` tags."""
    srcs: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if isinstance(src, list):
            src = src[0]
        if src:
            srcs.append(src.strip())
    return srcs


def _extract_link_hrefs(soup: BeautifulSoup) -> list[str]:
    """Return ``href`` values from ``<link>`` tags (stylesheets, icons, etc.)."""
    hrefs: list[str] = []
    for tag in soup.find_all("link", href=True):
        href = tag["href"]
        if isinstance(href, list):
            href = href[0]
        if href:
            hrefs.append(href.strip())
    return hrefs


def _extract_inline_scripts(soup: BeautifulSoup) -> list[str]:
    """Return truncated text content of inline ``<script>`` blocks.

    Only non-empty, non-src scripts are included.  Each block is
    capped at :data:`_INLINE_SCRIPT_MAX_LEN` characters to keep
    memory usage reasonable.
    """
    scripts: list[str] = []
    for tag in soup.find_all("script", src=False):
        text = tag.string or tag.get_text()
        text = text.strip()
        if text:
            scripts.append(text[:_INLINE_SCRIPT_MAX_LEN])
    return scripts


def _extract_comments(soup: BeautifulSoup) -> list[str]:
    """Extract HTML comments (e.g. ``<!-- Powered by Varnish -->``)."""
    comments: list[str] = []
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = comment.strip()
        if text:
            comments.append(text)
    return comments


_DATA_ATTR_RE = re.compile(r"^data-")


def _extract_data_attributes(soup: BeautifulSoup) -> dict[str, str]:
    """Extract ``data-*`` attributes from ``<html>`` and ``<body>`` tags.

    These often contain theme names, framework identifiers, or feature
    flags (e.g. ``<body data-rsssl="1">`` for Really Simple SSL).
    """
    attrs: dict[str, str] = {}
    for tag_name in ("html", "body"):
        tag = soup.find(tag_name)
        if tag is None:
            continue
        for attr_name, attr_val in tag.attrs.items():
            if _DATA_ATTR_RE.match(attr_name):
                if isinstance(attr_val, list):
                    attr_val = " ".join(attr_val)
                attrs[attr_name] = str(attr_val)
    return attrs


def _extract_dom_evidence(soup: BeautifulSoup, selectors: set[str]) -> dict[str, list[dict[str, Any]]]:
    """Extract information for specified DOM CSS selectors."""
    dom_findings: dict[str, list[dict[str, Any]]] = {}
    for sel in selectors:
        try:
            elements = soup.select(sel)
            if elements:
                findings = []
                for el in elements:
                    attrs = {}
                    for k, v in el.attrs.items():
                        if isinstance(v, list):
                            attrs[k] = " ".join(v)
                        else:
                            attrs[k] = str(v)
                    findings.append({
                        "text": el.get_text(strip=True),
                        "attributes": attrs,
                        "properties": attrs,  # Fall back to attributes statically
                    })
                dom_findings[sel] = findings
        except Exception:
            # BeautifulSoup select might throw syntax error on some selectors
            pass
    return dom_findings


def _extract_manifest_url(soup: BeautifulSoup) -> str | None:
    """Return the ``href`` of the first ``<link rel="manifest">`` tag, or ``None``.

    PWA fingerprinting relies on the presence of a Web App Manifest link.
    Extracting it separately ensures it is available even when DOM selector
    extraction is skipped or the CSS selector form differs from what
    BeautifulSoup supports.
    """
    tag = soup.find("link", rel=lambda r: isinstance(r, list) and "manifest" in r
                                          or r == "manifest")
    if tag is None:
        return None
    href = tag.get("href")
    if isinstance(href, list):
        href = href[0] if href else None
    return str(href).strip() if href else None
