"""Collect HTTP response headers from a target URL.

Uses :mod:`httpx` with an async client to:

* Follow redirects (up to ``max_redirects`` hops)
* Capture **all** response headers at the final destination
* Capture intermediate ``Server`` / ``X-Powered-By`` headers seen
  during redirect hops (useful for detecting reverse-proxies)
* Normalise header names to **lowercase** for consistent matching

Returned ``data`` dict shape
----------------------------
.. code-block:: python

    {
        "headers":   {"server": "nginx/1.25", "content-type": "text/html", ...},
        "final_url": "https://www.example.com/",
        "status":    200,
        "redirect_chain": [
            {"url": "http://example.com/", "status": 301, "headers": {...}},
            ...
        ],
    }
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from stacksniff.collectors.base import CollectorResult

logger = logging.getLogger(__name__)

# Headers we specifically want to track across redirect hops because
# they frequently leak backend technology info.
_HOP_HEADERS_OF_INTEREST: frozenset[str] = frozenset(
    {
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-varnish",
        "x-cache",
        "via",
    }
)

# Default connect + read + pool timeout in seconds.
_DEFAULT_TIMEOUT: float = 20.0

# Maximum number of HTTP redirects to follow.
_MAX_REDIRECTS: int = 10


class HeaderCollector:
    """Async collector that extracts HTTP response headers.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds (applied to connect, read, and pool).
    max_redirects:
        Maximum redirect hops to follow before giving up.
    user_agent:
        ``User-Agent`` header sent with the request.
    """

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_redirects: int = _MAX_REDIRECTS,
        user_agent: str = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
    ) -> None:
        self._timeout = timeout
        self._max_redirects = max_redirects
        self._user_agent = user_agent

    # ------------------------------------------------------------------
    # Collector protocol
    # ------------------------------------------------------------------

    async def collect(self, url: str) -> CollectorResult:
        """Fetch *url* and return all HTTP response headers.

        On network / SSL / timeout errors the method does **not** raise;
        it returns partial results with the error recorded in
        :attr:`CollectorResult.errors`.
        """
        result = CollectorResult()
        redirect_chain: list[dict[str, Any]] = []

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

                # ---- capture redirect chain ---------------------------
                if response.history:
                    for hop in response.history:
                        hop_headers = _normalise_headers(hop.headers)
                        redirect_chain.append(
                            {
                                "url": str(hop.url),
                                "status": hop.status_code,
                                "headers": {
                                    k: v
                                    for k, v in hop_headers.items()
                                    if k in _HOP_HEADERS_OF_INTEREST
                                },
                            }
                        )

                # ---- final response -----------------------------------
                final_headers = _normalise_headers(response.headers)

                result.data = {
                    "headers": final_headers,
                    "final_url": str(response.url),
                    "status": response.status_code,
                    "redirect_chain": redirect_chain,
                }

                if response.status_code >= 400:
                    result.add_error(f"HTTP {response.status_code} from {response.url}")

        except httpx.TimeoutException as exc:
            logger.warning("Timeout collecting headers from %s: %s", url, exc)
            result.add_error(f"Timeout: {exc}")

        except httpx.ConnectError as exc:
            logger.warning("Connection error for %s: %s", url, exc)
            result.add_error(f"Connection error: {exc}")

        except httpx.TooManyRedirects as exc:
            logger.warning("Too many redirects for %s: %s", url, exc)
            result.add_error(f"Too many redirects: {exc}")
            # Still include whatever redirect chain we captured so far.
            if redirect_chain:
                result.data["redirect_chain"] = redirect_chain

        except httpx.HTTPError as exc:
            # Catch-all for any other httpx errors (includes SSL via
            # httpx.ConnectError for certificate issues on modern httpx).
            logger.warning("HTTP error collecting headers from %s: %s", url, exc)
            result.add_error(f"HTTP error: {exc}")

        except Exception as exc:  # noqa: BLE001 — intentional broad catch
            logger.exception("Unexpected error collecting headers from %s", url)
            result.add_error(f"Unexpected error: {exc}")

        return result


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _normalise_headers(headers: httpx.Headers) -> dict[str, str]:
    """Return headers as a plain ``dict`` with **lowercase** keys.

    ``httpx.Headers`` is already case-insensitive, but downstream
    matchers work on plain dicts so we normalise explicitly.  When
    multiple values exist for the same header name they are joined
    with ``, `` (per RFC 7230 §3.2.2).
    """
    merged: dict[str, str] = {}
    for name, value in headers.multi_items():
        key = name.lower()
        if key in merged:
            merged[key] = f"{merged[key]}, {value}"
        else:
            merged[key] = value
    return merged
