"""Collect cookies set by a target URL.

Uses :mod:`httpx` to issue a GET request (following redirects) and
extracts every cookie from the jar that the server set via
``Set-Cookie`` headers — including cookies set during intermediate
redirect hops.

Returned ``data`` dict shape::

    {
        "cookies": {"PHPSESSID": "abc123", "_cfuid": "d…"},
        "raw_set_cookie_headers": [
            "PHPSESSID=abc123; path=/; HttpOnly",
            "__cf_bm=xyz; path=/; Secure; SameSite=None",
        ],
        "final_url": "https://www.example.com/",
    }
"""

from __future__ import annotations

import logging

import httpx

from stacksniff.collectors.base import DEFAULT_USER_AGENT, CollectorResult

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT: float = 20.0
_MAX_REDIRECTS: int = 10


class CookieCollector:
    """Async collector that harvests cookies from HTTP responses.

    Parameters
    ----------
    timeout:
        Per-request timeout in seconds.
    max_redirects:
        Maximum redirect hops to follow.
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
        """Fetch *url* and return all cookies set by the server.

        Never raises on transient network / SSL / timeout errors —
        returns partial results with the error recorded.
        """
        result = CollectorResult()

        transport = httpx.AsyncHTTPTransport(retries=1)
        client_kwargs = {
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

                # Extract cookies from jar (includes all hops)
                cookies: dict[str, str] = {}
                for name, value in client.cookies.items():
                    cookies[name] = value

                # Also pick up cookies from the final response
                for name, value in response.cookies.items():
                    cookies.setdefault(name, value)

                # Collect raw Set-Cookie headers from entire chain
                raw_set_cookies = _collect_raw_set_cookies(response)

                result.data = {
                    "cookies": cookies,
                    "raw_set_cookie_headers": raw_set_cookies,
                    "final_url": str(response.url),
                }

                if response.status_code >= 400:
                    result.add_error(f"HTTP {response.status_code} from {response.url}")

        except httpx.TimeoutException as exc:
            logger.warning("Timeout collecting cookies from %s: %s", url, exc)
            result.add_error(f"Timeout: {exc}")

        except httpx.ConnectError as exc:
            logger.warning("Connection error for %s: %s", url, exc)
            result.add_error(f"Connection error: {exc}")

        except httpx.TooManyRedirects as exc:
            logger.warning("Too many redirects for %s: %s", url, exc)
            result.add_error(f"Too many redirects: {exc}")

        except httpx.HTTPError as exc:
            logger.warning("HTTP error collecting cookies: %s: %s", url, exc)
            result.add_error(f"HTTP error: {exc}")

        except Exception as exc:  # noqa: BLE001
            logger.exception("Unexpected error collecting cookies from %s", url)
            result.add_error(f"Unexpected error: {exc}")

        return result


def _collect_raw_set_cookies(response: httpx.Response) -> list[str]:
    """Gather all Set-Cookie header values from the redirect chain + final."""
    raw: list[str] = []
    for hop in response.history:
        raw.extend(hop.headers.get_list("set-cookie"))
    raw.extend(response.headers.get_list("set-cookie"))
    return raw
