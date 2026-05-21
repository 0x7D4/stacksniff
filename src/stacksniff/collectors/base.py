"""Base protocols and shared data structures for all collectors.

Every collector in stacksniff implements the :class:`Collector` protocol so the
scanner can treat them uniformly.  The protocol is deliberately minimal —
a single ``collect`` async method that returns a :class:`CollectorResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Shared data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NetworkRequest:
    """A single network request captured from a browser session.

    Used by :class:`~stacksniff.collectors.network_collector.NetworkCollector`
    and fed into :class:`~stacksniff.analyzers.api_detector.ApiDetector`.
    """

    url: str
    method: str
    resource_type: str  # "xhr", "fetch", "script", "stylesheet", "document", …
    status: int | None = None
    content_type: str | None = None
    request_headers: dict[str, str] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class CollectorResult:
    """Uniform envelope returned by every collector.

    Parameters
    ----------
    data:
        Collector-specific payload.  The *scanner* knows which dict shape
        each collector produces.
    errors:
        Human-readable error strings accumulated during collection.
        An empty list signals a clean run; the presence of errors does
        **not** mean ``data`` is empty — partial results are encouraged.
    """

    data: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    # -- convenience helpers ------------------------------------------------

    @property
    def ok(self) -> bool:
        """Return ``True`` when no errors were recorded."""
        return len(self.errors) == 0

    def add_error(self, msg: str) -> None:
        """Append a non-fatal error message."""
        self.errors.append(msg)


# ---------------------------------------------------------------------------
# Collector protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class Collector(Protocol):
    """Structural protocol that all evidence collectors must satisfy.

    A collector is a thin, async adapter that fetches a single category
    of evidence (headers, cookies, HTML, JS globals, network traffic)
    from a target URL and returns a :class:`CollectorResult`.

    Implementations **must not raise** on transient network errors —
    instead they should catch exceptions, record an error string in
    :attr:`CollectorResult.errors`, and return whatever partial data
    they managed to gather.

    Usage::

        collector = HeaderCollector(timeout=15.0)
        result = await collector.collect("https://example.com")
        if result.ok:
            print(result.data)
        else:
            print("partial data with errors:", result.errors)
    """

    async def collect(self, url: str) -> CollectorResult:
        """Collect evidence from *url*.

        Parameters
        ----------
        url:
            Fully-qualified target URL (must include scheme).

        Returns
        -------
        CollectorResult
            Contains a collector-specific ``data`` dict and any
            non-fatal ``errors`` accumulated during the run.
        """
        ...  # pragma: no cover
