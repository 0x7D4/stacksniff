"""Data models for stacksniff.

Contains frozen dataclasses for scan results, matches, evidence, and detected endpoints.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime  # noqa: TC003
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from stacksniff.collectors.base import NetworkRequest


@dataclass(frozen=True, slots=True)
class Evidence:
    """A single piece of corroborating evidence for a technology detection."""

    source: str  # "header", "cookie", "meta", "script", "js_global", "html", "dom"
    key: str  # e.g., "Server", "PHPSESSID", "generator", or custom identifiers
    matched: str  # the actual value that triggered the match
    pattern: str  # the regex/pattern that matched


@dataclass(frozen=True, slots=True)
class TechMatch:
    """A matched technology with category, version, and confidence information."""

    name: str
    category: str
    version: str | None
    confidence: float  # 0.0 to 1.0
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DetectedEndpoint:
    """An exposed API endpoint detected during collection."""

    url: str
    method: str
    content_type: str | None
    pattern_matched: str  # e.g., "REST /api/v*", "GraphQL"
    confidence: float


@dataclass(frozen=True, slots=True)
class ScanMeta:
    """Metadata about a single scan run."""

    duration_seconds: float
    phases_completed: list[str]  # ["http", "browser"]
    fingerprints_version: str
    rules_count: int


@dataclass(frozen=True, slots=True)
class ScanResult:
    """The final completed scan report."""

    url: str
    scan_time: datetime
    technologies: list[TechMatch]
    api_endpoints: list[DetectedEndpoint]
    meta: ScanMeta
    openapi_spec_found: bool = field(default=False)
    external_dependencies: list[dict[str, Any]] = field(default_factory=list)
    internal_subdomains: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert the ScanResult to a JSON-serializable dictionary."""
        # Custom serialisation to handle datetime
        data = asdict(self)
        data["scan_time"] = self.scan_time.isoformat()
        return data

    def to_json(self, indent: int = 2) -> str:
        """Convert the ScanResult to a JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


@dataclass(slots=True)
class CollectedEvidence:
    """Raw evidence gathered from all collectors."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    html: str = ""
    meta_tags: dict[str, str] = field(default_factory=dict)
    script_srcs: list[str] = field(default_factory=list)
    link_hrefs: list[str] = field(default_factory=list)
    js_globals: dict[str, str] = field(default_factory=dict)
    dom: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    network_requests: list[NetworkRequest] = field(default_factory=list)
    probed_paths: list[NetworkRequest] = field(default_factory=list)
    static_endpoints: list[str] = field(default_factory=list)
    spec_endpoints: list[str] = field(default_factory=list)
    spec_title: str | None = None
    spec_version: str | None = None
    spec_methods: dict[str, list[str]] = field(default_factory=dict)
    framework_endpoints: list[dict[str, Any]] = field(default_factory=list)
    external_dependencies: list[dict[str, Any]] = field(default_factory=list)
    internal_subdomains: list[dict[str, Any]] = field(default_factory=list)
