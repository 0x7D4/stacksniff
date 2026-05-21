"""Detect exposed API endpoints from network traffic and probed paths."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from stacksniff.models import DetectedEndpoint

logger = logging.getLogger(__name__)

# Pattern regexes mapped to category names
_API_PATTERNS = {
    re.compile(r"/api/v\d", re.IGNORECASE): "REST API (Versioned)",
    re.compile(r"/api/", re.IGNORECASE): "REST API",
    re.compile(r"/rest/", re.IGNORECASE): "REST API",
    re.compile(r"/wp-json/", re.IGNORECASE): "WordPress REST API",
    re.compile(r"/__admin/", re.IGNORECASE): "Admin Endpoint",
    re.compile(r"/graphql", re.IGNORECASE): "GraphQL Endpoint",
    re.compile(r"/gql", re.IGNORECASE): "GraphQL Endpoint",
    re.compile(r"/rpc", re.IGNORECASE): "RPC Endpoint",
    re.compile(r"/trpc", re.IGNORECASE): "tRPC Endpoint",
}

# Mapping of probed paths to descriptions
_PROBE_MAP = {
    "/robots.txt": "Robots Configuration",
    "/sitemap.xml": "Sitemap Index",
    "/api-docs": "API Documentation",
    "/openapi.json": "OpenAPI Specification",
    "/swagger.json": "Swagger UI / Spec",
    "/graphql": "GraphQL Endpoint",
    "/.well-known/security.txt": "Security Contact Info",
}


def _normalize_path(url_str: str) -> str:
    """Extract and normalize the absolute path from a URL."""
    try:
        parsed = urlparse(url_str)
        path = parsed.path
        # Clean double slashes
        while "//" in path:
            path = path.replace("//", "/")
        # Strip trailing slash except if path is just "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        return path or "/"
    except Exception:
        return url_str


class ApiDetector:
    """Detects exposed API endpoints from browser requests and probed paths."""

    def detect(self, evidence_data: Any) -> list[DetectedEndpoint]:
        """Analyze network traffic and path probes to find API endpoints.

        Parameters
        ----------
        evidence_data:
            The raw evidence (dict, list, or CollectedEvidence object) containing:
            - network_requests
            - probed_paths

        Returns
        -------
        list[DetectedEndpoint]
            Deduplicated list of detected API endpoints.
        """
        raw_requests: list[Any] = []
        raw_probes: list[Any] = []
        static_endpoints: list[str] = []
        spec_endpoints: list[str] = []
        spec_methods: dict[str, list[str]] = {}

        if hasattr(evidence_data, "network_requests"):
            raw_requests = getattr(evidence_data, "network_requests", []) or []
            raw_probes = getattr(evidence_data, "probed_paths", []) or []
            static_endpoints = getattr(evidence_data, "static_endpoints", []) or []
            spec_endpoints = getattr(evidence_data, "spec_endpoints", []) or []
            spec_methods = getattr(evidence_data, "spec_methods", {}) or {}
        elif isinstance(evidence_data, dict):
            raw_requests = evidence_data.get("network_requests", []) or []
            raw_probes = evidence_data.get("probed_paths", []) or []
            static_endpoints = evidence_data.get("static_endpoints", []) or []
            spec_endpoints = evidence_data.get("spec_endpoints", []) or []
            spec_methods = evidence_data.get("spec_methods", {}) or {}
        elif isinstance(evidence_data, list):
            for item in evidence_data:
                res_type = ""
                if isinstance(item, dict):
                    res_type = item.get("resource_type", "")
                elif hasattr(item, "resource_type"):
                    res_type = getattr(item, "resource_type", "")

                if res_type == "probe":
                    raw_probes.append(item)
                else:
                    raw_requests.append(item)

        detected_map: dict[str, DetectedEndpoint] = {}

        # 0. Process OpenAPI Spec Endpoints first
        for ep in spec_endpoints:
            if not isinstance(ep, str):
                continue
            path = _normalize_path(ep)
            methods = spec_methods.get(ep, [])
            method = methods[0] if methods else "GET"

            endpoint = DetectedEndpoint(
                url=path,
                method=method,
                content_type=None,
                pattern_matched="OpenAPI spec",
                confidence=1.0,
            )
            detected_map[path] = endpoint

        # 1. Process Browser Network Requests
        for req in raw_requests:
            if isinstance(req, dict):
                url = req.get("url", "")
                method = req.get("method", "GET")
                content_type = req.get("content_type")
            elif req is not None:
                url = getattr(req, "url", "")
                method = getattr(req, "method", "GET")
                content_type = getattr(req, "content_type", None)
            else:
                continue

            # Match path against API patterns
            matched_pattern = None
            for rx, label in _API_PATTERNS.items():
                if rx.search(url):
                    matched_pattern = label
                    break

            if matched_pattern:
                path = _normalize_path(url)
                confidence = 0.7

                # Content-type application/json or application/graphql -> boost confidence
                if content_type:
                    ct_lower = content_type.lower()
                    if "application/json" in ct_lower or "application/graphql" in ct_lower:
                        confidence += 0.1

                endpoint = DetectedEndpoint(
                    url=path,
                    method=method,
                    content_type=content_type,
                    pattern_matched=matched_pattern,
                    confidence=round(min(confidence, 1.0), 2),
                )

                # Keep highest confidence match for this normalized path
                existing = detected_map.get(path)
                if not existing or endpoint.confidence > existing.confidence:
                    detected_map[path] = endpoint

        # 2. Process Probed Paths (if they returned status 200)
        for probe in raw_probes:
            if isinstance(probe, dict):
                url = probe.get("url", "")
                status = probe.get("status")
                method = probe.get("method", "GET")
                content_type = probe.get("content_type")
            elif probe is not None:
                url = getattr(probe, "url", "")
                status = getattr(probe, "status", None)
                method = getattr(probe, "method", "GET")
                content_type = getattr(probe, "content_type", None)
            else:
                continue

            # Only include probed paths that returned success (status 200)
            if status != 200:
                continue

            path = _normalize_path(url)

            # Determine matching label
            matched_pattern = None
            for path_suffix, label in _PROBE_MAP.items():
                if path.endswith(path_suffix):
                    matched_pattern = label
                    break

            # Fallback label
            if not matched_pattern:
                matched_pattern = "Probed API Endpoint"

            confidence = 0.8
            if content_type:
                ct_lower = content_type.lower()
                if "application/json" in ct_lower or "application/graphql" in ct_lower:
                    confidence += 0.1

            endpoint = DetectedEndpoint(
                url=path,
                method=method,
                content_type=content_type,
                pattern_matched=matched_pattern,
                confidence=round(min(confidence, 1.0), 2),
            )

            # Keep highest confidence match for this normalized path
            existing = detected_map.get(path)
            if not existing or endpoint.confidence > existing.confidence:
                detected_map[path] = endpoint

        # 3. Process Static Endpoints
        for ep in static_endpoints:
            if not isinstance(ep, str):
                continue
            matched_pattern = None
            for rx, label in _API_PATTERNS.items():
                if rx.search(ep):
                    matched_pattern = label
                    break

            if matched_pattern:
                path = _normalize_path(ep)
                endpoint = DetectedEndpoint(
                    url=path,
                    method="GET",
                    content_type=None,
                    pattern_matched=matched_pattern,
                    confidence=0.65,
                )
                existing = detected_map.get(path)
                if not existing or endpoint.confidence > existing.confidence:
                    detected_map[path] = endpoint

        return list(detected_map.values())
