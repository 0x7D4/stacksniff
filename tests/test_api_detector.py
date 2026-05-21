"""Unit tests for the ApiDetector."""

from __future__ import annotations

from stacksniff.analyzers.api_detector import ApiDetector


def test_api_detector_patterns() -> None:
    """Test matching typical endpoint URL patterns with content-type boosts."""
    detector = ApiDetector()

    evidence = {
        "network_requests": [
            # Matches /api/ -> base 0.7. Content-type json -> +0.1 -> 0.8
            {
                "url": "https://example.com/api/users",
                "method": "GET",
                "content_type": "application/json; charset=utf-8",
            },
            # Matches /graphql -> base 0.7. No content-type boost -> 0.7
            {
                "url": "https://example.com/graphql",
                "method": "POST",
                "content_type": "text/plain",
            },
            # Matches /api/v\\d -> base 0.7. Content-type graphql -> +0.1 -> 0.8
            {
                "url": "https://example.com/api/v2/items",
                "method": "GET",
                "content_type": "application/graphql",
            },
            # Non-matching pattern -> skipped
            {
                "url": "https://example.com/assets/app.js",
                "method": "GET",
                "content_type": "application/javascript",
            },
        ]
    }

    endpoints = detector.detect(evidence)
    assert len(endpoints) == 3

    users_endpoint = next((e for e in endpoints if e.url == "/api/users"), None)
    assert users_endpoint is not None
    assert users_endpoint.confidence == 0.8
    assert users_endpoint.pattern_matched == "REST API"

    graphql_endpoint = next((e for e in endpoints if e.url == "/graphql"), None)
    assert graphql_endpoint is not None
    assert graphql_endpoint.confidence == 0.7
    assert graphql_endpoint.pattern_matched == "GraphQL Endpoint"

    items_endpoint = next((e for e in endpoints if e.url == "/api/v2/items"), None)
    assert items_endpoint is not None
    assert items_endpoint.confidence == 0.8
    assert items_endpoint.pattern_matched == "REST API (Versioned)"


def test_api_detector_probes() -> None:
    """Test handling of probed paths with status code filtering."""
    detector = ApiDetector()

    evidence = {
        "probed_paths": [
            # Successful probe -> Included (base 0.8)
            {
                "url": "https://example.com/robots.txt",
                "method": "GET",
                "status": 200,
                "content_type": "text/plain",
            },
            # Unsuccessful probe (404) -> Excluded
            {
                "url": "https://example.com/openapi.json",
                "method": "GET",
                "status": 404,
                "content_type": "application/json",
            },
            # Successful json probe -> base 0.8 + 0.1 ct boost -> 0.9
            {
                "url": "https://example.com/swagger.json",
                "method": "GET",
                "status": 200,
                "content_type": "application/json",
            },
        ]
    }

    endpoints = detector.detect(evidence)
    assert len(endpoints) == 2

    robots = next((e for e in endpoints if e.url == "/robots.txt"), None)
    assert robots is not None
    assert robots.confidence == 0.8
    assert robots.pattern_matched == "Robots Configuration"

    swagger = next((e for e in endpoints if e.url == "/swagger.json"), None)
    assert swagger is not None
    assert swagger.confidence == 0.9
    assert swagger.pattern_matched == "Swagger UI / Spec"


def test_api_detector_deduplication() -> None:
    """Test normalized path deduplication prioritizing higher confidence."""
    detector = ApiDetector()

    evidence = {
        "network_requests": [
            # Same path: "/api/users" with different query string/trailing slash,
            # different methods/confidence
            {
                "url": "https://example.com/api/users/",
                "method": "GET",
                "content_type": "text/plain",  # confidence 0.7
            },
            {
                "url": "https://example.com/api/users?id=1",
                "method": "POST",
                "content_type": "application/json",  # confidence 0.8
            },
        ]
    }

    endpoints = detector.detect(evidence)
    assert len(endpoints) == 1
    assert endpoints[0].url == "/api/users"
    assert endpoints[0].confidence == 0.8
    assert endpoints[0].method == "POST"


def test_api_detector_static_endpoints() -> None:
    """Test ApiDetector parses static_endpoints with 0.65 confidence and respects deduplication."""
    detector = ApiDetector()

    evidence = {
        "network_requests": [
            {
                "url": "https://example.com/api/v1/active",
                "method": "GET",
                "content_type": "text/plain",  # confidence 0.7
            }
        ],
        "static_endpoints": [
            "/api/v1/active",  # Duplicate: active wins (0.7 > 0.65)
            "/api/v2/static",  # New endpoint, matches REST API (Versioned) -> 0.65 confidence
            "https://example.com/graphql",  # Matches GraphQL Endpoint -> 0.65 confidence
            "/not-an-api-route",  # Doesn't match pattern -> ignored
        ],
    }

    endpoints = detector.detect(evidence)
    assert len(endpoints) == 3

    # Check /api/v1/active has confidence 0.7 (active request wins over static)
    active_ep = next((e for e in endpoints if e.url == "/api/v1/active"), None)
    assert active_ep is not None
    assert active_ep.confidence == 0.7
    assert active_ep.pattern_matched == "REST API (Versioned)"

    # Check /api/v2/static has confidence 0.65
    static_ep = next((e for e in endpoints if e.url == "/api/v2/static"), None)
    assert static_ep is not None
    assert static_ep.confidence == 0.65
    assert static_ep.pattern_matched == "REST API (Versioned)"

    # Check /graphql has confidence 0.65
    graphql_ep = next((e for e in endpoints if e.url == "/graphql"), None)
    assert graphql_ep is not None
    assert graphql_ep.confidence == 0.65
    assert graphql_ep.pattern_matched == "GraphQL Endpoint"
