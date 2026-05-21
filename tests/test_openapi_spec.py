"""Unit tests for OpenAPI spec probing and parsing."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from stacksniff.analyzers.api_detector import ApiDetector
from stacksniff.collectors.network_collector import NetworkCollector
from stacksniff.models import CollectedEvidence

# Mock OpenAPI specification
VALID_OPENAPI_JSON = """{
  "openapi": "3.0.0",
  "info": {
    "title": "Test API",
    "version": "1.2.3"
  },
  "paths": {
    "/api/users": {
      "get": {},
      "post": {}
    },
    "/api/items": {
      "put": {}
    },
    "/api/no-methods": {}
  }
}"""

VALID_OPENAPI_YAML = """
openapi: 3.0.0
info:
  title: Test YAML API
  version: 0.1.0
paths:
  /api/books:
    get: {}
  /api/authors:
    post: {}
"""

INVALID_OPENAPI_JSON = "{invalid_json: true,"


@pytest.mark.asyncio
async def test_network_collector_openapi_parsing():
    async def mock_get(url: str, *args, **kwargs) -> httpx.Response:
        url_str = str(url)
        req = httpx.Request("GET", url_str)
        if "openapi.json" in url_str:
            return httpx.Response(
                200,
                request=req,
                text=VALID_OPENAPI_JSON,
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(404, request=req)

    collector = NetworkCollector(timeout=10.0)
    with (
        patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_client_get,
        patch.object(collector, "_collect_browser", return_value=([], [], [])),
    ):
        mock_client_get.side_effect = mock_get
        result = await collector.collect("https://example.com")

    assert not result.errors
    assert result.data["parsed_spec"] is not None
    assert result.data["parsed_spec"]["info"]["title"] == "Test API"
    assert result.data["parsed_spec"]["info"]["version"] == "1.2.3"

    spec_endpoints = result.data["spec_endpoints"]
    assert "/api/users" in spec_endpoints
    assert "/api/items" in spec_endpoints
    assert "/api/no-methods" in spec_endpoints


@pytest.mark.asyncio
async def test_network_collector_openapi_yaml_parsing():
    async def mock_get(url: str, *args, **kwargs) -> httpx.Response:
        url_str = str(url)
        req = httpx.Request("GET", url_str)
        if "swagger.yaml" in url_str:
            return httpx.Response(
                200,
                request=req,
                text=VALID_OPENAPI_YAML,
                headers={"Content-Type": "application/yaml"},
            )
        return httpx.Response(404, request=req)

    collector = NetworkCollector(timeout=10.0)
    with (
        patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_client_get,
        patch.object(collector, "_collect_browser", return_value=([], [], [])),
    ):
        mock_client_get.side_effect = mock_get
        result = await collector.collect("https://example.com")

    assert not result.errors
    assert result.data["parsed_spec"] is not None
    assert result.data["parsed_spec"]["info"]["title"] == "Test YAML API"

    spec_endpoints = result.data["spec_endpoints"]
    assert "/api/books" in spec_endpoints
    assert "/api/authors" in spec_endpoints


@pytest.mark.asyncio
async def test_network_collector_invalid_spec_graceful():
    async def mock_get(url: str, *args, **kwargs) -> httpx.Response:
        url_str = str(url)
        req = httpx.Request("GET", url_str)
        if "openapi.json" in url_str:
            return httpx.Response(
                200,
                request=req,
                text=INVALID_OPENAPI_JSON,
                headers={"Content-Type": "application/json"},
            )
        return httpx.Response(404, request=req)

    collector = NetworkCollector(timeout=10.0)
    with (
        patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_client_get,
        patch.object(collector, "_collect_browser", return_value=([], [], [])),
    ):
        mock_client_get.side_effect = mock_get
        result = await collector.collect("https://example.com")

    # Should not crash, and parsed_spec should be None
    assert not result.errors
    assert result.data["parsed_spec"] is None
    assert result.data["spec_endpoints"] == []


def test_api_detector_openapi_endpoints():
    evidence = CollectedEvidence(
        spec_endpoints=["/api/users", "/api/items", "/api/no-methods"],
        spec_methods={"/api/users": ["GET", "POST"], "/api/items": ["PUT"], "/api/no-methods": []},
    )
    detector = ApiDetector()
    endpoints = detector.detect(evidence)

    # All three endpoints detected
    assert len(endpoints) == 3

    # Check details
    endpoint_map = {ep.url: ep for ep in endpoints}

    # Methods matched correctly
    assert endpoint_map["/api/users"].method == "GET"  # first method
    assert endpoint_map["/api/items"].method == "PUT"
    assert endpoint_map["/api/no-methods"].method == "GET"  # fallback

    # Confidence and label
    for ep in endpoints:
        assert ep.confidence == 1.0
        assert ep.pattern_matched == "OpenAPI spec"
