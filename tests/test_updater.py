"""Unit tests for the live fingerprints updater module."""

from __future__ import annotations

from pathlib import Path  # noqa: TC003
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import yaml
from typer.testing import CliRunner

from stacksniff.cli import app
from stacksniff.fingerprints import FingerprintStore
from stacksniff.updater import fetch_and_convert


@pytest.fixture
def mock_wappalyzer_http() -> Any:
    """Fixture to mock Wappalyzer raw github responses."""

    def mock_get(url: str, *args: Any, **kwargs: Any) -> httpx.Response:
        url_str = str(url)
        req = httpx.Request("GET", url_str)
        if "categories.json" in url_str:
            return httpx.Response(
                200,
                request=req,
                json={
                    "1": {"name": "CMS"},
                    "12": {"name": "JavaScript libraries"},
                    "19": {"name": "Web servers"},
                    "41": {"name": "Payment processors"},
                    "67": {"name": "Live chat"},
                },
            )
        elif "a.json" in url_str:
            # Contains rule with custom confidence suffix
            return httpx.Response(
                200,
                request=req,
                json={
                    "a-blog cms": {
                        "cats": [1],
                        "website": "https://a-blogcms.jp",
                        "meta": {"generator": "a-blog cms\\;confidence:80"},
                        "implies": ["PHP\\;confidence:50"],
                    }
                },
            )
        elif "b.json" in url_str:
            # Contains rule with version suffix
            return httpx.Response(
                200,
                request=req,
                json={
                    "Backbone.js": {
                        "cats": [12],
                        "website": "https://backbonejs.org",
                        "js": {"Backbone": "([\\d.]+)\\;version:\\1"},
                    }
                },
            )
        elif "p.json" in url_str:
            # Contains a payment processor — non-standard category, must NOT collapse to 'other'
            return httpx.Response(
                200,
                request=req,
                json={
                    "PayPal": {
                        "cats": [41],
                        "website": "https://paypal.com",
                        "js": {"paypal": "."},
                    }
                },
            )
        else:
            # Return empty rules dict for other character files
            return httpx.Response(200, request=req, json={})

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get_mock:
        mock_get_mock.side_effect = mock_get
        yield mock_get_mock


@pytest.mark.asyncio
async def test_fetch_and_convert_success(mock_wappalyzer_http: AsyncMock, tmp_path: Path) -> None:
    """Test standard fetch, convert, and merge behavior of updater."""
    target_yaml = tmp_path / "tech.yaml"

    # Pre-populate custom rules file to verify merge logic
    initial_data = {
        "version": "1.0.0",
        "categories": {},
        "technologies": {
            "backbone.js": {
                "name": "Custom Backbone",
                "category": "js-library",
                "confidence": 0.99,
            },
            "my-unique-tech": {
                "name": "My Unique Tech",
                "category": "database",
                "website": "https://example.com/unique",
                "confidence": 0.95,
                "headers": {"X-Unique": "unique-pattern"},
            },
        },
    }

    with open(target_yaml, "w", encoding="utf-8") as f:
        yaml.dump(initial_data, f)

    result = await fetch_and_convert(target_yaml, timeout=10.0)

    # Validate counts
    assert result.techs_added == 2  # "a-blog cms" + "PayPal"
    assert result.techs_updated == 1  # "Backbone.js" (matches lowercase "backbone.js")
    assert result.techs_preserved == 1  # "my-unique-tech" (not in upstream)
    assert result.output_path == target_yaml

    # Validate file is written and parseable
    assert target_yaml.is_file()

    # Check loaded data
    with target_yaml.open("r", encoding="utf-8") as f:
        written_data = yaml.safe_load(f)

    assert "technologies" in written_data
    techs = written_data["technologies"]

    # Verify a-blog cms was parsed correctly
    assert "a-blog cms" in techs
    ablog = techs["a-blog cms"]
    assert ablog["name"] == "a-blog cms"
    assert ablog["category"] == "cms"  # cats: [1] -> CMS -> cms
    assert ablog["website"] == "https://a-blogcms.jp"
    # confidence extracted from suffix \;confidence:80
    assert ablog["confidence"] == 0.8
    assert ablog["meta"] == {"generator": "a-blog cms"}
    assert ablog["implies"] == ["PHP"]  # Cleaned from PHP\;confidence:50

    # Verify non-standard Wappalyzer category passes through verbatim (not collapsed to 'other')
    assert "paypal" in techs
    paypal = techs["paypal"]
    assert paypal["category"] == "payment-processors"  # cats: [41] -> Payment processors

    # Verify the categories block contains all categories from the mock, as slugs
    cats = written_data["categories"]
    assert "cms" in cats
    assert "javascript-libraries" in cats
    assert "web-servers" in cats
    assert "payment-processors" in cats
    assert "live-chat" in cats

    # Verify Backbone.js merged (custom overrides win on conflict)
    assert "backbone.js" in techs
    backbone = techs["backbone.js"]
    assert backbone["name"] == "Backbone.js"  # Upstream name
    assert backbone["category"] == "javascript-libraries"
    assert backbone["confidence"] == 0.99  # Preserved custom confidence
    assert backbone["js_globals"] == {"Backbone": "([\\d.]+)"}  # Suffix stripped

    # Verify my-unique-tech preserved
    assert "my-unique-tech" in techs
    unique = techs["my-unique-tech"]
    assert unique["name"] == "My Unique Tech"
    assert unique["category"] == "databases"  # Normalized from database
    assert unique["confidence"] == 0.95
    assert unique["headers"] == {"X-Unique": "unique-pattern"}

    # Load with FingerprintStore to verify compatibility
    store = FingerprintStore.from_yaml(target_yaml)
    # 3 upstream (a-blog cms, backbone.js, paypal) + 1 preserved (my-unique-tech)
    assert len(store.technologies) == 4
    assert "a-blog cms" in store.technologies
    assert "backbone.js" in store.technologies
    assert "paypal" in store.technologies
    assert "my-unique-tech" in store.technologies
    # Verify FingerprintStore resolves slugs to human-readable names
    assert store.technologies["paypal"].category == "Payment processors"
    assert store.technologies["a-blog cms"].category == "CMS"


@pytest.mark.asyncio
async def test_updater_progress_callback(mock_wappalyzer_http: AsyncMock, tmp_path: Path) -> None:
    """Test that progress callback is called once for each of the 27 files."""
    target_yaml = tmp_path / "tech.yaml"
    called_chars = []

    def progress_callback(char: str) -> None:
        called_chars.append(char)

    await fetch_and_convert(target_yaml, timeout=5.0, progress_callback=progress_callback)

    # 26 alphabet characters + '_'
    assert len(called_chars) == 27
    assert "a" in called_chars
    assert "z" in called_chars
    assert "_" in called_chars


def test_cli_update_fingerprints_dry_run(mock_wappalyzer_http: AsyncMock, tmp_path: Path) -> None:
    """Test the CLI subcommand with --dry-run option."""
    target_yaml = tmp_path / "tech.yaml"

    runner = CliRunner()
    result = runner.invoke(app, ["update-fingerprints", "--output", str(target_yaml), "--dry-run"])

    assert result.exit_code == 0
    # Dry run should not write to target_yaml
    assert not target_yaml.exists()
    assert "Fingerprints Update Summary" in result.stdout
    assert "No file written" in result.stdout
