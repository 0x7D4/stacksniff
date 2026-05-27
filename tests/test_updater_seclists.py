import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
import yaml

from stacksniff.updater_seclists import fetch_seclists, normalize_filename


def test_normalize_filename() -> None:
    """Verify filename stem normalization including JS special case."""
    assert normalize_filename("spring-boot.txt") == "spring boot"
    assert normalize_filename("django.txt") == "django"
    assert normalize_filename("node-js.txt") == "node.js"
    assert normalize_filename("react-js.txt") == "react.js"
    assert normalize_filename("graphql.txt") == "graphql"


@pytest.mark.asyncio
async def test_dynamic_manifest_maps_django_to_fingerprint() -> None:
    """Verify that a known technology file maps to its FingerprintStore key in the manifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        tech_yaml = tmp_path / "tech.yaml"
        tech_data = {
            "version": "1.0.0",
            "categories": {"cms": {"name": "CMS"}},
            "technologies": {
                "Django": {
                    "name": "Django",
                    "category": "cms",
                }
            }
        }
        tech_yaml.write_text(yaml.dump(tech_data), encoding="utf-8")

        seclists_dir = tmp_path / "seclists"

        async def mock_get(url, *args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            if "/contents/Discovery/Web-Content/api" in url:
                mock_resp.json = lambda: []
                return mock_resp
            elif "/contents/Discovery/Web-Content" in url:
                mock_resp.json = lambda: [
                    {
                        "name": "django.txt",
                        "type": "file",
                        "download_url": "https://example.com/django.txt",
                    }
                ]
                return mock_resp
            elif "example.com/django.txt" in url:
                mock_resp.text = "/admin\n/login\n"
                return mock_resp
            raise ValueError(f"Unexpected get URL: {url}")

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            res = await fetch_seclists(seclists_dir)

        assert res.files_fetched == 1
        assert (seclists_dir / "django.txt").is_file()
        assert (seclists_dir / "django.txt").read_text(encoding="utf-8") == "/admin\n/login"

        manifest_path = seclists_dir / "manifest.yaml"
        assert manifest_path.is_file()
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        assert manifest["source"] == "dynamic"
        files = manifest["files"]
        assert "django.txt" in files
        assert files["django.txt"]["tech_match"] == ["django"]
        assert not files["django.txt"]["always_probe"]


@pytest.mark.asyncio
async def test_dynamic_manifest_unknown_file_becomes_always_probe() -> None:
    """Verify that an unknown file gets tech_match = [] and always_probe = False."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        tech_yaml = tmp_path / "tech.yaml"
        tech_yaml.write_text(yaml.dump({"technologies": {}}), encoding="utf-8")

        seclists_dir = tmp_path / "seclists"

        async def mock_get(url, *args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            if "/contents/Discovery/Web-Content/api" in url:
                mock_resp.json = lambda: []
                return mock_resp
            elif "/contents/Discovery/Web-Content" in url:
                mock_resp.json = lambda: [
                    {
                        "name": "some-unknown-tool.txt",
                        "type": "file",
                        "download_url": "https://example.com/some-unknown-tool.txt",
                    }
                ]
                return mock_resp
            raise ValueError(f"Unexpected get URL: {url}")

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            res = await fetch_seclists(seclists_dir)

        # It shouldn't be downloaded
        assert res.files_fetched == 0
        assert not (seclists_dir / "some-unknown-tool.txt").exists()

        manifest_path = seclists_dir / "manifest.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        files = manifest["files"]
        assert "some-unknown-tool.txt" in files
        assert files["some-unknown-tool.txt"]["tech_match"] == []
        assert not files["some-unknown-tool.txt"]["always_probe"]


@pytest.mark.asyncio
async def test_api_seen_in_wild_is_always_probe() -> None:
    """Verify that api-seen-in-the-wild.txt is identified as always_probe = True."""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        tech_yaml = tmp_path / "tech.yaml"
        tech_yaml.write_text(yaml.dump({"technologies": {}}), encoding="utf-8")

        seclists_dir = tmp_path / "seclists"

        async def mock_get(url, *args, **kwargs):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            if "/contents/Discovery/Web-Content/api" in url:
                mock_resp.json = lambda: [
                    {
                        "name": "api-seen-in-the-wild.txt",
                        "type": "file",
                        "download_url": "https://example.com/api-seen-in-the-wild.txt",
                    }
                ]
                return mock_resp
            elif "/contents/Discovery/Web-Content" in url:
                mock_resp.json = lambda: []
                return mock_resp
            elif "example.com/api-seen-in-the-wild.txt" in url:
                mock_resp.text = "/v1/users\n"
                return mock_resp
            raise ValueError(f"Unexpected get URL: {url}")

        with patch("httpx.AsyncClient.get", side_effect=mock_get):
            res = await fetch_seclists(seclists_dir)

        assert res.files_fetched == 1
        assert (seclists_dir / "api-seen-in-the-wild.txt").is_file()

        manifest_path = seclists_dir / "manifest.yaml"
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        files = manifest["files"]
        assert "api-seen-in-the-wild.txt" in files
        assert files["api-seen-in-the-wild.txt"]["tech_match"] == []
        assert files["api-seen-in-the-wild.txt"]["always_probe"]
