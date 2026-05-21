"""Unit tests for the FingerprintMatcher."""

from __future__ import annotations

from pathlib import Path

import pytest

from stacksniff.analyzers.fingerprint_matcher import FingerprintMatcher
from stacksniff.fingerprints import FingerprintStore


@pytest.fixture
def store() -> FingerprintStore:
    """Load default fingerprint rules."""
    # Find the default tech.yaml
    path = Path(__file__).parents[1] / "fingerprints" / "tech.yaml"
    return FingerprintStore.from_yaml(path)


def test_matcher_basic_headers(store: FingerprintStore) -> None:
    """Test basic matching with headers, version extraction and confidence scoring."""
    matcher = FingerprintMatcher(store)

    evidence = {
        "headers": {
            "Server": "nginx/1.25.3",
        }
    }

    results = matcher.match(evidence)
    nginx_match = next((m for m in results if m.name == "Nginx"), None)

    assert nginx_match is not None
    assert nginx_match.version == "1.25.3"
    # Base confidence = 0.9, version boost = +0.1, capped at 1.0
    assert nginx_match.confidence == 1.0
    assert len(nginx_match.evidence) == 1
    assert nginx_match.evidence[0].source == "header"
    assert nginx_match.evidence[0].matched == "nginx/1.25.3"


def test_matcher_corroboration(store: FingerprintStore) -> None:
    """Test corroboration confidence boost from multiple sources."""
    matcher = FingerprintMatcher(store)

    # WordPress requires php and mysql. We only trigger direct WordPress evidence.
    # generator (meta) + wp-content (html) = 2 sources.
    # WordPress base = 0.85. 2 sources -> +0.1 boost -> 0.95.
    # Version group in generator (+0.1) -> 1.05 -> capped at 1.0.
    evidence = {
        "meta_tags": {
            "generator": "WordPress 6.4.2",
        },
        "html": "<html><body><div class='wp-content'>Hello</div></body></html>",
    }

    results = matcher.match(evidence)
    wp_match = next((m for m in results if m.name == "WordPress"), None)

    assert wp_match is not None
    assert wp_match.version == "6.4.2"
    assert wp_match.confidence == 1.0

    # Test implies logic also got triggered
    php_match = next((m for m in results if m.name == "PHP"), None)
    mysql_match = next((m for m in results if m.name == "MySQL"), None)

    assert php_match is not None
    assert php_match.confidence == 0.6
    assert mysql_match is not None
    assert mysql_match.confidence == 0.6


def test_matcher_js_globals(store: FingerprintStore) -> None:
    """Test JS global normalization and matching."""
    matcher = FingerprintMatcher(store)

    evidence = {
        "js_globals": {
            "window.React": "function",
            "window.React?.version": "18.2.0",
        }
    }

    results = matcher.match(evidence)
    react_match = next((m for m in results if m.name == "React"), None)

    assert react_match is not None
    assert react_match.version == "18.2.0"
    # Base confidence = 0.8. Version capture = 18.2.0 -> +0.1 -> 0.9.
    assert react_match.confidence == 0.9


def test_matcher_dom_rules() -> None:
    """Test matching with DOM selectors and nested rules."""
    from stacksniff.fingerprints import Fingerprint

    categories = {"1": {"name": "CMS"}}

    # We will test two scenarios:
    # 1. Simple list selector matching
    # 2. Dict selector matching with sub-rules
    fp1 = Fingerprint(
        name="LottieFiles",
        category="animation",
        dom=["lottie-player", "a[href*='lottie']"],
        confidence=0.8,
    )

    fp2 = Fingerprint(
        name="Google Font API",
        category="font",
        dom={
            "link[href*='fonts.googleapis.com']": {
                "exists": "",
            },
            "link[rel='stylesheet']": {
                "attributes": {
                    "href": "fonts\\.googleapis\\.com/css\\?family=(.+)"
                }
            }
        },
        confidence=0.7,
    )

    store = FingerprintStore(
        categories=categories,
        technologies={"lottiefiles": fp1, "google font api": fp2},
    )

    matcher = FingerprintMatcher(store)

    # Test fp1 (list) matching
    evidence1 = {
        "dom": {
            "lottie-player": [
                {
                    "text": "",
                    "attributes": {"src": "animation.json"},
                    "properties": {}
                }
            ]
        }
    }

    results1 = matcher.match(evidence1)
    lottie_match = next((m for m in results1 if m.name == "LottieFiles"), None)
    assert lottie_match is not None
    assert lottie_match.confidence == 0.8
    assert lottie_match.evidence[0].source == "dom"
    assert lottie_match.evidence[0].pattern == "lottie-player"

    # Test fp2 (dict attributes regex) matching and version/font family extraction
    evidence2 = {
        "dom": {
            "link[rel='stylesheet']": [
                {
                    "text": "",
                    "attributes": {
                        "rel": "stylesheet",
                        "href": "https://fonts.googleapis.com/css?family=Roboto:400,700"
                    },
                    "properties": {}
                }
            ]
        }
    }

    results2 = matcher.match(evidence2)
    font_match = next((m for m in results2 if m.name == "Google Font API"), None)
    assert font_match is not None
    # confidence = base (0.7) + version matched (+0.1) = 0.8
    assert font_match.confidence == 0.8
    assert font_match.version == "Roboto:400,700"
