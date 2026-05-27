"""Unit tests for DomainMapper."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from stacksniff.collectors.domain_mapper import DomainMapper
from stacksniff.fingerprints import Fingerprint, FingerprintStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_store(*fingerprints: Fingerprint) -> FingerprintStore:
    """Build a minimal FingerprintStore from a list of Fingerprint objects."""
    technologies = {fp.name.lower(): fp for fp in fingerprints}
    return FingerprintStore(categories={}, technologies=technologies, version="test")


def _make_fingerprint(
    name: str,
    category: str,
    *,
    scripts: list[str] | None = None,
    headers: dict[str, str] | None = None,
    confidence: float = 0.8,
) -> Fingerprint:
    return Fingerprint(
        name=name,
        category=category,
        scripts=scripts or [],
        headers=headers or {},
        confidence=confidence,
    )


def _har(url: str, resource_type: str = "script") -> dict:
    return {"url": url, "resource_type": resource_type}


# ---------------------------------------------------------------------------
# Part 1 — External dependencies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_external_category_from_fingerprint_store() -> None:
    """External domain classified via script literal pattern.

    cdn.jsdelivr.net should be classified as jsDelivr using the plain literal
    script pattern "cdn.jsdelivr.net" (Step 1 of the new priority).
    """
    fp_jsdelivr = _make_fingerprint(
        name="jsDelivr",
        category="CDN",
        scripts=["cdn.jsdelivr.net"],  # plain literal — no regex escapes
    )
    store = _make_store(fp_jsdelivr)

    har_entries = [
        _har("https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js"),
        _har("https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"),
    ]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    # DomainMapper.collect() makes I/O (crt.sh). Patch _discover_internal_subdomains
    # to return empty list so we only test Part 1.
    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1, f"Expected 1 external domain, got {ext}"
    dep = ext[0]
    assert dep["domain"] == "cdn.jsdelivr.net"
    assert dep["category"] == "CDN"
    assert dep["technology_name"] == "jsDelivr"
    assert dep["request_count"] == 2
    assert len(dep["example_urls"]) == 2


@pytest.mark.asyncio
async def test_unclassified_domain_no_fingerprint_match() -> None:
    """Domain with no matching fingerprint gets category 'Unclassified'."""
    store = _make_store()  # empty store — no fingerprints

    har_entries = [_har("https://some-unknown-cdn.example.io/lib.js")]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1
    dep = ext[0]
    assert dep["domain"] == "some-unknown-cdn.example.io"
    assert dep["category"] == "Unclassified"
    assert dep["technology_name"] is None


@pytest.mark.asyncio
async def test_same_origin_excluded() -> None:
    """Requests to the target domain itself must NOT appear in external_dependencies."""
    store = _make_store()

    har_entries = [
        _har("https://example.com/api/v1/users", "xhr"),        # same-origin → excluded
        _har("https://cdn.external.com/lib.js"),                  # external → included
        _har("https://example.com/static/app.js", "script"),    # same-origin → excluded
    ]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    domains = [d["domain"] for d in ext]

    assert "example.com" not in domains, f"Same-origin domain leaked: {domains}"
    assert "cdn.external.com" in domains, f"External domain missing: {domains}"
    assert len(ext) == 1


# ---------------------------------------------------------------------------
# Part 2 — Internal subdomains (crt.sh + probing)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crtsh_parsing() -> None:
    """crt.sh JSON is parsed correctly: wildcards filtered, off-domain filtered."""
    store = _make_store()
    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    # Simulate crt.sh response
    crtsh_payload = [
        {"name_value": "*.aiori.in"},          # wildcard — filtered
        {"name_value": "api.aiori.in"},         # valid
        {"name_value": "www.aiori.in"},         # valid
        {"name_value": "other.com"},             # off-domain — filtered
        {"name_value": "api.aiori.in"},         # duplicate — deduplicated
        {"name_value": "static.aiori.in\nwww.aiori.in"},  # multi-line entry
    ]

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = crtsh_payload

    with patch("httpx.AsyncClient.get", new=AsyncMock(return_value=mock_resp)):
        # Prevent actual subdomain probing
        with patch.object(
            mapper, "_probe_subdomain", new=AsyncMock(return_value=None)
        ):
            subdomains = await mapper._fetch_crtsh_subdomains()

    # Expected: api.aiori.in, www.aiori.in, static.aiori.in (deduplicated)
    assert "api.aiori.in" in subdomains
    assert "www.aiori.in" in subdomains
    assert "static.aiori.in" in subdomains
    # Wildcards and off-domain must be absent
    assert not any(s.startswith("*.") for s in subdomains), f"Wildcard found: {subdomains}"
    assert "other.com" not in subdomains
    # Deduplication
    assert subdomains.count("api.aiori.in") == 1


@pytest.mark.asyncio
async def test_subdomain_probe_responsive() -> None:
    """A subdomain returning HTTP 200 appears in internal_subdomains."""
    store = _make_store()
    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    # Pre-wire crt.sh to return one subdomain
    with patch.object(
        mapper, "_fetch_crtsh_subdomains", new=AsyncMock(return_value=["api.aiori.in"])
    ):
        # Mock HEAD response
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "application/json", "server": "nginx/1.24.0"}

        with patch("httpx.AsyncClient.head", new=AsyncMock(return_value=mock_resp)):
            result = await mapper.collect()

    subs = result.data.get("internal_subdomains", [])
    assert len(subs) == 1, f"Expected 1 subdomain, got {subs}"
    sub = subs[0]
    assert sub["subdomain"] == "api.aiori.in"
    assert sub["status_code"] == 200
    assert sub["content_type"] == "application/json"
    assert sub["redirect_location"] is None
    assert sub["response_time_ms"] >= 0.0


@pytest.mark.asyncio
async def test_subdomain_probe_dns_failure() -> None:
    """Subdomains that raise ConnectError must be excluded from results."""
    store = _make_store()
    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    with patch.object(
        mapper,
        "_fetch_crtsh_subdomains",
        new=AsyncMock(return_value=["nonexistent.aiori.in"]),
    ):
        with patch(
            "httpx.AsyncClient.head",
            new=AsyncMock(side_effect=httpx.ConnectError("DNS failure")),
        ):
            result = await mapper.collect()

    subs = result.data.get("internal_subdomains", [])
    assert subs == [], f"Expected empty list, got {subs}"


@pytest.mark.asyncio
async def test_subdomain_tech_detection() -> None:
    """Server: nginx header on a subdomain probe triggers fingerprint match."""
    fp_nginx = _make_fingerprint(
        name="Nginx",
        category="Web Servers",
        headers={"server": r"nginx"},
    )
    store = _make_store(fp_nginx)

    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    with patch.object(
        mapper, "_fetch_crtsh_subdomains", new=AsyncMock(return_value=["api.aiori.in"])
    ):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = {"server": "nginx/1.24.0", "content-type": "text/html"}

        with patch("httpx.AsyncClient.head", new=AsyncMock(return_value=mock_resp)):
            result = await mapper.collect()

    subs = result.data.get("internal_subdomains", [])
    assert len(subs) == 1
    sub = subs[0]
    assert sub["detected_tech"] == "Nginx", f"Expected Nginx detection, got {sub}"
    assert sub["detected_category"] == "Web Servers"


@pytest.mark.asyncio
async def test_low_confidence_tech_excluded() -> None:
    """Subdomain tech match with confidence < 0.75 should not report detected_tech."""
    fp_low = _make_fingerprint(
        name="Acquia Cloud Platform",
        category="PaaS",
        headers={"server": r"ah_ec2_ext"},
        confidence=0.5,
    )
    store = _make_store(fp_low)

    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    with patch.object(
        mapper, "_fetch_crtsh_subdomains", new=AsyncMock(return_value=["api.aiori.in"])
    ):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.headers = {"server": "ah_ec2_ext", "content-type": "text/html"}

        with patch("httpx.AsyncClient.head", new=AsyncMock(return_value=mock_resp)):
            result = await mapper.collect()

    subs = result.data.get("internal_subdomains", [])
    assert len(subs) == 1
    sub = subs[0]
    assert sub["detected_tech"] is None, f"Expected low confidence tech to be None, got {sub['detected_tech']}"
    assert sub["detected_category"] is None


@pytest.mark.asyncio
async def test_invalid_tech_name_format_excluded() -> None:
    """Subdomain tech match with special characters or long names should be excluded."""
    fp_invalid = _make_fingerprint(
        name="A" * 31,  # too long
        category="PaaS",
        headers={"server": r"invalid_long"},
        confidence=0.8,
    )
    fp_special = _make_fingerprint(
        name="Acquia! Platform",  # special character '!' not allowed
        category="PaaS",
        headers={"server": r"invalid_special"},
        confidence=0.8,
    )
    store = _make_store(fp_invalid, fp_special)

    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    with patch.object(
        mapper, "_fetch_crtsh_subdomains", new=AsyncMock(return_value=["api.aiori.in", "www.aiori.in"])
    ):
        # 1st probe
        mock_resp_1 = MagicMock(spec=httpx.Response)
        mock_resp_1.status_code = 200
        mock_resp_1.headers = {"server": "invalid_long", "content-type": "text/html"}

        # 2nd probe
        mock_resp_2 = MagicMock(spec=httpx.Response)
        mock_resp_2.status_code = 200
        mock_resp_2.headers = {"server": "invalid_special", "content-type": "text/html"}

        async def mock_head(url: str, **kwargs: Any) -> httpx.Response:
            if "api.aiori.in" in url:
                return mock_resp_1
            return mock_resp_2

        with patch("httpx.AsyncClient.head", new=AsyncMock(side_effect=mock_head)):
            result = await mapper.collect()

    subs = result.data.get("internal_subdomains", [])
    assert len(subs) == 2
    for sub in subs:
        assert sub["detected_tech"] is None
        assert sub["detected_category"] is None


@pytest.mark.asyncio
async def test_external_category_website_suffix_match() -> None:
    """Script literal (Step 1) takes cdn.jsdelivr.net; website suffix (Step 2) covers .jsdelivr.com.

    cdn.jsdelivr.net  → literal "cdn.jsdelivr.net" in domain → Step 1 match.
    www.jsdelivr.com  → no script literal matches → Step 2 website suffix match.
    cdn.jsdelivr.com  → no script literal matches → Step 2 website suffix match.
    """
    fp_jsdelivr = Fingerprint(
        name="jsDelivr",
        category="CDN",
        website="https://www.jsdelivr.com",
        scripts=["cdn.jsdelivr.net"],  # plain literal — no regex escapes
        confidence=0.8,
    )
    store = _make_store(fp_jsdelivr)

    har_entries = [
        _har("https://cdn.jsdelivr.net/npm/react@18/umd/react.production.min.js"),
        _har("https://www.jsdelivr.com/test.js"),
        _har("https://cdn.jsdelivr.com/test.js"),
    ]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 3

    # cdn.jsdelivr.net → Step 1: literal "cdn.jsdelivr.net" in domain
    cdn_net = next(x for x in ext if x["domain"] == "cdn.jsdelivr.net")
    assert cdn_net["category"] == "CDN"
    assert cdn_net["technology_name"] == "jsDelivr"

    # www.jsdelivr.com → Step 2: website suffix "jsdelivr.com" matches
    www_com = next(x for x in ext if x["domain"] == "www.jsdelivr.com")
    assert www_com["category"] == "CDN"
    assert www_com["technology_name"] == "jsDelivr"

    # cdn.jsdelivr.com → Step 2: website suffix "jsdelivr.com" matches
    cdn_com = next(x for x in ext if x["domain"] == "cdn.jsdelivr.com")
    assert cdn_com["category"] == "CDN"
    assert cdn_com["technology_name"] == "jsDelivr"


@pytest.mark.asyncio
async def test_external_category_no_regex_false_positive() -> None:
    """Complex regex patterns are excluded from external domain matching."""
    fp_complex = Fingerprint(
        name="Liferay CMS",
        category="CMS",
        website="https://www.liferay.com",
        scripts=[r"github\.(githubassets|usercontent)\.com"],  # complex regex in domain part
        confidence=0.8,
    )
    store = _make_store(fp_complex)

    har_entries = [
        _har("https://github.githubassets.com/app.js"),
    ]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1
    dep = ext[0]
    assert dep["domain"] == "github.githubassets.com"
    # Complex regex pattern from Liferay fingerprint must NOT match
    assert dep["technology_name"] is None
    assert dep["category"] == "Unclassified"


@pytest.mark.asyncio
async def test_dynamic_domain_classification() -> None:
    """Verify that Google/GitHub/jsDelivr domains resolve to correct tech names.

    Uses plain literal script patterns (as stored in real tech.yaml) so
    Step 1 (literal substring match) fires first.
    GitHub assets/githubusercontent domains fall through to Step 2
    (website suffix match on pages.github.com → github.com suffix).
    """
    fp_google_hosted = Fingerprint(
        name="Google Hosted Libraries",
        category="CDN",
        scripts=["ajax.googleapis.com"],  # plain literal — domain only, no path
        confidence=0.75,
    )
    fp_google_fonts = Fingerprint(
        name="Google Font API",
        category="Font scripts",
        scripts=["fonts.googleapis.com", "fonts.gstatic.com"],  # domain-only literals
        confidence=0.75,
    )
    fp_github_pages = Fingerprint(
        name="GitHub Pages",
        category="PaaS",
        website="https://pages.github.com/",
        confidence=0.75,
    )
    fp_jsdelivr = Fingerprint(
        name="jsDelivr",
        category="CDN",
        scripts=["cdn.jsdelivr.net"],  # plain literal
        confidence=0.75,
    )
    store = _make_store(fp_google_hosted, fp_google_fonts, fp_github_pages, fp_jsdelivr)

    har_entries = [
        _har("https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"),
        _har("https://github.githubassets.com/assets/app.js"),
        _har("https://avatars.githubusercontent.com/u/1234"),
        _har("https://fonts.gstatic.com/s/roboto/v30/font.woff2"),
        _har("https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"),
    ]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    by_domain = {d["domain"]: d for d in ext}

    # Step 1: literal "ajax.googleapis.com" found in domain
    assert by_domain["ajax.googleapis.com"]["technology_name"] == "Google Hosted Libraries"
    assert by_domain["ajax.googleapis.com"]["category"] == "CDN"

    # github.githubassets.com and avatars.githubusercontent.com have no script literal
    # and don't suffix-match "pages.github.com" — they are correctly Unclassified
    # under the strict two-step algorithm (no brand heuristic).
    assert by_domain["github.githubassets.com"]["technology_name"] is None
    assert by_domain["github.githubassets.com"]["category"] == "Unclassified"

    assert by_domain["avatars.githubusercontent.com"]["technology_name"] is None
    assert by_domain["avatars.githubusercontent.com"]["category"] == "Unclassified"

    # Step 1: literal "fonts.gstatic.com" found in domain
    assert by_domain["fonts.gstatic.com"]["technology_name"] == "Google Font API"
    assert by_domain["fonts.gstatic.com"]["category"] == "Font scripts"

    # Step 1: literal "cdn.jsdelivr.net" found in domain
    assert by_domain["cdn.jsdelivr.net"]["technology_name"] == "jsDelivr"
    assert by_domain["cdn.jsdelivr.net"]["category"] == "CDN"


@pytest.mark.asyncio
async def test_subdomain_redirect_to_external_clears_tech() -> None:
    """Fix 3: redirect_location pointing to an external apex domain clears detected_tech.

    shop.github.com (301 → thegithubshop.com) must NOT inherit any github.com
    tech labels — the redirect goes off-domain.
    copilot.github.com (301 → github.com/copilot) SHOULD keep its tech label
    because it stays on the same apex domain.
    """
    fp_nginx = _make_fingerprint(
        name="Nginx",
        category="Web Servers",
        headers={"server": r"nginx"},
        confidence=0.8,
    )
    store = _make_store(fp_nginx)

    mapper = DomainMapper(
        base_url="https://github.com",
        har_entries=[],
        fingerprint_store=store,
    )

    with patch.object(
        mapper,
        "_fetch_crtsh_subdomains",
        new=AsyncMock(return_value=["shop.github.com", "copilot.github.com"]),
    ):
        async def mock_head(url: str, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 301
            resp.headers = {"server": "nginx/1.24", "content-type": "text/html"}
            if "shop.github.com" in url:
                resp.headers = {"server": "nginx/1.24", "location": "https://thegithubshop.com/", "content-type": "text/html"}
            else:
                resp.headers = {"server": "nginx/1.24", "location": "https://github.com/copilot", "content-type": "text/html"}
            return resp

        with patch("httpx.AsyncClient.head", new=AsyncMock(side_effect=mock_head)):
            result = await mapper.collect()

    subs = {s["subdomain"]: s for s in result.data.get("internal_subdomains", [])}

    # shop.github.com → external redirect → tech must be None
    shop = subs.get("shop.github.com")
    assert shop is not None
    assert shop["detected_tech"] is None, f"Expected None for external redirect, got: {shop['detected_tech']}"
    assert shop["redirect_location"] == "https://thegithubshop.com/"

    # copilot.github.com → same apex domain redirect → tech detection kept
    copilot = subs.get("copilot.github.com")
    assert copilot is not None
    assert copilot["detected_tech"] == "Nginx", f"Expected Nginx for same-domain redirect, got: {copilot['detected_tech']}"
    assert copilot["redirect_location"] == "https://github.com/copilot"


@pytest.mark.asyncio
async def test_crtsh_retry_on_timeout() -> None:
    """crt.sh query retries on failure and succeeds on 3rd attempt."""
    store = _make_store()
    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    crtsh_payload = [{"name_value": "api.aiori.in"}]
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = crtsh_payload

    call_count = 0

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        if "hackertarget.com" in url:
            raise httpx.TimeoutException("HackerTarget timed out", request=MagicMock())
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise httpx.TimeoutException("Timeout", request=MagicMock())
        return mock_resp

    with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=mock_get)):
        with patch.object(mapper, "_probe_subdomain", new=AsyncMock(return_value=None)):
            with patch("asyncio.sleep", new=AsyncMock()) as mock_sleep:
                subdomains = await mapper._fetch_crtsh_subdomains()

    assert call_count == 3
    assert subdomains == ["api.aiori.in"]
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(2.0)
    mock_sleep.assert_any_call(4.0)


@pytest.mark.asyncio
async def test_crtsh_all_retries_fail() -> None:
    """crt.sh query logs warning and returns empty subdomain list on 3 consecutive timeouts."""
    store = _make_store()
    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=[],
        fingerprint_store=store,
    )

    async def mock_get(url: str, **kwargs: Any) -> httpx.Response:
        raise httpx.TimeoutException("Timeout", request=MagicMock())

    with patch("httpx.AsyncClient.get", new=AsyncMock(side_effect=mock_get)):
        with patch("asyncio.sleep", new=AsyncMock()):
            result = await mapper.collect()

    assert result.data.get("internal_subdomains") == []
    assert "crt.sh unavailable, subdomain discovery skipped" in result.errors


def test_extract_domain_from_pattern() -> None:
    mapper = DomainMapper("https://example.com", [], _make_store())

    # Simple domains
    assert mapper._extract_domain_from_pattern(r"cdn\.jsdelivr\.net") == "cdn.jsdelivr.net"
    assert mapper._extract_domain_from_pattern(r"ajax\.googleapis\.com/ajax/libs/") == "ajax.googleapis.com"

    # Protocols and ^ prefix
    assert mapper._extract_domain_from_pattern(r"^https?://cdn\.jsdelivr\.net") == "cdn.jsdelivr.net"
    assert mapper._extract_domain_from_pattern(r"https?:\/\/cdn\.jsdelivr\.net") == "cdn.jsdelivr.net"
    assert mapper._extract_domain_from_pattern(r"//cdn\.jsdelivr\.net") == "cdn.jsdelivr.net"
    assert mapper._extract_domain_from_pattern(r"\\/\\/cdn\.jsdelivr\.net") == "cdn.jsdelivr.net"

    # Complex regex (should return None)
    assert mapper._extract_domain_from_pattern(r"github\.(githubassets|usercontent)\.com") is None
    assert mapper._extract_domain_from_pattern(r"[^/]*\.github\.com") is None
    assert mapper._extract_domain_from_pattern(r"cdn\.jsdelivr\.(net|com)") is None
    assert mapper._extract_domain_from_pattern(r"") is None


def test_brand_matches() -> None:
    mapper = DomainMapper("https://example.com", [], _make_store())

    # Exact label match
    assert mapper._brand_matches("jsDelivr", "cdn.jsdelivr.net") is True
    assert mapper._brand_matches("Fastly", "fastly.net") is True

    # Starts with (length >= 5)
    assert mapper._brand_matches("GitHub Pages", "github.githubassets.com") is True
    assert mapper._brand_matches("GitHub Pages", "avatars.githubusercontent.com") is True
    assert mapper._brand_matches("Amazon Web Services", "amazonaws.com") is True
    assert mapper._brand_matches("Amazon CloudFront", "cloudfront.net") is True

    # Stop words and short words
    assert mapper._brand_matches("Google Font API", "google.com") is True  # brand word: google
    assert mapper._brand_matches("Google Font API", "fonts.gstatic.com") is False  # brand word: google, labels: fonts, gstatic
    assert mapper._brand_matches("Go Tech", "google.com") is False  # brand word: go (len 2 < 5), labels: google


# ---------------------------------------------------------------------------
# Fix 1 — Subdomains of the target domain excluded from external_dependencies
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_subdomain_treated_as_internal() -> None:
    """Fix 1: subdomains of the scan target must NOT appear in external_dependencies.

    v2.aiori.in, api.aiori.in, and static.aiori.in all share the same apex
    domain (aiori.in) as the target — they are internal and must be excluded.
    An unrelated CDN (cdn.example.net) must still appear as external.
    """
    store = _make_store()

    har_entries = [
        _har("https://v2.aiori.in/app.js"),            # subdomain → internal
        _har("https://api.aiori.in/api/v1/users"),     # subdomain → internal
        _har("https://static.aiori.in/img/logo.png"),  # subdomain → internal
        _har("https://cdn.example.net/lib.js"),        # external → included
    ]

    mapper = DomainMapper(
        base_url="https://aiori.in",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    domains = [d["domain"] for d in ext]

    # No subdomain of aiori.in should appear
    for sub in ("v2.aiori.in", "api.aiori.in", "static.aiori.in"):
        assert sub not in domains, f"Subdomain leaked into external_dependencies: {sub!r}"

    # The unrelated CDN must still be present
    assert "cdn.example.net" in domains, f"Expected cdn.example.net in {domains}"
    assert len(ext) == 1, f"Expected exactly 1 external dep, got: {domains}"


# ---------------------------------------------------------------------------
# Fix 2 — Most-specific website domain wins over broader suffix match
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_most_specific_pattern_wins() -> None:
    """Fix 2: when two fingerprints share a parent domain, the one whose
    website domain is the longest match for the incoming HAR domain wins.

    Example:
      fp_maps   → website "https://maps.google.com"       (maps.google.com, len=14)
      fp_google → website "https://google.com"            (google.com,      len=10)

    HAR domain "maps.googleapis.com" — neither website matches directly, but
    "maps.google.com" is a closer brand match than "google.com".

    Simpler, purely suffix-based example that doesn't depend on brand heuristics:
      fp_specific → website "https://specific.example.com" → matches specific.example.com
      fp_broad    → website "https://example.com"          → matches *.example.com

    Scanning "specific.example.com" must resolve to fp_specific (len 20 > 11).
    """
    fp_specific = Fingerprint(
        name="Specific Tool",
        category="Analytics",
        website="https://specific.example.com",
        confidence=0.8,
    )
    fp_broad = Fingerprint(
        name="Broad Platform",
        category="Marketing",
        website="https://example.com",
        confidence=0.9,  # higher confidence, but shorter match → must lose
    )
    store = _make_store(fp_specific, fp_broad)

    har_entries = [
        _har("https://specific.example.com/track.js"),
    ]

    mapper = DomainMapper(
        base_url="https://mysite.io",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1
    dep = ext[0]
    assert dep["domain"] == "specific.example.com"
    # The longer (more specific) match must win even though fp_broad has higher confidence
    assert dep["technology_name"] == "Specific Tool", (
        f"Expected 'Specific Tool' (most-specific match), got {dep['technology_name']!r}"
    )
    assert dep["category"] == "Analytics"


# ---------------------------------------------------------------------------
# New tests — Step 1 priority model
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_script_pattern_takes_priority_over_website() -> None:
    """Step 1 script literal match must win over Step 2 website suffix match.

    Two fingerprints share the same website domain (microsoft.com) but have
    different script patterns.  The external domain telemetry.microsoft.com
    must match fp_product_a via its specific script pattern, NOT fp_product_b
    whose pattern does not appear in the domain.
    """
    fp_product_a = Fingerprint(
        name="Product A",
        category="Analytics",
        website="https://microsoft.com",
        scripts=["telemetry.microsoft.com"],
        confidence=0.8,
    )
    fp_product_b = Fingerprint(
        name="Product B",
        category="Search engines",
        website="https://microsoft.com",
        scripts=["search.microsoft.com"],
        confidence=0.8,
    )
    store = _make_store(fp_product_a, fp_product_b)

    har_entries = [_har("https://telemetry.microsoft.com/collect")]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1
    dep = ext[0]
    assert dep["domain"] == "telemetry.microsoft.com"
    # Script literal "telemetry.microsoft.com" must win — Product A
    assert dep["technology_name"] == "Product A", (
        f"Expected 'Product A' (script literal match), got {dep['technology_name']!r}"
    )
    assert dep["category"] == "Analytics"
    # Product B must NOT be selected despite same website suffix
    assert dep["technology_name"] != "Product B"


@pytest.mark.asyncio
async def test_longest_script_pattern_wins() -> None:
    """Among multiple Step 1 script literal matches, the longest pattern wins.

    fp_generic  script "googleapis.com"      → len 14
    fp_maps     script "maps.googleapis.com" → len 19  (more specific)

    External domain "maps.googleapis.com" must resolve to fp_maps.
    """
    fp_generic = Fingerprint(
        name="Google APIs",
        category="CDN",
        scripts=["googleapis.com"],
        confidence=0.8,
    )
    fp_maps = Fingerprint(
        name="Google Maps",
        category="Maps",
        scripts=["maps.googleapis.com"],
        confidence=0.7,  # lower confidence, but longer pattern → must win
    )
    store = _make_store(fp_generic, fp_maps)

    har_entries = [_har("https://maps.googleapis.com/maps/api/js")]

    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1
    dep = ext[0]
    assert dep["domain"] == "maps.googleapis.com"
    # Longer pattern "maps.googleapis.com" must win over shorter "googleapis.com"
    assert dep["technology_name"] == "Google Maps", (
        f"Expected 'Google Maps' (longest pattern), got {dep['technology_name']!r}"
    )
    assert dep["category"] == "Maps"


@pytest.mark.asyncio
async def test_website_suffix_fallback_when_no_script_match() -> None:
    """Step 2 website suffix match fires when no script literal matches (Step 1 miss).

    Fingerprint has no script patterns — only a website URL.
    External domain cdn.example.com ends with example.com → Step 2 should match.
    """
    fp_example = Fingerprint(
        name="Example Platform",
        category="PaaS",
        website="https://example.com",
        scripts=[],  # no script patterns — Step 1 cannot fire
        confidence=0.8,
    )
    store = _make_store(fp_example)

    har_entries = [_har("https://cdn.example.com/assets/lib.js")]

    mapper = DomainMapper(
        base_url="https://myapp.io",
        har_entries=har_entries,
        fingerprint_store=store,
    )

    with patch.object(mapper, "_discover_internal_subdomains", new=AsyncMock(return_value=[])):
        result = await mapper.collect()

    ext = result.data.get("external_dependencies", [])
    assert len(ext) == 1
    dep = ext[0]
    assert dep["domain"] == "cdn.example.com"
    # Step 2: website suffix "example.com" matches cdn.example.com
    assert dep["technology_name"] == "Example Platform", (
        f"Expected 'Example Platform' (website suffix fallback), got {dep['technology_name']!r}"
    )
    assert dep["category"] == "PaaS"


@pytest.mark.asyncio
async def test_hackertarget_is_tried_first() -> None:
    """Verify that HackerTarget is attempted first and, if successful, crt.sh is skipped."""
    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=[],
        fingerprint_store=_make_store(),
    )

    get_urls = []

    async def mock_get(url, *args, **kwargs):
        get_urls.append(url)
        if "hackertarget.com" in url:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "api.example.com,1.2.3.4\ndev.example.com,5.6.7.8\n"
            return mock_resp
        elif "crt.sh" in url:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json = lambda: [{"name_value": "api.example.com"}]
            return mock_resp
        raise ValueError(f"Unexpected get URL: {url}")

    async def mock_head(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("httpx.AsyncClient.head", side_effect=mock_head):
        subs = await mapper._discover_internal_subdomains()

    assert len(subs) == 2
    assert subs[0]["subdomain"] == "api.example.com"
    assert subs[0]["ct_source"] == "hackertarget"
    assert subs[1]["subdomain"] == "dev.example.com"
    assert subs[1]["ct_source"] == "hackertarget"

    # Verify crt.sh was not called
    assert any("hackertarget.com" in u for u in get_urls)
    assert not any("crt.sh" in u for u in get_urls)


@pytest.mark.asyncio
async def test_crtsh_fallback_when_hackertarget_fails() -> None:
    """If HackerTarget fails, fallback to crt.sh and verify subdomain parsing + source field."""
    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=[],
        fingerprint_store=_make_store(),
    )

    async def mock_get(url, *args, **kwargs):
        if "hackertarget.com" in url:
            raise httpx.TimeoutException("HackerTarget timed out")
        elif "crt.sh" in url:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json = lambda: [
                {"name_value": "api.example.com"},
                {"name_value": "dev.example.com"}
            ]
            return mock_resp
        raise ValueError(f"Unexpected get URL: {url}")

    async def mock_head(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("httpx.AsyncClient.head", side_effect=mock_head):
        subs = await mapper._discover_internal_subdomains()

    assert len(subs) == 2
    assert subs[0]["subdomain"] == "api.example.com"
    assert subs[0]["ct_source"] == "crt.sh"
    assert subs[1]["subdomain"] == "dev.example.com"
    assert subs[1]["ct_source"] == "crt.sh"


@pytest.mark.asyncio
async def test_certspotter_fallback_when_both_fail() -> None:
    """If crt.sh and HackerTarget fail, fallback to CertSpotter."""
    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=[],
        fingerprint_store=_make_store(),
    )

    async def mock_get(url, *args, **kwargs):
        if "crt.sh" in url:
            raise httpx.TimeoutException("crt.sh timed out")
        elif "hackertarget.com" in url:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "API count exceeded"
            return mock_resp
        elif "certspotter.com" in url:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json = lambda: [
                {"dns_names": ["api.example.com", "v2.example.com"]},
                {"dns_names": ["dev.example.com"]}
            ]
            return mock_resp
        raise ValueError(f"Unexpected get URL: {url}")

    async def mock_head(url, *args, **kwargs):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {"Content-Type": "text/html"}
        return mock_resp

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("httpx.AsyncClient.head", side_effect=mock_head):
        subs = await mapper._discover_internal_subdomains()

    assert len(subs) == 3
    assert subs[0]["subdomain"] == "api.example.com"
    assert subs[0]["ct_source"] == "certspotter"
    assert subs[1]["subdomain"] == "dev.example.com"
    assert subs[1]["ct_source"] == "certspotter"
    assert subs[2]["subdomain"] == "v2.example.com"
    assert subs[2]["ct_source"] == "certspotter"


@pytest.mark.asyncio
async def test_all_sources_fail_returns_empty() -> None:
    """If all sources fail/return empty, logs a warning and returns empty list."""
    mapper = DomainMapper(
        base_url="https://example.com",
        har_entries=[],
        fingerprint_store=_make_store(),
    )

    async def mock_get(url, *args, **kwargs):
        raise httpx.TimeoutException("timeout connection error")

    with patch("httpx.AsyncClient.get", side_effect=mock_get), \
         patch("logging.Logger.warning") as mock_warning:
        subs = await mapper._discover_internal_subdomains()

    assert len(subs) == 0
    assert len(mapper.errors) == 1
    assert "crt.sh unavailable, subdomain discovery skipped" in mapper.errors[0]
    mock_warning.assert_called_once()
    warning_arg = mock_warning.call_args[0][0]
    assert "All subdomain sources failed:" in warning_arg
    assert "crt.sh" in warning_arg
    assert "HackerTarget" in warning_arg
    assert "CertSpotter" in warning_arg

