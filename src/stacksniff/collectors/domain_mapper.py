"""Map external and internal domain dependencies for a scan target.

Part 1 — External dependencies
    Parses HAR entries to find every cross-origin domain the page contacted.
    Groups requests by domain and reverse-looks up each domain against the
    loaded FingerprintStore to determine its technology category — no hardcoded
    category map, all labels come from the Wappalyzer-sourced tech.yaml.

Part 2 — Internal subdomains
    Queries crt.sh Certificate Transparency logs to discover every subdomain
    that has ever had a certificate issued for the target domain, then probes
    each one concurrently with httpx (30-connection semaphore, 5 s per probe)
    to record live status codes and response metadata.  Each responsive
    subdomain is also matched against the FingerprintStore using its response
    headers so we can report what tech stack it runs.

Returned ``data`` dict shape::

    {
        "external_dependencies": [<ExternalDep dict>, ...],
        "internal_subdomains": [<InternalSub dict>, ...],
    }

ExternalDep dict::

    {
        "domain":           str,
        "category":         str,   # from Wappalyzer fingerprint, or "Unclassified"
        "technology_name":  str | None,
        "resource_types":   list[str],
        "request_count":    int,
        "example_urls":     list[str],
    }

InternalSub dict::

    {
        "subdomain":          str,
        "full_url":           str,
        "status_code":        int,
        "content_type":       str | None,
        "redirect_location":  str | None,
        "response_time_ms":   float,
        "detected_tech":      str | None,
        "detected_category":  str | None,
    }
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from urllib.parse import urlparse

import httpx

from stacksniff.collectors.base import CollectorResult
from stacksniff.fingerprints import Fingerprint, FingerprintStore

logger = logging.getLogger(__name__)


def _apex_domain(host: str) -> str:
    """Return the apex (registered) domain for *host*.

    Handles common two-part ccTLDs (e.g. co.uk, com.au) by returning the last
    three labels in that case; otherwise returns the last two labels.

    Examples::

        _apex_domain("v2.aiori.in")          -> "aiori.in"
        _apex_domain("api.example.co.uk")    -> "example.co.uk"
        _apex_domain("maps.googleapis.com")  -> "googleapis.com"
    """
    host = host.lower().split(":")[0]  # strip port
    parts = host.split(".")
    if len(parts) >= 3:
        second_last = parts[-2]
        last = parts[-1]
        # Heuristic: short second-level (≤3 chars) + 2-char ccTLD → 3-part apex
        if len(second_last) <= 3 and len(last) == 2:
            return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


# Maximum concurrent subdomain probes (Pattern 9 from async playbook: Semaphore)
_PROBE_CONCURRENCY = 30
_PROBE_TIMEOUT = 5.0      # per-subdomain HEAD request timeout
_CRTSH_TIMEOUT = 10.0     # crt.sh JSON fetch timeout


class DomainMapper:
    """Collector that maps external and internal domain dependencies.

    Parameters
    ----------
    base_url:
        The scan target URL (e.g. ``https://aiori.in``).
    har_entries:
        Raw HAR entry dicts produced by
        :class:`~stacksniff.collectors.network_collector.NetworkCollector`.
        Each entry must have at least a ``url`` key.
    fingerprint_store:
        Loaded :class:`~stacksniff.fingerprints.FingerprintStore` used for
        reverse-lookup to classify external domains and subdomain stacks.
    timeout:
        Overall timeout budget (seconds).  crt.sh query uses its own
        ``_CRTSH_TIMEOUT`` cap; subdomain probes use ``_PROBE_TIMEOUT``.
    """

    def __init__(
        self,
        base_url: str,
        har_entries: list[dict],
        fingerprint_store: FingerprintStore,
        *,
        timeout: float = 30.0,
    ) -> None:
        self._base_url = base_url
        self._har_entries = har_entries
        self._store = fingerprint_store
        self._timeout = timeout
        self.errors: list[str] = []

        parsed = urlparse(base_url)
        self._target_netloc: str = parsed.netloc.lower()
        # Bare domain without www prefix / port for crt.sh query
        host = self._target_netloc.split(":")[0]
        self._target_domain: str = host.removeprefix("www.")
        # Apex domain used for same-origin subdomain check (Fix 1)
        self._target_apex: str = _apex_domain(self._target_domain)

    # ------------------------------------------------------------------
    # Public collector interface
    # ------------------------------------------------------------------

    async def collect(self) -> CollectorResult:
        """Run both mapping phases and return combined CollectorResult."""
        result = CollectorResult()
        self.errors = []

        # Phase 1: external dependencies — pure in-memory, no I/O
        try:
            external_deps = self._build_external_dependencies()
        except Exception as exc:  # noqa: BLE001
            logger.exception("DomainMapper external dependency phase error")
            result.add_error(f"External dependency mapping error: {exc}")
            external_deps = []

        # Phase 2: internal subdomains — async I/O
        try:
            internal_subs = await self._discover_internal_subdomains()
        except Exception as exc:  # noqa: BLE001
            logger.exception("DomainMapper internal subdomain phase error")
            result.add_error(f"Internal subdomain discovery error: {exc}")
            internal_subs = []

        for err in self.errors:
            result.add_error(err)

        result.data = {
            "external_dependencies": external_deps,
            "internal_subdomains": internal_subs,
        }
        return result

    # ------------------------------------------------------------------
    # Part 1 — External dependencies
    # ------------------------------------------------------------------

    def _build_external_dependencies(self) -> list[dict]:
        """Group HAR entries by cross-origin domain and classify via fingerprints."""
        # Group: domain -> accumulated info
        groups: dict[str, dict] = {}

        for entry in self._har_entries:
            url_str = entry.get("url", "")
            if not url_str:
                continue
            try:
                parsed = urlparse(url_str)
                netloc = parsed.netloc.lower()
            except Exception:
                continue

            # Skip same-origin (including subdomains) and entries with no netloc
            # Fix 1: compare apex domains so v2.aiori.in is treated as internal
            if not netloc:
                continue
            host_only = netloc.split(":")[0].removeprefix("www.")
            if _apex_domain(host_only) == self._target_apex:
                continue

            rtype = entry.get("resource_type", "") or ""

            if netloc not in groups:
                groups[netloc] = {
                    "domain": netloc,
                    "resource_types": set(),
                    "request_count": 0,
                    "example_urls": [],
                }

            g = groups[netloc]
            g["request_count"] += 1
            if rtype:
                g["resource_types"].add(rtype)
            if len(g["example_urls"]) < 3:
                g["example_urls"].append(url_str)

        # Fingerprint reverse-lookup for every external domain
        all_fingerprints = self._store.get_all()
        result: list[dict] = []

        for domain, info in sorted(groups.items(), key=lambda x: -x[1]["request_count"]):
            tech_name, tech_category = self._classify_domain(domain, all_fingerprints)
            result.append(
                {
                    "domain": domain,
                    "category": tech_category or "Unclassified",
                    "technology_name": tech_name,
                    "resource_types": sorted(info["resource_types"]),
                    "request_count": info["request_count"],
                    "example_urls": info["example_urls"],
                }
            )

        return result

    def _is_specific_match(self, pattern_str: str, target_string: str) -> bool:
        """Check if pattern_str matches target_string, but does NOT match a dummy random string."""
        try:
            if re.search(pattern_str, target_string, re.IGNORECASE):
                # Verify it doesn't match a generic dummy string
                dummy = "dummy-random-string-that-should-never-match-1234567890.com"
                if not re.search(pattern_str, dummy, re.IGNORECASE):
                    return True
        except re.error:
            # Fallback for plain string
            if pattern_str.lower() in target_string.lower():
                dummy = "dummy-random-string-that-should-never-match-1234567890.com"
                if pattern_str.lower() not in dummy:
                    return True
        return False

    def _extract_domain_from_pattern(self, pattern: str) -> str | None:
        """Scan a regex script pattern character-by-character to extract the longest
        leading static domain prefix, unescaping dots/hyphens/slashes/colons and stopping
        at regex control characters.
        """
        # Clean leading ^ and protocols
        pat = pattern
        if pat.startswith("^"):
            pat = pat[1:]

        pat = re.sub(r'^(?:https?\??(?::|\\:)?(?:[\\/]+)|[\\/]{2,})', '', pat, flags=re.IGNORECASE)

        prefix = ""
        i = 0
        n = len(pat)
        while i < n:
            char = pat[i]
            if char == "\\":
                if i + 1 < n:
                    next_char = pat[i + 1]
                    if next_char in {".", "-", ":"}:
                        prefix += next_char
                        i += 2
                        continue
                    elif next_char == "/":
                        break
                    else:
                        break
                else:
                    break
            elif char in "/([*+?{|$^":
                break
            else:
                prefix += char
                i += 1

        # Remove port if present
        prefix = prefix.split(":")[0]

        if not prefix:
            return None
        if "." not in prefix:
            return None

        # Validate domain labels
        labels = prefix.split(".")
        for label in labels:
            if not label:
                return None
            if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]$", label):
                if not (len(label) == 1 and label.isalnum()):
                    return None

        return prefix.lower()

    def _brand_matches(self, tech_name: str, domain: str) -> bool:
        """Check if the technology name brand matches the target domain.
        Normalises the technology name into brand words (ignoring stopwords) and matches
        if any brand word exactly equals a domain label (excluding TLD) or starts with it
        (for brand words of length >= 5).
        """
        STOPWORDS = {
            "api", "apis", "cdn", "sdk", "js", "static", "hosted", "libraries", 
            "font", "fonts", "page", "pages", "web", "service", "services", 
            "platform", "platforms", "cloud"
        }

        domain_labels = domain.lower().split(".")
        if len(domain_labels) > 1:
            domain_labels = domain_labels[:-1]

        brand_words = []
        for word in re.split(r"[^a-zA-Z0-9]+", tech_name):
            w = word.lower()
            if w and w not in STOPWORDS:
                brand_words.append(w)

        if not brand_words:
            return False

        for bw in brand_words:
            for label in domain_labels:
                if bw == label:
                    return True
                if len(bw) >= 5 and label.startswith(bw):
                    return True

        return False

    @staticmethod
    def _is_safe_literal_pattern(pattern: str) -> bool:
        """Return True if *pattern* contains no regex special characters.

        Safe literals can be used as plain ``in`` substring checks without
        risk of false positives from regex metacharacters accidentally
        matching unrelated text (e.g. ``google\\.com`` is not safe because
        the backslash is a special char, but ``googletagmanager.com/gtm.js``
        is safe).
        """
        _REGEX_SPECIALS = set(r"^$[]{}()|*+?\\")
        return not any(ch in _REGEX_SPECIALS for ch in pattern)

    def _classify_domain(
        self,
        domain: str,
        fingerprints: list[Fingerprint],
    ) -> tuple[str | None, str | None]:
        """Reverse-lookup *domain* against fingerprints.

        Priority order
        --------------
        1. **Script pattern literal match** (primary):
           For each fingerprint, check every script pattern that is a safe
           literal (no regex special characters).  If that literal appears
           as a substring of *domain*, it is a candidate.  Among all
           candidates pick the one with the *longest* matching pattern
           (most specific); ties broken by fingerprint confidence.

           Example::

               fp "Google Maps" script "maps.googleapis.com"
               domain = "maps.googleapis.com"
               "maps.googleapis.com" in "maps.googleapis.com" -> True

               fp "FullStory" script "fullstory.com"
               domain = "rs.fullstory.com"
               "fullstory.com" in "rs.fullstory.com" -> True

        2. **Website suffix match** (fallback):
           Only reached when Step 1 produces no result.
           Strip scheme and ``www.`` from each fingerprint's ``website``
           field and check whether *domain* ends with that string.
           Among matches pick the longest suffix first, then highest
           confidence fingerprint.

        3. **Unclassified**:
           ``(None, None)`` — caller maps this to ``"Unclassified"``.
        """
        domain_lower = domain.lower()

        # ------------------------------------------------------------------
        # Step 1 — Script pattern literal match (primary)
        # ------------------------------------------------------------------
        # (pattern_length, confidence, name, category)
        script_candidates: list[tuple[int, float, str, str]] = []

        for fp in fingerprints:
            for pattern in fp.scripts:
                if not pattern:
                    continue
                pat_lower = pattern.lower()
                if self._is_safe_literal_pattern(pat_lower) and pat_lower in domain_lower:
                    script_candidates.append(
                        (len(pat_lower), fp.confidence, fp.name, fp.category)
                    )

        if script_candidates:
            # Longest pattern first (most specific); ties broken by confidence
            script_candidates.sort(key=lambda t: (-t[0], -t[1]))
            _, _, best_name, best_category = script_candidates[0]
            return best_name, best_category

        # ------------------------------------------------------------------
        # Step 2 — Website suffix match (fallback)
        # ------------------------------------------------------------------
        website_lookup: dict[str, list[dict]] = {}
        for fp in fingerprints:
            if not fp.website:
                continue
            try:
                parsed = urlparse(fp.website)
                netloc = parsed.netloc.lower()
                if not netloc and "//" not in fp.website:
                    parsed = urlparse("//" + fp.website)
                    netloc = parsed.netloc.lower()
                if netloc:
                    host = netloc.split(":")[0]
                    site_domain = host.removeprefix("www.")
                    if site_domain:
                        website_lookup.setdefault(site_domain, []).append({
                            "name": fp.name,
                            "category": fp.category,
                            "confidence": fp.confidence,
                        })
            except Exception:
                continue

        # (match_len, confidence, name, category)
        website_candidates: list[tuple[int, float, str, str]] = []

        for site_domain, fp_infos in website_lookup.items():
            if domain_lower == site_domain or domain_lower.endswith("." + site_domain):
                match_len = len(site_domain)
                for info in fp_infos:
                    website_candidates.append(
                        (match_len, info["confidence"], info["name"], info["category"])
                    )

        if website_candidates:
            # Longest suffix first, then highest confidence
            website_candidates.sort(key=lambda t: (-t[0], -t[1]))
            _, _, best_name, best_category = website_candidates[0]
            return best_name, best_category

        # ------------------------------------------------------------------
        # Step 3 — Unclassified
        # ------------------------------------------------------------------
        return None, None

    # ------------------------------------------------------------------
    # Part 2 — Internal subdomain discovery via crt.sh
    # ------------------------------------------------------------------

    async def _discover_internal_subdomains(self) -> list[dict]:
        """Query crt.sh for CT log subdomains, then probe each one live."""
        if not self._target_domain:
            return []

        subdomains = await self._fetch_crtsh_subdomains()
        if not subdomains:
            logger.debug("DomainMapper: crt.sh returned no subdomains for %s", self._target_domain)
            return []

        logger.debug(
            "DomainMapper: probing %d subdomains for %s",
            len(subdomains),
            self._target_domain,
        )

        # Probe concurrently with a semaphore cap (Pattern 9)
        semaphore = asyncio.Semaphore(_PROBE_CONCURRENCY)
        all_fingerprints = self._store.get_all()

        async with httpx.AsyncClient(
            follow_redirects=False,   # capture 301/302 redirect_location manually
            verify=False,             # noqa: S501 — intentional, scanning unknown certs
            timeout=httpx.Timeout(_PROBE_TIMEOUT),
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/125.0.0.0 Safari/537.36"
                )
            },
        ) as client:
            tasks = [
                self._probe_subdomain(client, sub, semaphore, all_fingerprints)
                for sub in subdomains
            ]
            probe_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out None (connection errors) and exceptions
        internal_subs: list[dict] = []
        for r in probe_results:
            if isinstance(r, dict):
                internal_subs.append(r)
            elif isinstance(r, Exception):
                logger.debug("DomainMapper probe exception: %s", r)

        # Sort by subdomain name for deterministic output
        internal_subs.sort(key=lambda x: x["subdomain"])
        return internal_subs

    async def _fetch_crtsh_subdomains(self) -> list[str]:
        """Query crt.sh and return de-duped, filtered subdomains."""
        url = f"https://crt.sh/?q=%.{self._target_domain}&output=json"
        headers = {
            "User-Agent": "stacksniff/0.1.0 (Certificate Transparency lookup)"
        }
        entries = None
        backoff_delays = [0.0, 2.0, 4.0]

        for attempt, delay in enumerate(backoff_delays, start=1):
            if delay > 0:
                await asyncio.sleep(delay)
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(15.0),
                    follow_redirects=True,
                ) as client:
                    resp = await client.get(url, headers=headers)
                    if resp.status_code != 200:
                        logger.debug("crt.sh returned HTTP %d", resp.status_code)
                        resp.raise_for_status()
                    entries = resp.json()
                    break
            except (httpx.HTTPError, ValueError, Exception) as exc:
                logger.debug("crt.sh query failed on attempt %d: %s", attempt, exc)
                if attempt == 3:
                    msg = "crt.sh unavailable, subdomain discovery skipped"
                    logger.warning(msg)
                    self.errors.append(msg)
                    return []

        if entries is None:
            return []

        suffix = f".{self._target_domain}"
        seen: set[str] = set()
        result: list[str] = []

        for entry in entries:
            name_value = entry.get("name_value", "")
            # Each name_value may contain multiple names separated by \n
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if not name:
                    continue
                if name.startswith("*."):
                    continue  # skip wildcards
                if not name.endswith(suffix) and name != self._target_domain:
                    continue
                if name in seen:
                    continue
                seen.add(name)
                result.append(name)

        return result

    async def _probe_subdomain(
        self,
        client: httpx.AsyncClient,
        subdomain: str,
        semaphore: asyncio.Semaphore,
        fingerprints: list[Fingerprint],
    ) -> dict | None:
        """HEAD-probe a single subdomain and classify its tech stack.

        Returns a result dict on success (200/301/302/401/403), or
        ``None`` for connection errors / DNS failures.
        """
        full_url = f"https://{subdomain}"
        async with semaphore:
            t0 = time.monotonic()
            try:
                resp = await client.head(full_url)
            except (httpx.ConnectError, httpx.DNSLookupError):
                # Try http:// fallback silently
                try:
                    full_url = f"http://{subdomain}"
                    resp = await client.head(full_url)
                except Exception:
                    return None
            except httpx.TimeoutException:
                return None
            except Exception as exc:  # noqa: BLE001
                logger.debug("DomainMapper: probe %s error: %s", subdomain, exc)
                return None

            response_time_ms = (time.monotonic() - t0) * 1000

        status = resp.status_code
        # Only keep responses that indicate a live host
        if status not in {200, 201, 204, 301, 302, 307, 308, 401, 403}:
            return None

        # Normalise headers for easy lookup
        lower_headers = {k.lower(): v for k, v in resp.headers.items()}
        content_type = lower_headers.get("content-type")
        redirect_location = lower_headers.get("location") if status in {301, 302, 307, 308} else None

        # Tech detection from response headers
        server = lower_headers.get("server", "")
        x_powered = lower_headers.get("x-powered-by", "")
        header_text = f"{server} {x_powered}".strip()

        detected_tech: str | None = None
        detected_category: str | None = None
        if header_text:
            detected_tech, detected_category = self._classify_by_header_text(
                header_text, fingerprints
            )

        # Fix 3: If a redirect_location points to a completely different base domain
        # (not the same apex domain as the subdomain), the tech detection is
        # unreliable — clear it to avoid false positives like
        # "shop.github.com → thegithubshop.com" being labelled as GitHub tech.
        if redirect_location and detected_tech is not None:
            try:
                redirect_netloc = urlparse(redirect_location).netloc.lower().split(":")[0]
                # Strip www. for comparison
                redirect_base = redirect_netloc.removeprefix("www.")
                # Extract apex domain (last two parts) from both
                def _apex(host: str) -> str:
                    parts = host.split(".")
                    return ".".join(parts[-2:]) if len(parts) >= 2 else host

                if redirect_base and _apex(redirect_base) != _apex(self._target_domain):
                    logger.debug(
                        "DomainMapper: clearing tech for %s — redirect to external domain %s",
                        subdomain,
                        redirect_location,
                    )
                    detected_tech = None
                    detected_category = None
            except Exception:
                pass

        return {
            "subdomain": subdomain,
            "full_url": full_url,
            "status_code": status,
            "content_type": content_type,
            "redirect_location": redirect_location,
            "response_time_ms": round(response_time_ms, 1),
            "detected_tech": detected_tech,
            "detected_category": detected_category,
        }

    def _classify_by_header_text(
        self,
        header_text: str,
        fingerprints: list[Fingerprint],
    ) -> tuple[str | None, str | None]:
        """Match header text (Server / X-Powered-By) against fingerprint header patterns."""
        best_name: str | None = None
        best_category: str | None = None
        best_confidence: float = -1.0

        for fp in fingerprints:
            if fp.confidence <= best_confidence:
                continue
            for _key, pattern_str in fp.headers.items():
                if self._is_specific_match(pattern_str, header_text):
                    if fp.confidence > best_confidence:
                        best_name = fp.name
                        best_category = fp.category
                        best_confidence = fp.confidence
                    break

        # Apply minimum confidence threshold (Fix 3)
        if best_confidence < 0.75:
            best_name = None
            best_category = None

        # Apply formatting checks (Fix 3)
        if best_name:
            if len(best_name) > 30 or not re.match(r"^[A-Za-z0-9 .-]+$", best_name):
                best_name = None
                best_category = None

        return best_name, best_category
