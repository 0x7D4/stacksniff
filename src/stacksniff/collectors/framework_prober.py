"""Framework path prober powered by SecLists wordlists.

Reads the SecLists manifest written by :func:`~stacksniff.updater_seclists.fetch_seclists`
and fires HTTP probes against a target URL for paths relevant to the detected
technology stack.

The prober is intentionally self-limiting:

* **Zero probes** fire if no matched technology maps to any wordlist and there
  are no always-probe wordlists available.
* **500-path cap** prevents runaway scan times on targets with many matched
  frameworks.
* **Batch size of 50** keeps concurrency proportional to the target's load
  capacity.

Usage::

    from pathlib import Path
    from stacksniff.collectors.framework_prober import FrameworkProber

    prober = FrameworkProber(tech_matches, "https://example.com", timeout=20.0)
    result = await prober.collect()
    for ep in result.data.get("framework_endpoints", []):
        print(ep["url"], ep["status_code"], ep["confidence"])
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
import yaml

from stacksniff.collectors.base import CollectorResult
from stacksniff.models import TechMatch

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_PROBES = 500
_BATCH_SIZE = 50

# Canary path used to detect CMS canonical-redirect baselines.
# Deliberately nonsensical to guarantee a 404/redirect-to-home on any real site.
_CANARY_PATH = "/_stacksniff_canary_9f3e7a1b_404_test"

# Status codes we care about, mapped to (label, confidence)
_STATUS_MAP: dict[int, tuple[str, float]] = {
    200: ("exposed", 0.95),
    401: ("auth-required", 0.85),
    403: ("forbidden", 0.80),
    301: ("redirect", 0.70),
    302: ("redirect", 0.70),
}

# Generic wordlists that have no framework context — stricter filtering applies.
_GENERIC_WORDLISTS = ("actions.txt", "objects.txt", "api-endpoints.txt")


# ---------------------------------------------------------------------------
# Helper: locate seclists directory using the candidate-path pattern
# ---------------------------------------------------------------------------


def _default_seclists_dir() -> Path | None:
    """Resolve the default SecLists directory using the same candidate-path
    strategy as :meth:`~stacksniff.fingerprints.FingerprintStore.default`.

    Returns the first existing candidate, or ``None`` if neither exists.
    """
    candidates = [
        Path.cwd() / "fingerprints" / "seclists",
        # src/stacksniff/collectors/ → 4 parents up → repo root
        Path(__file__).parent.parent.parent.parent / "fingerprints" / "seclists",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


# ---------------------------------------------------------------------------
# FrameworkProber
# ---------------------------------------------------------------------------


class FrameworkProber:
    """Probe framework-specific paths derived from SecLists wordlists.

    Parameters
    ----------
    detected_techs:
        Technologies matched during Phase 3 fingerprint analysis.
    base_url:
        The scan target's root URL (scheme + host + optional path prefix).
    timeout:
        Per-request HTTP timeout in seconds.
    seclists_dir:
        Override the SecLists directory path.  When ``None``, the default
        candidate-path resolution is used.
    """

    def __init__(
        self,
        detected_techs: list[TechMatch],
        base_url: str,
        *,
        timeout: float = 30.0,
        seclists_dir: Path | None = None,
    ) -> None:
        self._techs = detected_techs
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._seclists_dir = seclists_dir

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    async def collect(self) -> CollectorResult:
        """Run the framework probe and return a :class:`~stacksniff.collectors.base.CollectorResult`.

        Returns
        -------
        CollectorResult
            ``data["framework_endpoints"]`` contains a list of dicts; one entry
            per HTTP response that matched a tracked status code.
        """
        result = CollectorResult()

        # Resolve seclists directory
        seclists_dir = self._seclists_dir or _default_seclists_dir()
        if seclists_dir is None:
            msg = "SecLists not found — run stacksniff update-fingerprints first"
            logger.warning(msg)
            result.add_error(msg)
            result.data["framework_endpoints"] = []
            return result

        manifest_path = seclists_dir / "manifest.yaml"
        if not manifest_path.is_file():
            msg = "SecLists not found — run stacksniff update-fingerprints first"
            logger.warning(
                "SecLists manifest missing at %s — run update-fingerprints first",
                manifest_path,
            )
            result.add_error(msg)
            result.data["framework_endpoints"] = []
            return result

        # Load manifest
        try:
            with manifest_path.open("r", encoding="utf-8") as fh:
                manifest: dict[str, Any] = yaml.safe_load(fh) or {}
        except Exception as exc:  # noqa: BLE001
            msg = f"Failed to read SecLists manifest: {exc}"
            logger.error(msg)
            result.add_error(msg)
            result.data["framework_endpoints"] = []
            return result

        files_meta: dict[str, Any] = manifest.get("files", {})

        # Build probe list
        paths_by_source = self._build_probe_list(files_meta, seclists_dir)
        if not paths_by_source:
            logger.debug("FrameworkProber: no matching paths found for detected techs")
            result.data["framework_endpoints"] = []
            return result

        # Apply 500-path cap with priority ordering
        capped_paths = self._apply_cap(paths_by_source, files_meta)

        # Detect CMS canonical-redirect baseline before probing
        redirect_baseline = await self._detect_redirect_baseline()

        # Fire probes in batches of 50
        endpoints = await self._probe_all(capped_paths, redirect_baseline)

        result.data["framework_endpoints"] = endpoints
        logger.info(
            "FrameworkProber: probed %d paths → %d findings on %s",
            len(capped_paths),
            len(endpoints),
            self._base_url,
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detected_tech_names_lower(self) -> set[str]:
        """Return a set of all detected technology names, lowercased."""
        return {tech.name.lower() for tech in self._techs}

    def _build_probe_list(
        self,
        files_meta: dict[str, Any],
        seclists_dir: Path,
    ) -> dict[str, list[str]]:
        """Build the probe list from the manifest.

        Returns
        -------
        dict[str, list[str]]
            Mapping of ``source_wordlist`` → list of unique paths to probe.
        """
        detected_names = self._detected_tech_names_lower()
        paths_by_source: dict[str, list[str]] = {}

        for filename, meta in files_meta.items():
            if not isinstance(meta, dict):
                continue

            always_probe: bool = meta.get("always_probe", False)
            tech_match: list[str] = meta.get("tech_match", [])

            # Decide inclusion
            include = always_probe
            if not include:
                # Case-insensitive substring match against detected tech names
                for keyword in tech_match:
                    keyword_lower = keyword.lower()
                    if any(keyword_lower in detected for detected in detected_names) or any(
                        detected in keyword_lower for detected in detected_names
                    ):
                        include = True
                        break

            if not include:
                continue

            # Load paths from the wordlist file on disk
            wl_path = seclists_dir / filename
            if not wl_path.is_file():
                logger.debug("SecLists wordlist not found on disk: %s", wl_path)
                continue

            try:
                paths = [
                    line.strip()
                    for line in wl_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
            except Exception as exc:  # noqa: BLE001
                logger.warning("Could not read wordlist %s: %s", filename, exc)
                continue

            if paths:
                paths_by_source[filename] = paths

        return paths_by_source

    def _apply_cap(
        self,
        paths_by_source: dict[str, list[str]],
        files_meta: dict[str, Any],
    ) -> list[tuple[str, str]]:
        """Apply the 500-path cap with priority ordering.

        Priority
        --------
        1. always_probe paths first (in their wordlist order)
        2. framework-specific paths sorted by path_count ascending
           (smallest lists first → most targeted)

        Returns
        -------
        list[tuple[str, str]]
            Ordered list of ``(source_wordlist, path)`` pairs, deduplicated,
            limited to :data:`_MAX_PROBES`.
        """
        always_entries: list[tuple[str, str]] = []
        framework_entries: list[tuple[int, str, list[str]]] = []  # (path_count, filename, paths)

        for filename, paths in paths_by_source.items():
            meta = files_meta.get(filename, {})
            if meta.get("always_probe", False):
                for path in paths:
                    always_entries.append((filename, path))
            else:
                path_count = meta.get("path_count", len(paths))
                framework_entries.append((path_count, filename, paths))

        # Sort framework entries by path_count ascending
        framework_entries.sort(key=lambda x: x[0])

        # Combine, deduplicate paths, apply cap
        seen_paths: set[str] = set()
        combined: list[tuple[str, str]] = []

        for filename, path in always_entries:
            if path not in seen_paths:
                seen_paths.add(path)
                combined.append((filename, path))

        for _, filename, paths in framework_entries:
            for path in paths:
                if path not in seen_paths:
                    seen_paths.add(path)
                    combined.append((filename, path))

        return combined[:_MAX_PROBES]

    # ------------------------------------------------------------------
    # Canonical-redirect baseline detection
    # ------------------------------------------------------------------

    async def _detect_redirect_baseline(self) -> str | None:
        """Send a canary request to detect CMS canonical-redirect targets.

        Many CMS platforms (especially WordPress) redirect *any* unknown path
        to the homepage or a fuzzy-matched slug via 301/302.  By probing a
        deliberately nonsensical path first, we learn the server's default
        redirect target so we can filter it out during real probing.

        Returns
        -------
        str | None
            The normalised redirect-target path (lowercased, trailing-slash
            stripped) if the canary was redirected, or ``None`` if the server
            returned a non-redirect status.
        """
        canary_url = self._base_url + _CANARY_PATH
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=False,
                headers={"User-Agent": "stacksniff/1.0 (framework-prober)"},
            ) as client:
                resp = await client.get(canary_url)
                if resp.status_code in (301, 302):
                    location = resp.headers.get("location", "")
                    if location:
                        resolved = urljoin(canary_url, location)
                        baseline = urlparse(resolved).path.rstrip("/").lower() or "/"
                        logger.info(
                            "FrameworkProber: canonical-redirect baseline detected → %s",
                            baseline,
                        )
                        return baseline
        except (httpx.TimeoutException, httpx.RequestError) as exc:
            logger.debug("Canary request failed: %s", exc)
        return None

    @staticmethod
    def _is_canonical_redirect(
        probed_path: str,
        redirect_location: str,
        probe_url: str,
        baseline: str | None,
        source_wordlist: str,
    ) -> bool:
        """Decide whether a 301/302 redirect is a CMS canonical rewrite.

        A redirect is considered canonical (and therefore a false positive) if:

        1. **Baseline match** — the redirect target matches the canary
           baseline path (the server sends *every* unknown path here).
        2. **Fuzzy-slug rewrite** (generic wordlists only) — the probed path
           is structurally unrelated to the redirect target, indicating the
           CMS guessed a slug rather than serving a real endpoint.

        Parameters
        ----------
        probed_path:
            The path that was probed (e.g. ``/Com``).
        redirect_location:
            The raw ``Location`` header value from the response.
        probe_url:
            The full URL that was probed.
        baseline:
            The canonical-redirect baseline from :meth:`_detect_redirect_baseline`,
            or ``None`` if no baseline was detected.
        source_wordlist:
            The wordlist filename that sourced this path.
        """
        try:
            resolved = urljoin(probe_url, redirect_location)
            loc_path = urlparse(resolved).path.rstrip("/").lower() or "/"
        except Exception:
            return False

        # Rule 1: redirect lands on the same target as the canary baseline
        if baseline and loc_path == baseline:
            logger.debug(
                "Prober: discarding %s → %s (matches canonical baseline %s)",
                probed_path, redirect_location, baseline,
            )
            return True

        # Rule 2: for generic wordlists, detect fuzzy-slug rewrites.
        # CMS platforms guess slugs for unknown paths, producing redirects
        # whose targets are structurally unrelated to the probed path.
        #
        # Heuristic (hybrid):
        #   • Single-segment paths (e.g. /Com): strict path-segment prefix
        #     check — the redirect target must equal or extend the probed path
        #     at a segment boundary.
        #   • Multi-segment paths (e.g. /api/v1): parent-directory check —
        #     the redirect target must share the same parent segments.  This
        #     allows legitimate version redirects like /api/v1 → /api/v1.0.
        if source_wordlist.endswith(_GENERIC_WORDLISTS):
            probed_norm = probed_path.rstrip("/").lower()
            if not probed_norm:
                return False

            probed_segments = probed_norm.strip("/").split("/")
            loc_segments = loc_path.strip("/").split("/")

            if len(probed_segments) <= 1:
                # Single-segment: strict path-segment prefix
                if loc_path != probed_norm and not loc_path.startswith(probed_norm + "/"):
                    logger.debug(
                        "Prober: discarding %s → %s (fuzzy-slug rewrite, generic wordlist)",
                        probed_path, redirect_location,
                    )
                    return True
            else:
                # Multi-segment: parent directory segments must match
                probed_parent = probed_segments[:-1]
                loc_parent = loc_segments[: len(probed_parent)]
                if probed_parent != loc_parent:
                    logger.debug(
                        "Prober: discarding %s → %s (fuzzy-slug rewrite, generic wordlist)",
                        probed_path, redirect_location,
                    )
                    return True

        return False

    async def _probe_one(
        self,
        client: httpx.AsyncClient,
        source_wordlist: str,
        path: str,
        redirect_baseline: str | None = None,
    ) -> dict[str, Any] | None:
        """Probe a single path and return an endpoint dict or ``None``."""
        url = self._base_url + path
        try:
            response = await client.get(url, follow_redirects=False)
            status = response.status_code

            if status not in _STATUS_MAP:
                return None

            ct = response.headers.get("content-type", "") or ""
            ct_lower = ct.lower().strip()

            logger.debug("probe %s status=%d ct=%s", path, status, ct)

            if status in (301, 302):
                location = response.headers.get("location", "") or ""
                if location:
                    try:
                        # Resolve same-origin trailing slash normalization redirects
                        # (e.g. /admin -> /admin/) by following them one hop.
                        orig_parsed = urlparse(url)
                        orig_path = orig_parsed.path.rstrip("/").lower()
                        loc_parsed = urlparse(urljoin(url, location))
                        loc_path = loc_parsed.path.rstrip("/").lower()

                        # If same host and same path (modulo trailing slash), follow one hop
                        if (loc_parsed.netloc == orig_parsed.netloc or not loc_parsed.netloc) and loc_path == orig_path:
                            resolved_url = urljoin(url, location)
                            next_resp = await client.get(resolved_url, follow_redirects=False)
                            status = next_resp.status_code
                            response = next_resp
                            ct = response.headers.get("content-type", "") or ""
                            ct_lower = ct.lower().strip()
                            logger.debug("probe trailing-slash resolved %s status=%d ct=%s", resolved_url, status, ct)

                            if status not in _STATUS_MAP:
                                return None
                    except Exception as e:
                        logger.debug("Failed to resolve trailing slash redirect: %s", e)

            if status == 200:
                # Generic wordlists (no framework context): only accept
                # structured data content-types — HTML is always noise here.
                _ACCEPTED_TYPES = (
                    "application/json",
                    "application/yaml",
                    "application/xml",
                    "application/vnd.",
                    "text/plain",
                    "text/yaml",
                    "text/xml",
                    "text/csv",
                )
                if source_wordlist.endswith(_GENERIC_WORDLISTS):
                    if not any(ct_lower.startswith(t) for t in _ACCEPTED_TYPES):
                        return None
                elif ct_lower.startswith("text/html") or (not ct_lower and "html" in response.text[:200].lower()):
                    # For all other wordlists: HTML responses are soft-404s unless:
                    #   (a) the body parses as JSON (Content-Type lie), or
                    #   (b) the response is ≤10KB AND the path has a file extension
                    body_text = response.text
                    try:
                        json.loads(body_text)
                        # Parsed as JSON — keep it
                    except (json.JSONDecodeError, ValueError, Exception):
                        # Not JSON — apply size + extension heuristics
                        path_no_qs = urlparse(url).path
                        path_has_ext = "." in path_no_qs.split("/")[-1] if "/" in path_no_qs else "." in path_no_qs
                        body_large = len(body_text) > 10_240  # 10 KB
                        if body_large or not path_has_ext:
                            logger.debug(
                                "Prober: discarding %s (HTML soft-404: large=%s, no_ext=%s)",
                                url,
                                body_large,
                                not path_has_ext,
                            )
                            return None

            # Redirect-noise filter (Fix 2b): discard 3xx responses that are
            # CMS-style rewrites rather than real API redirects.  Patterns:
            #   • Canonical-redirect baseline match (canary detection)
            #   • Fuzzy-slug rewrite (generic wordlists)
            #   • Location path ends with /login, /settings, /session, etc.
            #   • Location redirects to a completely different apex domain
            if status in (301, 302):
                location = response.headers.get("location", "") or ""
                if location:
                    # --- Canonical-redirect filter (WordPress et al.) ---
                    if self._is_canonical_redirect(
                        path, location, url, redirect_baseline, source_wordlist,
                    ):
                        return None

                    try:
                        loc_parsed = urlparse(location)
                        loc_path = loc_parsed.path.rstrip("/").lower()
                        _NAV_SUFFIXES = (
                            "/login", "/settings", "/session",
                            "/signin", "/auth", "/logon",
                        )
                        if any(loc_path.endswith(s) for s in _NAV_SUFFIXES):
                            logger.debug(
                                "Prober: discarding %s \u2192 %s (nav redirect)",
                                url,
                                location,
                            )
                            return None

                        # Discard if redirect exits the target's apex domain
                        base_parsed = urlparse(self._base_url)

                        def _apex(host: str) -> str:
                            parts = host.lower().split(".")
                            return ".".join(parts[-2:]) if len(parts) >= 2 else host

                        loc_host = loc_parsed.netloc.split(":")[0]
                        if loc_host and _apex(loc_host) != _apex(base_parsed.netloc.split(":")[0]):
                            logger.debug(
                                "Prober: discarding %s \u2192 %s (cross-domain redirect)",
                                url,
                                location,
                            )
                            return None
                    except Exception:
                        pass

            label, confidence = _STATUS_MAP[status]

            top_level_keys: list[str] | None = None
            if "application/json" in ct_lower or (status == 200 and ct_lower.startswith("text/html")):
                try:
                    body = response.json()
                    if isinstance(body, dict):
                        top_level_keys = list(body.keys())
                except Exception:
                    pass

            ep: dict[str, Any] = {
                "url": url,
                "status_code": status,
                "status_label": label,
                "content_type": ct or None,
                "confidence": confidence,
                "source_wordlist": source_wordlist,
                "top_level_keys": top_level_keys,
            }

            # Capture redirect Location for 301/302
            if status in (301, 302):
                location = response.headers.get("location")
                if location:
                    ep["redirect_location"] = location

            return ep

        except httpx.TimeoutException:
            logger.debug("Timeout probing %s", url)
            return None
        except httpx.RequestError as exc:
            logger.debug("Request error probing %s: %s", url, exc)
            return None

    async def _probe_all(
        self,
        capped_paths: list[tuple[str, str]],
        redirect_baseline: str | None = None,
    ) -> list[dict[str, Any]]:
        """Fire all probes in batches of :data:`_BATCH_SIZE` using a shared client."""
        endpoints: list[dict[str, Any]] = []

        async with httpx.AsyncClient(
            timeout=self._timeout,
            follow_redirects=False,
            headers={"User-Agent": "stacksniff/1.0 (framework-prober)"},
        ) as client:
            for batch_start in range(0, len(capped_paths), _BATCH_SIZE):
                batch = capped_paths[batch_start : batch_start + _BATCH_SIZE]
                tasks = [
                    self._probe_one(client, src, path, redirect_baseline)
                    for src, path in batch
                ]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                for item in batch_results:
                    if isinstance(item, Exception):
                        logger.debug("Probe raised exception: %s", item)
                    elif item is not None:
                        endpoints.append(item)

        return endpoints
