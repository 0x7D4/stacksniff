"""SecLists-based wordlist fetcher for stacksniff framework probing.

Fetches community-maintained discovery wordlists from the SecLists project on
GitHub and saves them locally under ``fingerprints/seclists/`` alongside a
manifest YAML that maps each file to its associated technology keywords.

Usage::

    from pathlib import Path
    from stacksniff.updater_seclists import fetch_seclists

    result = await fetch_seclists(Path("fingerprints/seclists"))
    print(f"Fetched {result.files_fetched} files, {result.total_paths} paths")
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path  # noqa: TC003
from typing import Any

import httpx
import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SecLists base URL
# ---------------------------------------------------------------------------

_BASE_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/"
)

# ---------------------------------------------------------------------------
# Wordlist manifest: remote_key → (disk_filename, tech_match list, always_probe flag)
# Each tuple element:
#   disk_filename – filename to save as under output_dir (no path separators)
#   tech_match    – list of lowercase tech keywords; empty list means always probe
#   always_probe  – True means include paths regardless of detected tech
# ---------------------------------------------------------------------------

_WORDLIST_CONFIG: dict[str, tuple[str, list[str], bool]] = {
    # Framework-specific (in CMS/ and Programming-Language-Specific/ subdirs)
    "Programming-Language-Specific/Java-Spring-Boot.txt": (
        "spring-boot.txt",
        ["spring boot", "spring", "java"],
        False,
    ),
    "CMS/Django.txt": (
        "django.txt",
        ["django", "python"],
        False,
    ),
    "Programming-Language-Specific/ror.txt": (
        "rails.txt",
        ["ruby on rails", "rails", "ruby"],
        False,
    ),
    "CMS/wordpress.fuzz.txt": (
        "wordpress.txt",
        ["wordpress", "woocommerce"],
        False,
    ),
    "Programming-Language-Specific/PHP.fuzz.txt": (
        "laravel.txt",
        ["laravel", "php"],
        False,
    ),
    "CMS/Drupal.txt": (
        "drupal.txt",
        ["drupal"],
        False,
    ),
    "CMS/joomla-plugins.fuzz.txt": (
        "joomla.txt",
        ["joomla"],
        False,
    ),
    # General API discovery — always probed regardless of detected tech
    "api/api-endpoints.txt": (
        "api-endpoints.txt",
        [],
        True,
    ),
    "Service-Specific/Swagger.txt": (
        "swagger.txt",
        [],
        True,
    ),
    "graphql.txt": (
        "graphql.txt",
        [],
        True,
    ),
}


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SeclistsUpdateResult:
    """Result of a SecLists wordlist fetch operation."""

    files_fetched: int
    total_paths: int
    output_dir: Path
    manifest_path: Path


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------



def _parse_wordlist(raw_text: str) -> list[str]:
    """Parse a SecLists wordlist from raw text.

    Rules
    -----
    * Strip leading/trailing whitespace from each line.
    * Skip blank lines.
    * Skip comment lines (starting with ``#``).
    * Ensure every path starts with ``/``.
    * Deduplicate while preserving original order.
    """
    seen: set[str] = set()
    paths: list[str] = []

    for line in raw_text.splitlines():
        path = line.strip()
        if not path or path.startswith("#"):
            continue
        if not path.startswith("/"):
            path = "/" + path
        if path not in seen:
            seen.add(path)
            paths.append(path)

    return paths


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_seclists(
    output_dir: Path,
    *,
    timeout: float = 30.0,
) -> SeclistsUpdateResult:
    """Fetch SecLists wordlists concurrently and persist them to *output_dir*.

    All 11 wordlists are fetched in a single :class:`httpx.AsyncClient` session
    using :func:`asyncio.gather` for maximum concurrency.  Each file is parsed,
    deduplicated, and written to ``output_dir/<filename>.txt``.  A
    ``manifest.yaml`` is written alongside the wordlist files.

    Parameters
    ----------
    output_dir:
        Directory where wordlist ``.txt`` files and ``manifest.yaml`` will be
        written.  Created if it does not exist.
    timeout:
        Per-request HTTP timeout in seconds.

    Returns
    -------
    SeclistsUpdateResult
        Summary of the fetch operation.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    async def _fetch_one(
        client: httpx.AsyncClient,
        remote_key: str,
    ) -> tuple[str, list[str]]:
        """Fetch a single wordlist file and return ``(remote_key, paths)``."""
        url = _BASE_URL + remote_key
        try:
            response = await client.get(url)
            response.raise_for_status()
            paths = _parse_wordlist(response.text)
            logger.debug("Fetched %s → %d paths", remote_key, len(paths))
            return remote_key, paths
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "HTTP %s fetching SecLists wordlist %s: %s",
                exc.response.status_code,
                remote_key,
                exc,
            )
            return remote_key, []
        except httpx.RequestError as exc:
            logger.warning("Network error fetching SecLists wordlist %s: %s", remote_key, exc)
            return remote_key, []

    # Fetch all wordlists concurrently
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        fetch_tasks = [
            _fetch_one(client, remote_key) for remote_key in _WORDLIST_CONFIG
        ]
        raw_results: list[tuple[str, list[str]]] = await asyncio.gather(*fetch_tasks)

    # Build result map and persist to disk
    manifest_entries: dict[str, Any] = {}
    total_paths = 0
    files_fetched = 0

    for remote_key, paths in raw_results:
        disk_name, tech_match, always_probe = _WORDLIST_CONFIG[remote_key]

        # Save wordlist file
        out_file = output_dir / disk_name
        out_file.write_text("\n".join(paths), encoding="utf-8")

        path_count = len(paths)
        total_paths += path_count
        if path_count > 0:
            files_fetched += 1

        manifest_entries[disk_name] = {
            "tech_match": tech_match,
            "path_count": path_count,
            "always_probe": always_probe,
        }

    # Write manifest YAML
    manifest: dict[str, Any] = {
        "version": datetime.now(UTC).isoformat(),
        "files": manifest_entries,
    }
    manifest_path = output_dir / "manifest.yaml"
    manifest_path.write_text(
        yaml.dump(manifest, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )

    logger.info(
        "SecLists update complete: %d files, %d total paths → %s",
        files_fetched,
        total_paths,
        output_dir,
    )

    return SeclistsUpdateResult(
        files_fetched=files_fetched,
        total_paths=total_paths,
        output_dir=output_dir,
        manifest_path=manifest_path,
    )
