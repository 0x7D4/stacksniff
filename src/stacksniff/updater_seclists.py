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
# Helpers
# ---------------------------------------------------------------------------


def normalize_filename(filename: str) -> str:
    """Normalize filename: strip .txt, lowercase, replace hyphens/underscores with space, special case: js -> .js."""
    stem = filename.lower()
    if stem.endswith(".txt"):
        stem = stem[:-4]
    normalized = stem.replace("-", " ").replace("_", " ")
    # Special case: js -> .js
    # Replace " js" with ".js"
    normalized = normalized.replace(" js", ".js")
    return normalized


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

    Retrieves the directory listings for danielmiessler/SecLists Web-Content
    and its api/ subdirectory from GitHub API. Files are normalized and mapped
    to FingerprintStore technologies. Relevant files are fetched concurrently
    using their download_urls.

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

    # Load FingerprintStore from newly-updated tech.yaml if present, or fallback
    tech_yaml_path = output_dir.parent / "tech.yaml"
    from stacksniff.fingerprints import FingerprintStore
    if tech_yaml_path.is_file():
        store = FingerprintStore.from_yaml(tech_yaml_path)
    else:
        store = FingerprintStore.default()

    headers = {
        "User-Agent": "stacksniff/0.1.0 (SecLists dynamic updater)"
    }

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        # Fetch root listing
        try:
            resp1 = await client.get(
                "https://api.github.com/repos/danielmiessler/SecLists/contents/Discovery/Web-Content",
                headers=headers,
            )
            resp1.raise_for_status()
            items1 = resp1.json()
        except Exception as e:
            logger.error("Failed to fetch SecLists directory listing: %s", e)
            items1 = []

        # Fetch api/ subdirectory listing
        try:
            resp2 = await client.get(
                "https://api.github.com/repos/danielmiessler/SecLists/contents/Discovery/Web-Content/api",
                headers=headers,
            )
            resp2.raise_for_status()
            items2 = resp2.json()
        except Exception as e:
            logger.error("Failed to fetch SecLists api subdirectory listing: %s", e)
            items2 = []

    all_items = []
    if isinstance(items1, list):
        all_items.extend(items1)
    if isinstance(items2, list):
        all_items.extend(items2)

    unique_files = {}
    for item in all_items:
        if isinstance(item, dict) and item.get("type") == "file":
            name = item.get("name", "")
            if name.endswith(".txt") and item.get("download_url"):
                unique_files[name] = item

    always_probe_names = {
        "api-endpoints.txt",
        "swagger.txt",
        "graphql.txt",
        "api-seen-in-the-wild.txt",
        "api-seen-in-wild.txt",
        "objects.txt",
        "actions.txt",
    }

    files_to_download = []
    for filename, item in unique_files.items():
        normalized = normalize_filename(filename)

        # Check matches in FingerprintStore (case-insensitive substring match)
        tech_match = []
        for tech_key in store.technologies.keys():
            if normalized in tech_key:
                tech_match.append(tech_key)

        tech_match.sort()

        if tech_match:
            always_probe = False
        else:
            always_probe = filename in always_probe_names

        if tech_match or always_probe:
            files_to_download.append({
                "name": filename,
                "download_url": item["download_url"],
                "tech_match": tech_match,
                "always_probe": always_probe,
            })

    async def _fetch_one_file(
        client: httpx.AsyncClient,
        file_info: dict,
    ) -> tuple[str, list[str]]:
        url = file_info["download_url"]
        name = file_info["name"]
        try:
            response = await client.get(url)
            response.raise_for_status()
            paths = _parse_wordlist(response.text)
            logger.debug("Fetched %s → %d paths", name, len(paths))
            return name, paths
        except Exception as exc:
            logger.warning("Error fetching SecLists file %s: %s", name, exc)
            return name, []

    if files_to_download:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            download_tasks = [
                _fetch_one_file(client, f) for f in files_to_download
            ]
            download_results = await asyncio.gather(*download_tasks)
    else:
        download_results = []

    # Build result map and persist to disk
    manifest_entries: dict[str, Any] = {}
    total_paths = 0
    files_fetched = 0

    download_results_map = dict(download_results)

    for filename, item in unique_files.items():
        normalized = normalize_filename(filename)

        # Check matches in FingerprintStore
        tech_match = []
        for tech_key in store.technologies.keys():
            if normalized in tech_key:
                tech_match.append(tech_key)

        tech_match.sort()

        if tech_match:
            always_probe = False
        else:
            always_probe = filename in always_probe_names

        path_count = 0
        if filename in download_results_map:
            paths = download_results_map[filename]
            path_count = len(paths)
            total_paths += path_count
            if path_count > 0:
                files_fetched += 1

            # Save wordlist file
            out_file = output_dir / filename
            out_file.write_text("\n".join(paths), encoding="utf-8")

        manifest_entries[filename] = {
            "tech_match": tech_match,
            "path_count": path_count,
            "always_probe": always_probe,
        }

    # Write manifest YAML
    manifest: dict[str, Any] = {
        "version": datetime.now(UTC).isoformat(),
        "source": "dynamic",
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

