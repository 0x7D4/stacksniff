"""JSON file-based cache for scan results."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from stacksniff.models import ScanResult

logger = logging.getLogger(__name__)


class ScanCache:
    """A thread-safe, JSON-file-based result cache."""

    def __init__(self, directory: Path | None = None, default_ttl: int = 1800) -> None:
        if directory is None:
            cache_env = os.environ.get("STACKSNIFF_CACHE_DIR")
            if cache_env:
                self.directory = Path(cache_env)
            else:
                self.directory = Path.home() / ".stacksniff" / "cache"
        else:
            self.directory = Path(directory)

        self.default_ttl = default_ttl
        self._hits = 0
        self._misses = 0

    def _make_key(self, url: str, options: dict[str, Any]) -> str:
        """Compute SHA-256 hash from URL and non-transient options."""
        def _as_bool(val: Any, default: bool) -> bool:
            if val is None:
                return default
            if isinstance(val, bool):
                return val
            if isinstance(val, str):
                return val.lower() in ("true", "1", "yes")
            return bool(val)

        canonical = {
            "browser": _as_bool(options.get("browser"), True),
            "scan_technologies": _as_bool(options.get("scan_technologies"), True),
            "scan_subdomains": _as_bool(options.get("scan_subdomains", options.get("subdomains")), True),
            "scan_endpoints": _as_bool(options.get("scan_endpoints"), True),
            "fingerprints_path": options.get("fingerprints_path"),
            "crawl_depth": int(options.get("crawl_depth", 1)),
        }
        # Normalize fingerprints_path to either a string or None
        fp_path = canonical["fingerprints_path"]
        canonical["fingerprints_path"] = str(fp_path) if fp_path else None

        payload = f"{url.strip()}:{json.dumps(canonical, sort_keys=True)}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, url: str, options: dict[str, Any]) -> ScanResult | None:
        """Retrieve a cached ScanResult if present, valid, and not expired."""
        key = self._make_key(url, options)
        file_path = self.directory / f"{key}.json"

        if not file_path.is_file():
            self._misses += 1
            return None

        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

            expires_at = data.get("expires_at")
            if expires_at is not None and time.time() > expires_at:
                # Expired
                logger.debug("Cache entry for %s expired, invalidating", url)
                self.invalidate(url, options)
                self._misses += 1
                return None

            result_dict = data.get("result")
            if not result_dict:
                self._misses += 1
                return None

            scan_result = ScanResult.from_dict(result_dict)
            self._hits += 1
            return scan_result

        except Exception as e:
            logger.warning("Failed to read cache file %s: %s", file_path, e)
            self._misses += 1
            return None

    def set(
        self,
        url: str,
        options: dict[str, Any],
        result: ScanResult,
        ttl: int | None = None,
    ) -> None:
        """Cache a ScanResult atomically."""
        key = self._make_key(url, options)
        self.directory.mkdir(parents=True, exist_ok=True)
        file_path = self.directory / f"{key}.json"

        use_ttl = ttl if ttl is not None else self.default_ttl
        expires_at = time.time() + use_ttl

        # Serialize options to keep in metadata for auditability
        clean_opts = {
            k: str(v)
            for k, v in options.items()
            if k not in ("timeout", "cache_bypass", "cache_ttl", "progress_callback")
        }

        cache_data = {
            "url": url,
            "options": clean_opts,
            "expires_at": expires_at,
            "result": result.to_dict(),
        }

        # Atomic write
        fd, temp_path = tempfile.mkstemp(dir=str(self.directory), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)
            os.replace(temp_path, file_path)
        except Exception as e:
            logger.error("Failed to write cache file %s: %s", file_path, e)
            if os.path.exists(temp_path):
                import contextlib
                with contextlib.suppress(OSError):
                    os.remove(temp_path)

    def invalidate(self, url: str, options: dict[str, Any]) -> bool:
        """Remove a cached result if it exists. Returns True if removed."""
        key = self._make_key(url, options)
        file_path = self.directory / f"{key}.json"
        if file_path.is_file():
            try:
                file_path.unlink()
                return True
            except OSError as e:
                logger.warning("Failed to delete cache file %s: %s", file_path, e)
        return False

    def clear(self) -> int:
        """Clear all entries in the cache. Returns number of files deleted."""
        if not self.directory.is_dir():
            return 0

        count = 0
        for entry in self.directory.iterdir():
            if entry.is_file() and (entry.suffix == ".json" or entry.suffix == ".tmp"):
                try:
                    entry.unlink()
                    count += 1
                except OSError as e:
                    logger.warning("Failed to delete cache file %s during clear: %s", entry, e)
        return count

    def clear_expired(self) -> int:
        """Remove all expired cache entries. Returns number of files deleted."""
        if not self.directory.is_dir():
            return 0

        now = time.time()
        count = 0
        for entry in self.directory.iterdir():
            if entry.is_file() and entry.suffix == ".json":
                try:
                    with open(entry, encoding="utf-8") as f:
                        data = json.load(f)
                    expires_at = data.get("expires_at")
                    if expires_at is not None and now > expires_at:
                        entry.unlink()
                        count += 1
                except Exception as e:
                    logger.debug("Failed to check/unlink cache entry %s: %s", entry, e)
        return count

    def stats(self) -> dict[str, Any]:
        """Return cache usage statistics and directory information."""
        total_files = 0
        total_size = 0
        if self.directory.is_dir():
            for entry in self.directory.iterdir():
                if entry.is_file() and entry.suffix == ".json":
                    total_files += 1
                    import contextlib
                    with contextlib.suppress(OSError):
                        total_size += entry.stat().st_size

        return {
            "cache_directory": str(self.directory),
            "total_entries": total_files,
            "size_bytes": total_size,
            "hits": self._hits,
            "misses": self._misses,
        }


_cache: ScanCache | None = None


def get_cache(default_ttl: int | None = None) -> ScanCache:
    """Return the global singleton ScanCache instance."""
    global _cache
    if _cache is None:
        ttl = default_ttl
        if ttl is None:
            ttl = int(os.environ.get("STACKSNIFF_CACHE_TTL", "1800"))
        _cache = ScanCache(default_ttl=ttl)
    return _cache
