"""Updater module for fetching and converting live Wappalyzer fingerprint rules."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path  # noqa: TC003
from typing import TYPE_CHECKING, Any

import httpx
import yaml

if TYPE_CHECKING:
    from collections.abc import Callable


@dataclass(frozen=True, slots=True)
class UpdateResult:
    """Result of the update-fingerprints execution."""

    techs_added: int
    techs_updated: int
    techs_preserved: int
    output_path: Path
    source_url: str
    openapi_spec_found: bool = field(default=False)


STANDARD_CATEGORIES = {
    "web-server": {"name": "Web Server"},
    "framework": {"name": "Web Framework"},
    "cdn": {"name": "CDN"},
    "cms": {"name": "CMS"},
    "database": {"name": "Database"},
    "js-library": {"name": "JavaScript Library"},
    "analytics": {"name": "Analytics"},
    "programming-language": {"name": "Programming Language"},
    "other": {"name": "Other"},
}


def map_category(cat_name: str) -> str:
    """Map a Wappalyzer category name to a stacksniff category key."""
    name_lower = cat_name.lower()
    if "web server" in name_lower:
        return "web-server"
    if "framework" in name_lower:
        return "framework"
    if "cdn" in name_lower:
        return "cdn"
    if (
        "cms" in name_lower
        or "blog" in name_lower
        or "web shop" in name_lower
        or "ecommerce" in name_lower
        or "wiki" in name_lower
        or "message board" in name_lower
    ):
        return "cms"
    if "database" in name_lower:
        return "database"
    if (
        "javascript library" in name_lower
        or "js library" in name_lower
        or "javascript libraries" in name_lower
    ):
        return "js-library"
    if "analytics" in name_lower or "tag manager" in name_lower:
        return "analytics"
    if "programming language" in name_lower:
        return "programming-language"
    return "other"


def get_tech_category(cat_ids: list[int | str], categories_map: dict[str, Any]) -> str:
    """Resolve a list of Wappalyzer category IDs to a single stacksniff category."""
    mapped = []
    for cid in cat_ids:
        cid_str = str(cid)
        cat_info = categories_map.get(cid_str)
        if cat_info and "name" in cat_info:
            mapped.append(map_category(cat_info["name"]))

    # Return the first non-other category, or fallback to the first mapped, or "other"
    for cat in mapped:
        if cat != "other":
            return cat
    if mapped:
        return mapped[0]
    return "other"


def parse_pattern(pattern: str) -> tuple[str, float | None]:
    """Parse a Wappalyzer pattern, stripping version/confidence suffixes.

    Returns a tuple of (clean_regex, confidence_float).
    """
    if not pattern:
        return "", None

    parts = pattern.split("\\;")
    regex = parts[0]
    confidence = None

    for part in parts[1:]:
        if part.startswith("confidence:"):
            try:
                val = float(part.split(":")[1]) / 100.0
                confidence = val
            except (ValueError, IndexError):
                pass

    return regex, confidence


def parse_implies(implies_raw: str | list[str]) -> list[str]:
    """Normalize and clean implies list, stripping version/confidence suffixes."""
    if not implies_raw:
        return []
    if isinstance(implies_raw, str):
        implies_raw = [implies_raw]

    res = []
    for imp in implies_raw:
        if imp:
            cleaned = imp.split("\\;")[0]
            if cleaned:
                res.append(cleaned)
    return res


async def fetch_and_convert(
    output_path: Path,
    *,
    timeout: float = 30.0,
    progress_callback: Callable[[str], None] | None = None,
) -> UpdateResult:
    """Fetch Wappalyzer rules, convert to stacksniff schema, merge with custom rules.

    Parameters
    ----------
    output_path:
        Path where the final tech.yaml will be written.
    timeout:
        Timeout in seconds for HTTP requests.
    progress_callback:
        Optional callback called with the file character key on successful fetch.
    """
    source_url = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/"
    categories_url = (
        "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/categories.json"
    )

    async with httpx.AsyncClient(timeout=timeout) as client:
        # 1. Fetch categories
        r_cats = await client.get(categories_url)
        r_cats.raise_for_status()
        categories_map = r_cats.json()

        # 2. Concurrently fetch all 27 technology rule files
        chars = [chr(c) for c in range(ord("a"), ord("z") + 1)] + ["_"]

        async def fetch_one(char: str) -> dict[str, Any]:
            url = f"{source_url}{char}.json"
            res = await client.get(url)
            res.raise_for_status()
            data = res.json()
            if progress_callback:
                progress_callback(char)
            return data

        results = await asyncio.gather(*(fetch_one(c) for c in chars))

    # 3. Parse and map Wappalyzer JSON files
    upstream_techs: dict[str, dict[str, Any]] = {}

    for file_data in results:
        if not isinstance(file_data, dict):
            continue
        for tech_name, data in file_data.items():
            if not isinstance(data, dict):
                continue

            confidences: list[float] = []

            # Headers
            headers = {}
            for k, v in data.get("headers", {}).items():
                patterns = [v] if isinstance(v, str) else v
                for pat in patterns:
                    if not isinstance(pat, str):
                        continue
                    reg, conf = parse_pattern(pat)
                    if reg:
                        headers[k] = reg
                        if conf is not None:
                            confidences.append(conf)
                        break

            # Cookies
            cookies = {}
            for k, v in data.get("cookies", {}).items():
                patterns = [v] if isinstance(v, str) else v
                for pat in patterns:
                    if not isinstance(pat, str):
                        continue
                    reg, conf = parse_pattern(pat)
                    if reg:
                        cookies[k] = reg
                        if conf is not None:
                            confidences.append(conf)
                        break

            # Meta
            meta = {}
            for k, v in data.get("meta", {}).items():
                patterns = [v] if isinstance(v, str) else v
                for pat in patterns:
                    if not isinstance(pat, str):
                        continue
                    reg, conf = parse_pattern(pat)
                    if reg:
                        meta[k] = reg
                        if conf is not None:
                            confidences.append(conf)
                        break

            # HTML
            html = []
            raw_html = data.get("html", [])
            raw_html_list = [raw_html] if isinstance(raw_html, str) else raw_html
            for pat in raw_html_list:
                if not isinstance(pat, str):
                    continue
                reg, conf = parse_pattern(pat)
                if reg:
                    html.append(reg)
                    if conf is not None:
                        confidences.append(conf)

            # Scripts
            scripts = []
            raw_script = data.get("scriptSrc", []) or data.get("scripts", []) or data.get("script", [])
            raw_script_list = [raw_script] if isinstance(raw_script, str) else raw_script
            for pat in raw_script_list:
                if not isinstance(pat, str):
                    continue
                reg, conf = parse_pattern(pat)
                if reg:
                    scripts.append(reg)
                    if conf is not None:
                        confidences.append(conf)

            # JS Globals
            js_globals = {}
            for k, v in data.get("js", {}).items():
                patterns = [v] if isinstance(v, str) else v
                for pat in patterns:
                    if not isinstance(pat, str):
                        continue
                    reg, conf = parse_pattern(pat)
                    if not reg:
                        reg = "."
                    js_globals[k] = reg
                    if conf is not None:
                        confidences.append(conf)
                    break

            # DOM
            dom = None
            raw_dom = data.get("dom")
            if raw_dom:
                if isinstance(raw_dom, str):
                    dom = [raw_dom]
                elif isinstance(raw_dom, list):
                    dom = [item for item in raw_dom if isinstance(item, str)]
                elif isinstance(raw_dom, dict):
                    dom = {}
                    for sel, rule in raw_dom.items():
                        if not isinstance(rule, dict):
                            dom[sel] = {}
                            continue
                        normalized_rule = {}
                        if "exists" in rule:
                            normalized_rule["exists"] = ""
                        if "text" in rule:
                            patterns = [rule["text"]] if isinstance(rule["text"], str) else rule["text"]
                            for pat in patterns:
                                if isinstance(pat, str):
                                    reg, conf = parse_pattern(pat)
                                    if reg:
                                        normalized_rule["text"] = reg
                                        if conf is not None:
                                            confidences.append(conf)
                                        break
                        if "properties" in rule and isinstance(rule["properties"], dict):
                            props = {}
                            for prop_name, pat in rule["properties"].items():
                                patterns = [pat] if isinstance(pat, str) else pat
                                for ppat in patterns:
                                    if isinstance(ppat, str):
                                        reg, conf = parse_pattern(ppat)
                                        if not reg:
                                            reg = "."
                                        props[prop_name] = reg
                                        if conf is not None:
                                            confidences.append(conf)
                                        break
                            if props:
                                normalized_rule["properties"] = props
                        if "attributes" in rule and isinstance(rule["attributes"], dict):
                            attrs = {}
                            for attr_name, pat in rule["attributes"].items():
                                patterns = [pat] if isinstance(pat, str) else pat
                                for ppat in patterns:
                                    if isinstance(ppat, str):
                                        reg, conf = parse_pattern(ppat)
                                        if not reg:
                                            reg = "."
                                        attrs[attr_name] = reg
                                        if conf is not None:
                                            confidences.append(conf)
                                        break
                            if attrs:
                                normalized_rule["attributes"] = attrs
                        dom[sel] = normalized_rule

            # Implies
            implies = parse_implies(data.get("implies", []))

            # Confidence (max from patterns, fallback to 0.75)
            confidence = max(confidences) if confidences else 0.75

            # Construct stacksniff fingerprint format
            mapped_tech = {
                "name": tech_name,
                "category": get_tech_category(data.get("cats", []), categories_map),
                "website": data.get("website") or "https://github.com/enthec/webappanalyzer",
                "confidence": confidence,
            }
            if headers:
                mapped_tech["headers"] = headers
            if cookies:
                mapped_tech["cookies"] = cookies
            if meta:
                mapped_tech["meta"] = meta
            if html:
                mapped_tech["html"] = html
            if scripts:
                mapped_tech["scripts"] = scripts
            if js_globals:
                mapped_tech["js_globals"] = js_globals
            if dom:
                mapped_tech["dom"] = dom
            if implies:
                mapped_tech["implies"] = implies

            upstream_techs[tech_name] = mapped_tech

    # 4. Merge with existing custom rules (upstream wins on conflict)
    custom_techs = {}
    if output_path.is_file():
        try:
            with output_path.open("r", encoding="utf-8") as f:
                existing_data = yaml.safe_load(f) or {}
                custom_techs = existing_data.get("technologies", {})
        except Exception:
            pass

    upstream_keys_lower = {k.lower() for k in upstream_techs}

    techs_added = 0
    techs_updated = 0
    techs_preserved = 0

    merged_technologies = {}

    # 1. Add preserved custom rules (not present in upstream)
    for custom_key, custom_data in custom_techs.items():
        if custom_key.lower() not in upstream_keys_lower:
            merged_technologies[custom_key] = custom_data
            techs_preserved += 1

    # 2. Add upstream rules
    for upstream_name, upstream_data in upstream_techs.items():
        upstream_key_lower = upstream_name.lower()

        # Check conflict
        has_conflict = False
        custom_key_matching = None
        for ck in custom_techs:
            if ck.lower() == upstream_key_lower:
                has_conflict = True
                custom_key_matching = ck
                break

        if has_conflict:
            techs_updated += 1
            # Hybrid merge: upstream data updated with custom rules taking precedence
            custom_data = custom_techs[custom_key_matching]
            merged_tech = upstream_data.copy()
            
            # Confidence overrides
            if "confidence" in custom_data:
                merged_tech["confidence"] = custom_data["confidence"]
                
            # Merge list properties (html, scripts)
            for list_key in ["html", "scripts"]:
                if list_key in custom_data:
                    c_val = custom_data[list_key]
                    c_list = c_val if isinstance(c_val, list) else [c_val]
                    u_val = merged_tech.get(list_key, [])
                    u_list = u_val if isinstance(u_val, list) else [u_val]
                    
                    combined = list(u_list)
                    for val in c_list:
                        if val not in combined:
                            combined.append(val)
                    if combined:
                        merged_tech[list_key] = combined
                        
            # Merge dict properties (js_globals, headers, cookies, meta)
            for dict_key in ["js_globals", "headers", "cookies", "meta"]:
                if dict_key in custom_data and isinstance(custom_data[dict_key], dict):
                    merged_dict = merged_tech.get(dict_key, {}).copy()
                    merged_dict.update(custom_data[dict_key])
                    merged_tech[dict_key] = merged_dict
            
            # Merge dom property
            if "dom" in custom_data:
                c_dom = custom_data["dom"]
                u_dom = merged_tech.get("dom")
                if isinstance(c_dom, list) and isinstance(u_dom, list):
                    combined = list(u_dom)
                    for item in c_dom:
                        if item not in combined:
                            combined.append(item)
                    merged_tech["dom"] = combined
                elif isinstance(c_dom, dict) and isinstance(u_dom, dict):
                    merged_dict = u_dom.copy() if u_dom else {}
                    merged_dict.update(c_dom)
                    merged_tech["dom"] = merged_dict
                else:
                    merged_tech["dom"] = c_dom
            
            merged_technologies[upstream_key_lower] = merged_tech
        else:
            techs_added += 1
            merged_technologies[upstream_key_lower] = upstream_data

    # 5. Output merged results
    final_data = {
        "version": "1.0.0",
        "categories": STANDARD_CATEGORIES,
        "technologies": merged_technologies,
    }

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        yaml.dump(final_data, f, sort_keys=False, allow_unicode=True)

    return UpdateResult(
        techs_added=techs_added,
        techs_updated=techs_updated,
        techs_preserved=techs_preserved,
        output_path=output_path,
        source_url=source_url,
    )
