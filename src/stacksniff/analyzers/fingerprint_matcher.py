"""Match evidence against technology fingerprints."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from stacksniff.fingerprints import FingerprintStore
from stacksniff.models import Evidence, TechMatch

logger = logging.getLogger(__name__)


def _normalize_js_key(k: str) -> str:
    """Normalize a JS global variable name for matching.

    Removes 'window.' prefix, handles optional chaining, and lowercases.
    """
    if k.startswith("window."):
        k = k[7:]
    k = k.replace("?.", ".")
    if k.endswith("()"):
        k = k[:-2]
    return k.lower().strip()


class FingerprintMatcher:
    """Matches collected evidence against technology fingerprints."""

    def __init__(self, store: FingerprintStore) -> None:
        self.store = store

    def match(self, evidence_data: dict[str, Any]) -> list[TechMatch]:
        """Match collected evidence against all fingerprints in the store.

        Parameters
        ----------
        evidence_data:
            The raw evidence dictionary containing:
            - headers (dict[str, str])
            - cookies (dict[str, str])
            - meta_tags (dict[str, str])
            - script_srcs (list[str])
            - link_hrefs (list[str])
            - html (str or raw_html)
            - js_globals (dict[str, str])

        Returns
        -------
        list[TechMatch]
            List of matched technologies sorted by confidence descending.
        """
        # Extract fields with safe fallbacks
        headers = {k.lower(): v for k, v in evidence_data.get("headers", {}).items()}
        cookies = {k.lower(): v for k, v in evidence_data.get("cookies", {}).items()}
        meta_tags = {k.lower(): v for k, v in evidence_data.get("meta_tags", {}).items()}
        script_srcs = list(evidence_data.get("script_srcs", []))
        link_hrefs = list(evidence_data.get("link_hrefs", []))
        raw_html = str(evidence_data.get("html", "") or evidence_data.get("raw_html", ""))
        js_globals = {
            _normalize_js_key(k): v for k, v in evidence_data.get("js_globals", {}).items()
        }

        # Combine scripts and link hrefs for broader script matching
        all_scripts = script_srcs + link_hrefs

        matches: list[TechMatch] = []

        for fp in self.store.get_all():
            matched_sources: set[str] = set()
            evidences: list[Evidence] = []
            versions: list[str] = []

            # 1. Match Headers
            for header_key, pattern in fp.headers.items():
                header_val = headers.get(header_key.lower())
                if header_val is not None:
                    try:
                        rx = re.compile(pattern, re.IGNORECASE)
                        match = rx.search(header_val)
                        if match:
                            matched_sources.add("header")
                            evidences.append(
                                Evidence(
                                    source="header",
                                    key=header_key,
                                    matched=header_val,
                                    pattern=pattern,
                                )
                            )
                            if rx.groups > 0 and len(match.groups()) >= 1:
                                v = match.group(1)
                                if v:
                                    versions.append(v)
                    except re.error as exc:
                        logger.warning(
                            "Invalid regex in header rule for %s -> %s: %s",
                            fp.name,
                            header_key,
                            exc,
                        )

            # 2. Match Cookies
            for cookie_key, pattern in fp.cookies.items():
                cookie_val = cookies.get(cookie_key.lower())
                if cookie_val is not None:
                    try:
                        rx = re.compile(pattern, re.IGNORECASE)
                        match = rx.search(cookie_val)
                        if match:
                            matched_sources.add("cookie")
                            evidences.append(
                                Evidence(
                                    source="cookie",
                                    key=cookie_key,
                                    matched=cookie_val,
                                    pattern=pattern,
                                )
                            )
                            if rx.groups > 0 and len(match.groups()) >= 1:
                                v = match.group(1)
                                if v:
                                    versions.append(v)
                    except re.error as exc:
                        logger.warning(
                            "Invalid regex in cookie rule for %s -> %s: %s",
                            fp.name,
                            cookie_key,
                            exc,
                        )

            # 3. Match Meta Tags
            for meta_key, pattern in fp.meta.items():
                meta_val = meta_tags.get(meta_key.lower())
                if meta_val is not None:
                    try:
                        rx = re.compile(pattern, re.IGNORECASE)
                        match = rx.search(meta_val)
                        if match:
                            matched_sources.add("meta")
                            evidences.append(
                                Evidence(
                                    source="meta",
                                    key=meta_key,
                                    matched=meta_val,
                                    pattern=pattern,
                                )
                            )
                            if rx.groups > 0 and len(match.groups()) >= 1:
                                v = match.group(1)
                                if v:
                                    versions.append(v)
                    except re.error as exc:
                        logger.warning(
                            "Invalid regex in meta rule for %s -> %s: %s",
                            fp.name,
                            meta_key,
                            exc,
                        )

            # 4. Match Script Src / Link Hrefs
            for pattern in fp.scripts:
                matched_script = None
                matched_val = ""
                # Try substring check first for speed
                for script in all_scripts:
                    if pattern in script:
                        matched_script = script
                        matched_val = script
                        break

                # Fallback to full regex matching
                if not matched_script:
                    try:
                        rx = re.compile(pattern, re.IGNORECASE)
                        for script in all_scripts:
                            match = rx.search(script)
                            if match:
                                matched_script = script
                                matched_val = script
                                if rx.groups > 0 and len(match.groups()) >= 1:
                                    v = match.group(1)
                                    if v:
                                        versions.append(v)
                                break
                    except re.error as exc:
                        logger.warning(
                            "Invalid regex in script rule for %s -> %s: %s",
                            fp.name,
                            pattern,
                            exc,
                        )

                if matched_script:
                    matched_sources.add("script")
                    evidences.append(
                        Evidence(
                            source="script",
                            key="script_src",
                            matched=matched_val,
                            pattern=pattern,
                        )
                    )

            # 5. Match HTML
            for pattern in fp.html:
                try:
                    rx = re.compile(pattern, re.IGNORECASE)
                    match = rx.search(raw_html)
                    if match:
                        matched_sources.add("html")
                        evidences.append(
                            Evidence(
                                source="html",
                                key="raw_html",
                                matched=match.group(0)[:100] + "...",
                                pattern=pattern,
                            )
                        )
                        if rx.groups > 0 and len(match.groups()) >= 1:
                            v = match.group(1)
                            if v:
                                versions.append(v)
                except re.error as exc:
                    logger.warning(
                        "Invalid regex in html rule for %s -> %s: %s",
                        fp.name,
                        pattern,
                        exc,
                    )

            # 6. Match JS Globals
            for global_key, pattern in fp.js_globals.items():
                normalized_rule_key = _normalize_js_key(global_key)
                # Check for existence of the normalized key
                if normalized_rule_key in js_globals:
                    global_val = js_globals[normalized_rule_key]
                    matched_js = False
                    if pattern == ".":
                        matched_js = True
                    else:
                        try:
                            rx = re.compile(pattern, re.IGNORECASE)
                            match = rx.search(global_val)
                            if match:
                                matched_js = True
                                if rx.groups > 0 and len(match.groups()) >= 1:
                                    v = match.group(1)
                                    if v:
                                        versions.append(v)
                        except re.error as exc:
                            logger.warning(
                                "Invalid regex in js_global rule for %s -> %s: %s",
                                fp.name,
                                global_key,
                                exc,
                            )

                    if matched_js:
                        matched_sources.add("js_global")
                        truncated_val = (
                            global_val[:100] + "..." if len(global_val) > 100 else global_val
                        )
                        evidences.append(
                            Evidence(
                                source="js_global",
                                key=global_key,
                                matched=truncated_val,
                                pattern=pattern,
                            )
                        )

            # 7. Match DOM selectors
            dom_data = evidence_data.get("dom", {})
            if fp.dom:
                if isinstance(fp.dom, list):
                    for sel in fp.dom:
                        if sel in dom_data:
                            matched_sources.add("dom")
                            matched_el = dom_data[sel][0]
                            matched_text = f"Found element: {sel}"
                            if matched_el.get("text"):
                                matched_text += f" (text: {matched_el['text']})"
                            evidences.append(
                                Evidence(
                                    source="dom",
                                    key="selector",
                                    matched=matched_text[:100],
                                    pattern=sel,
                                )
                            )
                elif isinstance(fp.dom, dict):
                    for sel, sub_rule in fp.dom.items():
                        if sel in dom_data:
                            elements = dom_data[sel]
                            if not sub_rule or "exists" in sub_rule:
                                matched_sources.add("dom")
                                matched_text = f"Element exists: {sel}"
                                evidences.append(
                                    Evidence(
                                        source="dom",
                                        key=sel,
                                        matched=matched_text,
                                        pattern="",
                                    )
                                )
                                continue

                            matched_any_el = False
                            for el in elements:
                                matched_el_criteria = True

                                # Check text regex
                                if "text" in sub_rule:
                                    pat = sub_rule["text"]
                                    try:
                                        rx = re.compile(pat, re.IGNORECASE)
                                        match = rx.search(el.get("text", ""))
                                        if not match:
                                            matched_el_criteria = False
                                        else:
                                            if rx.groups > 0 and len(match.groups()) >= 1:
                                                v = match.group(1)
                                                if v:
                                                    versions.append(v)
                                    except re.error:
                                        matched_el_criteria = False

                                # Check attributes
                                if matched_el_criteria and "attributes" in sub_rule:
                                    el_attrs = el.get("attributes", {})
                                    for attr_name, pat in sub_rule["attributes"].items():
                                        attr_val = el_attrs.get(attr_name)
                                        if attr_val is None:
                                            matched_el_criteria = False
                                            break
                                        try:
                                            rx = re.compile(pat, re.IGNORECASE)
                                            match = rx.search(attr_val)
                                            if not match:
                                                matched_el_criteria = False
                                                break
                                            else:
                                                if rx.groups > 0 and len(match.groups()) >= 1:
                                                    v = match.group(1)
                                                    if v:
                                                        versions.append(v)
                                        except re.error:
                                            matched_el_criteria = False
                                            break

                                # Check properties
                                if matched_el_criteria and "properties" in sub_rule:
                                    el_props = el.get("properties", {})
                                    for prop_name, pat in sub_rule["properties"].items():
                                        prop_val = el_props.get(prop_name)
                                        if prop_val is None:
                                            matched_el_criteria = False
                                            break
                                        try:
                                            rx = re.compile(pat, re.IGNORECASE)
                                            match = rx.search(prop_val)
                                            if not match:
                                                matched_el_criteria = False
                                                break
                                            else:
                                                if rx.groups > 0 and len(match.groups()) >= 1:
                                                    v = match.group(1)
                                                    if v:
                                                        versions.append(v)
                                        except re.error:
                                            matched_el_criteria = False
                                            break

                                if matched_el_criteria:
                                    matched_any_el = True
                                    matched_details = []
                                    if "text" in sub_rule:
                                        matched_details.append(f"text: {el.get('text')}")
                                    if "attributes" in sub_rule:
                                        matched_details.append(
                                            f"attributes: { {k: el.get('attributes', {}).get(k) for k in sub_rule['attributes']} }"
                                        )
                                    matched_str = (
                                        f"Found: {sel} ({', '.join(matched_details)})"
                                        if matched_details
                                        else f"Found: {sel}"
                                    )
                                    evidences.append(
                                        Evidence(
                                            source="dom",
                                            key=sel,
                                            matched=matched_str[:120],
                                            pattern=str(sub_rule),
                                        )
                                    )
                                    break

                            if matched_any_el:
                                matched_sources.add("dom")

            # Calculate final confidence and build match
            if evidences:
                num_sources = len(matched_sources)
                confidence = fp.confidence

                # +0.1 per additional corroborating source type
                if num_sources > 1:
                    confidence += 0.1 * (num_sources - 1)

                # +0.1 if version capture group matched
                version = versions[0] if versions else None
                if version:
                    confidence += 0.1

                confidence = min(confidence, 1.0)

                matches.append(
                    TechMatch(
                        name=fp.name,
                        category=fp.category,
                        version=version,
                        confidence=round(confidence, 2),
                        evidence=evidences,
                    )
                )

        # Resolve implies chains
        matches = self.store.resolve_implies(matches)

        # Sort matches by confidence descending
        matches.sort(key=lambda m: m.confidence, reverse=True)

        return matches
