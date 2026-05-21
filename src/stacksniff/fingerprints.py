"""Fingerprint rule models and storage for stacksniff.

Loads, validates, and provides access to technology fingerprints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from stacksniff.models import Evidence, TechMatch


@dataclass
class Fingerprint:
    """A technology fingerprint rule."""

    name: str
    category: str
    website: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    meta: dict[str, str] = field(default_factory=dict)
    scripts: list[str] = field(default_factory=list)
    html: list[str] = field(default_factory=list)
    js_globals: dict[str, str] = field(default_factory=dict)
    dom: dict | list = field(default_factory=dict)
    implies: list[str] = field(default_factory=list)
    confidence: float = 0.5


class FingerprintStore:
    """Loads, validates, and provides access to fingerprint rules."""

    def __init__(
        self,
        categories: dict[str, dict[str, str]],
        technologies: dict[str, Fingerprint],
        version: str = "1.0.0",
    ) -> None:
        self.categories = categories
        self.technologies = technologies
        self.version = version

    @classmethod
    def from_yaml(cls, path: Path) -> FingerprintStore:
        """Load and parse fingerprints from a YAML file."""
        if not path.is_file():
            raise FileNotFoundError(f"Fingerprint file not found: {path}")

        with path.open("r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}

        categories = raw_data.get("categories", {})
        version = str(raw_data.get("version", "1.0.0"))
        technologies: dict[str, Fingerprint] = {}

        raw_techs = raw_data.get("technologies", {})
        for name, data in raw_techs.items():
            if not isinstance(data, dict):
                continue

            # Standardize tech key (lowercase) for lookup
            tech_key = name.lower()
            technologies[tech_key] = Fingerprint(
                name=data.get("name", name),  # fallback to key if name not specified
                category=data.get("category", "other"),
                website=data.get("website"),
                headers=data.get("headers", {}),
                cookies=data.get("cookies", {}),
                meta=data.get("meta", {}),
                scripts=data.get("scripts", []),
                html=data.get("html", []),
                js_globals=data.get("js_globals", {}),
                dom=data.get("dom", {}),
                implies=data.get("implies", []),
                confidence=float(data.get("confidence", 0.5)),
            )

        return cls(categories=categories, technologies=technologies, version=version)

    @classmethod
    def default(cls) -> FingerprintStore:
        """Load the default bundled tech.yaml."""
        # Try local dev tree first, fallback to package root, or same directory
        possible_paths = [
            Path(__file__).parents[2] / "fingerprints" / "tech.yaml",
            Path(__file__).parent / "fingerprints" / "tech.yaml",
            Path(__file__).parent / "tech.yaml",
        ]
        for p in possible_paths:
            if p.is_file():
                return cls.from_yaml(p)

        raise FileNotFoundError("Could not locate default tech.yaml in any candidate location.")

    def get_all(self) -> list[Fingerprint]:
        """Return all fingerprint rules."""
        return list(self.technologies.values())

    def get_all_dom_selectors(self) -> set[str]:
        """Return a set of all unique DOM selectors used in technologies."""
        selectors = set()
        for f in self.technologies.values():
            if isinstance(f.dom, list):
                for sel in f.dom:
                    selectors.add(sel)
            elif isinstance(f.dom, dict):
                for sel in f.dom:
                    selectors.add(sel)
        return selectors

    def get_by_category(self, category: str) -> list[Fingerprint]:
        """Return all fingerprint rules belonging to the specified category."""
        return [f for f in self.technologies.values() if f.category == category]

    def resolve_implies(self, matches: list[TechMatch]) -> list[TechMatch]:
        """Resolve implied technologies recursively.

        Adds implied technologies at 0.6 confidence if not already present with
        higher confidence. Does not override higher confidence direct matches.
        """
        # Index matches by lowercase technology name
        match_map = {m.name.lower(): m for m in matches}
        queue = list(match_map.keys())

        # Track visited to avoid infinite loops in cyclic dependencies
        visited = set(queue)

        while queue:
            current_tech = queue.pop(0)
            rule = self.technologies.get(current_tech)
            if not rule or not rule.implies:
                continue

            for implied in rule.implies:
                implied_key = implied.lower()

                # Get implied technology details
                implied_rule = self.technologies.get(implied_key)
                implied_name = implied_rule.name if implied_rule else implied
                implied_category = implied_rule.category if implied_rule else "other"

                # Check if we already matched this tech
                existing = match_map.get(implied_key)
                if existing is not None:
                    # If existing has lower confidence, raise it to 0.6
                    if existing.confidence < 0.6:
                        # Rebuild TechMatch with higher confidence
                        match_map[implied_key] = TechMatch(
                            name=existing.name,
                            category=existing.category,
                            version=existing.version,
                            confidence=0.6,
                            evidence=existing.evidence
                            + [
                                Evidence(
                                    source="implies",
                                    key="implies",
                                    matched=f"Implied by {rule.name}",
                                    pattern="",
                                )
                            ],
                        )
                else:
                    # Not matched yet, add as new implied tech at 0.6 confidence
                    match_map[implied_key] = TechMatch(
                        name=implied_name,
                        category=implied_category,
                        version=None,
                        confidence=0.6,
                        evidence=[
                            Evidence(
                                source="implies",
                                key="implies",
                                matched=f"Implied by {rule.name}",
                                pattern="",
                            )
                        ],
                    )

                if implied_key not in visited:
                    visited.add(implied_key)
                    queue.append(implied_key)

        return list(match_map.values())
