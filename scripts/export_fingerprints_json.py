#!/usr/bin/env python3
import os
import json
import yaml
from pathlib import Path

def main():
    # Resolve paths
    project_root = Path(__file__).resolve().parent.parent
    yaml_path = project_root / "fingerprints" / "tech.yaml"
    output_dir = project_root / "stacksniff-api" / "scanner" / "static" / "scanner"
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "fingerprints.json"

    print(f"Reading fingerprints from {yaml_path}...")
    with open(yaml_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    # Bake FINGERPRINTS_VERSION env var
    version = os.environ.get("FINGERPRINTS_VERSION")
    if version:
        print(f"Baking FINGERPRINTS_VERSION={version}...")
        data["version"] = version
    else:
        print(f"Using default version from YAML: {data.get('version')}")

    # Write minified JSON
    print(f"Writing minified JSON to {json_path}...")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"))

    size_kb = json_path.stat().st_size / 1024
    print(f"Done! Created fingerprints.json ({size_kb:.2f} KB)")

if __name__ == "__main__":
    main()
