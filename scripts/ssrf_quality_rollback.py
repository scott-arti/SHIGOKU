#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _dump_yaml(path: Path, data: dict[str, Any]) -> None:
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")


def _get_ssrf_quality(doc: dict[str, Any]) -> dict[str, Any]:
    return (
        doc.get("features", {})
        .get("phase3", {})
        .get("ssrf_quality", {})
    )


def _set_ssrf_quality(doc: dict[str, Any], value: dict[str, Any]) -> None:
    doc.setdefault("features", {})
    doc["features"].setdefault("phase3", {})
    doc["features"]["phase3"]["ssrf_quality"] = value


def main() -> int:
    parser = argparse.ArgumentParser(description="Rollback SSRF quality settings to stable profile")
    parser.add_argument("--features", default="config/features.yaml", help="Path to features.yaml")
    parser.add_argument("--stable", default="config/ssrf_quality_profiles/stable.yaml", help="Path to stable profile")
    parser.add_argument("--dry-run", action="store_true", help="Do not write files")
    parser.add_argument("--summary", default="", help="Optional JSON output path")
    args = parser.parse_args()

    features_path = Path(args.features)
    stable_path = Path(args.stable)

    features = _load_yaml(features_path)
    stable = _load_yaml(stable_path)

    stable_quality = stable.get("ssrf_quality", {})
    current_quality = _get_ssrf_quality(features)

    changed = current_quality != stable_quality
    summary = {
        "changed": changed,
        "dry_run": bool(args.dry_run),
        "features_path": str(features_path),
        "stable_path": str(stable_path),
        "before": current_quality,
        "after": stable_quality,
    }

    if changed and not args.dry_run:
        _set_ssrf_quality(features, stable_quality)
        _dump_yaml(features_path, features)

    if args.summary:
        out_path = Path(args.summary)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
