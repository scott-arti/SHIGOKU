from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.models.ops_artifacts import (
    AttackTargetBundle,
    AttackTargetSpec,
    ExportManifest,
    load_attack_target_bundle,
    write_attack_target_bundle,
)


def _sample_bundle() -> AttackTargetBundle:
    manifest = ExportManifest(
        source_session="/tmp/session_20260721_120000.json",
        allowed_hosts=["api.example.com"],
        provenance={
            "single_session": True,
            "scope_snapshot": {
                "allowed_hosts": ["api.example.com"],
                "target_count": 1,
            },
        },
        item_count=1,
    )
    return AttackTargetBundle(
        manifest=manifest,
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/users?id=1",
                method="GET",
                category="api_endpoint",
                tags=["api_endpoint", "has_params"],
                source_kind="tagged_url",
                source_path="/tmp/tagged_api_data.jsonl",
            )
        ],
    )


def test_attack_target_bundle_roundtrip_preserves_manifest_hash(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    out = tmp_path / "attack_targets.json"

    write_attack_target_bundle(bundle, out)
    loaded = load_attack_target_bundle(out)

    assert loaded.manifest.manifest_hash
    assert loaded.manifest.manifest_hash == bundle.manifest.manifest_hash
    assert loaded.manifest.allowed_hosts == ["api.example.com"]
    assert loaded.targets[0].host == "api.example.com"
    assert loaded.targets[0].tags == ["api_endpoint", "has_params"]


def test_attack_target_bundle_rejects_tampered_payload(tmp_path: Path) -> None:
    bundle = _sample_bundle()
    out = tmp_path / "attack_targets.json"
    write_attack_target_bundle(bundle, out)

    raw = json.loads(out.read_text(encoding="utf-8"))
    raw["targets"][0]["url"] = "https://evil.example.net/pwn"
    out.write_text(json.dumps(raw, ensure_ascii=False, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="manifest_hash"):
        load_attack_target_bundle(out)


def test_attack_target_bundle_rejects_allowed_hosts_mismatch(tmp_path: Path) -> None:
    bundle = AttackTargetBundle(
        manifest=ExportManifest(
            source_session="/tmp/session_20260721_120000.json",
            allowed_hosts=["other.example.com"],
            provenance={
                "single_session": True,
                "scope_snapshot": {
                    "allowed_hosts": ["other.example.com"],
                    "target_count": 1,
                },
            },
            item_count=1,
        ),
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/users?id=1",
                method="GET",
                category="api_endpoint",
                tags=["api_endpoint", "has_params"],
                source_kind="tagged_url",
                source_path="/tmp/tagged_api_data.jsonl",
            )
        ],
    )
    out = tmp_path / "attack_targets.json"

    write_attack_target_bundle(bundle, out)

    with pytest.raises(ValueError, match="allowed_hosts mismatch"):
        load_attack_target_bundle(out)


def test_attack_target_bundle_rejects_expired_manifest(tmp_path: Path) -> None:
    bundle = AttackTargetBundle(
        manifest=ExportManifest(
            source_session="/tmp/session_20260701_120000.json",
            generated_at="2026-07-01T00:00:00+00:00",
            ttl_days=7,
            allowed_hosts=["api.example.com"],
            provenance={
                "single_session": True,
                "scope_snapshot": {
                    "allowed_hosts": ["api.example.com"],
                    "target_count": 1,
                },
            },
            item_count=1,
        ),
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/users?id=1",
                method="GET",
                category="api_endpoint",
                tags=["api_endpoint", "has_params"],
                source_kind="tagged_url",
                source_path="/tmp/tagged_api_data.jsonl",
            )
        ],
    )
    out = tmp_path / "attack_targets.json"

    write_attack_target_bundle(bundle, out)

    with pytest.raises(ValueError, match="attack target bundle expired"):
        load_attack_target_bundle(out)


def test_attack_target_bundle_rejects_missing_scope_snapshot_provenance(tmp_path: Path) -> None:
    bundle = AttackTargetBundle(
        manifest=ExportManifest(
            source_session="/tmp/session_20260721_120000.json",
            allowed_hosts=["api.example.com"],
            provenance={"single_session": True},
            item_count=1,
        ),
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/users?id=1",
                method="GET",
                category="api_endpoint",
                tags=["api_endpoint", "has_params"],
                source_kind="tagged_url",
                source_path="/tmp/tagged_api_data.jsonl",
            )
        ],
    )
    out = tmp_path / "attack_targets.json"

    write_attack_target_bundle(bundle, out)

    with pytest.raises(ValueError, match="scope_snapshot"):
        load_attack_target_bundle(out)
