from __future__ import annotations

import json
from pathlib import Path

from src.core.models.ops_artifacts import AttackTargetBundle, AttackTargetSpec, ExportManifest
from src.reporting.endpoint_extractor import (
    build_attack_target_bundle_from_session,
    write_attack_target_artifacts,
)


def test_write_attack_target_artifacts_redacts_human_outputs_only(tmp_path: Path) -> None:
    bundle = AttackTargetBundle(
        manifest=ExportManifest(
            source_session="/tmp/session_access_token=SECRET123.json",
            allowed_hosts=["api.example.com"],
            item_count=1,
        ),
        targets=[
            AttackTargetSpec(
                url="https://api.example.com/v1/users?access_token=SECRET123&safe=1",
                method="GET",
                category="api_endpoint",
                tags=["api_endpoint", "has_params"],
                source_kind="finding",
                source_path="/tmp/raw/api_key=XYZ987.txt",
                provenance={
                    "authorization": "Bearer top-secret-token",
                    "nested": {"api_key": "XYZ987"},
                },
            )
        ],
    )

    artifacts = write_attack_target_artifacts(bundle, tmp_path, overwrite=True)

    canonical_payload = json.loads(Path(artifacts["attack_targets"]).read_text(encoding="utf-8"))
    endpoints_json = Path(artifacts["endpoints_json"]).read_text(encoding="utf-8")
    endpoints_csv = Path(artifacts["endpoints_csv"]).read_text(encoding="utf-8")
    endpoints_md = Path(artifacts["endpoints_md"]).read_text(encoding="utf-8")

    assert "SECRET123" in canonical_payload["targets"][0]["url"]
    assert "XYZ987" in canonical_payload["targets"][0]["source_path"]

    for rendered in (endpoints_json, endpoints_csv, endpoints_md):
        assert "SECRET123" not in rendered
        assert "XYZ987" not in rendered
        assert "top-secret-token" not in rendered
        assert "[REDACTED]" in rendered


def test_build_attack_target_bundle_from_session_records_scope_snapshot(tmp_path: Path) -> None:
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    tagged_file.parent.mkdir(parents=True, exist_ok=True)
    tagged_file.write_text(
        json.dumps(
            {
                "url": "https://api.example.com/v1/users?id=1",
                "method": "GET",
                "tags": ["api_endpoint", "has_params"],
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    session_file = tmp_path / "session_20260721_120000.json"
    session_file.write_text(
        json.dumps(
            {
                "completed_tasks": [
                    {
                        "id": "task_001",
                        "result": {
                            "data": {
                                "results": {
                                    "tagged_api_data": {
                                        "file": str(tagged_file),
                                        "count": 1,
                                        "description": "Tagged URLs",
                                        "tags": ["api_endpoint", "has_params"],
                                    }
                                }
                            }
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    bundle = build_attack_target_bundle_from_session(session_file)

    scope_snapshot = bundle.manifest.provenance["scope_snapshot"]
    assert scope_snapshot["target_count"] == 1
    assert scope_snapshot["allowed_hosts"] == ["api.example.com"]
