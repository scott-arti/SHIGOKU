from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_review_observability_slo_weekly_schema_warn_only(tmp_path: Path) -> None:
    daily_json = tmp_path / "daily.json"
    payload = {
        "daily": [
            {
                "date": "2026-05-21",
                "failed_tasks": 10,
                "unknown_failures": 0,
                "findings_total": 5,
                "schema_severity_missing": 2,
                "pr_execution_time_slo": {
                    "sample_count": 120,
                    "observed_p95_seconds": 100.0,
                    "observed_p99_seconds": 200.0,
                },
            }
        ]
    }
    daily_json.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    out_json = tmp_path / "weekly_review.json"
    out_md = tmp_path / "weekly_review.md"

    result = subprocess.run(
        [
            "python3",
            "scripts/review_observability_slo_weekly.py",
            "--daily-json",
            str(daily_json),
            "--schema-severity-required",
            "--schema-severity-warn-only",
            "--out-json",
            str(out_json),
            "--out-md",
            str(out_md),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    review = json.loads(out_json.read_text(encoding="utf-8"))
    assert review["status"] == "provisional"
    assert review["warnings"]
    assert not review["violations"]
    assert out_md.exists()


def test_review_observability_slo_weekly_schema_required_enforced(tmp_path: Path) -> None:
    daily_json = tmp_path / "daily.json"
    payload = {
        "daily": [
            {
                "date": "2026-05-21",
                "failed_tasks": 10,
                "unknown_failures": 0,
                "findings_total": 3,
                "schema_severity_missing": 1,
                "pr_execution_time_slo": {
                    "sample_count": 150,
                    "observed_p95_seconds": 100.0,
                    "observed_p99_seconds": 200.0,
                },
            },
            {
                "date": "2026-05-22",
                "failed_tasks": 10,
                "unknown_failures": 0,
                "findings_total": 2,
                "schema_severity_missing": 0,
                "pr_execution_time_slo": {
                    "sample_count": 150,
                    "observed_p95_seconds": 100.0,
                    "observed_p99_seconds": 200.0,
                },
            },
            {
                "date": "2026-05-23",
                "failed_tasks": 10,
                "unknown_failures": 0,
                "findings_total": 2,
                "schema_severity_missing": 0,
                "pr_execution_time_slo": {
                    "sample_count": 150,
                    "observed_p95_seconds": 100.0,
                    "observed_p99_seconds": 200.0,
                },
            },
        ]
    }
    daily_json.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    out_json = tmp_path / "weekly_review.json"

    result = subprocess.run(
        [
            "python3",
            "scripts/review_observability_slo_weekly.py",
            "--daily-json",
            str(daily_json),
            "--schema-severity-required",
            "--out-json",
            str(out_json),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    review = json.loads(out_json.read_text(encoding="utf-8"))
    assert review["status"] == "fail"
    assert any("schema_severity_missing" in item for item in review["violations"])
