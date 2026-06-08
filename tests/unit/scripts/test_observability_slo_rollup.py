from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def test_observability_slo_rollup_generates_weekly_with_quality_guard(tmp_path: Path) -> None:
    workspace_projects_dir = tmp_path / "workspace" / "projects" / "demo-target"
    sessions_dir = workspace_projects_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_payload = {
        "completed_tasks": [
            {
                "id": "task_1",
                "state": "failed",
                "failure_reason_code": "unknown_error",
                "error": "random unexpected failure",
                "result": {
                    "findings": [
                        {
                            "title": "Potential schema issue",
                            "target_url": "http://example.test/api/a",
                            "vuln_type": "broken_access_control",
                            "additional_info": {
                                "schema_severity": "high",
                            },
                        }
                    ]
                },
            }
        ],
        "task_queue": [],
        "context": {},
    }
    session_file = sessions_dir / "session_20260521_000001.json"
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    daily_json = tmp_path / "daily.json"
    weekly_md = tmp_path / "weekly.md"

    result = subprocess.run(
        [
            "python3",
            "scripts/observability_slo_rollup.py",
            "--workspace-projects-dir",
            str(tmp_path / "workspace" / "projects"),
            "--days",
            "7",
            "--weekly-min-sample-count",
            "100",
            "--daily-json-out",
            str(daily_json),
            "--weekly-md-out",
            str(weekly_md),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert daily_json.exists()
    assert weekly_md.exists()

    daily_payload = json.loads(daily_json.read_text(encoding="utf-8"))
    assert daily_payload["weekly_min_sample_count"] == 100
    assert len(daily_payload["daily"]) >= 1
    assert daily_payload["daily"][0]["findings_total"] == 1
    assert daily_payload["daily"][0]["schema_severity_missing"] == 0

    weekly_text = weekly_md.read_text(encoding="utf-8")
    assert "## Quality Guard" in weekly_text
    assert "## Schema Severity Coverage" in weekly_text
    assert "sample_count < 100" in weekly_text
    assert "| date | sessions | failed_tasks | unknown_rate | sample_count | quality | p95(s) | p99(s) |" in weekly_text
