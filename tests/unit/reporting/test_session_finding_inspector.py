from __future__ import annotations

import json
import subprocess
from pathlib import Path

from src.reporting.session_finding_inspector import inspect_session_findings


def test_inspect_session_findings_deduplicates_mirrored_task_result_lists(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260509_145029.json"
    finding_a = {
        "title": "Potential IDOR/BOLA Object Access Surface",
        "target_url": "http://127.0.0.1:8888/account/settings",
        "vuln_type": "broken_access_control",
        "additional_info": {
            "detection_class": "idor_bola",
            "heuristic_candidate": True,
            "verification_required": True,
        },
    }
    finding_b = {
        "title": "Potential IDOR/BOLA Object Access Surface",
        "target_url": "http://127.0.0.1:8888/account/security",
        "vuln_type": "broken_access_control",
        "additional_info": {
            "detection_class": "idor_bola",
            "heuristic_candidate": True,
            "verification_required": True,
        },
    }
    session_payload = {
        "completed_tasks": [
            {
                "id": "scenario_probe_10_9976329a",
                "result": {
                    "findings": [finding_a, finding_b],
                    "data": {"findings": [finding_a, finding_b]},
                },
            }
        ]
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    summary = inspect_session_findings(session_file, detection_class="idor_bola")

    assert summary["findings_count"] == 2
    assert [item["target_url"] for item in summary["findings"]] == [
        "http://127.0.0.1:8888/account/settings",
        "http://127.0.0.1:8888/account/security",
    ]
    assert all(item["task_id"] == "scenario_probe_10_9976329a" for item in summary["findings"])


def test_inspect_session_findings_cli_works_with_python3(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260509_145029.json"
    finding = {
        "title": "Potential IDOR/BOLA Object Access Surface",
        "target_url": "http://127.0.0.1:8888/account/settings",
        "vuln_type": "broken_access_control",
        "additional_info": {
            "detection_class": "idor_bola",
            "heuristic_candidate": True,
            "verification_required": True,
        },
    }
    session_payload = {
        "completed_tasks": [
            {
                "id": "scenario_probe_10_9976329a",
                "result": {
                    "findings": [finding],
                    "data": {"findings": [finding]},
                },
            }
        ]
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "scripts/inspect_session_findings.py",
            "--session",
            str(session_file),
            "--detection-class",
            "idor_bola",
        ],
        cwd=Path(__file__).resolve().parents[3],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["findings_count"] == 1


def test_inspect_session_findings_supports_max_findings_and_field_projection(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260509_145029.json"
    finding_a = {
        "title": "Potential IDOR/BOLA Object Access Surface",
        "target_url": "http://127.0.0.1:8888/account/settings",
        "vuln_type": "broken_access_control",
        "additional_info": {
            "detection_class": "idor_bola",
            "heuristic_candidate": True,
            "verification_required": True,
        },
    }
    finding_b = {
        "title": "Potential IDOR/BOLA Object Access Surface",
        "target_url": "http://127.0.0.1:8888/account/security",
        "vuln_type": "broken_access_control",
        "additional_info": {
            "detection_class": "idor_bola",
            "heuristic_candidate": True,
            "verification_required": True,
        },
    }
    session_payload = {
        "completed_tasks": [
            {
                "id": "scenario_probe_10_9976329a",
                "result": {
                    "findings": [finding_a, finding_b],
                    "data": {"findings": [finding_a, finding_b]},
                },
            }
        ]
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    summary = inspect_session_findings(
        session_file,
        detection_class="idor_bola",
        max_findings=1,
        finding_fields=["title", "target_url"],
    )

    assert summary["findings_count"] == 1
    assert len(summary["findings"]) == 1
    assert sorted(summary["findings"][0].keys()) == ["target_url", "title"]
