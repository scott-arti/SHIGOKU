from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_session_with_tagged_file(session_file: Path, tagged_file: Path) -> None:
    tagged_file.parent.mkdir(parents=True, exist_ok=True)
    tagged_file.write_text(
        json.dumps(
            {
                "url": "http://127.0.0.1:8888/chatbot/genai/state",
                "method": "GET",
                "tags": ["api_endpoint", "has_params"],
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )

    payload = {
        "completed_tasks": [
            {
                "id": "task_002",
                "result": {
                    "data": {
                        "results": {
                            "tagged_api_data": {
                                "file": str(tagged_file),
                                "count": 1,
                                "description": "Tagged URLs (api_data)",
                                "tags": ["api_endpoint", "has_params"],
                            }
                        }
                    }
                },
            }
        ]
    }
    session_file.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_ops_cli_session_export_targets_writes_machine_and_human_outputs(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    output_dir = tmp_path / "exported_targets"
    _write_session_with_tagged_file(session_file, tagged_file)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "export-targets",
            "--session",
            str(session_file),
            "--output-dir",
            str(output_dir),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["target_count"] == 1
    assert payload["manifest"]["manifest_hash"]
    assert Path(payload["artifacts"]["attack_targets"]).exists()
    assert Path(payload["artifacts"]["endpoints_json"]).exists()
    assert Path(payload["artifacts"]["endpoints_csv"]).exists()
    assert Path(payload["artifacts"]["endpoints_md"]).exists()


def test_ops_cli_report_export_targets_blocks_inconsistent_report(tmp_path: Path) -> None:
    report_file = tmp_path / "haddix_report_20260721_120100.md"
    report_file.write_text(
        "\n".join(
            [
                "# Vulnerability Report",
                "",
                "**Target:** http://127.0.0.1:8888/",
                "**Generated:** 2026-07-21 12:01:00",
                "**Source Session:** /tmp/other_session.json",
                "**Tool:** SHIGOKU - Sovereign VAPT Engine",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "export-targets",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "report_consistency_inconsistent" in payload["reason_codes"]


def test_ops_cli_session_endpoints_lists_extracted_targets(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    _write_session_with_tagged_file(session_file, tagged_file)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "endpoints",
            "--session",
            str(session_file),
            "--host",
            "127.0.0.1",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["endpoint_count"] == 1
    assert payload["endpoints"][0]["host"] == "127.0.0.1"


def test_ops_cli_report_endpoints_lists_extracted_targets(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    tagged_file = tmp_path / "tagged_urls" / "tagged_api_data.jsonl"
    report_file = tmp_path / "haddix_report_20260721_120100.md"
    _write_session_with_tagged_file(session_file, tagged_file)
    report_file.write_text(
        "\n".join(
            [
                "# Vulnerability Report",
                "",
                "**Target:** http://127.0.0.1:8888/",
                "**Generated:** 2026-07-21 12:01:00",
                f"**Source Session:** {session_file.resolve()}",
                "**Tool:** SHIGOKU - Sovereign VAPT Engine",
            ]
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "endpoints",
            "--report",
            str(report_file),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["endpoint_count"] == 1
    assert payload["endpoints"][0]["url"].startswith("http://127.0.0.1:8888/")


def test_ops_cli_session_export_targets_blocks_empty_export(tmp_path: Path) -> None:
    session_file = tmp_path / "session_20260721_120000.json"
    session_file.write_text(json.dumps({"completed_tasks": []}, ensure_ascii=False), encoding="utf-8")

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "session",
            "export-targets",
            "--session",
            str(session_file),
            "--output-dir",
            str(tmp_path / "empty_export"),
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"
    assert "empty_export" in payload["reason_codes"]
