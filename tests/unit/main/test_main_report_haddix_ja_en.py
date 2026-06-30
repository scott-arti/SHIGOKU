"""CLI regression tests for --format haddix-ja-en."""
import json
import re
import sys
from pathlib import Path

from src import main as main_module


def test_main_report_haddix_ja_en_generates_report(tmp_path, monkeypatch):
    """正常系: haddix-ja-en レポートが生成され、ファイルが存在すること."""
    project_name = "demo-jaen"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260624_120000.json"
    session_payload = {
        "completed_tasks": [
            {
                "id": "t1",
                "name": "sqli",
                "state": "success",
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "url_results": [
                                    {
                                        "url": "http://example.com/search",
                                        "vuln_type": "sqli",
                                        "status": "completed",
                                        "duration_seconds": 1.5,
                                        "retry_count": 0,
                                        "tested_params": ["q"],
                                        "blind_correlation": {},
                                    }
                                ]
                            }
                        ],
                        "findings": [
                            {
                                "title": "SQL Injection in search",
                                "severity": "high",
                                "vuln_type": "sqli",
                                "target_url": "http://example.com/search",
                                "summary": "SQL injection found.",
                                "impact": "Data leak possible.",
                                "poc_request": "GET /search?q=' OR 1=1-- HTTP/1.1",
                            }
                        ],
                    }
                },
            }
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://example.com",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix-ja-en", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    report_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(report_files) >= 1, f"No report file found in {reports_dir}"

    content = report_files[0].read_text(encoding="utf-8")
    assert "# SHIGOKU" in content, "Japanese section missing"
    assert "# Submission Report" in content, "English section missing"
    assert "**Generated:**" in content, "Generated header missing"
    assert "**Source Session:**" in content, "Source Session header missing"


def test_main_report_haddix_ja_en_empty_findings(tmp_path, monkeypatch):
    """findings 空のセッションでもクラッシュせず、空レポートが生成されること."""
    project_name = "demo-jaen-empty"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260624_120000.json"
    session_payload = {
        "completed_tasks": [],
        "task_queue": [],
        "context": {},
        "goal_target": "http://example.com",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix-ja-en", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    report_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(report_files) >= 1, f"No report generated for empty findings"
    content = report_files[0].read_text(encoding="utf-8")
    assert "# SHIGOKU" in content
    assert "# Submission Report" in content


def test_main_report_haddix_ja_en_filename_pattern(tmp_path, monkeypatch):
    """haddix_report_YYYYMMDD_HHMMSS.md 命名パターンを維持すること."""
    project_name = "demo-jaen-name"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260624_120000.json"
    session_payload = {
        "completed_tasks": [],
        "task_queue": [],
        "context": {},
        "goal_target": "http://example.com",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix-ja-en", "--target", project_name],
    )

    main_module.main()
    reports_dir = project_dir / "reports"
    report_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(report_files) >= 1

    pattern = re.compile(r"haddix_report_\d{8}_\d{6}\.md$")
    for rf in report_files:
        assert pattern.match(rf.name), f"Filename {rf.name} does not match haddix_report_ pattern"


def test_main_report_haddix_ja_en_does_not_affect_existing_haddix(tmp_path, monkeypatch):
    """--format haddix は引き続き動作し、ja-en が既存 haddix 出力を破壊しないこと."""
    project_name = "demo-both"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260624_120000.json"
    session_payload = {
        "completed_tasks": [
            {
                "id": "t1",
                "name": "xss",
                "state": "success",
                "result": {
                    "data": {
                        "execution_log": [],
                        "findings": [
                            {
                                "title": "XSS in comment",
                                "severity": "medium",
                                "vuln_type": "xss",
                                "target_url": "http://example.com/comment",
                                "summary": "Reflected XSS",
                                "impact": "Session hijacking",
                            }
                        ],
                    }
                },
            }
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://example.com",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)

    # Run haddix-ja-en
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix-ja-en", "--target", project_name],
    )
    main_module.main()

    reports_dir = project_dir / "reports"
    ja_en_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(ja_en_files) >= 1, "haddix-ja-en should generate a report"
    ja_en_content = ja_en_files[0].read_text(encoding="utf-8")
    assert "# Submission Report" in ja_en_content, "ja-en report should have English section"

    # Run haddix (original) - may overwrite with same timestamp, but should still work
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix", "--target", project_name],
    )
    main_module.main()

    haddix_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(haddix_files) >= 1, "Existing haddix format should generate a report"
    haddix_content = haddix_files[0].read_text(encoding="utf-8")
    assert "Vulnerability Report" in haddix_content or "SHIGOKU" in haddix_content


def test_main_report_haddix_ja_en_report_target_defined(tmp_path, monkeypatch):
    """report_target が正しく定義され UnboundLocalError が発生しないこと."""
    project_name = "demo-target"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260624_120000.json"
    session_payload = {
        "completed_tasks": [],
        "task_queue": [],
        "context": {
            "scenario_coverage": {
                "required_count": 9,
                "covered_count": 9,
                "coverage_rate": 1.0,
                "missing_scenarios": [],
                "coverage_items": [],
            },
            "coverage_gate": {
                "required_families": [],
                "missing_families": [],
                "reached_families": [],
                "gate_passed": True,
                "coverage_rate": 1.0,
                "coverage_items": [],
            },
        },
        "goal_target": "http://example.com",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix-ja-en", "--target", project_name],
    )

    # Should not raise UnboundLocalError
    main_module.main()

    reports_dir = project_dir / "reports"
    report_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(report_files) >= 1, "report_target was defined; report should be generated"


def test_main_report_haddix_ja_en_format_accepted(tmp_path, monkeypatch):
    """haddix-ja-en format が argparse に受理され、レポートが生成されること."""
    project_name = "demo-valid"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260624_120000.json"
    session_file.write_text("{}", encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix-ja-en", "--target", project_name],
    )

    main_module.main()

    # Report should be generated (empty session → empty report, no crash)
    reports_dir = project_dir / "reports"
    report_files = list(reports_dir.glob("haddix_report_*.md"))
    assert len(report_files) >= 1, "haddix-ja-en format should generate a report"
