import json
import sys

from src import main as main_module


def test_main_report_haddix_includes_authz_and_timeout_kpi(tmp_path, monkeypatch):
    project_name = "demo-authz"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260322_001800.json"
    session_payload = {
        "completed_tasks": [
            {
                "id": "t1",
                "name": "idor",
                "state": "success",
                "params": {"instruction": "run idor"},
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "url_results": [
                                    {
                                        "url": "http://example.com/api/users/1",
                                        "vuln_type": "idor",
                                        "status": "timeout",
                                        "duration_seconds": 60,
                                        "retry_count": 2,
                                        "tested_params": ["id"],
                                        "blind_correlation": {},
                                    }
                                ]
                            }
                        ],
                        "findings": [
                            {
                                "title": "IDOR differential",
                                "severity": "high",
                                "vuln_type": "idor",
                                "target_url": "http://example.com/api/users/1",
                                "summary": "Potential IDOR",
                                "poc_request": "GET /api/users/2 HTTP/1.1",
                                "poc_response": "HTTP/1.1 200 OK",
                                "additional_info": {
                                    "authz_differential": {
                                        "scenario": "cross_session_access",
                                        "confidence": 0.88,
                                        "signals": ["id_reflected"],
                                        "baseline_status": 200,
                                        "test_status": 200,
                                        "original_id": "1",
                                        "test_id": "2",
                                    }
                                },
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
        ["shigoku", "--report", "--format", "haddix", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    generated_reports = sorted(reports_dir.glob("haddix_report_*.md"))
    assert generated_reports, "Haddix report file was not generated"
    generated_gates = sorted(reports_dir.glob("haddix_gate_*.json"))
    assert generated_gates, "Initial-release gate JSON was not generated"
    generated_deferred = sorted(reports_dir.glob("haddix_deferred_*.json"))
    assert generated_deferred, "Deferred scenario backlog JSON was not generated"
    generated_evidence_dirs = sorted(reports_dir.glob("haddix_evidence_*"))
    assert generated_evidence_dirs, "Finding evidence artifacts were not generated"

    content = generated_reports[-1].read_text(encoding="utf-8")
    assert f"**Source Session:** {session_file.resolve()}" in content
    assert "AuthZ differential: cross_session_access" in content
    assert "KPI: total=1, completed=0, timeout=1, error=0, timeout_rate=100.0%, avg_retry=2.00" in content
    assert "## 🧪 Scenario Coverage (SCN01-12)" in content
    assert "| SCN01 |" in content
    assert "## 🚦 Initial Release Gate" in content

    gate_payload = json.loads(generated_gates[-1].read_text(encoding="utf-8"))
    assert "status" in gate_payload
    assert "reason_codes" in gate_payload
    assert "recommended_actions" in gate_payload

    deferred_payload = json.loads(generated_deferred[-1].read_text(encoding="utf-8"))
    assert "deferred_scenarios" in deferred_payload
    assert isinstance(deferred_payload["deferred_scenarios"], list)

    evidence_files = sorted(generated_evidence_dirs[-1].glob("EV-*.json"))
    assert evidence_files, "No evidence artifact file was generated"
    evidence_payload = json.loads(evidence_files[0].read_text(encoding="utf-8"))
    assert evidence_payload["raw_request"].startswith("GET /api/users/2")
    assert evidence_payload["raw_response"].startswith("HTTP/1.1 200")
    assert str(evidence_payload.get("replay_command", "")).startswith("curl -i -X")
    assert isinstance(evidence_payload.get("detector_verdict", {}), dict)
    assert isinstance(evidence_payload.get("key_signals", []), list)


def test_main_report_haddix_prefers_latest_repairable_session(tmp_path, monkeypatch):
    project_name = "demo-repairable"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    older_session = sessions_dir / "session_20260322_001800.json"
    older_payload = {
        "completed_tasks": [
            {
                "id": "old-t1",
                "name": "older",
                "state": "success",
                "params": {"instruction": "old"},
                "result": {
                    "data": {
                        "findings": [
                            {
                                "title": "Old session finding",
                                "severity": "medium",
                                "vuln_type": "xss",
                                "target_url": "http://example.com/old",
                                "summary": "old",
                            }
                        ]
                    }
                },
            }
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://example.com",
    }
    older_session.write_text(json.dumps(older_payload, ensure_ascii=False), encoding="utf-8")

    newer_session = sessions_dir / "session_20260322_001900.json"
    newer_payload = {
        "completed_tasks": [
            {
                "id": "new-t1",
                "name": "newer",
                "state": "success",
                "params": {"instruction": "new"},
                "result": {
                    "data": {
                        "findings": [
                            {
                                "title": "Recovered latest session finding",
                                "severity": "high",
                                "vuln_type": "idor",
                                "target_url": "http://example.com/new",
                                "summary": "new",
                            }
                        ]
                    }
                },
            }
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://example.com",
    }
    # 末尾に余分な } を付与して軽微破損を再現（safe_json_loads で復旧可能）
    newer_session.write_text(json.dumps(newer_payload, ensure_ascii=False) + "}", encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    generated_reports = sorted(reports_dir.glob("haddix_report_*.md"))
    assert generated_reports, "Haddix report file was not generated"

    content = generated_reports[-1].read_text(encoding="utf-8")
    assert f"**Source Session:** {newer_session.resolve()}" in content
    assert "Recovered latest session finding" in content
    assert "Old session finding" not in content


def test_main_report_haddix_promotes_execution_note_candidates_when_findings_empty(tmp_path, monkeypatch):
    project_name = "demo-heuristic-candidate"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260415_010101.json"
    session_payload = {
        "completed_tasks": [
            {
                "id": "t1",
                "name": "api-check",
                "state": "success",
                "params": {"instruction": "run api check"},
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "url_results": [
                                    {
                                        "url": "http://127.0.0.1:8888/account/%F0%9F%A4%96",
                                        "vuln_type": "api",
                                        "status": "completed",
                                        "duration_seconds": 0.002,
                                        "retry_count": 0,
                                        "tested_params": ["role", "is_admin"],
                                        "blind_correlation": {},
                                    }
                                ]
                            }
                        ],
                        "findings": [],
                    }
                },
            }
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://127.0.0.1:8888/",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    generated_reports = sorted(reports_dir.glob("haddix_report_*.md"))
    assert generated_reports, "Haddix report file was not generated"

    content = generated_reports[-1].read_text(encoding="utf-8")
    assert "Potential privilege parameter tampering surface" in content
    assert "| 🟡 MEDIUM | 1 |" in content


def test_main_report_haddix_heuristic_promoted_with_poc_becomes_confirmed(tmp_path, monkeypatch):
    project_name = "demo-heuristic-confirmed"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260423_131005.json"
    session_payload = {
        "completed_tasks": [
            {
                "id": "t1",
                "name": "api-check-1",
                "state": "success",
                "params": {"instruction": "run api check"},
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "url_results": [
                                    {
                                        "url": "http://127.0.0.1:8888/account/settings",
                                        "vuln_type": "api",
                                        "status": "completed",
                                        "duration_seconds": 0.024,
                                        "retry_count": 0,
                                        "tested_params": ["role", "is_admin"],
                                        "probe_sent": True,
                                        "poc_request": "PATCH /account/settings HTTP/1.1\nContent-Type: application/json\n\n{\"role\":\"admin\"}",
                                        "poc_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"role\":\"admin\"}",
                                        "blind_correlation": {},
                                    }
                                ]
                            }
                        ],
                        "findings": [],
                    }
                },
            },
            {
                "id": "t2",
                "name": "api-check-2",
                "state": "success",
                "params": {"instruction": "run api check"},
                "result": {
                    "data": {
                        "execution_log": [
                            {
                                "url_results": [
                                    {
                                        "url": "http://127.0.0.1:8888/account/settings",
                                        "vuln_type": "api",
                                        "status": "completed",
                                        "duration_seconds": 0.031,
                                        "retry_count": 0,
                                        "tested_params": ["role", "is_admin"],
                                        "probe_sent": True,
                                        "poc_request": "PATCH /account/settings HTTP/1.1\nContent-Type: application/json\n\n{\"role\":\"auditor\"}",
                                        "poc_response": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"role\":\"auditor\"}",
                                        "blind_correlation": {},
                                    }
                                ]
                            }
                        ],
                        "findings": [],
                    }
                },
            },
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://127.0.0.1:8888/",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    generated_reports = sorted(reports_dir.glob("haddix_report_*.md"))
    assert generated_reports, "Haddix report file was not generated"

    content = generated_reports[-1].read_text(encoding="utf-8")
    assert "Potential privilege parameter tampering surface" in content
    assert "Confirmed: 1 / Candidate: 0" in content
    assert "### ✅ Confirmed Findings" in content


def test_main_report_haddix_structured_evidence_is_promoted_to_poc_and_confirmed(tmp_path, monkeypatch):
    project_name = "demo-structured-evidence"
    project_dir = tmp_path / "projects" / project_name
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)

    session_file = sessions_dir / "session_20260423_154037.json"
    session_payload = {
        "completed_tasks": [
            {
                "id": "t1",
                "name": "api-data-check",
                "state": "success",
                "params": {"instruction": "run api check"},
                "result": {
                    "data": {
                        "findings": [
                            {
                                "title": "Potential Unauthenticated API Access",
                                "severity": "medium",
                                "vuln_type": "broken_access_control",
                                "target_url": "http://127.0.0.1:8888/chatbot/genai/state",
                                "summary": "Potential auth bypass on API endpoint",
                                "additional_info": {
                                    "detection_mode": "phase1",
                                    "authz_differential": {
                                        "scenario": "unauthenticated_api_access",
                                        "confidence": 0.85,
                                        "signals": [
                                            "auth_success",
                                            "unauth_success",
                                            "auth_json_like",
                                            "unauth_json_like",
                                            "body_length_close",
                                        ],
                                        "baseline_status": 200,
                                        "test_status": 200,
                                    },
                                },
                                "evidence": {
                                    "request_method": "GET",
                                    "request_url": "http://127.0.0.1:8888/chatbot/genai/state",
                                    "request_headers": {"Accept": "application/json"},
                                    "request_body": "",
                                    "response_status": 200,
                                    "response_headers": {"Content-Type": "application/json"},
                                    "response_body": "{\"status\":\"ok\",\"balance\":1000}",
                                },
                            }
                        ],
                    }
                },
            }
        ],
        "task_queue": [],
        "context": {},
        "goal_target": "http://127.0.0.1:8888/",
    }
    session_file.write_text(json.dumps(session_payload, ensure_ascii=False), encoding="utf-8")

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", "haddix", "--target", project_name],
    )

    main_module.main()

    reports_dir = project_dir / "reports"
    generated_reports = sorted(reports_dir.glob("haddix_report_*.md"))
    assert generated_reports, "Haddix report file was not generated"

    content = generated_reports[-1].read_text(encoding="utf-8")
    assert "Potential Unauthenticated API Access" in content
    assert "Confirmed: 1 / Candidate: 0" in content
    assert "| PoC Request Captured | yes |" in content
    assert "| PoC Response Captured | yes |" in content
