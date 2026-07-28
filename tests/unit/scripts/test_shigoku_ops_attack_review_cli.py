"""
Tests for shigoku-ops report attack-review CLI command (SGK-2026-0324 Step 5)
and real-session validation (SGK-2026-0324 Step 6).
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_session(tmp_path: Path, session_data: dict, name: str = "test_session.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(session_data), encoding="utf-8")
    return path


def _run_ops(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "--json", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )


# ===================================================================
# Step 5: CLI command tests
# ===================================================================


def test_report_attack_review_help_shows():
    """Help output must include the attack-review subcommand."""
    result = subprocess.run(
        ["python3", "scripts/shigoku_ops_cli.py", "report", "--help"],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "attack-review" in result.stdout, f"Missing attack-review in: {result.stdout}"


def test_report_attack_review_session_generates_output(tmp_path: Path):
    """--session flag must generate attack_review.md from session data."""
    session = {
        "session_id": "test-sess-001",
        "run_id": "test-run-001",
        "context": {
            "target_info": {
                "url": "https://example.test",
                "domain": "example.test",
                "auth_mechanisms": ["JWT"],
            },
        },
        "completed_tasks": [
            {"id": "t1", "target_url": "https://example.test/login", "action": "scan",
             "agent_type": "Recon", "result": {"findings": []}},
        ],
        "decision_traces": [
            {"decision_id": "d1", "action": "dispatch_recon", "phase": "recon",
             "context": "Started", "outcome": "OK"},
        ],
        "coverage_gate": {"missing_families": ["xss"]},
        "scenario_coverage": {"missing_scenarios": ["scn_01"]},
    }
    session_path = _write_session(tmp_path, session)

    result = _run_ops(["report", "attack-review", "--session", str(session_path)], _repo_root())

    assert result.returncode == 0, f"stderr: {result.stderr}\nstdout: {result.stdout}"
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    # The markdown must contain the attack review header
    assert "攻撃レビューレポート" in payload.get("markdown", "")


def test_report_attack_review_session_generates_all_five_sections(tmp_path: Path):
    """Generated attack_review.md must contain all 5 expected sections."""
    session = {
        "session_id": "test-sess-002",
        "run_id": "test-run-002",
        "context": {
            "target_info": {
                "url": "https://example.test",
                "domain": "example.test",
                "tech_stack": {"framework": "Django"},
                "auth_mechanisms": ["JWT"],
            },
        },
        "completed_tasks": [
            {"id": "t1", "target_url": "https://example.test", "action": "scan",
             "agent_type": "Recon", "result": {}},
        ],
        "decision_traces": [
            {"decision_id": "d1", "action": "scan", "phase": "recon",
             "context": "Discovered", "outcome": "OK"},
        ],
        "coverage_gate": {"missing_families": ["api"]},
        "scenario_coverage": {"missing_scenarios": ["scn_01"]},
    }
    session_path = _write_session(tmp_path, session)

    result = _run_ops(["report", "attack-review", "--session", str(session_path)], _repo_root())

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    markdown = payload.get("markdown", "")

    for section in ("今回わかったこと", "根拠つきレビュー履歴", "未確認", "次にやる候補", "制約"):
        assert section in markdown, f"Missing section '{section}' in:\n{markdown[:500]}"


def test_report_attack_review_missing_session_returns_blocked(tmp_path: Path):
    """Missing --session must return blocked status."""
    result = _run_ops(
        ["report", "attack-review", "--session", str(tmp_path / "nonexistent.json")],
        _repo_root(),
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked"


def test_report_attack_review_output_to_file(tmp_path: Path):
    """--output flag must write attack_review.md to the specified file."""
    session = {
        "session_id": "sess-file",
        "run_id": "run-file",
        "context": {"target_info": {"url": "https://example.test"}},
        "completed_tasks": [],
        "decision_traces": [{"decision_id": "d1", "action": "test", "phase": "test",
                              "context": "", "outcome": ""}],
        "coverage_gate": {},
        "scenario_coverage": {},
    }
    session_path = _write_session(tmp_path, session)
    output_path = tmp_path / "attack_review_out.md"

    result = _run_ops(
        ["report", "attack-review", "--session", str(session_path), "--output", str(output_path)],
        _repo_root(),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["output"] == str(output_path)
    assert output_path.exists()
    content = output_path.read_text()
    assert "攻撃レビューレポート" in content


def test_report_attack_review_consistency_checked_with_both_flags(tmp_path: Path):
    """When both --session and --report are passed, the consistency check
    must run and block mismatched pairs (regression: session-only path
    used to bypass the check entirely)."""
    session_data: dict = {
        "session_id": "test-consistency-both-001",
        "run_id": "test-run-both-001",
        "context": {
            "target_info": {
                "url": "https://example.test",
                "domain": "example.test",
                "auth_mechanisms": ["JWT"],
            },
        },
        "completed_tasks": [
            {"id": "t1", "target_url": "https://example.test", "action": "scan",
             "agent_type": "Recon", "result": {"findings": []}},
        ],
        "decision_traces": [
            {"decision_id": "d1", "action": "dispatch_recon", "phase": "recon",
             "context": "Started", "outcome": "OK"},
        ],
        "coverage_gate": {"missing_families": ["xss"]},
        "scenario_coverage": {
            "covered_count": 3,
            "required_count": 10,
            "missing_scenarios": ["scn_01"],
        },
    }
    session_path = _write_session(tmp_path, session_data)

    # Fake haddix report whose scenario_coverage DIFFERS from the session
    fake_report = tmp_path / "haddix_report_20260721_120000.md"
    fake_report.write_text(
        "# Haddix Report - Test\n\n"
        "**Generated:** 2026-07-21 12:00:00 JST\n\n"
        "**Source Session:** /fake/other/session.json\n\n"
        "Coverage: 5/10 (50%), Missing: scn_02\n",
        encoding="utf-8",
    )

    result = _run_ops(
        ["report", "attack-review",
         "--session", str(session_path),
         "--report", str(fake_report)],
        _repo_root(),
    )

    # Consistency mismatch must be detected and blocked
    assert result.returncode == 2, (
        f"Expected exit code 2 (blocked), got {result.returncode}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "blocked", (
        f"Expected status 'blocked', got {payload}"
    )
    assert "reason_codes" in payload


# ===================================================================
# Step 6: Real session validation tests
# ===================================================================


def test_real_session_attack_review_self_contained():
    """format_attack_review() must produce 5 sections from a real session
    without any separate profile/trail/candidates kwargs."""
    from src.reporting.attack_review_formatter import format_attack_review

    sessions_dir = _repo_root() / "workspace" / "projects"
    session_files = sorted(sessions_dir.glob("*/sessions/session_*.json"))
    if not session_files:
        pytest.skip("No real session artifacts available")

    tested = 0
    for sf in session_files[:3]:
        data = json.loads(sf.read_text())
        report = format_attack_review(data)
        sections_present = sum(
            1 for s in ("今回わかったこと", "レビュー履歴", "未確認", "次にやる候補", "制約")
            if s in report
        )
        assert sections_present == 5, (
            f"Session {sf.name}: only {sections_present}/5 sections present"
        )
        # No raw secrets
        for secret in ("cookie=", "token=", "Bearer ", "Authorization:", "password="):
            assert secret.lower() not in report.lower(), (
                f"Session {sf.name}: LEAK {secret}"
            )
        tested += 1

    assert tested >= 1, "No real sessions were tested"


def test_real_session_target_profile_uses_persisted_profile():
    """TargetProfileFormatter must prefer persisted target_system_profile
    when it exists in a real session."""
    from src.reporting.target_profile_formatter import TargetProfileFormatter

    sessions_dir = _repo_root() / "workspace" / "projects"
    session_files = sorted(sessions_dir.glob("*/sessions/session_*.json"))
    if not session_files:
        pytest.skip("No real session artifacts available")

    # Find a session with diversity
    for sf in session_files:
        data = json.loads(sf.read_text())
        formatter = TargetProfileFormatter()
        report = formatter.format(data)
        assert "# ターゲットプロファイルレポート" in report
        break


def test_real_session_review_artifact_no_crash():
    """End-to-end: build_all_review_fields -> format_attack_review must not crash
    on any available real session."""
    from src.reporting.attack_review_builder import build_all_review_fields
    from src.reporting.attack_review_formatter import format_attack_review

    sessions_dir = _repo_root() / "workspace" / "projects"
    session_files = list(sessions_dir.glob("*/sessions/session_*.json"))
    if not session_files:
        pytest.skip("No real session artifacts available")

    for sf in session_files[:5]:
        data = json.loads(sf.read_text())
        fields = build_all_review_fields(data)
        report = format_attack_review(
            data,
            profile=fields["target_system_profile"],
            trail=fields["attack_review_trail"],
            candidates=fields["scenario_candidates"],
        )
        assert isinstance(report, str)
        assert len(report) > 0


def test_real_session_ops_cli_attack_review():
    """shigoku-ops report attack-review must work on a real session."""
    sessions_dir = _repo_root() / "workspace" / "projects"
    session_files = sorted(sessions_dir.glob("*/sessions/session_*.json"))
    if not session_files:
        pytest.skip("No real session artifacts available")

    sf = session_files[0]
    result = _run_ops(
        ["report", "attack-review", "--session", str(sf)],
        _repo_root(),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert "攻撃レビューレポート" in payload.get("markdown", "")


def test_attack_review_source_refs_traceable():
    """Review artifact must include source_refs for traceability."""
    from src.reporting.attack_review_builder import build_all_review_fields
    from src.reporting.attack_review_formatter import format_attack_review

    sessions_dir = _repo_root() / "workspace" / "projects"
    session_files = sorted(sessions_dir.glob("*/sessions/session_*.json"))
    if not session_files:
        pytest.skip("No real session artifacts available")

    for sf in session_files[:3]:
        data = json.loads(sf.read_text())
        fields = build_all_review_fields(data)

        # Profile must have source_refs
        if fields["target_system_profile"]:
            assert fields["target_system_profile"].get("source_refs"), (
                f"Session {sf.name}: profile missing source_refs"
            )

        # Trail entries must have source_refs
        if fields["attack_review_trail"]:
            for entry in fields["attack_review_trail"].get("entries", []):
                assert entry.get("source_refs"), (
                    f"Session {sf.name}: trail entry missing source_refs"
                )

        # Candidates must have source_refs
        if fields["scenario_candidates"]:
            for c in fields["scenario_candidates"]:
                assert c.get("source_refs"), (
                    f"Session {sf.name}: candidate missing source_refs"
                )
