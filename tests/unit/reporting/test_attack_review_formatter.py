"""
Tests for AttackReviewFormatter: review data → Markdown artifact.
"""
import pytest

from src.reporting.attack_review_formatter import (
    format_attack_review,
    _section_1_overview,
    _section_2_review_trail,
    _section_3_unverified,
    _section_4_candidates,
    _section_5_constraints,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def review_session():
    return {
        "session_id": "sess-review",
        "run_id": "run-review",
    }


@pytest.fixture
def sample_profile():
    return {
        "schema_version": 1,
        "run_id": "run-review",
        "session_id": "sess-review",
        "target_host": "example.test",
        "auth_methods": ["JWT", "OAuth2"],
        "tech_stack": {"framework": "Django", "server": "nginx"},
        "key_features": ["Recon", "Fuzzer"],
        "source_refs": ["context.target_info", "completed_tasks.3"],
        "status": "partial",
        "reason_codes": [],
    }


@pytest.fixture
def sample_trail():
    return {
        "schema_version": 1,
        "run_id": "run-review",
        "session_id": "sess-review",
        "status": "complete",
        "reason_codes": [],
        "entries": [
            {
                "trail_id": "trail-0000",
                "phase": "recon",
                "action": "dispatch_recon",
                "observation": "Found login page",
                "result": "Discovered auth flow",
                "source_refs": ["decision_traces.d1"],
                "source_type": "decision_traces",
                "source_id": "d1",
                "redaction_status": "clean",
            },
            {
                "trail_id": "trail-0001",
                "phase": "execution",
                "action": "scan",
                "observation": "Discovered 3 endpoints",
                "result": "success",
                "source_refs": ["task_execution_records.r1"],
                "source_type": "task_execution_records",
                "source_id": "r1",
                "redaction_status": "clean",
            },
        ],
    }


@pytest.fixture
def sample_candidates():
    return [
        {
            "candidate_id": "cand-001",
            "title": "IDOR/BOLA Object Access",
            "risk_level": "medium",
            "adoption_status": "candidate",
            "rationale": "Scenario not covered",
            "source_refs": ["scenario_coverage.missing_scenarios"],
        },
        {
            "candidate_id": "cand-002",
            "title": "Skipped: OOB channel",
            "risk_level": "low",
            "adoption_status": "deferred",
            "rationale": "Skipped during execution",
            "source_refs": ["decision_traces.d2"],
        },
    ]


# ---------------------------------------------------------------------------
# Section 1: 今回わかったこと
# ---------------------------------------------------------------------------

def test_section_1_includes_host_and_auth(sample_profile, sample_trail):
    output = _section_1_overview(sample_profile, sample_trail)
    assert "example.test" in output
    assert "JWT" in output
    assert "OAuth2" in output


def test_section_1_includes_tech_stack(sample_profile):
    output = _section_1_overview(sample_profile, None)
    assert "Django" in output
    assert "nginx" in output


def test_section_1_includes_trail_status(sample_profile, sample_trail):
    output = _section_1_overview(sample_profile, sample_trail)
    assert "complete" in output


def test_section_1_includes_source_refs(sample_profile):
    output = _section_1_overview(sample_profile, None)
    assert "context.target_info" in output
    assert "completed_tasks" in output


def test_section_1_handles_none_inputs():
    output = _section_1_overview(None, None)
    assert isinstance(output, str)
    assert "No data available" in output


# ---------------------------------------------------------------------------
# Section 2: 根拠つきレビュー履歴
# ---------------------------------------------------------------------------

def test_section_2_includes_all_entries(sample_trail):
    output = _section_2_review_trail(sample_trail)
    assert "trail-0000" in output
    assert "trail-0001" in output
    assert "decision_traces.d1" in output
    assert "task_execution_records.r1" in output


def test_section_2_source_refs_visible(sample_trail):
    """source_refs must be displayed for traceability."""
    output = _section_2_review_trail(sample_trail)
    assert "source_refs" in output or "decision_traces.d1" in output
    assert "decision_traces" in output
    assert "task_execution_records" in output


def test_section_2_handles_none():
    output = _section_2_review_trail(None)
    assert "No data available" in output


def test_section_2_handles_empty_entries():
    trail = {"entries": [], "status": "empty", "reason_codes": []}
    output = _section_2_review_trail(trail)
    assert "履歴エントリなし" in output


# ---------------------------------------------------------------------------
# Section 3: 未確認
# ---------------------------------------------------------------------------

def test_section_3_shows_degraded_status():
    trail = {"status": "degraded", "reason_codes": ["max_entries_truncated"]}
    output = _section_3_unverified(trail)
    assert "degraded" in output
    assert "max_entries_truncated" in output


def test_section_3_shows_empty_status():
    trail = {"status": "empty", "reason_codes": []}
    output = _section_3_unverified(trail)
    assert "empty" in output


def test_section_3_handles_none():
    output = _section_3_unverified(None)
    assert "未確認項目なし" in output


# ---------------------------------------------------------------------------
# Section 4: 次にやる候補
# ---------------------------------------------------------------------------

def test_section_4_includes_all_candidates(sample_candidates):
    output = _section_4_candidates(sample_candidates)
    assert "cand-001" in output
    assert "cand-002" in output
    assert "IDOR/BOLA Object Access" in output
    assert "deferred" in output


def test_section_4_includes_source_refs(sample_candidates):
    output = _section_4_candidates(sample_candidates)
    assert "scenario_coverage.missing_scenarios" in output
    assert "decision_traces.d2" in output


def test_section_4_handles_none():
    output = _section_4_candidates(None)
    assert "次回候補なし" in output


def test_section_4_handles_empty():
    output = _section_4_candidates([])
    assert "次回候補なし" in output


# ---------------------------------------------------------------------------
# Section 5: 制約 / 不完全情報
# ---------------------------------------------------------------------------

def test_section_5_includes_constraints(sample_profile, sample_trail, sample_candidates):
    output = _section_5_constraints(sample_profile, sample_trail, sample_candidates)
    assert "候補数: 2" in output or "候補数:2" in output
    assert "entry" in output.lower() or "エントリ" in output


def test_section_5_handles_all_none():
    output = _section_5_constraints(None, None, None)
    assert isinstance(output, str)
    assert "メタデータ" in output or "なし" in output


# ---------------------------------------------------------------------------
# Full format
# ---------------------------------------------------------------------------

def test_full_format_produces_complete_markdown(
    review_session, sample_profile, sample_trail, sample_candidates
):
    output = format_attack_review(
        review_session,
        profile=sample_profile,
        trail=sample_trail,
        candidates=sample_candidates,
    )
    assert "# 攻撃レビューレポート" in output
    assert "sess-review" in output
    assert "run-review" in output
    # All 5 sections present
    assert "## 1. 今回わかったこと" in output
    assert "## 2. 根拠つきレビュー履歴" in output
    assert "## 3. 未確認" in output
    assert "## 4. 次にやる候補" in output
    assert "## 5. 制約 / 不完全情報" in output


def test_full_format_no_raw_secrets(
    review_session, sample_profile, sample_trail, sample_candidates
):
    """Raw secrets (tokens, cookies, passwords) must never appear in output."""
    output = format_attack_review(
        review_session,
        profile=sample_profile,
        trail=sample_trail,
        candidates=sample_candidates,
    )
    assert "token=" not in output.lower()
    assert "cookie=" not in output.lower()
    assert "Bearer " not in output
    assert "password" not in output.lower()
    assert "Authorization: " not in output


def test_full_format_empty_session(review_session):
    """Empty data must not crash the formatter."""
    output = format_attack_review(
        review_session,
        profile=None,
        trail=None,
        candidates=None,
    )
    assert isinstance(output, str)
    assert len(output) > 0
    assert "# 攻撃レビューレポート" in output


def test_full_format_degraded_session(review_session):
    """Degraded trail data must not crash."""
    degraded_trail = {
        "status": "degraded",
        "reason_codes": ["max_entries_truncated", "partial_spool"],
        "entries": [],
    }
    output = format_attack_review(
        review_session,
        profile=None,
        trail=degraded_trail,
        candidates=None,
    )
    assert "degraded" in output
    assert "max_entries_truncated" in output


def test_full_format_source_refs_present_everywhere(
    review_session, sample_profile, sample_trail, sample_candidates
):
    """source_refs must be visible in the output for every data section."""
    output = format_attack_review(
        review_session,
        profile=sample_profile,
        trail=sample_trail,
        candidates=sample_candidates,
    )
    # Profile source
    assert "context.target_info" in output
    # Trail source
    assert "decision_traces.d1" in output
    assert "task_execution_records.r1" in output
    # Candidate source
    assert "scenario_coverage.missing_scenarios" in output
    assert "decision_traces.d2" in output


def test_full_format_none_session_not_crash():
    """Passing None-like session must not crash."""
    output = format_attack_review({}, profile=None, trail=None, candidates=None)
    assert isinstance(output, str)
    assert len(output) > 0


# ---------------------------------------------------------------------------
# Auto-resolution from session_data
# ---------------------------------------------------------------------------


def test_full_format_with_session_data_only(sample_profile, sample_trail, sample_candidates):
    """Pass only session_data with embedded review fields – no separate kwargs."""
    session = {
        "session_id": "sess-embed",
        "run_id": "run-embed",
        "target_system_profile": sample_profile,
        "attack_review_trail": sample_trail,
        "scenario_candidates": sample_candidates,
    }
    output = format_attack_review(session)
    assert "# 攻撃レビューレポート" in output
    assert "sess-embed" in output
    # All 5 sections present
    assert "## 1. 今回わかったこと" in output
    assert "## 2. 根拠つきレビュー履歴" in output
    assert "## 3. 未確認" in output
    assert "## 4. 次にやる候補" in output
    assert "## 5. 制約 / 不完全情報" in output
    # Content not just No data available
    assert "example.test" in output
    assert "trail-0000" in output
    assert "cand-001" in output
    assert "No data available" not in output


def test_full_format_fallback_builds_from_raw_data():
    """Session with raw data but no pre-built review fields triggers build fallback."""
    session = {
        "session_id": "sess-raw",
        "run_id": "run-raw",
        "context": {
            "target_info": {
                "domain": "api.raw-example.com",
                "url": "https://api.raw-example.com/v1",
                "auth_mechanisms": ["API-Key"],
                "tech_stack": {"backend": "Flask", "db": "PostgreSQL"},
            },
        },
        "decision_traces": [
            {
                "decision_id": "d1",
                "phase": "recon",
                "timestamp": "2026-01-01T00:00:00Z",
                "observation": "Discovered login",
                "rationale": "Start auth testing",
                "action": "scan_login",
                "outcome": "Found 2 endpoints",
            },
            {
                "decision_id": "d2",
                "phase": "execution",
                "action": "skip",
                "target": "OOB-blind",
                "reason": "Out of scope",
            },
        ],
        "coverage_gate": {
            "missing_families": [
                {"family": "IDOR", "reason": "Not tested"},
            ],
        },
        "scenario_coverage": {
            "missing_scenarios": [
                {"scenario_id": "sc-001", "title": "JWT Token Manipulation"},
            ],
        },
        "completed_tasks": [
            {"agent_type": "Recon", "target_url": "https://api.raw-example.com/v1"},
        ],
    }
    output = format_attack_review(session)
    assert "# 攻撃レビューレポート" in output
    assert "sess-raw" in output
    # All 5 sections present
    assert "## 1. 今回わかったこと" in output
    assert "## 2. 根拠つきレビュー履歴" in output
    assert "## 3. 未確認" in output
    assert "## 4. 次にやる候補" in output
    assert "## 5. 制約 / 不完全情報" in output
    # Built content visible
    assert "api.raw-example.com" in output
    assert "Flask" in output
    assert "trail-dt-0000" in output
    assert "d1" in output
    assert "cand-ms-sc-001" in output  # from missing_scenarios
    assert "cand-dt-0001" in output     # from skipped decision


# ---------------------------------------------------------------------------
# Per-field fallback: when only some fields are pre-saved, the rest are auto-built
# ---------------------------------------------------------------------------


def test_full_format_partial_profile_only_builds_rest(sample_profile):
    """Session has target_system_profile but no trail/candidates – builder fills the rest."""
    session = {
        "session_id": "sess-partial-profile",
        "run_id": "run-partial-profile",
        "target_system_profile": sample_profile,
        "context": {
            "target_info": {
                "domain": "api.partial.com",
                "url": "https://api.partial.com/v1",
                "auth_mechanisms": ["Bearer"],
                "tech_stack": {"backend": "Express", "db": "MongoDB"},
            },
        },
        "decision_traces": [
            {
                "decision_id": "d1",
                "phase": "recon",
                "timestamp": "2026-07-01T00:00:00Z",
                "observation": "Discovered API docs",
                "rationale": "Begin mapping",
                "action": "swagger_scan",
                "outcome": "Found 5 endpoints",
            },
        ],
        "coverage_gate": {
            "missing_families": [
                {"family": "XSS", "reason": "Not tested"},
            ],
        },
        "scenario_coverage": {
            "missing_scenarios": [
                {"scenario_id": "sc-partial", "title": "Reflected XSS"},
            ],
        },
        "completed_tasks": [
            {"agent_type": "Recon", "target_url": "https://api.partial.com/v1"},
        ],
    }
    output = format_attack_review(session)
    assert "# 攻撃レビューレポート" in output
    assert "sess-partial-profile" in output
    # All 5 sections present
    assert "## 1. 今回わかったこと" in output
    assert "## 2. 根拠つきレビュー履歴" in output
    assert "## 3. 未確認" in output
    assert "## 4. 次にやる候補" in output
    assert "## 5. 制約 / 不完全情報" in output
    # Profile was pre-saved – "example.test" from sample_profile should appear
    assert "example.test" in output
    # Trail was auto-built from decision_traces
    assert "trail-dt-0000" in output
    # Candidates were auto-built from missing_scenarios
    assert "cand-ms-sc-partial" in output


def test_full_format_partial_trail_only_builds_rest(sample_trail):
    """Session has attack_review_trail but no profile/candidates – builder fills the rest."""
    session = {
        "session_id": "sess-partial-trail",
        "run_id": "run-partial-trail",
        "attack_review_trail": sample_trail,
        "context": {
            "target_info": {
                "domain": "api.trail-only.com",
                "url": "https://api.trail-only.com/v1",
                "auth_mechanisms": ["API-Key"],
                "tech_stack": {"backend": "FastAPI", "db": "SQLite"},
            },
        },
        "decision_traces": [
            {
                "decision_id": "d1",
                "phase": "execution",
                "timestamp": "2026-07-02T00:00:00Z",
                "observation": "Rate limiting detected",
                "rationale": "Check throttling",
                "action": "burst_test",
                "outcome": "429 responses",
            },
        ],
        "coverage_gate": {
            "missing_families": [
                {"family": "SSRF", "reason": "Not tested"},
            ],
        },
        "scenario_coverage": {
            "missing_scenarios": [
                {"scenario_id": "sc-trail-only", "title": "Blind SSRF via webhook"},
            ],
        },
        "completed_tasks": [
            {"agent_type": "Fuzzer", "target_url": "https://api.trail-only.com/v1"},
        ],
    }
    output = format_attack_review(session)
    assert "# 攻撃レビューレポート" in output
    assert "sess-partial-trail" in output
    # All 5 sections present
    assert "## 1. 今回わかったこと" in output
    assert "## 2. 根拠つきレビュー履歴" in output
    assert "## 3. 未確認" in output
    assert "## 4. 次にやる候補" in output
    assert "## 5. 制約 / 不完全情報" in output
    # Trail was pre-saved – "trail-0000" from sample_trail should appear
    assert "trail-0000" in output
    # Profile was auto-built from context.target_info
    assert "api.trail-only.com" in output
    # Candidates were auto-built from missing_scenarios
    assert "cand-ms-sc-trail-only" in output
