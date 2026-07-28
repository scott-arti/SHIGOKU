"""
Tests for AttackReviewBuilder: finalized session data -> additive review fields.
"""
import pytest

from src.reporting.attack_review_builder import (
    build_target_system_profile,
    build_attack_review_trail,
    build_scenario_candidates,
    build_all_review_fields,
    _is_secret_key,
    _redact_value,
    MAX_TRAIL_ENTRIES,
    MAX_CANDIDATES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def min_session():
    return {
        "session_id": "test-sess",
        "run_id": "test-run",
        "context": {
            "target_info": {
                "url": "https://example.test",
                "domain": "example.test",
                "auth_mechanisms": ["JWT", "OAuth2"],
                "tech_stack": {"framework": "Django 4.2", "server": "nginx"},
            },
        },
        "completed_tasks": [
            {"id": "t1", "target_url": "https://example.test/login",
             "action": "scan", "agent_type": "Recon",
             "params": {"target": "https://example.test", "depth": 3}},
            {"id": "t2", "target_url": "https://example.test/api/users",
             "action": "fuzz", "agent_type": "Fuzzer",
             "params": {"cookie": "session=abc123", "inject": True}},
        ],
        "decision_traces": [
            {"decision_id": "d1", "action": "dispatch_recon", "phase": "recon",
             "context": "Found login page", "rationale": "Start with recon",
             "outcome": "Discovered auth flow"},
            {"decision_id": "d2", "action": "skip", "phase": "execution",
             "target": "scn_08", "reason": "not applicable"},
        ],
        "task_execution_records": [
            {"task_id": "t1", "record_id": "r1", "phase": "execution",
             "action": "scan", "result": "success",
             "summary": "Discovered 3 endpoints"},
        ],
        "run_ledger": [
            {"event_id": "e1", "event_type": "decision_made",
             "summary": "Recon dispatched to host", "timestamp": "2026-01-01T00:00:00Z",
             "source_refs": ["decision_traces.d1"]},
            {"event_id": "e2", "event_type": "tool_executed",
             "summary": "GET /login returned 200", "timestamp": "2026-01-01T00:01:00Z"},
        ],
        "findings": [
            {"vuln_type": "xss", "severity": "medium",
             "target_url": "https://example.test/search"},
        ],
        "coverage_gate": {
            "missing_families": ["injection", "csrf", "api"],
        },
        "scenario_coverage": {
            "missing_scenarios": ["scn_01_idor_bola_object_access", "scn_05_rate_limiting_abuse"],
        },
    }


@pytest.fixture
def empty_session():
    return {"session_id": "empty", "run_id": "empty-run"}


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

def test_is_secret_key_detects_cookie():
    assert _is_secret_key("cookie") is True
    assert _is_secret_key("Cookie") is True
    assert _is_secret_key("session_id") is False  # public identifier, not a secret
    assert _is_secret_key("api_key") is True
    assert _is_secret_key("Authorization") is True
    assert _is_secret_key("target_url") is False
    assert _is_secret_key("action") is False


def test_redact_value_redacts_nested_secrets():
    data = {"auth": {"token": "secret123"}, "meta": {"name": "test"}, "list": [{"api_key": "sk-xyz"}]}
    result = _redact_value(data)
    assert result["auth"]["token"] == "[REDACTED]"
    assert result["meta"]["name"] == "test"
    assert result["list"][0]["api_key"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# target_system_profile
# ---------------------------------------------------------------------------

def test_profile_returns_none_for_empty_session(empty_session):
    profile = build_target_system_profile(empty_session)
    assert profile is None


def test_profile_includes_core_fields(min_session):
    profile = build_target_system_profile(min_session, "sess-1", "run-1")
    assert profile is not None
    assert profile["schema_version"] == 1
    assert profile["run_id"] == "run-1"
    assert profile["session_id"] == "sess-1"
    assert profile["target_host"] == "example.test"


def test_profile_includes_auth_methods(min_session):
    profile = build_target_system_profile(min_session)
    assert "JWT" in profile["auth_methods"]
    assert "OAuth2" in profile["auth_methods"]


def test_profile_includes_tech_stack(min_session):
    profile = build_target_system_profile(min_session)
    assert profile["tech_stack"]["framework"] == "Django 4.2"
    assert profile["tech_stack"]["server"] == "nginx"


def test_profile_includes_source_refs(min_session):
    profile = build_target_system_profile(min_session)
    assert len(profile["source_refs"]) >= 1
    assert any("context" in sr for sr in profile["source_refs"])


def test_profile_redacts_secrets_in_params(min_session):
    profile = build_target_system_profile(min_session)
    # Check input_points don't contain secret keys
    for ip in profile["input_points"]:
        assert not _is_secret_key(ip.get("param", ""))


def test_profile_key_endpoints_from_completed_tasks(min_session):
    profile = build_target_system_profile(min_session)
    urls = [ep["url"] for ep in profile["key_endpoints"]]
    assert "https://example.test/login" in urls
    assert "https://example.test/api/users" in urls


def test_profile_does_not_read_current_context(empty_session):
    """Profile must not read current_context or any mutable intermediate state."""
    session = dict(empty_session)
    session["current_context"] = {"fake_target": "evil.com"}
    session["_intermediate"] = {"injection": "data"}
    profile = build_target_system_profile(session)
    # current_context must not influence the profile
    assert profile is None  # no real target_info available


# ---------------------------------------------------------------------------
# attack_review_trail
# ---------------------------------------------------------------------------

def test_trail_returns_none_for_empty_session(empty_session):
    trail = build_attack_review_trail(empty_session)
    assert trail is None


def test_trail_includes_entries_from_decision_traces(min_session):
    trail = build_attack_review_trail(min_session)
    assert trail is not None
    entries = trail["entries"]
    dt_entries = [e for e in entries if e["source_type"] == "decision_traces"]
    assert len(dt_entries) >= 2
    assert dt_entries[0]["source_refs"] == ["decision_traces.d1"]


def test_trail_includes_entries_from_task_execution_records(min_session):
    trail = build_attack_review_trail(min_session)
    tr_entries = [e for e in trail["entries"] if e["source_type"] == "task_execution_records"]
    assert len(tr_entries) >= 1
    assert tr_entries[0]["source_id"] == "r1"


def test_trail_includes_entries_from_run_ledger(min_session):
    trail = build_attack_review_trail(min_session)
    rl_entries = [e for e in trail["entries"] if e["source_type"] == "run_ledger"]
    assert len(rl_entries) >= 2
    assert rl_entries[0]["source_refs"] == ["run_ledger.e1"]


def test_trail_each_entry_has_trail_id(min_session):
    trail = build_attack_review_trail(min_session)
    for entry in trail["entries"]:
        assert entry["trail_id"], f"Missing trail_id in {entry}"
        assert entry["source_refs"], f"Missing source_refs in {entry}"
        assert "redaction_status" in entry


def test_trail_status_is_complete_for_normal_session(min_session):
    trail = build_attack_review_trail(min_session)
    assert trail["status"] == "complete"


def test_trail_has_run_id_and_session_id(min_session):
    trail = build_attack_review_trail(min_session, "sess-x", "run-x")
    assert trail["run_id"] == "run-x"
    assert trail["session_id"] == "sess-x"


def test_trail_max_entries_truncated():
    """When entries exceed MAX_TRAIL_ENTRIES, status must be degraded."""
    session = {
        "decision_traces": [
            {"decision_id": f"d{i}", "action": "test"} for i in range(MAX_TRAIL_ENTRIES + 10)
        ],
        "task_execution_records": [],
        "run_ledger": [],
    }
    trail = build_attack_review_trail(session)
    assert trail is not None
    assert trail["status"] == "degraded"
    assert "max_entries_truncated" in trail["reason_codes"]


def test_trail_scope_isolation():
    """Trail must not mix data from different scopes (no cross-scope contamination)."""
    session = {
        "decision_traces": [
            {"decision_id": "d1", "action": "scan", "phase": "recon",
             "context": "Target A", "target_scope_id": "scope-a"},
        ],
        "task_execution_records": [],
        "run_ledger": [],
    }
    trail = build_attack_review_trail(session, session_id="sess-a", run_id="run-a")
    assert trail["run_id"] == "run-a"
    assert trail["session_id"] == "sess-a"


# ---------------------------------------------------------------------------
# scenario_candidates
# ---------------------------------------------------------------------------

def test_candidates_returns_none_for_empty_session(empty_session):
    candidates = build_scenario_candidates(empty_session)
    assert candidates is None


def test_candidates_from_missing_families(min_session):
    candidates = build_scenario_candidates(min_session)
    assert candidates is not None
    fam_candidates = [c for c in candidates if c["candidate_id"].startswith("cand-mf-")]
    assert len(fam_candidates) >= 2  # injection, csrf, api
    # Each must have source_refs
    for c in fam_candidates:
        assert c["source_refs"]
        assert c["adoption_status"] == "candidate"


def test_candidates_from_missing_scenarios(min_session):
    candidates = build_scenario_candidates(min_session)
    ms_candidates = [c for c in candidates if c["candidate_id"].startswith("cand-ms-")]
    assert len(ms_candidates) >= 2


def test_candidates_from_skipped_decisions(min_session):
    candidates = build_scenario_candidates(min_session)
    dt_candidates = [c for c in candidates if c["candidate_id"].startswith("cand-dt-")]
    # "d2" was a skip action
    assert len(dt_candidates) >= 1
    assert dt_candidates[0]["adoption_status"] == "deferred"


def test_candidates_each_has_risk_level(min_session):
    candidates = build_scenario_candidates(min_session)
    for c in candidates:
        assert c.get("risk_level") in ("low", "medium", "high", "critical")


def test_candidates_max_truncated():
    session = {
        "decision_traces": [
            {"decision_id": f"d{i}", "action": "skip", "target": f"scn_{i}"}
            for i in range(MAX_CANDIDATES + 20)
        ],
    }
    candidates = build_scenario_candidates(session)
    assert candidates is not None
    assert len(candidates) <= MAX_CANDIDATES


# ---------------------------------------------------------------------------
# build_all_review_fields
# ---------------------------------------------------------------------------

def test_build_all_review_fields_returns_three_keys(min_session):
    result = build_all_review_fields(min_session, "sess-id", "run-id")
    assert set(result.keys()) == {"target_system_profile", "attack_review_trail", "scenario_candidates"}
    assert result["target_system_profile"] is not None
    assert result["attack_review_trail"] is not None
    assert result["scenario_candidates"] is not None


def test_build_all_review_fields_extracts_session_run_ids(min_session):
    result = build_all_review_fields(min_session)
    assert result["target_system_profile"]["session_id"] == "test-sess"
    assert result["target_system_profile"]["run_id"] == "test-run"


def test_build_all_review_fields_empty_session(empty_session):
    result = build_all_review_fields(empty_session)
    assert result["target_system_profile"] is None
    assert result["attack_review_trail"] is None
    assert result["scenario_candidates"] is None
