"""Unit tests for takeover_report_normalizer.py

Tests cover:
- normalizer accepts runner result dict with takeover_verdict
- normalizer returns structured report block with provider, evidence, verdict
- takeover_verdict "confirmed" -> takeover_status "confirmed" but global_confirmed False
- takeover_verdict "manual_review_required" -> shows manual checklist items
- takeover_verdict "no_finding" -> shows insufficient evidence note
- takeover_verdict "blocked" -> shows blocking reason from verdict_reason_codes
- takeover_verdict "failed" -> shows infrastructure_state details
- report block includes provider_name, evidence_summary, verification_urls, manual_checklist
- report block includes infrastructure_state alongside verdict
- report block includes verdict_reason_codes as human-readable descriptions
- automation_boundary field clearly marks where automation ends and HITL begins
- manual_review_required entries have non-empty manual_checklist from provider matrix
- normalized output is JSON-serializable
"""

import json
from datetime import datetime, timezone

import pytest

from src.reporting.takeover_report_normalizer import normalize_takeover_for_report
from src.core.adapters.external.takeover_provider_matrix_adapter import ProviderEntry


# ── Helper: build a realistic runner result dict ──────────────────────────

def _make_runner_result(
    takever_verdict: str = "no_finding",
    success_count: int = 0,
    total_steps: int = 3,
    failed_steps: int = 1,
    blocked_steps: int = 0,
    major_failure: bool = False,
    all_blocked: bool = False,
    infrastructure_state: str = "ok",
    verdict_reason_codes: list | None = None,
    cname_chain_in_steps: list | None = None,
    http_status_in_steps: int | None = None,
    error_token_in_steps: str | None = None,
) -> dict:
    """Build a runner result dict matching _finalize_results() output."""
    steps = {}
    for i in range(success_count):
        sid = f"step_{i+1}"
        sd = {"step_id": sid, "action": "cname_resolve", "status": "success",
              "error_code": None, "reason": "ok", "retryable": False}
        if cname_chain_in_steps and i == 0:
            sd["data"] = {"cname_chain": cname_chain_in_steps}
        if http_status_in_steps is not None and i == 1:
            sd["data"] = {"http_status": http_status_in_steps}
        if error_token_in_steps and i == 2:
            sd["data"] = {"error_token": error_token_in_steps}
        steps[sid] = sd
    for i in range(failed_steps):
        sid = f"step_fail_{i+1}"
        steps[sid] = {"step_id": sid, "action": "http_probe", "status": "failed",
                      "error_code": "TOOL_ERROR", "reason": "dns_timeout",
                      "retryable": True}
    for i in range(blocked_steps):
        sid = f"step_block_{i+1}"
        steps[sid] = {"step_id": sid, "action": "claim_check", "status": "blocked",
                      "error_code": "BLOCKED_SCOPE", "reason": "scope_policy",
                      "retryable": False}
    total = success_count + failed_steps + blocked_steps
    return {
        "recipe_name": "recon.takeover",
        "success": not major_failure and total > 0 and not all_blocked,
        "summary": {
            "total_steps": total,
            "success_count": success_count,
            "failed_steps": failed_steps,
            "blocked_steps": blocked_steps,
            "failed_ratio": failed_steps / total if total else 0.0,
            "major_failure": major_failure,
            "all_blocked": all_blocked,
            "stale_candidate": False,
        },
        "steps": steps,
        "infrastructure_state": infrastructure_state,
        "takeover_verdict": takever_verdict,
        "manual_review_required": takever_verdict == "manual_review_required",
        "confirmed": takever_verdict == "confirmed",
        "verdict_reason_codes": verdict_reason_codes or [],
    }


def _make_provider_entry(**overrides) -> ProviderEntry:
    """Build a ProviderEntry with sensible defaults."""
    defaults = {
        "provider_id": "github_pages",
        "fingerprint_domains": ["github.io"],
        "error_tokens": ["There isn't a GitHub Pages site here"],
        "claim_prerequisites": ["GitHub account required"],
        "verification_urls": ["https://github.com/verify"],
        "tool_preference": ["subjack", "subzy"],
        "false_positive_twins": [],
        "hitl_checkpoint_types": [
            "Verify resource is claimable at provider UI",
            "Confirm no third-party impact",
        ],
        "supports_auto_confirm": False,
        "rollback_target": None,
    }
    defaults.update(overrides)
    return ProviderEntry(**defaults)


# ── Test: normalizer accepts runner result and returns structured block ──

def test_normalize_accepts_runner_result_returns_structured_block():
    """normalize_takeover_for_report() should accept a runner result dict
    and return a structured dict with expected top-level keys."""
    rr = _make_runner_result(takever_verdict="manual_review_required", success_count=2)
    result = normalize_takeover_for_report(rr)

    assert isinstance(result, dict)
    assert "takeover_status" in result
    assert "global_confirmed" in result
    assert result["global_confirmed"] is False
    assert "automation_boundary" in result
    assert "provider_name" in result
    assert "evidence_summary" in result
    assert "verdict_reason_codes" in result
    assert "verdict_reason_descriptions" in result
    assert "manual_review_required" in result
    assert "manual_checklist" in result
    assert "verification_urls" in result
    assert "infrastructure_state" in result
    assert "trace" in result


# ── Test: confirmed verdict -> takeover_status "confirmed", global_confirmed False ──

def test_confirmed_verdict_maps_takeover_status_but_global_confirmed_false():
    """Even when takeover_verdict is 'confirmed', global_confirmed must be False."""
    rr = _make_runner_result(
        takever_verdict="confirmed",
        success_count=3,
        verdict_reason_codes=[],
    )
    result = normalize_takeover_for_report(rr, provider_entry=_make_provider_entry())

    assert result["takeover_status"] == "confirmed"
    assert result["global_confirmed"] is False
    assert "hitl required" in result["automation_boundary"].lower()


# ── Test: manual_review_required -> shows manual checklist items ──────────

def test_manual_review_required_shows_checklist_from_provider():
    """When takeover_verdict is 'manual_review_required', the report block
    must include manual_checklist items from the provider entry."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=2,
        verdict_reason_codes=["provider_no_auto_confirm"],
    )
    result = normalize_takeover_for_report(rr, provider_entry=_make_provider_entry())

    assert result["takeover_status"] == "manual_review_required"
    assert result["manual_review_required"] is True
    assert isinstance(result["manual_checklist"], list)
    assert len(result["manual_checklist"]) >= 2
    assert any("claimable" in item.lower() for item in result["manual_checklist"])
    assert any("third-party" in item.lower() for item in result["manual_checklist"])


# ── Test: no_finding -> shows insufficient evidence note ──────────────────

def test_no_finding_shows_insufficient_evidence():
    """When takeover_verdict is 'no_finding', the report block should
    reflect that evidence is insufficient."""
    rr = _make_runner_result(
        takever_verdict="no_finding",
        success_count=0,
        total_steps=1,
        failed_steps=1,
        verdict_reason_codes=["missing_cname", "insufficient_evidence"],
    )
    result = normalize_takeover_for_report(rr)

    assert result["takeover_status"] == "no_finding"
    assert result["evidence_summary"]["evidence_count"] == 0
    assert "insufficient_evidence" in result["verdict_reason_codes"]
    expected_desc = "Not enough evidence types collected (minimum 2 required)"
    assert expected_desc in result["verdict_reason_descriptions"]


# ── Test: blocked -> shows blocking reason ────────────────────────────────

def test_blocked_shows_blocking_reason():
    """When all steps are blocked, takeover_status should be 'blocked'
    and the report must include the blocking reason codes."""
    rr = _make_runner_result(
        takever_verdict="no_finding",
        success_count=0,
        total_steps=2,
        failed_steps=0,
        blocked_steps=2,
        all_blocked=True,
        verdict_reason_codes=["scope_policy_blocks_claim"],
    )
    result = normalize_takeover_for_report(rr)

    assert result["takeover_status"] == "blocked"
    assert "scope_policy_blocks_claim" in result["verdict_reason_codes"]
    expected_desc = "Scope policy blocks automated claim action"
    assert expected_desc in result["verdict_reason_descriptions"]


# ── Test: failed -> shows infrastructure_state details ────────────────────

def test_failed_shows_infrastructure_state():
    """When a major failure occurs, takeover_status is 'failed' and
    infrastructure_state details are included in the report block."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=0,
        total_steps=3,
        failed_steps=3,
        major_failure=True,
        infrastructure_state="probe_failed",
        verdict_reason_codes=["infrastructure_unhealthy"],
    )
    result = normalize_takeover_for_report(rr)

    assert result["takeover_status"] == "failed"
    assert result["infrastructure_state"] == "probe_failed"
    assert "infrastructure_unhealthy" in result["verdict_reason_codes"]
    expected_desc = "Infrastructure issue prevented complete verification"
    assert expected_desc in result["verdict_reason_descriptions"]


# ── Test: report block includes provider_name, evidence_summary, etc. ─────

def test_report_block_includes_provider_name_evidence_verification_urls():
    """The normalized report block must include provider_name, evidence_summary,
    verification_urls, and manual_checklist."""
    rr = _make_runner_result(
        takever_verdict="confirmed",
        success_count=3,
        verdict_reason_codes=[],
        cname_chain_in_steps=["dead.example.com", "bad.github.io"],
        http_status_in_steps=404,
        error_token_in_steps="There isn't a GitHub Pages site here",
    )
    entry = _make_provider_entry()
    result = normalize_takeover_for_report(rr, provider_entry=entry)

    assert result["provider_name"] == "github_pages"
    assert result["verification_urls"] == ["https://github.com/verify"]
    assert isinstance(result["evidence_summary"], dict)
    assert result["evidence_summary"]["evidence_count"] == 3
    assert len(result["evidence_summary"]["tool_results"]) > 0
    assert result["evidence_summary"]["cname_chain"] == (
        ["dead.example.com", "bad.github.io"]
    )
    assert result["evidence_summary"]["http_status"] == 404
    assert result["evidence_summary"]["error_token"] == (
        "There isn't a GitHub Pages site here"
    )
    assert isinstance(result["manual_checklist"], list)
    assert len(result["manual_checklist"]) > 0


# ── Test: infrastructure_state alongside verdict ──────────────────────────

def test_infrastructure_state_included_alongside_verdict():
    """infrastructure_state must appear in the normalized output for every verdict."""
    for inf_state in ("ok", "tool_unavailable", "probe_failed", "timeout", "missing_binary"):
        rr = _make_runner_result(
            takever_verdict="manual_review_required",
            success_count=1,
            infrastructure_state=inf_state,
        )
        result = normalize_takeover_for_report(rr)
        assert result["infrastructure_state"] == inf_state, (
            f"Expected infrastructure_state={inf_state}"
        )


# ── Test: verdict_reason_codes mapped to human-readable descriptions ──────

def test_verdict_reason_codes_mapped_to_human_readable():
    """Each verdict_reason_code must be mapped to a human-readable description."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=1,
        verdict_reason_codes=[
            "missing_cname",
            "stale_candidate",
            "tool_disagreement",
            "provider_no_auto_confirm",
            "scope_policy_blocks_claim",
            "insufficient_evidence",
            "infrastructure_unhealthy",
        ],
    )
    result = normalize_takeover_for_report(rr)

    descriptions = result["verdict_reason_descriptions"]
    assert isinstance(descriptions, list)
    assert len(descriptions) == 7

    expected_map = {
        "missing_cname": "No CNAME chain detected for candidate",
        "stale_candidate": "Candidate data is older than 30 days",
        "tool_disagreement": "Multiple takeover tools returned conflicting results",
        "provider_no_auto_confirm": "Provider does not support automated confirmation",
        "scope_policy_blocks_claim": "Scope policy blocks automated claim action",
        "insufficient_evidence": "Not enough evidence types collected (minimum 2 required)",
        "infrastructure_unhealthy": "Infrastructure issue prevented complete verification",
    }
    for code in rr["verdict_reason_codes"]:
        assert expected_map[code] in descriptions, (
            f"Missing description for {code}"
        )


# ── Test: automation_boundary field ───────────────────────────────────────

def test_automation_boundary_field_marks_hitl_transition():
    """The automation_boundary field must clearly state that
    provider resource creation is never automated."""
    rr = _make_runner_result(takever_verdict="confirmed", success_count=2)
    result = normalize_takeover_for_report(rr)

    ab = result["automation_boundary"]
    assert isinstance(ab, str)
    assert len(ab) > 10
    # Key phrases that must appear
    assert "never automated" in ab.lower()
    assert "hitl" in ab.lower()


# ── Test: manual_review_required entries have non-empty checklist from provider ──

def test_manual_checklist_non_empty_from_provider():
    """When provider_entry is supplied, manual_checklist must be populated
    from hitl_checkpoint_types and must be non-empty."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=2,
    )
    entry = _make_provider_entry(
        hitl_checkpoint_types=[
            "Verify resource claimable at provider dashboard",
            "Check scope policy allows takeover PoC",
            "Ensure DNS records match expected provider",
        ],
    )
    result = normalize_takeover_for_report(rr, provider_entry=entry)

    checklist = result["manual_checklist"]
    assert isinstance(checklist, list)
    assert len(checklist) == 3
    assert checklist == entry.hitl_checkpoint_types


# ── Test: normalizer handles missing provider_entry gracefully ────────────

def test_manual_checklist_empty_when_no_provider_entry():
    """When no provider_entry is provided, manual_checklist should
    be an empty list, not crash."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=2,
    )
    result = normalize_takeover_for_report(rr)

    assert result["manual_checklist"] == []
    assert result["provider_name"] is None
    assert result["verification_urls"] == []


# ── Test: output is JSON-serializable ─────────────────────────────────────

def test_output_is_json_serializable():
    """The entire normalized output dict must be JSON-serializable."""
    rr = _make_runner_result(
        takever_verdict="confirmed",
        success_count=3,
        verdict_reason_codes=[],
        cname_chain_in_steps=["dead.example.com", "bad.github.io"],
        http_status_in_steps=404,
        error_token_in_steps="There isn't a GitHub Pages site here",
    )
    entry = _make_provider_entry()
    result = normalize_takeover_for_report(rr, provider_entry=entry)

    # Should not raise
    serialized = json.dumps(result, indent=2)
    deserialized = json.loads(serialized)
    assert deserialized == result


# ── Test: evidence extracted from steps when provider_entry absent ────────

def test_evidence_extracted_from_steps_without_provider_entry():
    """The normalizer should extract cname_chain, http_status, error_token
    from step data even when no provider_entry is supplied."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=3,
        cname_chain_in_steps=["sub.example.com", "herokuapp.com"],
        http_status_in_steps=404,
        error_token_in_steps="No such app",
    )
    result = normalize_takeover_for_report(rr)

    assert result["evidence_summary"]["cname_chain"] == (
        ["sub.example.com", "herokuapp.com"]
    )
    assert result["evidence_summary"]["http_status"] == 404
    assert result["evidence_summary"]["error_token"] == "No such app"


# ── Test: unknown verdict reason code does not crash ──────────────────────

def test_unknown_verdict_reason_code_included_as_is():
    """An unknown verdict_reason_code should be included with a generic
    description rather than crashing."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=1,
        verdict_reason_codes=["missing_cname", "unknown_future_code"],
    )
    result = normalize_takeover_for_report(rr)

    # known code mapped
    assert "No CNAME chain detected for candidate" in result["verdict_reason_descriptions"]
    # unknown code included with a fallback
    has_fallback = any("unknown_future_code" in d for d in result["verdict_reason_descriptions"])
    assert has_fallback, "Unknown reason code should appear in descriptions"


# ── Test: trace block is present ──────────────────────────────────────────

def test_trace_block_included():
    """The normalized output must include a trace block."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=1,
    )
    result = normalize_takeover_for_report(rr)

    trace = result["trace"]
    assert "producer_step" in trace
    assert trace["producer_step"] == "recon.step3_live_check"
    assert "session_id" in trace or "session_id" not in trace  # optional


def test_trace_block_reads_from_runner_result():
    """When runner_result has trace fields (producer_step, source_line, session_id,
    artifact_hash), the trace block must use them."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=1,
    )
    rr["producer_step"] = "recon.custom_step"
    rr["source_line"] = "takeover_candidates.json:15"
    rr["session_id"] = "sess_20260625_001"
    rr["artifact_hash"] = "sha256:abc123"
    result = normalize_takeover_for_report(rr)

    trace = result["trace"]
    assert trace["producer_step"] == "recon.custom_step"
    assert trace["source_line"] == "takeover_candidates.json:15"
    assert trace["session_id"] == "sess_20260625_001"
    assert trace["artifact_hash"] == "sha256:abc123"


def test_trace_block_falls_back_to_defaults():
    """When runner_result has no trace fields, trace block uses constants/defaults."""
    rr = _make_runner_result(
        takever_verdict="no_finding",
        success_count=1,
    )
    # These keys should NOT be present
    rr.pop("recipe_name", None)
    result = normalize_takeover_for_report(rr)

    trace = result["trace"]
    assert trace["producer_step"] == "recon.step3_live_check"
    assert trace["source_line"] is None
    assert trace["recipe_name"] == ""
    # session_id and artifact_hash should be absent (not even keys)
    assert "session_id" not in trace
    assert "artifact_hash" not in trace


# ── Test: blocked verdict inferred from all_blocked summary flag ──────────

def test_blocked_verdict_inferred_from_all_blocked_when_verdict_is_not_blocked():
    """When summary.all_blocked is True but takeover_verdict is something
    else (e.g. 'no_finding'), the normalizer should override to 'blocked'."""
    rr = _make_runner_result(
        takever_verdict="no_finding",
        success_count=0,
        total_steps=1,
        failed_steps=0,
        blocked_steps=1,
        all_blocked=True,
    )
    result = normalize_takeover_for_report(rr)
    assert result["takeover_status"] == "blocked"


# ── Test: failed verdict inferred from major_failure ──────────────────────

def test_failed_verdict_inferred_from_major_failure():
    """When summary.major_failure is True, takeover_status should be 'failed'
    regardless of the raw takeover_verdict."""
    rr = _make_runner_result(
        takever_verdict="manual_review_required",
        success_count=0,
        total_steps=2,
        failed_steps=2,
        major_failure=True,
        infrastructure_state="probe_failed",
    )
    result = normalize_takeover_for_report(rr)
    assert result["takeover_status"] == "failed"


# ── Test: empty steps dict does not crash evidence extraction ─────────────

def test_empty_steps_handled_gracefully():
    """When steps is empty or has no successes, evidence extraction
    should not crash."""
    rr = _make_runner_result(
        takever_verdict="no_finding",
        success_count=0,
        total_steps=0,
        failed_steps=0,
        blocked_steps=0,
    )
    result = normalize_takeover_for_report(rr)

    assert result["takeover_status"] == "no_finding"
    assert result["evidence_summary"]["evidence_count"] == 0
    assert result["evidence_summary"]["cname_chain"] == []
    assert result["evidence_summary"]["http_status"] is None
    assert result["evidence_summary"]["error_token"] is None
    assert result["evidence_summary"]["tool_results"] == []
