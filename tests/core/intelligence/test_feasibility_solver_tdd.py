from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.models.finding import Finding, Severity, VulnType


VERIFY_CHAINING_FLOW_PATH = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "scripts"
    / "verify_chaining_flow.py"
)


class StaticProposalEngine:
    def __init__(self, candidates: list[dict[str, Any]]) -> None:
        self._candidates = candidates
        self.last_skip_reason = None

    def propose(
        self,
        findings: list[Finding],
        runtime_context: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        return list(self._candidates)


def _finding(
    *,
    vuln_type: VulnType,
    title: str,
    description: str,
    target_url: str,
    primitive: str,
    auth_level: str = "user",
    same_origin: bool = True,
    asset_scope: str = "in_scope",
    extra_info: dict[str, Any] | None = None,
) -> Finding:
    additional_info = {
        "auth_level": auth_level,
        "user_interaction": "none",
        "same_origin": same_origin,
        "asset_scope": asset_scope,
        "primitive": primitive,
    }
    if extra_info:
        additional_info.update(extra_info)
    return Finding(
        vuln_type=vuln_type,
        severity=Severity.HIGH if vuln_type is VulnType.XSS else Severity.MEDIUM,
        title=title,
        description=description,
        target_url=target_url,
        source_agent="unit_test",
        tags=[vuln_type.value],
        additional_info=additional_info,
    )


def _xss(**overrides: Any) -> Finding:
    params = {
        "vuln_type": VulnType.XSS,
        "title": "Reflected XSS in search endpoint",
        "description": "xss sink confirmed on /search?q=",
        "target_url": "https://example.com/search",
        "primitive": "exec",
    }
    params.update(overrides)
    return _finding(**params)


def _csrf(**overrides: Any) -> Finding:
    params = {
        "vuln_type": VulnType.DEBUG_ENABLED,
        "title": "Missing CSRF token in profile update",
        "description": "Cross-site request forgery protection was not enforced.",
        "target_url": "https://example.com/profile",
        "primitive": "write",
    }
    params.update(overrides)
    return _finding(**params)


def _base_findings() -> list[Finding]:
    return [_xss(), _csrf()]


def _base_candidate(findings: list[Finding]) -> dict[str, Any]:
    return {
        "rule_id": "account_takeover_xss_csrf",
        "chain_key": "candidate-key",
        "matched_signals": ["csrf", "xss"],
        "component_findings": [finding.id for finding in findings],
        "required_findings": [finding.id for finding in findings],
        "origin": "heuristic",
        "state": "draft",
        "excluded_reasons": [],
    }


def _equivalent_ai_candidate(findings: list[Finding]) -> dict[str, Any]:
    return {
        "objective": "account_takeover",
        "path": ["xss", "csrf"],
        "required_findings": [finding.id for finding in findings],
        "missing_evidence": [],
        "exploitability_evidence": ["state_change_success"],
        "foothold_reliability": 0.8,
        "expected_attempts_to_success": 2,
        "business_impact_hypothesis": "Stored XSS can drive CSRF-like state change.",
        "recommended_probe": "verify state change replay",
        "reasoning_summary": "equivalent chain",
    }


def test_feasibility_solver_exposes_shared_evaluator_contract() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    evaluator = getattr(builder, "evaluate_feasibility", None)

    assert callable(evaluator)


@pytest.mark.parametrize(
    ("constraint_name", "finding", "constraints", "expected_reason"),
    [
        (
            "auth",
            _xss(auth_level=""),
            {"auth": {"required": "user"}},
            "feasibility:constraint_data_missing",
        ),
        (
            "same_origin",
            _xss(same_origin="unknown"),
            {"same_origin": {"required": True}},
            "feasibility:constraint_data_missing",
        ),
        (
            "primitive",
            _xss(primitive=""),
            {"primitive": {"required": "exec"}},
            "feasibility:constraint_data_missing",
        ),
        (
            "asset_scope",
            _xss(asset_scope="out_of_scope"),
            {"asset_scope": {"required": "in_scope"}},
            "feasibility:constraint_data_missing",
        ),
        (
            "token_lifetime",
            _xss(extra_info={"token_lifetime": None}),
            {"token_lifetime": {"max_seconds": 300}},
            "feasibility:constraint_data_missing",
        ),
        (
            "session_generation",
            _xss(extra_info={"session_generation": None}),
            {"session_generation": {"requires_rotation": True}},
            "feasibility:constraint_data_missing",
        ),
    ],
)
def test_feasibility_solver_blocks_missing_constraint_data_with_structured_reason(
    constraint_name: str,
    finding: Finding,
    constraints: dict[str, Any],
    expected_reason: str,
) -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    evaluator = getattr(builder, "evaluate_feasibility", None)
    assert callable(evaluator)

    findings = [finding, _csrf()]
    result = evaluator(
        candidate=_base_candidate(findings),
        findings=findings,
        constraints=constraints,
        mode="enforce",
    )

    assert result["verdict"] == "blocked"
    assert expected_reason in result["excluded_reasons"]
    assert result["failed_constraints"][0]["constraint"] == constraint_name
    assert result["failed_constraints"][0]["evidence_source"].startswith("Finding.additional_info")


def test_feasibility_solver_keeps_unsupported_constraints_out_of_actionable() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    evaluator = getattr(builder, "evaluate_feasibility", None)
    assert callable(evaluator)

    findings = _base_findings()
    result = evaluator(
        candidate=_base_candidate(findings),
        findings=findings,
        constraints={"session_generation": {"comparison": "monotonic_increase"}},
        mode="enforce",
    )

    assert result["verdict"] == "draft"
    assert "feasibility:constraint_not_supported" in result["excluded_reasons"]
    assert result["state"] == "draft"


def test_feasibility_shadow_mode_records_verdict_without_enforcing() -> None:
    builder = AttackChainBuilder(
        enforce_data_contract=True,
        proposal_engine=StaticProposalEngine([]),
    )

    hybrid = builder.analyze_hybrid(_base_findings(), runtime_context={"feasibility_mode": "shadow"})

    assert hybrid["draft_candidates"]
    trace = hybrid["draft_candidates"][0]["decision_trace"]["feasibility"]
    assert trace["mode"] == "shadow"
    assert trace["verdict"] in {"pass", "blocked", "draft"}
    assert hybrid["draft_candidates"][0]["state"] == "draft"


def test_feasibility_shadow_mode_keeps_equivalent_heuristic_and_ai_verdicts_aligned() -> None:
    findings = _base_findings()
    builder = AttackChainBuilder(
        enforce_data_contract=True,
        proposal_engine=StaticProposalEngine([_equivalent_ai_candidate(findings)]),
    )

    hybrid = builder.analyze_hybrid(findings, runtime_context={"feasibility_mode": "shadow"})

    heuristic = next(candidate for candidate in hybrid["draft_candidates"] if candidate["origin"] == "heuristic")
    ai_candidate = next(candidate for candidate in hybrid["draft_candidates"] if candidate["origin"] == "ai_proposal")

    assert heuristic["decision_trace"]["feasibility"]["verdict"] == ai_candidate["decision_trace"]["feasibility"]["verdict"]
    assert heuristic["decision_trace"]["feasibility"]["canonical_material"] == ai_candidate["decision_trace"]["feasibility"]["canonical_material"]


def test_feasibility_decision_trace_uses_structured_failed_constraints() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    evaluator = getattr(builder, "evaluate_feasibility", None)
    assert callable(evaluator)

    findings = [_xss(same_origin=False), _csrf()]
    result = evaluator(
        candidate=_base_candidate(findings),
        findings=findings,
        constraints={"same_origin": {"required": True}},
        mode="enforce",
    )

    trace = result["decision_trace"]["feasibility"]
    assert trace["used_fallback"] is False
    assert trace["constraint_schema_version"] == "2026-06-02"
    assert trace["decision_trace_version"] == "2026-06-02"
    assert isinstance(trace["failed_constraints"], list)
    assert trace["failed_constraints"][0] == {
        "constraint": "same_origin",
        "observed_value": False,
        "expected_value": True,
        "evidence_source": f"Finding.additional_info.same_origin:{findings[0].id}",
    }


def test_feasibility_budget_fallback_surfaces_reason_and_metrics() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)

    result = builder.analyze_with_budget(
        findings=_base_findings(),
        top_k=3,
        timeout_ms=1,
    )

    assert result["used_fallback"] is True
    assert result["fallback_reason"] == "solver_timeout_budget_exceeded"
    assert result["metrics"]["used_fallback_count"] >= 1
    assert result["metrics"]["solver_timeout_count"] >= 1
    assert result["metrics"]["avg_solver_latency_ms"] >= 0.0
    assert result["metrics"]["p95_solver_latency_ms"] >= result["metrics"]["avg_solver_latency_ms"]


def test_verify_chaining_flow_avoids_hardcoded_async_sleep() -> None:
    text = VERIFY_CHAINING_FLOW_PATH.read_text(encoding="utf-8")

    assert "asyncio.sleep(" not in text
