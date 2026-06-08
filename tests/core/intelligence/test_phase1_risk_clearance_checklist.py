from __future__ import annotations

from pathlib import Path

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.models.finding import Finding, Severity, VulnType
from src.core.reporting.platform_integration import ReportDraft
from src.reporting.haddix_formatter import HaddixFormatter


PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "plans"
    / "2026-06-01_task_plan.md"
)


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def _xss_finding() -> Finding:
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Stored XSS in comments",
        description="Cross-site scripting in comment preview.",
        target_url="https://example.com/comments",
        additional_info={
            "auth_level": "user",
            "user_interaction": "click",
            "same_origin": True,
            "asset_scope": "in_scope",
            "primitive": "read",
        },
    )


def _csrf_finding() -> Finding:
    return Finding(
        vuln_type=VulnType.DEBUG_ENABLED,
        severity=Severity.LOW,
        title="Missing CSRF token on profile update",
        description="CSRF protections are absent on account mutation endpoint.",
        target_url="https://example.com/profile",
        additional_info={
            "auth_level": "user",
            "user_interaction": "none",
            "same_origin": True,
            "asset_scope": "in_scope",
            "primitive": "write",
        },
    )


def _idor_finding() -> Finding:
    return Finding(
        vuln_type=VulnType.IDOR,
        severity=Severity.HIGH,
        title="Cross-tenant IDOR on invoice API",
        description="Broken access control allows cross-tenant invoice reads.",
        target_url="https://example.com/api/invoices/42",
        additional_info={
            "auth_level": "user",
            "user_interaction": "none",
            "same_origin": True,
            "asset_scope": "in_scope",
            "primitive": "read",
        },
    )


def test_phase1_plan_documents_required_gates() -> None:
    text = _read_plan_text()

    assert "Phase 1（価値創出MVP / Step 7〜18）" in text
    assert "falsification_checks" in text
    assert "business_impact_sentence" in text
    assert "goal_state_assertions" in text
    assert "Expected Bounty@5" in text
    assert "High-value chain hit rate" in text


def test_phase1_actor_model_requires_valid_actor_transition() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    analyze_with_context = getattr(builder, "analyze_with_context", None)
    assert callable(analyze_with_context)

    result = analyze_with_context(
        findings=[_xss_finding(), _csrf_finding()],
        runtime_context={
            "actor_model": {
                "actors": ["attacker", "victim", "admin"],
                "transitions": [("attacker", "victim")],
            }
        },
    )

    assert result
    assert result[0].additional_info["decision_trace"]["actor_path"] == ["attacker", "victim"]


def test_phase1_exploitability_evidence_promotes_chain_priority() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    rank_chains = getattr(builder, "rank_chains", None)
    assert callable(rank_chains)

    ranked = rank_chains(
        [
            {
                "rule_id": "weak_chain",
                "matched_signals": ["xss", "csrf"],
                "exploitability_evidence": [],
            },
            {
                "rule_id": "strong_chain",
                "matched_signals": ["xss", "csrf"],
                "exploitability_evidence": ["state_change_success", "cross_user_impact"],
            },
        ]
    )

    assert ranked[0]["rule_id"] == "strong_chain"


def test_phase1_reliability_and_attempt_cost_affect_priority() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    score_chain = getattr(builder, "score_chain", None)
    assert callable(score_chain)

    stable = score_chain(
        {
            "matched_signals": ["idor", "open_redirect"],
            "foothold_reliability": 0.95,
            "expected_attempts_to_success": 1.2,
        }
    )
    unstable = score_chain(
        {
            "matched_signals": ["idor", "open_redirect"],
            "foothold_reliability": 0.30,
            "expected_attempts_to_success": 5.0,
        }
    )

    assert stable["priority_score"] > unstable["priority_score"]


def test_phase1_counterfactual_scoring_identifies_critical_edge() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    evaluate_counterfactual = getattr(builder, "evaluate_counterfactual", None)
    assert callable(evaluate_counterfactual)

    result = evaluate_counterfactual(
        {
            "rule_id": "ato_chain",
            "path": ["xss", "csrf", "password_change"],
        }
    )

    assert result["critical_edge_identification"] == [("csrf", "password_change")]
    assert result["counterfactual_penalty"] > 0


def test_phase1_negative_chain_learning_reduces_repeated_near_miss_priority() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    record_negative_chain = getattr(builder, "record_negative_chain", None)
    rank_chains = getattr(builder, "rank_chains", None)
    assert callable(record_negative_chain)
    assert callable(rank_chains)

    record_negative_chain(
        {
            "rule_id": "tenant_idor_chain",
            "component_fingerprint": "idor|invoice",
            "failure_reason": "auth_mismatch",
        }
    )
    ranked = rank_chains(
        [
            {
                "rule_id": "tenant_idor_chain",
                "component_fingerprint": "idor|invoice",
            }
        ]
    )

    assert ranked[0]["assumption_penalty"] > 0


def test_phase1_program_memory_prior_affects_chain_ranking() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    remember_chain_outcome = getattr(builder, "remember_chain_outcome", None)
    rank_for_program = getattr(builder, "rank_for_program", None)
    assert callable(remember_chain_outcome)
    assert callable(rank_for_program)

    remember_chain_outcome(
        program="example-program",
        rule_id="tenant_idor_chain",
        outcome="success",
    )

    ranked = rank_for_program(
        program="example-program",
        candidates=[
            {"rule_id": "tenant_idor_chain"},
            {"rule_id": "generic_xss_chain"},
        ],
    )

    assert ranked[0]["rule_id"] == "tenant_idor_chain"


def test_phase1_program_memory_persists_anonymized_records_with_eviction(tmp_path: Path) -> None:
    store = tmp_path / "program_memory.json"
    builder = AttackChainBuilder(
        enforce_data_contract=True,
        program_memory_path=str(store),
        program_memory_max_entries=2,
        program_memory_ttl_seconds=3600,
    )

    builder.remember_chain_outcome(
        program="example-program",
        rule_id="tenant_idor_chain",
        outcome="success",
    )
    builder.remember_chain_outcome(
        program="second-program",
        rule_id="generic_xss_chain",
        outcome="failure",
    )
    builder.remember_chain_outcome(
        program="third-program",
        rule_id="ssrf_chain",
        outcome="success",
    )

    persisted = store.read_text(encoding="utf-8")
    assert "example-program" not in persisted
    assert "tenant_idor_chain" not in persisted

    reloaded = AttackChainBuilder(
        enforce_data_contract=True,
        program_memory_path=str(store),
        program_memory_max_entries=2,
        program_memory_ttl_seconds=3600,
    )
    ranked = reloaded.rank_for_program(
        program="third-program",
        candidates=[
            {"rule_id": "ssrf_chain"},
            {"rule_id": "generic_xss_chain"},
        ],
    )

    assert ranked[0]["rule_id"] == "ssrf_chain"
    assert reloaded.rank_for_program(
        program="example-program",
        candidates=[{"rule_id": "tenant_idor_chain"}],
    )[0]["program_prior"] == 0.0


def test_phase1_master_conductor_runs_chain_evaluation_on_all_required_triggers() -> None:
    mc = MasterConductor.__new__(MasterConductor)
    trigger_chain_evaluation = getattr(mc, "trigger_chain_evaluation", None)
    assert callable(trigger_chain_evaluation)

    observed = [
        trigger_chain_evaluation("finding_added"),
        trigger_chain_evaluation("batch_recheck"),
        trigger_chain_evaluation("pre_action_gate"),
    ]

    assert observed == ["draft_refresh", "confirmed_refresh", "actionable_gate"]


def test_phase1_chain_evaluation_trigger_is_idempotent_per_trigger_and_state_version() -> None:
    mc = MasterConductor.__new__(MasterConductor)

    first = mc.trigger_chain_evaluation("finding_added", chain_key="chain-1", state_version=1)
    duplicate = mc.trigger_chain_evaluation("finding_added", chain_key="chain-1", state_version=1)
    next_stage = mc.trigger_chain_evaluation("batch_recheck", chain_key="chain-1", state_version=1)
    repeated_stage = mc.trigger_chain_evaluation("batch_recheck", chain_key="chain-1", state_version=1)
    new_version = mc.trigger_chain_evaluation("batch_recheck", chain_key="chain-1", state_version=2)

    assert first == "draft_refresh"
    assert duplicate == "noop"
    assert next_stage == "confirmed_refresh"
    assert repeated_stage == "noop"
    assert new_version == "confirmed_refresh"


def test_phase1_actionable_requires_falsification_checks() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    promote_chain = getattr(builder, "promote_chain", None)
    assert callable(promote_chain)

    result = promote_chain(
        {
            "rule_id": "ato_chain",
            "state": "confirmed",
            "falsification_checks": [],
            "replay_evidence": True,
        }
    )

    assert result["state"] != "actionable"
    assert "falsification_checks_missing" in result["excluded_reasons"]


def test_phase1_falsification_checklist_is_auto_generated() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    generate_falsification_checks = getattr(builder, "generate_falsification_checks", None)
    assert callable(generate_falsification_checks)

    checks = generate_falsification_checks(
        {
            "rule_id": "ato_chain",
            "path": ["xss", "csrf", "password_change"],
            "goal_state_assertions": {
                "privilege_changed": True,
                "cross_user_data_access": False,
                "persistent_control": False,
            },
        }
    )

    assert checks
    assert any("re-login" in item.lower() or "relogin" in item.lower() for item in checks)
    assert any("cache" in item.lower() or "csrf" in item.lower() for item in checks)


def test_phase1_report_quality_gate_requires_business_impact_and_repro_fields() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    validate_report_payload = getattr(builder, "validate_report_payload", None)
    assert callable(validate_report_payload)

    verdict = validate_report_payload(
        {
            "title": "Account Takeover via XSS + CSRF",
            "business_impact_sentence": "",
            "reproduction_steps": ["1. login"],
            "boundary_cross_proof": "",
            "victim_impact": "",
            "remediation": "",
            "falsification_result": "",
        }
    )

    assert verdict["accepted"] is False
    assert set(verdict["missing_fields"]) == {
        "business_impact_sentence",
        "boundary_cross_proof",
        "victim_impact",
        "remediation",
        "falsification_result",
    }


def test_phase1_canonical_report_payload_drives_haddix_and_platform_adapters() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    build_canonical_report_payload = getattr(builder, "build_canonical_report_payload", None)
    to_haddix_finding_dict = getattr(builder, "to_haddix_finding_dict", None)
    assert callable(build_canonical_report_payload)
    assert callable(to_haddix_finding_dict)

    canonical = build_canonical_report_payload(
        {
            "title": "Account Takeover via XSS + CSRF",
            "severity": "high",
            "target_url": "https://example.com/profile",
            "business_impact_sentence": "An attacker can change a victim password and take over the account.",
            "reproduction_steps": ["1. Login as attacker", "2. Send crafted link"],
            "boundary_cross_proof": "Victim account password changed without consent.",
            "victim_impact": "Account access loss for the victim.",
            "remediation": "Require CSRF validation and origin checks.",
            "falsification_result": "Reproduced after re-login; cache-only hypothesis rejected.",
            "goal_state_assertions": {
                "privilege_changed": True,
                "cross_user_data_access": True,
                "persistent_control": False,
            },
            "minimal_success_runbook": ["1. Trigger XSS", "2. Replay CSRF password change"],
        }
    )

    draft = ReportDraft.from_canonical_payload(canonical)
    haddix_data = to_haddix_finding_dict(canonical)

    assert draft.title == canonical["title"]
    assert draft.reproduction_steps == canonical["reproduction_steps"]
    assert canonical["business_impact_sentence"] in draft.summary
    assert haddix_data["title"] == canonical["title"]
    assert haddix_data["impact"] == canonical["victim_impact"]
    assert haddix_data["steps_to_reproduce"] == canonical["reproduction_steps"]

    formatter = HaddixFormatter()
    formatter.set_target("https://example.com/profile", "Example Program")
    formatter.add_finding_from_dict(haddix_data)
    markdown = formatter.format_markdown()
    assert canonical["title"] in markdown
    assert "Account access loss for the victim." in markdown


def test_phase1_goal_state_assertions_and_runbook_are_emitted() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    finalize_actionable_chain = getattr(builder, "finalize_actionable_chain", None)
    assert callable(finalize_actionable_chain)

    result = finalize_actionable_chain(
        findings=[_xss_finding(), _csrf_finding(), _idor_finding()],
        objective="account_takeover",
    )

    assert result["goal_state_assertions"] == {
        "privilege_changed": True,
        "cross_user_data_access": True,
        "persistent_control": False,
    }
    assert result["minimal_success_runbook"][0].startswith("1.")


def test_phase1_report_payload_requires_goal_state_assertions() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    validate_report_payload = getattr(builder, "validate_report_payload", None)
    assert callable(validate_report_payload)

    verdict = validate_report_payload(
        {
            "title": "Account Takeover via XSS + CSRF",
            "business_impact_sentence": "Account takeover is possible.",
            "reproduction_steps": ["1. login"],
            "boundary_cross_proof": "cross-user action confirmed",
            "victim_impact": "user loses account access",
            "remediation": "add CSRF validation",
            "falsification_result": "relogin reproduced",
            "goal_state_assertions": {},
        }
    )

    assert verdict["accepted"] is False
    assert "goal_state_assertions" in verdict["missing_fields"]


def test_phase1_gate_metrics_are_documented() -> None:
    text = _read_plan_text()

    assert "Phase 1ゲート:" in text
    assert "有効提出率（Valid Submission Rate）" in text
    assert "Expected Bounty@5" in text
    assert "誤報告率（最終ゲート後）" in text
    assert "Phase 1終了判定" in text
