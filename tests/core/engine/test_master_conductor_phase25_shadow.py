from src.core.engine.master_conductor import MasterConductor
from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.intelligence.chain_proposal import LLMChainProposalEngine
from src.core.models.finding import Finding, Severity, VulnType


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            vuln_type=VulnType.IDOR,
            severity=Severity.HIGH,
            title="IDOR on profile endpoint",
            description="Broken access control allows cross-user read.",
            target_url="https://example.com/api/profile/124",
            source_agent="unit_test",
            tags=["idor"],
            additional_info={
                "auth_level": "user",
                "user_interaction": "none",
                "same_origin": True,
                "asset_scope": "in_scope",
                "primitive": "read",
            },
        ),
        Finding(
            vuln_type=VulnType.OPEN_REDIRECT,
            severity=Severity.MEDIUM,
            title="Open redirect in handoff",
            description="Redirect flow can be steered to attacker destinations.",
            target_url="https://example.com/redirect?next=/export",
            source_agent="unit_test",
            tags=["open_redirect"],
            additional_info={
                "auth_level": "user",
                "user_interaction": "none",
                "same_origin": True,
                "asset_scope": "in_scope",
                "primitive": "pivot",
            },
        ),
    ]


def test_pre_action_gate_shadow_records_comparison_without_mutating_public_output() -> None:
    findings = _sample_findings()
    payload = (
        '{"candidates": ['
        '{"objective": "data_exfiltration", "path": ["idor", "open_redirect"], '
        f'"required_findings": ["{findings[0].id}", "{findings[1].id}"], "missing_evidence": [], '
        '"exploitability_evidence": ["cross_user_impact"], "foothold_reliability": 0.72, '
        '"expected_attempts_to_success": 2, "business_impact_hypothesis": "Cross-user export is plausible.", '
        '"recommended_probe": "verify export replay", "reasoning_summary": "short"}'
        ']}'
    )
    builder = AttackChainBuilder(
        enforce_data_contract=True,
        proposal_engine=LLMChainProposalEngine(
            response_provider=lambda findings, runtime_context: payload,
            timeout_ms=50,
            max_candidates=3,
            session_budget=2,
        ),
    )
    mc = MasterConductor.__new__(MasterConductor)
    mc.chain_builder = builder
    mc._chain_shadow_reports = []
    mc._emitted_attack_chain_keys = {"existing-key"}

    report = mc.run_pre_action_gate_shadow(
        findings,
        benchmark_manifest={"manifest_id": "bm-shadow-001"},
        runtime_context={"mode": "shadow"},
    )

    assert report["trigger_action"] == "actionable_gate"
    assert report["benchmark_manifest_id"] == "bm-shadow-001"
    assert report["ai_candidate_count"] == 1
    assert mc._emitted_attack_chain_keys == {"existing-key"}
    assert mc._chain_shadow_reports[-1]["draft_candidate_count"] >= report["ai_candidate_count"]


def test_pre_action_gate_shadow_can_be_disabled(monkeypatch) -> None:
    mc = MasterConductor.__new__(MasterConductor)
    monkeypatch.setattr("src.core.engine.master_conductor_facade.settings.chain_llm_shadow_mode", False)

    report = mc.run_pre_action_gate_shadow([])

    assert report == {"state": "skipped", "reason": "shadow_mode_disabled"}


def test_pre_action_gate_shadow_includes_proposal_diagnostics() -> None:
    findings = _sample_findings()
    builder = AttackChainBuilder(
        enforce_data_contract=True,
        proposal_engine=LLMChainProposalEngine(
            response_provider=lambda findings, runtime_context: "not-json",
            timeout_ms=75,
            max_candidates=4,
            session_budget=2,
        ),
    )
    mc = MasterConductor.__new__(MasterConductor)
    mc.chain_builder = builder
    mc._chain_shadow_reports = []

    report = mc.run_pre_action_gate_shadow(findings, runtime_context={"mode": "shadow"})

    assert report["proposal_skip_reason"] == "invalid_json"
    assert report["proposal_engine"] == "LLMChainProposalEngine"
    assert report["proposal_timeout_ms"] == 75
    assert report["proposal_max_candidates"] == 4
    assert report["proposal_budget_remaining"] == 1
    assert report["proposal_budget_consumed"] == 1


def test_pre_action_gate_shadow_reports_explainable_feasibility_diff() -> None:
    findings = _sample_findings()
    builder = AttackChainBuilder(enforce_data_contract=True)
    mc = MasterConductor.__new__(MasterConductor)
    mc.chain_builder = builder
    mc._chain_shadow_reports = []

    report = mc.run_pre_action_gate_shadow(
        findings,
        runtime_context={
            "feasibility_mode": "shadow",
            "feasibility_constraints": {"same_origin": {"required": False}},
        },
    )

    assert report["feasibility_mode"] == "shadow"
    assert report["shadow_blocked_count"] >= 1
    assert report["shadow_diff_count"] >= 1
    assert report["shadow_diff_reasons"]


def test_pre_action_gate_shadow_with_real_builder_reports_temporal_demotion_metrics() -> None:
    findings = [
        Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Reflected XSS in account page",
            description="xss sink confirmed",
            target_url="https://example.com/account",
            source_agent="unit_test",
            tags=["xss"],
            additional_info={
                "auth_level": "user",
                "user_interaction": "none",
                "same_origin": True,
                "asset_scope": "in_scope",
                "primitive": "write",
                "token_epoch": "epoch-7",
                "csrf_epoch": "epoch-7",
                "session_rotation_state": "stable",
                "session_generation": 9,
            },
        ),
        Finding(
            vuln_type=VulnType.DEBUG_ENABLED,
            severity=Severity.MEDIUM,
            title="Missing CSRF token in transfer flow",
            description="csrf check missing",
            target_url="https://example.com/account",
            source_agent="unit_test",
            tags=["csrf"],
            additional_info={
                "auth_level": "user",
                "user_interaction": "none",
                "same_origin": True,
                "asset_scope": "in_scope",
                "primitive": "write",
                "token_epoch": "epoch-7",
                "csrf_epoch": "epoch-7",
                "session_rotation_state": "rotating",
                "session_generation": 8,
            },
        ),
    ]

    builder = AttackChainBuilder(enforce_data_contract=True)
    mc = MasterConductor.__new__(MasterConductor)
    mc.chain_builder = builder
    mc._chain_shadow_reports = []

    report = mc.run_pre_action_gate_shadow(
        findings,
        runtime_context={
            "feasibility_mode": "shadow",
            "feasibility_constraints": {
                "temporal_consistency": {
                    "require_matching_token_epoch": True,
                    "require_matching_csrf_epoch": True,
                    "allow_rotation_states": ["stable"],
                    "require_monotonic_session_generation": True,
                }
            },
            "missing_temporal_metadata_threshold": 0.25,
        },
    )

    assert report["draft_demotion_count"] >= 1
    assert report["blocked_demotion_count"] == 0
    assert report["temporal_reason_counts"]["temporal:rotation_in_progress"] >= 1
    assert report["missing_temporal_metadata_ratio"] == 0.0
