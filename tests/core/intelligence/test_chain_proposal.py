from src.core.intelligence.chain_builder import AttackChainBuilder, get_chain_builder
from src.core.intelligence.chain_proposal import LLMChainProposalEngine, NullChainProposalEngine
from src.core.models.finding import Finding, Severity, VulnType



from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def test_llm_chain_proposal_engine_can_use_llm_client_generate() -> None:
    payload = (
        '{"candidates": ['
        '{"objective": "data_exfiltration", "path": ["idor", "open_redirect"], '
        '"required_findings": ["f1", "f2"], "missing_evidence": ["replay"], '
        '"exploitability_evidence": ["cross_user_impact"], "foothold_reliability": 0.8, '
        '"expected_attempts_to_success": 2, "business_impact_hypothesis": "Cross-user export.", '
        '"recommended_probe": "verify export", "reasoning_summary": "short"}'
        ']}'
    )
    mock_resp_client = MagicMock()
    mock_resp_client.generate.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=payload))]
    )
    llm_client = MagicMock()
    with patch('src.core.models.llm.LLMClient', return_value=mock_resp_client):
        engine = LLMChainProposalEngine.from_llm_client(
            llm_client=llm_client,
            model_name="deepseek/deepseek-v4-pro",
            timeout_ms=50,
            max_candidates=2,
            session_budget=2,
        )

        result = engine.propose(_sample_findings(), {"mode": "shadow", "target_program": "acme"})

    assert len(result) == 1
    assert result[0]["objective"] == "data_exfiltration"
    mock_resp_client.generate.assert_called_once()
    kwargs = mock_resp_client.generate.call_args.kwargs
    assert kwargs["response_format"] == {"type": "json_object"}
    assert kwargs["temperature"] == 0.1
    assert kwargs["timeout"] == 0.05


def test_get_chain_builder_uses_llm_proposal_engine_when_enabled(monkeypatch) -> None:
    import src.core.intelligence.chain_builder as chain_builder_module

    monkeypatch.setattr(chain_builder_module, "_DEFAULT_CHAIN_BUILDER", None)
    monkeypatch.setattr(chain_builder_module.settings, "chain_llm_enabled", True, raising=False)
    monkeypatch.setattr(chain_builder_module.settings, "chain_llm_model", "deepseek/deepseek-v4-pro", raising=False)

    llm_client = MagicMock()
    builder = get_chain_builder(llm_client=llm_client)

    assert isinstance(builder.proposal_engine, LLMChainProposalEngine)

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


def test_null_chain_proposal_engine_returns_no_candidates() -> None:
    engine = NullChainProposalEngine()

    result = engine.propose(_sample_findings(), {"mode": "shadow"})

    assert result == []


def test_llm_chain_proposal_engine_discards_invalid_json() -> None:
    engine = LLMChainProposalEngine(
        response_provider=lambda findings, runtime_context: "not-json",
        timeout_ms=50,
        max_candidates=3,
        session_budget=2,
    )

    result = engine.propose(_sample_findings(), {"mode": "shadow"})

    assert result == []
    assert engine.last_skip_reason == "invalid_json"


def test_llm_chain_proposal_engine_enforces_budget_and_max_candidates() -> None:
    payload = (
        '{"candidates": ['
        '{"objective": "data_exfiltration", "path": ["idor", "open_redirect"], '
        '"required_findings": ["f1", "f2"], "missing_evidence": [], '
        '"exploitability_evidence": ["cross_user_impact"], "foothold_reliability": 0.7, '
        '"expected_attempts_to_success": 2, "business_impact_hypothesis": "Cross-user read.", '
        '"recommended_probe": "replay export flow", "reasoning_summary": "short"},'
        '{"objective": "account_takeover", "path": ["xss", "csrf"], '
        '"required_findings": ["f3", "f4"], "missing_evidence": ["replay"], '
        '"exploitability_evidence": ["state_change_success"], "foothold_reliability": 0.6, '
        '"expected_attempts_to_success": 3, "business_impact_hypothesis": "Credential reset.", '
        '"recommended_probe": "verify reset flow", "reasoning_summary": "short"}'
        ']}'
    )
    engine = LLMChainProposalEngine(
        response_provider=lambda findings, runtime_context: payload,
        timeout_ms=50,
        max_candidates=1,
        session_budget=1,
    )

    first = engine.propose(_sample_findings(), {"mode": "shadow"})
    second = engine.propose(_sample_findings(), {"mode": "shadow"})

    assert len(first) == 1
    assert first[0]["objective"] == "data_exfiltration"
    assert second == []
    assert engine.last_skip_reason == "budget_exceeded"


def test_get_chain_builder_uses_null_proposal_engine_when_flag_disabled(monkeypatch) -> None:
    import src.core.intelligence.chain_builder as chain_builder_module

    monkeypatch.setattr(chain_builder_module, "_DEFAULT_CHAIN_BUILDER", None)
    monkeypatch.setattr(chain_builder_module.settings, "chain_llm_enabled", False, raising=False)

    builder = get_chain_builder()

    assert isinstance(builder.proposal_engine, NullChainProposalEngine)


def test_analyze_hybrid_matches_existing_chain_keys_when_proposals_disabled() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True, proposal_engine=NullChainProposalEngine())
    findings = _sample_findings()

    base = builder.analyze(findings)
    hybrid = builder.analyze_hybrid(findings, runtime_context={"mode": "shadow"})

    assert [chain.chain_key for chain in hybrid["heuristic_chains"]] == [chain.chain_key for chain in base]
    assert [candidate["chain_key"] for candidate in hybrid["draft_candidates"]] == [chain.chain_key for chain in base]
    assert hybrid["ai_candidates"] == []


def test_analyze_hybrid_merges_ai_candidates_as_draft_only() -> None:
    findings = _sample_findings()
    idor_id = findings[0].id
    redirect_id = findings[1].id
    payload = (
        '{"candidates": ['
        '{"objective": "data_exfiltration", "path": ["idor", "open_redirect"], '
        f'"required_findings": ["{idor_id}", "{redirect_id}"], "missing_evidence": ["replay_evidence"], '
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

    hybrid = builder.analyze_hybrid(findings, runtime_context={"mode": "shadow"})

    assert hybrid["ai_candidates"]
    candidate = hybrid["ai_candidates"][0]
    assert candidate["state"] == "draft"
    assert candidate["origin"] == "ai_proposal"
    assert candidate["business_impact_sentence"] == "Cross-user export is plausible."
    assert candidate["recommended_probe"] == "verify export replay"


def test_belief_state_tracks_partial_rule_progress() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True, proposal_engine=NullChainProposalEngine())
    findings = [_sample_findings()[0]]

    belief = builder.update_belief_state(findings)

    assert belief["candidate_rules"]
    top = belief["candidate_rules"][0]
    assert top["rule_id"] == "data_exfil_idor_redirect"
    assert top["observed_signals"] == ["idor"]
    assert top["missing_signals"] == ["open_redirect"]
    assert top["confidence"] >= 0.5


def test_analyze_hybrid_keeps_partial_candidates_when_observation_missing() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True, proposal_engine=NullChainProposalEngine())
    findings = [_sample_findings()[0]]

    hybrid = builder.analyze_hybrid(findings, runtime_context={"mode": "shadow"})

    assert hybrid["heuristic_chains"] == []
    assert hybrid["draft_candidates"] == []
    assert hybrid["belief_state"]["candidate_rules"]
    partial = hybrid["belief_state"]["candidate_rules"][0]
    assert partial["state"] == "partial_observation"
    assert partial["next_best_probe"]
