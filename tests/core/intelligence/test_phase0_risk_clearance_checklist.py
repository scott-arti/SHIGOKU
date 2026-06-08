from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.domain.model.task import Task
import src.core.intelligence as intelligence_module
import src.core.intelligence.chain_builder as chain_builder_module
from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.models.finding import Finding, Severity, VulnType


PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "plans"
    / "2026-06-01_task_plan.md"
)

SUBTASK_PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "subtasks"
    / "2026-06-02_task_subtask_plan.md"
)

_UNSET = object()


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def _read_subtask_plan_text() -> str:
    return SUBTASK_PLAN_PATH.read_text(encoding="utf-8")


def _extract_block(text: str, start_heading: str, next_heading: str) -> str:
    start = text.index(start_heading)
    end = text.index(next_heading, start)
    return text[start:end]


def _sample_xss(title: str = "Reflected XSS in search endpoint") -> Finding:
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title=title,
        description="xss sink confirmed on /search?q=",
        target_url="https://example.com/search",
    )


def _sample_csrf(title: str = "Missing CSRF token in profile update") -> Finding:
    return Finding(
        vuln_type=VulnType.DEBUG_ENABLED,
        severity=Severity.LOW,
        title=title,
        description="Cross-site request forgery protection was not enforced.",
        target_url="https://example.com/profile",
    )


def _sample_temporal_finding(
    *,
    title: str,
    vuln_type: VulnType,
    token_epoch: object = "epoch-7",
    csrf_epoch: object = "epoch-7",
    session_rotation_state: object = "stable",
    session_generation: object = 7,
) -> Finding:
    info = {
        "auth_level": "user",
        "user_interaction": "none",
        "same_origin": True,
        "asset_scope": "in_scope",
        "primitive": "write",
    }
    if token_epoch is not _UNSET:
        info["token_epoch"] = token_epoch
    if csrf_epoch is not _UNSET:
        info["csrf_epoch"] = csrf_epoch
    if session_rotation_state is not _UNSET:
        info["session_rotation_state"] = session_rotation_state
    if session_generation is not _UNSET:
        info["session_generation"] = session_generation
    return Finding(
        vuln_type=vuln_type,
        severity=Severity.HIGH,
        title=title,
        description=f"{title} evidence",
        target_url="https://example.com/account",
        additional_info=info,
    )


def _temporal_candidate(findings: list[Finding]) -> dict[str, object]:
    return {
        "rule_id": "temporal_ato_chain",
        "state": "confirmed",
        "required_findings": [finding.id for finding in findings],
        "component_findings": [finding.id for finding in findings],
        "matched_signals": ["xss", "csrf"],
        "excluded_reasons": [],
    }


def _temporal_constraints() -> dict[str, dict[str, object]]:
    return {
        "temporal_consistency": {
            "require_matching_token_epoch": True,
            "require_matching_csrf_epoch": True,
            "allow_rotation_states": ["stable"],
            "require_monotonic_session_generation": True,
        }
    }


def test_risk_001_step_sync_between_section4_and_4_2() -> None:
    text = _read_plan_text()
    section4 = _extract_block(text, "## 4. 実装ステップ（AIに指示する手順）", "### 4.1 検証指標（完了条件）")
    section42 = _extract_block(text, "### 4.2 即実装着手用チェックリスト（Done条件付き）", "## 5. 既知のリスクと次回の申し送り")

    step_nums_section4 = re.findall(r"- \[[ x]\] ステップ(\d+):", section4)
    step_nums_section42 = re.findall(r"- \[[ x]\] Step (\d+) Action:", section42)

    assert step_nums_section4 == [str(i) for i in range(1, 38)]
    assert step_nums_section42 == [str(i) for i in range(1, 38)]


def test_risk_002_phase_gate_rules_are_explicit_and_ordered() -> None:
    text = _read_plan_text()
    rules = _extract_block(text, "### 4.0 実行ルール（8点改善の反映）", "### Phase 0（基盤整備 / Step 1〜6）")

    assert "Phase 0 -> 1" in rules
    assert "Phase 1 -> 2" in rules
    assert "Phase 2 -> 2.5" in rules
    assert "Phase 2.5 -> 3" in rules
    assert "2連続達成" in text
    assert "Phase 3 の着手を禁止" in text


def test_risk_001_runtime_default_enables_data_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(chain_builder_module.settings, "chain_builder_enforce_data_contract", True, raising=False)
    monkeypatch.setattr(chain_builder_module, "_DEFAULT_CHAIN_BUILDER", None, raising=False)
    builder = intelligence_module.get_chain_builder()
    assert builder.enforce_data_contract is True


def test_risk_001_runtime_default_injects_program_memory_settings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    store = tmp_path / "chain_program_memory.json"
    monkeypatch.setattr(chain_builder_module.settings, "chain_builder_enforce_data_contract", True, raising=False)
    monkeypatch.setattr(chain_builder_module.settings, "chain_builder_program_memory_path", str(store), raising=False)
    monkeypatch.setattr(chain_builder_module.settings, "chain_builder_program_memory_max_entries", 7, raising=False)
    monkeypatch.setattr(chain_builder_module.settings, "chain_builder_program_memory_ttl_seconds", 7200, raising=False)
    monkeypatch.setattr(chain_builder_module, "_DEFAULT_CHAIN_BUILDER", None, raising=False)

    builder = intelligence_module.get_chain_builder()

    assert builder.enforce_data_contract is True
    assert builder._program_memory_path == store
    assert builder._program_memory_max_entries == 7
    assert builder._program_memory_ttl_seconds == 7200


def test_risk_003_data_contract_blocks_incomplete_findings() -> None:
    builder = AttackChainBuilder(enforce_data_contract=True)
    chains = builder.analyze([_sample_xss(), _sample_csrf()])

    # 期待仕様: auth_level/same_origin/primitive等の契約情報が無い入力は昇格しない
    assert chains == []


def test_risk_004_equivalent_chain_sets_produce_same_chain_key() -> None:
    builder = AttackChainBuilder()

    chains_a = builder.analyze([_sample_xss("XSS in /search"), _sample_csrf("CSRF gap in profile")])
    chains_b = builder.analyze([_sample_xss("Reflected XSS search sink"), _sample_csrf("Profile update missing CSRF")])

    assert chains_a
    assert chains_b
    assert chains_a[0].chain_key == chains_b[0].chain_key


def test_risk_005_active_probing_policy_rejects_disallowed_attempt() -> None:
    evaluator = getattr(MasterConductor, "evaluate_active_probe_policy", None)
    assert callable(evaluator)

    conductor = MasterConductor.__new__(MasterConductor)
    decision = evaluator(
        conductor,
        probe={
            "asset": "https://example.com/api",
            "strategy": "burst_probe",
            "qps": 50,
        },
        policy={
            "allow": ["light_probe"],
            "deny": ["burst_probe"],
            "per_asset_qps_cap": 5,
        },
    )

    assert decision == {"allowed": False, "reason": "strategy_denied"}


def test_risk_005_active_probing_policy_is_enforced_in_probe_task_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mc = MasterConductor.__new__(MasterConductor)

    class _Ctx:
        discovered_assets = []
        target_info = {}

    mc.context = _Ctx()
    monkeypatch.setattr(mc, "_evaluate_intervention_scenario_coverage", lambda *a, **k: {"missing_scenarios": ["scn_01_idor_bola_object_access"]})
    monkeypatch.setattr(mc, "_extract_scn_number", lambda sid: 1)
    monkeypatch.setattr(mc, "_collect_scenario_probe_seed_targets", lambda **k: (["https://example.com/api/users/1"], {"https://example.com/api/users/1": {}}))
    monkeypatch.setattr(mc, "_get_context_cookie_string", lambda: "")
    monkeypatch.setattr(mc, "_get_context_auth_headers", lambda: {})
    monkeypatch.setattr(mc, "_select_targets_for_scenario_probe", lambda **k: (["https://example.com/api/users/1"], {"https://example.com/api/users/1": {}}))
    monkeypatch.setattr(mc, "_apply_phase2_on_empty_policy", lambda v: v)
    monkeypatch.setattr(mc, "_resolve_active_probe_policy", lambda: {"allow": ["light_probe"], "deny": ["scenario_probe"], "per_asset_qps_cap": 5})

    seed = Task(
        id="seed",
        name="seed task",
        action="scan",
        agent_type="InjectionSwarm",
        params={"category": "api_endpoint"},
    )
    tasks = mc._create_missing_core_scenario_probe_tasks(existing_tasks=[seed], recon_results={})
    assert tasks == []


def test_risk_006_legacy_and_dsl_rule_parity(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy_rules.json"
    legacy.write_text(
        """
        {
          "version": 1,
          "rules": [
            {
              "id": "ato_chain",
              "name": "ATO Chain",
              "description": "XSS + CSRF",
              "severity": "critical",
              "required_signals": ["xss", "csrf"],
              "min_components": 2
            }
          ]
        }
        """.strip(),
        encoding="utf-8",
    )

    dsl = tmp_path / "dsl_rules.json"
    dsl.write_text(
        """
        {
          "dsl_version": 1,
          "rules": [
            {
              "id": "ato_chain",
              "name": "ATO Chain",
              "description": "XSS + CSRF",
              "severity": "critical",
              "preconditions": [{"auth_level": "user"}],
              "transitions": [{"from": "xss", "to": "csrf"}],
              "required_evidence": ["state_change_success"],
              "falsification": ["relogin_non_repro"]
            }
          ]
        }
        """.strip(),
        encoding="utf-8",
    )

    findings = [_sample_xss(), _sample_csrf()]
    chains_legacy = AttackChainBuilder(rules_path=str(legacy)).analyze(findings)
    chains_dsl = AttackChainBuilder(rules_path=str(dsl)).analyze(findings)

    assert len(chains_legacy) == len(chains_dsl)
    assert [c.rule_id for c in chains_legacy] == [c.rule_id for c in chains_dsl]


def test_risk_007_chain_finding_contains_decision_trace_fields() -> None:
    builder = AttackChainBuilder()
    chain = builder.analyze([_sample_xss(), _sample_csrf()])[0]
    finding = chain.to_finding()

    trace = finding.additional_info["decision_trace"]
    assert trace["selected_rule_id"] == chain.rule_id
    assert trace["final_state"] in {"draft", "confirmed", "actionable", "blocked"}
    assert isinstance(trace["excluded_reasons"], list)


def test_risk_008_kpi_split_go_no_go_and_diagnostic_is_documented() -> None:
    text = _read_plan_text()

    assert "#### 4.1.1 Go/No-Go KPI（意思決定用）" in text
    assert "#### 4.1.2 Diagnostic KPI（診断用）" in text
    assert "#### 4.1.0 フェーズ別の指標利用タイミング" in text
    assert "Phase 2終了判定" in text


def test_risk_009_advanced_search_has_time_budget_fallback() -> None:
    builder = AttackChainBuilder()
    analyze_with_budget = getattr(builder, "analyze_with_budget", None)
    assert callable(analyze_with_budget)

    result = analyze_with_budget(
        findings=[_sample_xss(), _sample_csrf()],
        top_k=3,
        timeout_ms=1,
    )
    assert result["used_fallback"] is True
    assert result["timeouts"] >= 1


def test_risk_010_chain_finding_requires_business_impact_sentence() -> None:
    builder = AttackChainBuilder()
    chain = builder.analyze([_sample_xss(), _sample_csrf()])[0]
    finding = chain.to_finding()

    assert "business_impact_sentence" in finding.additional_info
    assert finding.additional_info["business_impact_sentence"].strip() != ""


def test_risk_011_temporal_consistency_promotes_epoch_aligned_chain() -> None:
    builder = AttackChainBuilder()
    findings = [
        _sample_temporal_finding(title="Reflected XSS in account page", vuln_type=VulnType.XSS),
        _sample_temporal_finding(title="Missing CSRF token in transfer flow", vuln_type=VulnType.DEBUG_ENABLED),
    ]

    result = builder.evaluate_feasibility(
        _temporal_candidate(findings),
        findings,
        constraints=_temporal_constraints(),
    )

    assert result.get("verdict") == "pass"
    assert result.get("state") == "confirmed"
    assert result.get("excluded_reasons") == []


def test_risk_012_temporal_consistency_blocks_epoch_mismatch_with_reason_code() -> None:
    builder = AttackChainBuilder()
    findings = [
        _sample_temporal_finding(title="Reflected XSS in account page", vuln_type=VulnType.XSS),
        _sample_temporal_finding(
            title="Missing CSRF token in transfer flow",
            vuln_type=VulnType.DEBUG_ENABLED,
            csrf_epoch="epoch-8",
        ),
    ]

    result = builder.evaluate_feasibility(
        _temporal_candidate(findings),
        findings,
        constraints=_temporal_constraints(),
    )

    assert result.get("verdict") == "blocked"
    assert result.get("state") == "blocked"
    assert "temporal:epoch_mismatch" in result.get("excluded_reasons", [])


def test_risk_013_temporal_consistency_drafts_missing_metadata_instead_of_blocking() -> None:
    builder = AttackChainBuilder()
    findings = [
        _sample_temporal_finding(title="Reflected XSS in account page", vuln_type=VulnType.XSS),
        _sample_temporal_finding(
            title="Missing CSRF token in transfer flow",
            vuln_type=VulnType.DEBUG_ENABLED,
            token_epoch=_UNSET,
            csrf_epoch=_UNSET,
        ),
    ]

    result = builder.evaluate_feasibility(
        _temporal_candidate(findings),
        findings,
        constraints=_temporal_constraints(),
    )

    assert result.get("verdict") == "draft"
    assert result.get("state") == "draft"
    assert "temporal:metadata_missing" in result.get("excluded_reasons", [])


def test_risk_014_temporal_consistency_drafts_rotation_in_progress() -> None:
    builder = AttackChainBuilder()
    findings = [
        _sample_temporal_finding(title="Reflected XSS in account page", vuln_type=VulnType.XSS),
        _sample_temporal_finding(
            title="Missing CSRF token in transfer flow",
            vuln_type=VulnType.DEBUG_ENABLED,
            session_rotation_state="rotating",
        ),
    ]

    result = builder.evaluate_feasibility(
        _temporal_candidate(findings),
        findings,
        constraints=_temporal_constraints(),
    )

    assert result.get("verdict") == "draft"
    assert result.get("state") == "draft"
    assert "temporal:rotation_in_progress" in result.get("excluded_reasons", [])


def test_risk_015_temporal_consistency_blocks_session_generation_rollback() -> None:
    builder = AttackChainBuilder()
    findings = [
        _sample_temporal_finding(
            title="Reflected XSS in account page",
            vuln_type=VulnType.XSS,
            session_generation=9,
        ),
        _sample_temporal_finding(
            title="Missing CSRF token in transfer flow",
            vuln_type=VulnType.DEBUG_ENABLED,
            session_generation=8,
        ),
    ]

    result = builder.evaluate_feasibility(
        _temporal_candidate(findings),
        findings,
        constraints=_temporal_constraints(),
    )

    assert result.get("verdict") == "blocked"
    assert result.get("state") == "blocked"
    assert "temporal:session_generation_rollback" in result.get("excluded_reasons", [])


def test_risk_016_subtask_plan_locks_temporal_acceptance_criteria() -> None:
    text = _read_subtask_plan_text()

    assert "誤昇格を新規に発生させないこと" in text
    assert "既存の妥当なチェーンを不要に降格させないこと" in text
    assert "metadata 欠損時は安全側に `draft` へ倒れ" in text


def test_risk_017_subtask_plan_locks_temporal_scope_and_rollback_strategy() -> None:
    text = _read_subtask_plan_text()

    assert "chain state 判定、監査ログ、関連 integration test expectation に限定する" in text
    assert "他の公開出力形式の変更は本タスクでは行わない" in text
    assert "異常時に旧挙動へ切り戻しやすい差分構造を保つ" in text
