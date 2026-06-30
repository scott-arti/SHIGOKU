from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor


PLAN_PATH = (
    Path(__file__).resolve().parents[3]
    / "docs"
    / "shigoku"
    / "plans"
    / "2026-06-01_sgk-2026-0251_task_plan.md"
)


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def _new_mc() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        discovered_assets=["https://app.example.com/api/users/1"],
        target_info={
            "target": "https://app.example.com",
            "tech_stack": [],
            "auth_tokens": {},
            "program_probe_policy": {},
        },
    )
    return mc


def _seed_task() -> Task:
    return Task(
        id="seed",
        name="seed task",
        action="scan",
        agent_type="InjectionSwarm",
        params={"category": "api_endpoint"},
    )


def test_step14_plan_documents_information_gain_and_policy_order() -> None:
    text = _read_plan_text()

    assert "Step 14 Action" in text
    assert "max_information_gain" in text
    assert "program override > runtime flag > config default" in text
    assert "global_probe_budget" in text
    assert "`blocked` 遷移" in text
    assert "`defer` 遷移" in text


def test_step14_ranks_missing_links_by_information_gain() -> None:
    mc = _new_mc()
    ranker = getattr(mc, "_rank_missing_link_targets_by_information_gain", None)
    assert callable(ranker)

    ranked = ranker(
        candidates=[
            {
                "target": "https://app.example.com/api/users/1",
                "missing_links": ["authz_replay"],
                "evidence": {"cross_user_impact": True},
            },
            {
                "target": "https://app.example.com/api/orders/9",
                "missing_links": ["authz_replay", "state_change_confirmation"],
                "evidence": {"cross_user_impact": True, "state_change_success": True},
            },
        ]
    )

    assert [item["target"] for item in ranked] == [
        "https://app.example.com/api/orders/9",
        "https://app.example.com/api/users/1",
    ]


def test_step14_program_override_beats_global_probe_policy() -> None:
    mc = _new_mc()
    mc.context.target_info["program_probe_policy"] = {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
    }
    resolver = getattr(mc, "_resolve_active_probe_policy_for_program", None)
    assert callable(resolver)

    resolved = resolver(runtime_policy=None)

    assert resolved == {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
    }


def test_step14_runtime_policy_beats_config_default_when_no_program_override() -> None:
    mc = _new_mc()
    resolver = getattr(mc, "_resolve_active_probe_policy_for_program", None)
    assert callable(resolver)

    resolved = resolver(
        runtime_policy={
            "allow": ["scenario_probe"],
            "deny": [],
            "per_asset_qps_cap": 1,
        }
    )

    assert resolved["allow"] == ["scenario_probe"]
    assert resolved["per_asset_qps_cap"] == 1


def test_step14_source_program_precedence_matrix_keeps_program_winner() -> None:
    mc = _new_mc()
    mc.context.target_info["program_probe_policy"] = {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
        "global_probe_budget": 3,
    }

    resolved = mc._resolve_active_probe_policy_for_program(
        runtime_policy={
            "allow": ["different_runtime_probe"],
            "deny": ["destructive_probe"],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 1,
        }
    )

    assert resolved["source"] == "program_override", "source_program should win over runtime/config"
    assert resolved["global_probe_budget"] == 3, "source_program expected winner for budget contract"


def test_step14_source_runtime_precedence_matrix_keeps_runtime_winner() -> None:
    mc = _new_mc()

    resolved = mc._resolve_active_probe_policy_for_program(
        runtime_policy={
            "allow": ["scenario_probe"],
            "deny": [],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 2,
        }
    )

    assert resolved["source"] == "runtime_flag", "source_runtime should win when no program override exists"
    assert resolved["global_probe_budget"] == 2, "source_runtime expected winner for budget contract"


def test_step14_source_config_precedence_matrix_uses_config_default(monkeypatch: pytest.MonkeyPatch) -> None:
    mc = _new_mc()
    monkeypatch.setattr(
        mc,
        "_resolve_active_probe_policy",
        lambda: {
            "allow": ["scenario_probe"],
            "deny": ["destructive_probe"],
            "per_asset_qps_cap": 4,
            "global_probe_budget": 6,
        },
    )

    resolved = mc._resolve_active_probe_policy_for_program(runtime_policy=None)

    assert resolved["source"] == "config_default", "source_config should win when no program/runtime override exists"
    assert resolved["global_probe_budget"] == 6, "source_config expected winner for budget contract"


def test_step14_source_invalid_precedence_matrix_reports_ignored_keys() -> None:
    mc = _new_mc()
    mc.context.target_info["program_probe_policy"] = {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
        "global_probe_budget": 3,
        "unexpected_key": "drop-me",
    }

    resolved = mc._resolve_active_probe_policy_for_program(runtime_policy=None)

    assert resolved["ignored_keys"] == ["unexpected_key"], "source_invalid should report ignored keys for debugging"


def test_step14_budget_exhaustion_defers_probe_planning() -> None:
    mc = _new_mc()
    planner = getattr(mc, "plan_missing_link_probes", None)
    assert callable(planner)

    result = planner(
        existing_tasks=[_seed_task()],
        recon_results={},
        runtime_policy={"global_probe_budget": 0},
    )

    assert result["tasks"] == []
    assert result["state"] == "defer"
    assert result["reason"] == "global_probe_budget_exhausted"


def test_step14_probe_outcome_guard_blocks_or_defers() -> None:
    mc = _new_mc()
    evaluator = getattr(mc, "evaluate_active_probe_runtime_guard", None)
    assert callable(evaluator)

    blocked = evaluator(
        outcomes=[
            {"status_code": 403, "waf_detected": True},
            {"status_code": 503, "waf_detected": False},
        ],
        dependency_error=False,
    )
    deferred = evaluator(
        outcomes=[],
        dependency_error=True,
    )

    assert blocked["state"] == "blocked"
    assert blocked["reason"] == "waf_or_5xx_threshold"
    assert deferred["state"] == "defer"
    assert deferred["reason"] == "external_dependency_failure"


def test_step14_builds_runtime_context_from_chain_finding_snapshot() -> None:
    mc = _new_mc()

    finding = {
        "resolved_workflow_template": {
            "template_id": "wf-fintech",
            "steps": ["probe-fintech"],
            "source": "fintech",
        },
        "resolved_tactical_policy": {
            "allow": ["scenario_probe"],
            "deny": [],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 2,
            "source": "program_override",
        },
    }

    result = mc.build_probe_runtime_context_from_chain_finding(finding)

    assert result == {
        "runtime_policy": {
            "allow": ["scenario_probe"],
            "deny": [],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 2,
            "source": "program_override",
        },
        "workflow_template": {
            "template_id": "wf-fintech",
            "steps": ["probe-fintech"],
            "source": "fintech",
        },
    }


def test_step14_rollout_guard_switches_to_read_only_when_baseline_exceeded() -> None:
    mc = _new_mc()

    result = mc.assess_missing_link_probe_rollout(
        baseline_metrics={
            "blocked_defer_ratio": 0.10,
            "planned_task_count": 2,
            "qps_cap_hits": 0,
        },
        current_metrics={
            "blocked_defer_ratio": 0.30,
            "planned_task_count": 5,
            "qps_cap_hits": 2,
        },
        thresholds={
            "blocked_defer_ratio_delta": 0.05,
            "planned_task_delta": 1,
            "qps_cap_hit_delta": 1,
        },
    )

    assert result["workflow_template_mode"] == "read_only"
    assert "blocked_defer_ratio_exceeded" in result["reasons"]


def test_step14_rollout_guard_allows_execution_within_baseline() -> None:
    mc = _new_mc()

    result = mc.assess_missing_link_probe_rollout(
        baseline_metrics={
            "blocked_defer_ratio": 0.10,
            "planned_task_count": 2,
            "qps_cap_hits": 0,
        },
        current_metrics={
            "blocked_defer_ratio": 0.11,
            "planned_task_count": 3,
            "qps_cap_hits": 1,
        },
        thresholds={
            "blocked_defer_ratio_delta": 0.05,
            "planned_task_delta": 2,
            "qps_cap_hit_delta": 2,
        },
    )

    assert result["workflow_template_mode"] == "enabled"
    assert result["reasons"] == []
