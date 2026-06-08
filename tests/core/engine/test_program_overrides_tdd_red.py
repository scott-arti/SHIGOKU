from __future__ import annotations

from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor


def _new_mc() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        discovered_assets=[
            "https://app.example.com/api/users/1",
            "https://app.example.com/api/orders/9",
        ],
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


def test_program_policy_resolution_records_program_source_and_budget_contract() -> None:
    mc = _new_mc()
    mc.context.target_info["program_probe_policy"] = {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
        "global_probe_budget": 3,
    }

    resolved = mc._resolve_active_probe_policy_for_program(
        runtime_policy={
            "allow": ["scenario_probe"],
            "deny": ["destructive_probe"],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 1,
        }
    )

    assert resolved == {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
        "global_probe_budget": 3,
        "source": "program_override",
    }


def test_runtime_policy_resolution_records_runtime_source_when_program_override_missing() -> None:
    mc = _new_mc()

    resolved = mc._resolve_active_probe_policy_for_program(
        runtime_policy={
            "allow": ["scenario_probe"],
            "deny": [],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 2,
        }
    )

    assert resolved == {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 1,
        "global_probe_budget": 2,
        "source": "runtime_flag",
    }


def test_invalid_override_keys_are_ignored_and_reported() -> None:
    mc = _new_mc()
    mc.context.target_info["program_probe_policy"] = {
        "allow": ["scenario_probe"],
        "deny": [],
        "per_asset_qps_cap": 2,
        "global_probe_budget": 3,
        "unexpected_key": "drop-me",
    }

    resolved = mc._resolve_active_probe_policy_for_program(runtime_policy=None)

    assert "unexpected_key" not in resolved
    assert resolved["ignored_keys"] == ["unexpected_key"]


def test_probe_plan_reports_before_after_counts_for_override_budget() -> None:
    mc = _new_mc()

    result = mc.plan_missing_link_probes(
        existing_tasks=[_seed_task()],
        recon_results={
            "https://app.example.com/api/orders/9": {
                "missing_links": ["authz_replay", "state_change_confirmation"],
                "evidence": {"cross_user_impact": True, "state_change_success": True},
            }
        },
        runtime_policy={"global_probe_budget": 1},
    )

    assert result["planned_task_count_before_override"] >= result["planned_task_count_after_override"]
    assert result["planned_task_count_after_override"] == len(result["tasks"])


def test_probe_plan_reports_qps_cap_target_when_policy_caps_asset() -> None:
    mc = _new_mc()

    result = mc.plan_missing_link_probes(
        existing_tasks=[_seed_task()],
        recon_results={
            "https://app.example.com/api/orders/9": {
                "missing_links": ["authz_replay"],
                "evidence": {"cross_user_impact": True},
            }
        },
        runtime_policy={
            "global_probe_budget": 1,
            "per_asset_qps_cap": 1,
        },
    )

    assert result["qps_cap_target"] == "https://app.example.com/api/orders/9"


def test_workflow_template_stays_read_only_until_guard_allows_execution() -> None:
    mc = _new_mc()

    result = mc.plan_missing_link_probes(
        existing_tasks=[_seed_task()],
        recon_results={
            "https://app.example.com/api/orders/9": {
                "missing_links": ["authz_replay"],
                "evidence": {"cross_user_impact": True},
            }
        },
        runtime_policy={
            "global_probe_budget": 1,
            "workflow_template": {"template_id": "wf-fintech", "steps": ["probe-fintech"]},
        },
    )

    assert result["workflow_template_applied"] is False
    assert result["workflow_template"]["template_id"] == "wf-fintech"

