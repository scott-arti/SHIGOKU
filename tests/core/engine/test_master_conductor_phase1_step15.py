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
    / "2026-06-01_task_plan.md"
)


def _read_plan_text() -> str:
    return PLAN_PATH.read_text(encoding="utf-8")


def _new_mc() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        discovered_assets=["https://app.example.com/api/orders/9"],
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


def test_step15_plan_documents_safe_mutation_rules() -> None:
    text = _read_plan_text()

    assert "Step 15 Action" in text
    assert "dry-run" in text
    assert "allowlist" in text
    assert "fail-closed" in text
    assert "許可戦術内でのみ再評価" in text


def test_step15_builds_race_profile_with_order_permutations() -> None:
    mc = _new_mc()
    builder = getattr(mc, "build_race_profile", None)
    assert callable(builder)

    profile = builder(mode="burst")

    assert profile["mode"] == "burst"
    assert profile["burst"] >= 1
    assert profile["order_permutations"] >= 1


def test_step15_safe_variations_respect_allowlist_and_fail_closed() -> None:
    mc = _new_mc()
    planner = getattr(mc, "build_safe_probe_variations", None)
    assert callable(planner)

    allowed = planner(
        waf_name="aws_waf",
        dry_run=True,
        allowlist=["encode", "case"],
        fail_closed=True,
    )
    denied = planner(
        waf_name="aws_waf",
        dry_run=True,
        allowlist=[],
        fail_closed=True,
    )

    assert [item["mutation_type"] for item in allowed] == ["encode"]
    assert denied == []


def test_step15_dry_run_and_execute_mode_choose_same_candidates() -> None:
    mc = _new_mc()
    planner = getattr(mc, "build_safe_probe_variations", None)
    assert callable(planner)

    dry_run = planner(
        waf_name="cloudflare",
        dry_run=True,
        allowlist=["encode", "case"],
        fail_closed=False,
    )
    execute = planner(
        waf_name="cloudflare",
        dry_run=False,
        allowlist=["encode", "case"],
        fail_closed=False,
    )

    assert [item["mutation_type"] for item in dry_run] == [item["mutation_type"] for item in execute]


def test_step15_plan_missing_link_probes_injects_race_profile_and_safe_variations() -> None:
    mc = _new_mc()
    planner = getattr(mc, "plan_missing_link_probes", None)
    assert callable(planner)

    probe_task = Task(
        id="probe",
        name="probe",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={
            "source_category": "scenario_probe_planner",
            "scenario_probe": "scn_11_multi_vector_chain",
            "category": "api_data",
            "target": "https://app.example.com/api/orders/9",
            "targets": ["https://app.example.com/api/orders/9"],
        },
        target="https://app.example.com/api/orders/9",
        tags=["api_endpoint"],
        priority=80,
    )
    mc._create_missing_core_scenario_probe_tasks = lambda existing_tasks, recon_results: [probe_task]  # type: ignore[method-assign]

    result = planner(
        existing_tasks=[_seed_task()],
        recon_results={},
        runtime_policy={
            "global_probe_budget": 1,
            "race_mode": "burst",
            "dry_run": True,
            "allowlist": ["encode", "case"],
            "fail_closed": False,
            "waf_name": "cloudflare",
        },
    )

    task = result["tasks"][0]
    assert task.params["race_profile"]["mode"] == "burst"
    assert task.params["safe_variations"]
    assert task.params["safe_variations"][0]["mutation_type"] in {"encode", "case"}
