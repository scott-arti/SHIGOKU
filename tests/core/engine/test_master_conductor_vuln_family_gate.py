from types import SimpleNamespace

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor import MasterConductor


def _mk_task(task_id: str, category: str, findings: list[dict] | None = None) -> Task:
    task = Task(
        id=task_id,
        name=f"{category} scan",
        agent_type="test_agent",
        action="scan",
        params={"category": category},
    )
    task.state = TaskState.SUCCESS
    task.result = {"success": True, "findings": findings or []}
    return task


def _new_mc(required_families: list[str], tasks: list[Task]) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.completed_tasks = tasks
    mc.task_queue = []
    mc.context = SimpleNamespace(
        discovered_assets=[],
        bypass_methods=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
        target_info={"required_vuln_families": required_families},
    )
    return mc


def test_vuln_family_gate_passes_with_category_evidence():
    mc = _new_mc(
        required_families=["access_control", "injection", "csrf", "api"],
        tasks=[
            _mk_task("t1", "admin"),
            _mk_task("t2", "id_param"),
            _mk_task("t3", "api_candidate"),
            _mk_task("t4", "csrf_candidate"),
        ],
    )

    summary = mc._generate_summary()

    assert summary["coverage_gate_passed"] is True
    assert summary["coverage_gate_missing"] == []
    assert summary["coverage_gate_required"] == 4
    assert summary["coverage_gate_covered"] == 4


def test_vuln_family_gate_reports_missing_families():
    mc = _new_mc(
        required_families=["xss", "csrf"],
        tasks=[
            _mk_task("t1", "admin"),
            _mk_task("t2", "api_data"),
        ],
    )

    summary = mc._generate_summary()

    assert summary["coverage_gate_passed"] is False
    assert set(summary["coverage_gate_missing"]) == {"xss", "csrf"}
    assert summary["coverage_gate_required"] == 2
    assert summary["coverage_gate_covered"] == 0


def test_vuln_family_gate_uses_finding_evidence():
    mc = _new_mc(
        required_families=["csrf"],
        tasks=[
            _mk_task("t1", "meta_observability", findings=[{"type": "csrf", "severity": "medium"}]),
        ],
    )

    summary = mc._generate_summary()
    coverage = summary["vulnerability_family_coverage"]

    assert summary["coverage_gate_passed"] is True
    assert "csrf" in coverage["reached_families"]
    csrf_items = [i for i in coverage["coverage_items"] if i["family"] == "csrf"]
    assert csrf_items
    assert csrf_items[0]["finding_evidence"] == ["csrf"]


def test_generate_summary_includes_intervention_scenario_coverage():
    task = _mk_task("t1", "id_param")
    task.params["_intervention"] = {
        "decision": {
            "scenario_id": "scn_01_idor_bola_object_access",
            "route": "shigoku_only",
        }
    }
    task2 = _mk_task("t2", "api_data")
    task2.params["_intervention"] = {
        "decision": {
            "scenario_id": "scn_07_token_trust_boundary",
            "route": "shigoku_hitl",
        }
    }

    mc = _new_mc(required_families=["api"], tasks=[task, task2])
    summary = mc._generate_summary()

    assert "scenario_coverage" in summary
    assert summary["scenario_covered"] >= 2
    assert summary["scenario_required"] >= 12
    covered = summary["scenario_coverage"]["covered_scenarios"]
    assert "scn_01_idor_bola_object_access" in covered
    assert "scn_07_token_trust_boundary" in covered


def test_scenario_coverage_normalizes_hitl_category_routes_to_scn_ids():
    auth_task = _mk_task("t_auth", "auth")
    auth_task.params["_intervention"] = {
        "decision": {
            "scenario_id": "category_route:auth",
            "route": "shigoku_hitl",
        }
    }

    csrf_task = _mk_task("t_csrf", "csrf_candidate")
    csrf_task.params["_intervention"] = {
        "decision": {
            "scenario_id": "category_route:csrf_candidate",
            "route": "shigoku_hitl",
        }
    }

    mc = _new_mc(required_families=["api"], tasks=[auth_task, csrf_task])
    summary = mc._generate_summary()
    covered = set(summary["scenario_coverage"]["covered_scenarios"])

    assert "scn_07_token_trust_boundary" in covered
    assert "scn_09_multi_step_state_machine" in covered


def test_scenario_coverage_ignores_skipped_hitl_waiting_tasks():
    pending_task = _mk_task("t_pending", "auth")
    pending_task.state = TaskState.SKIPPED
    pending_task.failure_reason = "intervention_gate_pending_hitl"
    pending_task.params["_intervention"] = {
        "decision": {
            "scenario_id": "category_route:auth",
            "route": "shigoku_hitl",
        }
    }

    mc = _new_mc(required_families=["api"], tasks=[pending_task])
    summary = mc._generate_summary()
    covered = set(summary["scenario_coverage"]["covered_scenarios"])

    assert "scn_07_token_trust_boundary" not in covered


def test_scenario_coverage_maps_injection_category_to_scn03():
    injection_task = _mk_task("t_injection", "api_data")
    mc = _new_mc(required_families=["api"], tasks=[injection_task])

    summary = mc._generate_summary()
    covered = set(summary["scenario_coverage"]["covered_scenarios"])

    assert "scn_03_injection_input_tampering" in covered


def test_scenario_coverage_maps_data_exposure_category_to_scn06():
    exposure_task = _mk_task("t_exposure", "meta_observability")
    mc = _new_mc(required_families=["api"], tasks=[exposure_task])

    summary = mc._generate_summary()
    covered = set(summary["scenario_coverage"]["covered_scenarios"])

    assert "scn_06_data_exposure_diff" in covered
