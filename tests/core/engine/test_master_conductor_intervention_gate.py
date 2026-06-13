import threading
from types import SimpleNamespace

from src.config import settings
from src.core.domain.model.task import Task, TaskState
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.master_conductor import MasterConductor
from src.core.models.task_execution_log import TaskExecutionRecord, TaskResult


def _new_conductor_for_intervention_tests(callback=None) -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.human_approval_callback = callback
    mc.intervention_policy = InterventionPolicy(settings.get_intervention_scenarios())
    mc._state_lock = threading.RLock()
    mc.pending_hitl = []
    return mc


def _new_task(name: str) -> Task:
    return Task(
        id="task_intervention_test",
        name=name,
        action="scan",
        agent_type="InjectionSwarm",
        params={},
    )


def test_intervention_gate_observe_mode_does_not_block(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "observe", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", True, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=None)
    task = _new_task("Password Reset email verification flow")

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("manual_deferred") is True
    decision = task.params.get("_intervention", {}).get("decision", {})
    assert decision.get("route") == "human_preferred"
    assert task.state == TaskState.SKIPPED


def test_intervention_gate_enforce_human_preferred_fail_closed_blocks_without_callback(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_human_preferred", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", True, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=None)
    task = _new_task("Password Reset reset token email verification")

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("pending_hitl") is False
    assert blocked.get("manual_deferred") is True
    assert blocked.get("skipped") is True
    assert task.state == TaskState.SKIPPED
    assert len(mc.pending_hitl) == 0


def test_intervention_gate_enforce_hitl_blocks_when_callback_denies(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=lambda _info: False)
    task = _new_task("JWT alg:none token forgery attempt")

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("manual_deferred") is True
    assert blocked.get("skipped") is True
    assert task.state == TaskState.SKIPPED


def test_intervention_gate_enforce_hitl_allows_when_callback_approves(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=lambda _info: True)
    task = _new_task("JWT kid injection validation")

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("manual_deferred") is True
    approval = task.params.get("_intervention", {}).get("approval", {})
    assert approval.get("required") is True
    assert approval.get("approved") is False
    assert approval.get("status") == "deferred_manual_v1"
    assert task.state == TaskState.SKIPPED


def test_intervention_precheck_notifies_for_scn07_to_12(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "observe", raising=False)

    captured: list[dict] = []

    class _DummyNotifier:
        def notify(self, message: str, provider=None, bulk=False):
            captured.append(
                {
                    "message": message,
                    "provider": provider,
                    "bulk": bulk,
                }
            )
            return True

    monkeypatch.setattr(
        "src.core.engine.master_conductor.get_notifier",
        lambda: _DummyNotifier(),
    )

    mc = _new_conductor_for_intervention_tests(callback=None)
    task = Task(
        id="task_notify_scn10",
        name="Business logic semantic abuse flow",
        action="scan",
        agent_type="InjectionSwarm",
        params={
            "_intervention": {
                "decision": {
                    "scenario_id": "scn_10_semantic_business_logic",
                    "route": "human_preferred",
                    "confidence": 0.9,
                    "reasons": ["matched"],
                    "matched_signals": ["business logic"],
                }
            }
        },
    )

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("manual_deferred") is True
    assert len(captured) == 1
    assert "scn_10_semantic_business_logic" in captured[0]["message"].lower()
    assert "Target(s):" in captured[0]["message"]
    assert captured[0]["bulk"] is True


def test_intervention_precheck_notification_is_deduped_per_task_scenario(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "observe", raising=False)

    calls = {"count": 0}

    class _DummyNotifier:
        def notify(self, message: str, provider=None, bulk=False):
            calls["count"] += 1
            return True

    monkeypatch.setattr(
        "src.core.engine.master_conductor.get_notifier",
        lambda: _DummyNotifier(),
    )

    mc = _new_conductor_for_intervention_tests(callback=None)
    task = Task(
        id="task_notify_scn11",
        name="Multi vector chain candidate",
        action="scan",
        agent_type="InjectionSwarm",
        params={
            "_intervention": {
                "decision": {
                    "scenario_id": "scn_11_multi_vector_chain",
                    "route": "shigoku_hitl",
                    "confidence": 0.8,
                    "reasons": ["matched"],
                    "matched_signals": ["chain"],
                }
            }
        },
    )

    mc._run_intervention_precheck(task)
    mc._run_intervention_precheck(task)

    assert calls["count"] == 1


def test_intervention_precheck_does_not_manual_defer_scn11_in_v1_policy(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "observe", raising=False)

    mc = _new_conductor_for_intervention_tests(callback=None)
    task = Task(
        id="task_scn11_exec",
        name="SCN11 Multi-Vector Chain Probe",
        action="scan",
        agent_type="InjectionSwarm",
        params={
            "scenario_probe": "scn_11_multi_vector_chain",
            "category": "api_data",
            "scenario": "api chaining attack chain privilege escalation chain takeover chain multi vector trust transition authz data mutation",
        },
    )

    blocked = mc._run_intervention_precheck(task)

    assert blocked is None
    decision = task.params.get("_intervention", {}).get("decision", {})
    assert decision.get("scenario_id") == "scn_11_multi_vector_chain"
    assert task.state != TaskState.SKIPPED


def test_intervention_precheck_with_exec_record_mutation(monkeypatch) -> None:
    """exec_record が渡された場合、side-effect として mark_completed と execution_log 追加が行われる。"""
    import logging
    from src.core.models.task_execution_log import TaskExecutionRecord

    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=None)
    mc.execution_log = SimpleNamespace()
    mc.execution_log.add_record = lambda rec: setattr(mc.execution_log, "_last", rec)
    mc._record_failure_context = lambda task, stage, reason: None

    task = Task(
        id="task_exec_record_test",
        name="exec record mutation test",
        action="scan",
        agent_type="InjectionSwarm",
        params={"requires_human_input": True},
    )
    exec_record = TaskExecutionRecord(
        task_id=task.id,
        task_name=task.name,
        agent_type=task.agent_type,
        action=task.action,
        target_url="",
    )

    blocked = mc._run_intervention_precheck(task, exec_record=exec_record)

    assert blocked is not None
    assert blocked.get("pending_hitl") is True
    last_record = getattr(mc.execution_log, "_last", None)
    assert last_record is not None
    assert last_record.result == TaskResult.SUCCESS
    assert "pending" in str(last_record.result_summary or "").lower()
    meta = last_record.metadata or {}
    assert meta.get("metadata", {}).get("intervention", {}).get("pending_hitl") is True


def test_intervention_precheck_callback_explicitly_denies_rejected_path(monkeypatch) -> None:
    """callback が明示的に False を返した場合、denial error が返り task.state=SKIPPED になる。"""
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "intervention_human_preferred_fail_closed", False, raising=False)
    monkeypatch.setattr(settings, "defer_scn07_12_hitl_v1", False, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=lambda _info: False)
    mc._record_failure_context = lambda task, stage, reason: None
    task = Task(
        id="task_rejected",
        name="Explicitly rejected by callback",
        action="scan",
        agent_type="InjectionSwarm",
        params={"requires_human_input": True},
    )

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("success") is False
    assert blocked.get("skipped") is True
    assert "Blocked by intervention gate" in str(blocked.get("error", ""))
    assert task.state == TaskState.SKIPPED
    approval = task.params.get("_intervention", {}).get("approval", {})
    assert approval.get("required") is True
    assert approval.get("approved") is False


def test_intervention_precheck_defer_v1_disabled_allows_scn08(monkeypatch) -> None:
    """defer_scn07_12_hitl_v1=False のとき、SCN08 は manual defer されずに通常の approval 判定に進む。"""
    monkeypatch.setattr(settings, "intervention_gate_mode", "enforce_hitl", raising=False)
    monkeypatch.setattr(settings, "defer_scn07_12_hitl_v1", False, raising=False)

    mc = _new_conductor_for_intervention_tests(callback=None)
    mc._record_failure_context = lambda task, stage, reason: None
    task = Task(
        id="task_scn08_no_defer",
        name="SCN08 OOB External Channel",
        action="scan",
        agent_type="InjectionSwarm",
        params={
            "_intervention": {
                "decision": {
                    "scenario_id": "scn_08_oob_external_channel",
                    "route": "shigoku_hitl",
                    "confidence": 0.4,
                    "reasons": ["oob detected"],
                    "matched_signals": ["external channel"],
                }
            }
        },
    )

    blocked = mc._run_intervention_precheck(task)

    # defer_v1=False なので manual_deferred ではなく pending_hitl へ進む
    assert blocked is not None
    assert blocked.get("pending_hitl") is True
    assert blocked.get("manual_deferred", False) is False
    assert task.state == TaskState.SKIPPED
    # 1 ticket が pending_hitl に登録されている
    assert len(mc.pending_hitl) == 1
