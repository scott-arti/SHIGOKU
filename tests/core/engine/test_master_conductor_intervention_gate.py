import threading
from types import SimpleNamespace

from src.config import settings
from src.core.domain.model.task import Task, TaskState
from src.core.engine.intervention_policy import InterventionPolicy
from src.core.engine.master_conductor import MasterConductor


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
    monkeypatch.setattr(
        mc,
        "_get_intervention_decision",
        lambda _task: {
            "scenario_id": "scn_10_semantic_business_logic",
            "route": "human_preferred",
            "confidence": 0.9,
            "reasons": ["matched"],
            "matched_signals": ["business logic"],
        },
    )
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
    assert "SCN10 手動検証候補" in captured[0]["message"]
    assert "- シナリオ: セマンティックなビジネスロジック (scn_10_semantic_business_logic)" in captured[0]["message"]
    assert "- 対象: -" in captured[0]["message"]
    assert "- タスク: Business logic semantic abuse flow" in captured[0]["message"]
    assert "- ルート/ゲート: human_preferred / observe" in captured[0]["message"]
    assert "- 信頼度: 0.9" in captured[0]["message"]
    assert "- 検知シグナル: business logic" in captured[0]["message"]
    assert "- 判定理由: matched" in captured[0]["message"]
    assert "- 必要な対応: このシナリオを手動で検証し、結果を記録してください（verified / not reproducible / needs more evidence）。" in captured[0]["message"]
    assert captured[0]["bulk"] is True


def test_intervention_precheck_notification_handles_string_and_missing_fields(monkeypatch) -> None:
    monkeypatch.setattr(settings, "intervention_gate_mode", "observe", raising=False)

    captured: list[str] = []

    class _DummyNotifier:
        def notify(self, message: str, provider=None, bulk=False):
            captured.append(message)
            return True

    monkeypatch.setattr(
        "src.core.engine.master_conductor.get_notifier",
        lambda: _DummyNotifier(),
    )

    mc = _new_conductor_for_intervention_tests(callback=None)
    monkeypatch.setattr(
        mc,
        "_get_intervention_decision",
        lambda _task: {
            "scenario_id": "scn_08_oob_external_channel_flow",
            "route": "human_preferred",
            "confidence": 0.0,
            "reasons": "email verification",
            "matched_signals": "oob",
        },
    )
    task = Task(
        id="task_notify_scn08",
        name="SCN08 OOB External Channel Surface Probe",
        action="scan",
        agent_type="InjectionSwarm",
        params={
            "_intervention": {
                "decision": {
                    "scenario_id": "scn_08_oob_external_channel_flow",
                    "route": "human_preferred",
                    "confidence": 0.0,
                    "reasons": "email verification",
                    "matched_signals": "oob",
                }
            }
        },
    )

    blocked = mc._run_intervention_precheck(task)

    assert blocked is not None
    assert blocked.get("manual_deferred") is True
    assert len(captured) == 1
    assert "- 対象: -" in captured[0]
    assert "- 検知シグナル: oob" in captured[0]
    assert "- 判定理由: email verification" in captured[0]


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
