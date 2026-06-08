from collections import deque
from types import SimpleNamespace

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.engine.observation_reason import ObservationReason


def _new_min_mc() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.llm_client = object()
    mc.context = type("Ctx", (), {"metrics": {}})()
    mc._react_observation_executed_total = 0
    mc._react_observation_executed_by_target = {}
    mc._react_observation_metrics = {"attempted": 0, "executed": 0, "skipped": 0, "skip_reasons": {}}
    mc._react_observation_retry_used = 0
    mc._react_observation_cb_failures = 0
    mc._react_observation_cb_open_until = 0.0
    mc._react_observation_inflight = 0
    mc._react_observation_pending_queue = deque()
    return mc


def _patch_core_react_settings(monkeypatch, **overrides):
    import src.core.config.settings as core_settings_module

    defaults = {
        "enable_react_observation": True,
        "react_observation_max_calls_per_run": 50,
        "react_observation_max_calls_per_target": 10,
        "react_observation_sampling_rate": 1.0,
        "react_observation_low_value_task_patterns": "read,list,fetch",
        "react_observation_retry_budget_per_run": 20,
        "react_observation_queue_maxsize": 100,
        "max_inflight_react_requests_global": 8,
    }
    defaults.update(overrides)
    monkeypatch.setattr(
        core_settings_module,
        "get_settings",
        lambda **kwargs: SimpleNamespace(**defaults),
        raising=True,
    )


def test_should_observe_budget_priority_over_high_value(monkeypatch):
    _patch_core_react_settings(
        monkeypatch,
        react_observation_max_calls_per_run=1,
        react_observation_max_calls_per_target=10,
        react_observation_sampling_rate=1.0,
        react_observation_low_value_task_patterns="read,list",
    )

    mc = _new_min_mc()
    mc._react_observation_executed_total = 1
    task = Task(id="t1", name="active recon", action="scan", params={"target": "https://example.com"})
    result = {"success": True, "data": {"note": "critical vulnerability"}, "findings": ["f1"]}

    allowed, reason = mc._should_observe(task, result)
    assert allowed is False
    assert reason == ObservationReason.SKIP_BUDGET_EXCEEDED


def test_should_observe_high_value_beats_sampling(monkeypatch):
    _patch_core_react_settings(
        monkeypatch,
        react_observation_sampling_rate=0.0,
        react_observation_low_value_task_patterns="read,list",
    )

    mc = _new_min_mc()
    task = Task(id="t2", name="active recon", action="scan", params={"target": "https://example.com"})
    result = {"success": True, "data": {"message": "unexpected behavior"}}

    allowed, reason = mc._should_observe(task, result)
    assert allowed is True
    assert reason == ObservationReason.ALLOW_HIGH_VALUE_SIGNAL


def test_should_observe_skip_low_value(monkeypatch):
    _patch_core_react_settings(
        monkeypatch,
        react_observation_low_value_task_patterns="read,list,fetch",
    )

    mc = _new_min_mc()
    task = Task(id="t3", name="read artifact", action="fetch", params={"target": "https://example.com"})
    result = {"success": True, "data": {"foo": "bar"}}

    allowed, reason = mc._should_observe(task, result)
    assert allowed is False
    assert reason == ObservationReason.SKIP_LOW_VALUE_TASK


def test_should_observe_skip_when_circuit_open(monkeypatch):
    _patch_core_react_settings(monkeypatch, react_observation_retry_budget_per_run=20)

    mc = _new_min_mc()
    mc._react_observation_cb_open_until = 10**10  # far future
    task = Task(id="t4", name="scan", action="scan", params={"target": "https://example.com"})
    result = {"success": True, "data": {"foo": "bar"}}
    allowed, reason = mc._should_observe(task, result)
    assert allowed is False
    assert reason == ObservationReason.SKIP_CIRCUIT_OPEN


def test_should_observe_skip_when_retry_budget_exhausted(monkeypatch):
    _patch_core_react_settings(monkeypatch, react_observation_retry_budget_per_run=1)

    mc = _new_min_mc()
    mc._react_observation_retry_used = 1
    task = Task(id="t5", name="scan", action="scan", params={"target": "https://example.com"})
    result = {"success": True, "data": {"foo": "bar"}}
    allowed, reason = mc._should_observe(task, result)
    assert allowed is False
    assert reason == ObservationReason.SKIP_BUDGET_EXCEEDED


def test_should_observe_skip_when_queue_overflow(monkeypatch):
    _patch_core_react_settings(
        monkeypatch,
        react_observation_retry_budget_per_run=20,
        react_observation_queue_maxsize=1,
    )

    mc = _new_min_mc()
    mc._react_observation_pending_queue.append("queued-token")
    task = Task(id="t6", name="scan", action="scan", params={"target": "https://example.com"})
    result = {"success": True, "data": {"foo": "bar"}}
    allowed, reason = mc._should_observe(task, result)
    assert allowed is False
    assert reason == ObservationReason.SKIP_QUEUE_OVERFLOW


def test_record_react_decision_updates_context_snapshot():
    mc = _new_min_mc()
    mc._record_react_decision(ObservationReason.SKIP_SAMPLING_POLICY, False)
    snap = mc.context.metrics.get("react_observation", {})
    assert snap.get("attempted") == 1
    assert snap.get("skipped") == 1
    assert snap.get("skip_reasons", {}).get("react_sampling_policy") == 1


def test_react_setting_prefers_core_settings(monkeypatch):
    from src.config import settings as legacy_settings
    import src.core.config.settings as core_settings_module

    mc = _new_min_mc()
    monkeypatch.setattr(legacy_settings, "react_observation_sampling_rate", 0.1, raising=False)
    monkeypatch.setattr(
        core_settings_module,
        "get_settings",
        lambda **kwargs: SimpleNamespace(react_observation_sampling_rate=0.9),
        raising=True,
    )
    assert mc._react_setting("react_observation_sampling_rate", 1.0) == 0.9
