from types import SimpleNamespace

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor_session_service import build_async_session_payload


def test_build_async_session_payload_serializes_queue_completed_context_and_adjacency() -> None:
    queue_task = Task(
        id="queue-1",
        name="Queue Task",
        agent_type="InjectionSwarm",
        action="scan",
        phase="attack",
        params={"target": "https://example.test"},
        priority=42,
        parent_id="parent-1",
        replan_depth=1,
    )
    queue_task.state = TaskState.PENDING

    completed_task = Task(
        id="done-1",
        name="Done Task",
        agent_type="AuthSwarm",
        action="analyze",
        phase="attack",
        params={"category": "auth"},
        state=TaskState.FAILED,
        error="boom",
        result={"ok": False},
        priority=77,
    )
    completed_task.failure_phase = "dispatch_result"
    completed_task.failure_reason = "phase2_timeout"
    completed_task.failure_reason_code = "TIMEOUT_PHASE2"
    completed_task.timeout_retry_count = 2

    context = SimpleNamespace(
        _total_attempts=7,
        _successful_attempts=5,
        bypass_methods=["jwt_bypass"],
        discovered_assets=["api.example.test"],
        target_info={"target": "https://example.test", "start_time": 123.0},
    )
    pending_hitl = [{"ticket_id": "ticket-1", "task": {"id": "task-1"}}]
    coverage_gate = {"gate_passed": True}
    scenario_coverage = {"covered_count": 3}

    payload = build_async_session_payload(
        task_queue=[queue_task],
        completed_tasks=[completed_task],
        context=context,
        pending_hitl=pending_hitl,
        coverage_gate=coverage_gate,
        scenario_coverage=scenario_coverage,
        timestamp=456.0,
        default_start_time=999.0,
    )

    assert payload["task_queue"] == [
        {
            "id": "queue-1",
            "name": "Queue Task",
            "agent_type": "InjectionSwarm",
            "action": "scan",
            "phase": "attack",
            "params": {"target": "https://example.test"},
            "state": "pending",
            "priority": 42,
            "parent_id": "parent-1",
            "replan_depth": 1,
        }
    ]
    assert payload["completed_tasks"] == [
        {
            "id": "done-1",
            "name": "Done Task",
            "agent_type": "AuthSwarm",
            "action": "analyze",
            "phase": "attack",
            "params": {"category": "auth"},
            "state": "failed",
            "error": "boom",
            "result": {"ok": False},
            "priority": 77,
            "failure_phase": "dispatch_result",
            "failure_reason": "phase2_timeout",
            "failure_reason_code": "TIMEOUT_PHASE2",
            "timeout_retry_count": 2,
        }
    ]
    assert payload["context"]["total_attempts"] == 7
    assert payload["context"]["successful_attempts"] == 5
    assert payload["context"]["bypass_methods"] == ["jwt_bypass"]
    assert payload["context"]["discovered_assets"] == ["api.example.test"]
    assert payload["context"]["target_info"] == {"target": "https://example.test", "start_time": 123.0}
    assert payload["context"]["pending_hitl"] == [{"ticket_id": "ticket-1", "task": {"id": "task-1"}}]
    assert payload["coverage_gate"] == {"gate_passed": True}
    assert payload["scenario_coverage"] == {"covered_count": 3}
    assert payload["pending_hitl"] == [{"ticket_id": "ticket-1", "task": {"id": "task-1"}}]
    assert payload["start_time"] == 123.0
    assert payload["timestamp"] == 456.0
    assert payload["adjacency_list"] == {"parent-1": ["queue-1"]}


def test_build_async_session_payload_deep_copies_pending_hitl() -> None:
    context = SimpleNamespace(
        _total_attempts=0,
        _successful_attempts=0,
        bypass_methods=[],
        discovered_assets=[],
        target_info={},
    )
    pending_hitl = [{"ticket_id": "ticket-1", "task": {"params": {"nested": {"value": 1}}}}]

    payload = build_async_session_payload(
        task_queue=[],
        completed_tasks=[],
        context=context,
        pending_hitl=pending_hitl,
        coverage_gate={},
        scenario_coverage={},
        timestamp=1.0,
        default_start_time=2.0,
    )

    pending_hitl[0]["task"]["params"]["nested"]["value"] = 99

    assert payload["pending_hitl"][0]["task"]["params"]["nested"]["value"] == 1
    assert payload["context"]["pending_hitl"][0]["task"]["params"]["nested"]["value"] == 1
