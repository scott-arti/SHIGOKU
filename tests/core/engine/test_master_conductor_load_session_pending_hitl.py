import json
from pathlib import Path

from src.core.engine.master_conductor import ExecutionContext, MasterConductor
from src.core.engine.task_queue import DynamicTaskQueue


def _new_mc_for_load_session() -> MasterConductor:
    mc = MasterConductor.__new__(MasterConductor)
    mc.task_queue = DynamicTaskQueue()
    mc.completed_tasks = []
    mc.context = ExecutionContext()
    mc.pending_hitl = []
    return mc


def test_load_session_uses_context_pending_hitl_fallback_when_top_level_missing(tmp_path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [],
                "context": {
                    "pending_hitl": [
                        {
                            "ticket_id": "ctx-ticket-1",
                            "status": "pending",
                            "task": {"id": "task-1"},
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert mc.pending_hitl == [
        {
            "ticket_id": "ctx-ticket-1",
            "status": "pending",
            "task": {"id": "task-1"},
        }
    ]


def test_load_session_prefers_top_level_pending_hitl_over_context_fallback(tmp_path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [],
                "pending_hitl": [
                    {
                        "ticket_id": "top-ticket-1",
                        "status": "approved",
                        "task": {"id": "task-top"},
                    }
                ],
                "context": {
                    "pending_hitl": [
                        {
                            "ticket_id": "ctx-ticket-1",
                            "status": "pending",
                            "task": {"id": "task-ctx"},
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert mc.pending_hitl == [
        {
            "ticket_id": "top-ticket-1",
            "status": "approved",
            "task": {"id": "task-top"},
        }
    ]


def test_load_session_deep_copies_pending_hitl_payload(tmp_path) -> None:
    source_payload = [
        {
            "ticket_id": "top-ticket-1",
            "status": "approved",
            "task": {"id": "task-top", "params": {"nested": {"value": 1}}},
        }
    ]
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [],
                "pending_hitl": source_payload,
                "context": {},
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    source_payload[0]["task"]["params"]["nested"]["value"] = 99
    assert mc.pending_hitl[0]["task"]["params"]["nested"]["value"] == 1


def test_load_session_restores_context_fields_from_payload(tmp_path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [],
                "context": {
                    "total_attempts": 7,
                    "successful_attempts": 5,
                    "bypass_methods": ["jwt_bypass", "encoding_bypass"],
                    "discovered_assets": ["api.example.test", "admin.example.test"],
                    "target_info": {"target": "https://example.test", "mode": "bugbounty"},
                },
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert mc.context.total_attempts == 7
    assert mc.context.successful_attempts == 5
    assert mc.context.bypass_methods == ["jwt_bypass", "encoding_bypass"]
    assert mc.context.discovered_assets == ["api.example.test", "admin.example.test"]
    assert mc.context.target_info == {"target": "https://example.test", "mode": "bugbounty"}


def test_load_session_context_restoration_replaces_existing_mutable_values(tmp_path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [],
                "context": {
                    "total_attempts": 2,
                    "successful_attempts": 1,
                    "bypass_methods": ["fresh_method"],
                    "discovered_assets": ["fresh.example.test"],
                    "target_info": {"target": "https://fresh.example.test"},
                },
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()
    mc.context.bypass_methods = ["stale_method"]
    mc.context.discovered_assets = ["stale.example.test"]
    mc.context.target_info = {"target": "https://stale.example.test", "mode": "old"}

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert mc.context.bypass_methods == ["fresh_method"]
    assert mc.context.discovered_assets == ["fresh.example.test"]
    assert mc.context.target_info == {"target": "https://fresh.example.test"}


def test_load_session_restores_completed_tasks_and_backfills_reason_code(tmp_path, monkeypatch) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [
                    {
                        "id": "done-1",
                        "name": "Done Task",
                        "agent_type": "InjectionSwarm",
                        "action": "scan",
                        "phase": "attack",
                        "params": {"category": "api_candidate"},
                        "state": "not_a_real_state",
                        "error": "Phase 2 timed out after 60s",
                        "result": {"ok": False},
                        "failure_phase": "dispatch_result",
                        "failure_reason": "phase2_timeout",
                        "timeout_retry_count": 3,
                    }
                ],
                "context": {},
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()
    monkeypatch.setattr(
        mc,
        "_normalize_failure_reason_code",
        lambda phase, reason, error=None: f"norm:{phase}:{reason}:{error}",
    )

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert len(mc.completed_tasks) == 1
    restored = mc.completed_tasks[0]
    assert restored.state.value == "success"
    assert restored.failure_phase == "dispatch_result"
    assert restored.failure_reason == "phase2_timeout"
    assert restored.failure_reason_code == "norm:dispatch_result:phase2_timeout:Phase 2 timed out after 60s"
    assert restored.timeout_retry_count == 3


def test_load_session_keeps_existing_completed_task_reason_code_when_present(tmp_path, monkeypatch) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [],
                "completed_tasks": [
                    {
                        "id": "done-2",
                        "name": "Done Task",
                        "state": "failed",
                        "failure_phase": "dispatch_result",
                        "failure_reason": "phase2_timeout",
                        "failure_reason_code": "TIMEOUT_PHASE2",
                    }
                ],
                "context": {},
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()
    monkeypatch.setattr(
        mc,
        "_normalize_failure_reason_code",
        lambda phase, reason, error=None: "SHOULD_NOT_BE_USED",
    )

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert mc.completed_tasks[0].failure_reason_code == "TIMEOUT_PHASE2"


def test_load_session_restores_task_queue_running_tasks_as_pending_by_default(tmp_path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [
                    {
                        "id": "queue-1",
                        "name": "Queued Task",
                        "agent_type": "InjectionSwarm",
                        "action": "scan",
                        "state": "running",
                        "phase": "attack",
                        "params": {"target": "https://example.test"},
                        "priority": 42,
                        "parent_id": "parent-queue",
                        "replan_depth": 1,
                    },
                    {
                        "id": "queue-2",
                        "name": "Invalid State Task",
                        "agent_type": "AuthSwarm",
                        "action": "analyze",
                        "state": "not_a_real_state",
                    },
                ],
                "completed_tasks": [],
                "context": {},
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert len(mc.task_queue) == 2
    restored_tasks = list(mc.task_queue)
    first = restored_tasks[0]
    second = restored_tasks[1]
    assert first.state.value == "pending"
    assert first.phase == "attack"
    assert first.priority == 42
    assert first.parent_id == "parent-queue"
    assert first.replan_depth == 1
    assert second.state.value == "pending"


def test_load_session_marks_running_tasks_skipped_when_user_declines_rerun(tmp_path, monkeypatch) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [
                    {
                        "id": "queue-3",
                        "name": "Queued Task",
                        "agent_type": "InjectionSwarm",
                        "action": "scan",
                        "state": "running",
                    }
                ],
                "completed_tasks": [],
                "context": {},
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()
    monkeypatch.setattr("builtins.input", lambda _: "n")

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    assert len(mc.task_queue) == 1
    restored_tasks = list(mc.task_queue)
    assert restored_tasks[0].state.value == "skipped"


def test_load_session_keeps_running_tasks_pending_when_prompt_errors(tmp_path, monkeypatch) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "task_queue": [
                    {
                        "id": "queue-4",
                        "name": "Queued Task",
                        "agent_type": "InjectionSwarm",
                        "action": "scan",
                        "state": "running",
                    }
                ],
                "completed_tasks": [],
                "context": {},
            }
        ),
        encoding="utf-8",
    )

    mc = _new_mc_for_load_session()

    def _raise_prompt(_: str) -> str:
        raise EOFError("non-interactive")

    monkeypatch.setattr("builtins.input", _raise_prompt)

    loaded = mc.load_session(str(session_file))

    assert loaded is True
    restored_tasks = list(mc.task_queue)
    assert restored_tasks[0].state.value == "pending"


def test_load_session_returns_false_when_file_is_missing(tmp_path) -> None:
    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(tmp_path / "missing-session.json"))

    assert loaded is False


def test_load_session_returns_false_for_non_mapping_session_payload(tmp_path) -> None:
    session_file = tmp_path / "broken-session.json"
    session_file.write_text("[", encoding="utf-8")
    mc = _new_mc_for_load_session()

    loaded = mc.load_session(str(session_file))

    assert loaded is False
