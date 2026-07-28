import json
from pathlib import Path
from types import SimpleNamespace
from datetime import datetime

from src.core.engine.master_conductor_session_service import (
    build_start_session_payload,
    build_checkpoint_session_state,
    load_session_payload_from_path,
    await_session_save_future,
    resolve_running_task_resume_policy,
    restore_legacy_resume_session_state,
    serialize_legacy_session_task_queue,
    deserialize_legacy_session_task_queue,
    build_async_session_payload,
)
from src.core.domain.model.task import Task, TaskState
from src.core.session.session_manager import Session


def test_resolve_running_task_resume_policy_returns_false_for_explicit_no() -> None:
    policy = resolve_running_task_resume_policy(
        running_count=2,
        prompt_for_resume=lambda _: "n",
    )

    assert policy is False


def test_resolve_running_task_resume_policy_returns_true_when_prompt_errors() -> None:
    def _raise_prompt(_: str) -> str:
        raise EOFError("non-interactive")

    policy = resolve_running_task_resume_policy(
        running_count=2,
        prompt_for_resume=_raise_prompt,
    )

    assert policy is True


def test_resolve_running_task_resume_policy_returns_true_when_no_running_tasks() -> None:
    called: list[str] = []

    policy = resolve_running_task_resume_policy(
        running_count=0,
        prompt_for_resume=lambda prompt: called.append(prompt) or "n",
    )

    assert policy is True
    assert called == []


def test_load_session_payload_from_path_returns_none_for_missing_file(tmp_path) -> None:
    payload = load_session_payload_from_path(str(tmp_path / "missing-session.json"))

    assert payload is None


def test_load_session_payload_from_path_returns_parsed_payload(tmp_path) -> None:
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"task_queue": [], "context": {}}), encoding="utf-8")

    payload = load_session_payload_from_path(str(session_file))

    assert payload == {"task_queue": [], "context": {}}


def test_load_session_payload_from_path_returns_repaired_non_mapping_payload(tmp_path) -> None:
    session_file = tmp_path / "broken-session.json"
    session_file.write_text("[", encoding="utf-8")

    payload = load_session_payload_from_path(str(session_file))

    assert payload == []


def test_build_start_session_payload_sanitizes_project_name_and_preserves_context() -> None:
    payload = build_start_session_payload(
        target="https://example.com/path/to/deeply/nested/resource",
        mode="bugbounty",
        context_target_info={"target": "https://example.com", "program": "Example"},
    )

    assert payload == {
        "project_name": "example.com_path_to_deeply_nested_resource",
        "mode": "bugbounty",
        "target_url": "https://example.com/path/to/deeply/nested/resource",
        "metadata": {
            "context": {"target": "https://example.com", "program": "Example"},
        },
    }


def test_await_session_save_future_waits_with_timeout() -> None:
    class FakeFuture:
        def __init__(self) -> None:
            self.timeout = None

        def result(self, timeout=None):
            self.timeout = timeout
            return "done"

    future = FakeFuture()

    await_session_save_future(future)

    assert future.timeout == 15


def test_await_session_save_future_ignores_none() -> None:
    await_session_save_future(None)


def test_build_checkpoint_session_state_serializes_pending_completed_and_metadata() -> None:
    pending_task = Task(
        id="pending-1",
        name="Pending Task",
        agent_type="Recon",
        action="scan",
        params={"target": "https://example.test"},
        priority=10,
        parent_id="parent-1",
    )
    completed_task = Task(
        id="done-1",
        name="Done Task",
        agent_type="Auth",
        action="verify",
        state=TaskState.SUCCESS,
    )
    context = SimpleNamespace(
        target_info={"target": "https://example.test"},
        success_rate=0.75,
        total_attempts=4,
        successful_attempts=3,
        discovered_assets=["example.test"],
        bypass_methods=["jwt_bypass"],
        current_attack_chain=["recon", "auth"],
    )
    pending_hitl = [{"ticket_id": "ticket-1", "task": {"id": "pending-1"}}]

    pending_targets, completed_targets, metadata = build_checkpoint_session_state(
        task_queue=[pending_task],
        completed_tasks=[completed_task],
        context=context,
        pending_hitl=pending_hitl,
    )

    assert pending_targets == [
        json.dumps(
            {
                "id": "pending-1",
                "name": "Pending Task",
                "agent_type": "Recon",
                "target": "",
                "action": "scan",
                "params": {"target": "https://example.test"},
                "state": "pending",
                "priority": 10,
                "replan_depth": 0,
                "result": None,
                "error": None,
                "tags": [],
                "is_aggressive": False,
                "depends_on_task_ids": [],
                "supersedes_task_ids": [],
                "invalidated_by_event": None,
                "metadata": {},
            },
            ensure_ascii=False,
        )
    ]
    assert completed_targets == ["done-1"]
    assert metadata == {
        "context": {"target": "https://example.test"},
        "success_rate": 0.75,
        "total_attempts": 4,
        "successful_attempts": 3,
        "discovered_assets": ["example.test"],
        "bypass_methods": ["jwt_bypass"],
        "attack_chain": ["recon", "auth"],
        "pending_hitl": [{"ticket_id": "ticket-1", "task": {"id": "pending-1"}}],
    }


def test_build_checkpoint_session_state_deep_copies_pending_hitl() -> None:
    context = SimpleNamespace(
        target_info={},
        success_rate=0.0,
        total_attempts=0,
        successful_attempts=0,
        discovered_assets=[],
        bypass_methods=[],
        current_attack_chain=[],
    )
    pending_hitl = [{"ticket_id": "ticket-1", "task": {"params": {"nested": {"value": 1}}}}]

    _, _, metadata = build_checkpoint_session_state(
        task_queue=[],
        completed_tasks=[],
        context=context,
        pending_hitl=pending_hitl,
    )

    pending_hitl[0]["task"]["params"]["nested"]["value"] = 99

    assert metadata["pending_hitl"][0]["task"]["params"]["nested"]["value"] == 1


def test_serialize_legacy_session_task_queue_preserves_existing_schema() -> None:
    pending_task = Task(
        id="pending-1",
        name="Pending Task",
        agent_type="Recon",
        action="scan",
        params={"target": "https://example.test"},
        priority=10,
        parent_id="parent-1",
    )

    serialized = serialize_legacy_session_task_queue([pending_task])

    assert serialized == [
        json.dumps(
            {
                "id": "pending-1",
                "name": "Pending Task",
                "agent_type": "Recon",
                "target": "",
                "action": "scan",
                "params": {"target": "https://example.test"},
                "state": "pending",
                "priority": 10,
                "replan_depth": 0,
                "result": None,
                "error": None,
                "tags": [],
                "is_aggressive": False,
                "depends_on_task_ids": [],
                "supersedes_task_ids": [],
                "invalidated_by_event": None,
                "metadata": {},
            },
            ensure_ascii=False,
        )
    ]


def test_restore_legacy_resume_session_state_restores_context_pending_hitl_and_queue() -> None:
    session = Session(
        session_id="sess-1",
        project_name="example",
        mode="ctf",
        target_url="https://target.example.com",
        created_at=datetime.now(),
        last_updated=datetime.now(),
        pending_targets=[
            json.dumps(
                {
                    "id": "task-1",
                    "name": "Task 1",
                    "agent_type": "Recon",
                    "action": "scan",
                    "params": {"target": "https://target.example.com"},
                    "priority": 5,
                    "parent_id": "parent-1",
                },
                ensure_ascii=False,
            )
        ],
        metadata={
            "context": {"target": "https://target.example.com"},
            "total_attempts": 4,
            "successful_attempts": 3,
            "discovered_assets": ["asset1.example.com"],
            "bypass_methods": ["jwt_bypass"],
            "attack_chain": ["recon", "auth"],
            "pending_hitl": [{"ticket_id": "ticket-1", "task": {"params": {"nested": {"value": 1}}}}],
        },
    )

    restored = restore_legacy_resume_session_state(session)

    assert restored["context_target_info"] == {"target": "https://target.example.com"}
    assert restored["total_attempts"] == 4
    assert restored["successful_attempts"] == 3
    assert restored["discovered_assets"] == ["asset1.example.com"]
    assert restored["bypass_methods"] == ["jwt_bypass"]
    assert restored["attack_chain"] == ["recon", "auth"]
    assert restored["pending_hitl"] == [{"ticket_id": "ticket-1", "task": {"params": {"nested": {"value": 1}}}}]
    assert len(restored["task_queue"]) == 1
    assert restored["task_queue"][0].id == "task-1"
    assert restored["task_queue"][0].parent_id == "parent-1"
    assert restored["failed_task_deserializations"] == []


def test_restore_legacy_resume_session_state_tracks_failed_task_deserializations() -> None:
    session = Session(
        session_id="sess-1",
        project_name="example",
        mode="ctf",
        target_url="https://target.example.com",
        created_at=datetime.now(),
        last_updated=datetime.now(),
        pending_targets=["{"],
        metadata={},
    )

    restored = restore_legacy_resume_session_state(session)

    assert restored["task_queue"] == []
    assert restored["failed_task_deserializations"] == ["{"]
    assert restored["pending_hitl"] == []


# ---------------------------------------------------------------------------
# Phase 1 (SGK-2026-0310): execution contract metadata in legacy checkpoint
# ---------------------------------------------------------------------------

class TestLegacyCheckpointMetadata:
    """serialize/deserialize legacy checkpoint must preserve Task metadata."""

    def test_serialize_legacy_task_queue_includes_metadata(self) -> None:
        task = Task(
            id="meta-1",
            name="Meta Task",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            priority=10,
            parent_id="parent-1",
            metadata={
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "schema_version": 1,
            },
        )

        serialized = serialize_legacy_session_task_queue([task])

        assert len(serialized) == 1
        d = json.loads(serialized[0])
        assert d["id"] == "meta-1"
        assert "metadata" in d
        assert d["metadata"]["target_key"] == "https://example.test"
        assert d["metadata"]["origin_key"] == "recon://scenario-1"

    def test_serialize_legacy_task_queue_without_metadata_produces_empty(self) -> None:
        task = Task(
            id="no-meta",
            name="No Meta Task",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            priority=5,
            parent_id="parent-1",
        )

        serialized = serialize_legacy_session_task_queue([task])

        d = json.loads(serialized[0])
        assert d["metadata"] == {}

    def test_deserialize_legacy_task_queue_restores_metadata(self) -> None:
        serialized = [
            json.dumps(
                {
                    "id": "meta-2",
                    "name": "Meta Task 2",
                    "agent_type": "Recon",
                    "action": "scan",
                    "params": {"target": "https://example.test"},
                    "priority": 5,
                    "parent_id": "parent-1",
                    "metadata": {
                        "target_key": "https://example.test",
                        "correlation_id": "corr-xyz",
                        "lifecycle_status": "admitted",
                    },
                },
                ensure_ascii=False,
            )
        ]

        tasks, failed = deserialize_legacy_session_task_queue(serialized)

        assert len(tasks) == 1
        assert failed == []
        assert tasks[0].id == "meta-2"
        assert tasks[0].metadata["target_key"] == "https://example.test"
        assert tasks[0].metadata["correlation_id"] == "corr-xyz"
        assert tasks[0].metadata["lifecycle_status"] == "admitted"

    def test_deserialize_legacy_task_queue_without_metadata_defaults_to_empty(self) -> None:
        """Legacy JSON without metadata field must deserialize with empty metadata."""
        serialized = [
            json.dumps(
                {
                    "id": "old-task",
                    "name": "Old Task",
                    "agent_type": "Recon",
                    "action": "scan",
                },
                ensure_ascii=False,
            )
        ]

        tasks, failed = deserialize_legacy_session_task_queue(serialized)

        assert len(tasks) == 1
        assert failed == []
        assert tasks[0].id == "old-task"
        assert tasks[0].metadata == {}

    def test_roundtrip_legacy_checkpoint_preserves_metadata(self) -> None:
        original = Task(
            id="meta-rt",
            name="Roundtrip Task",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            priority=10,
            parent_id="parent-1",
            metadata={
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "lifecycle_status": "admitted",
                "lifecycle_reason": "scope_verified",
            },
        )

        serialized = serialize_legacy_session_task_queue([original])
        restored, failed = deserialize_legacy_session_task_queue(serialized)

        assert failed == []
        assert restored[0].id == original.id
        assert restored[0].name == original.name
        # Metadata preserved (schema_version auto-injected by to_dict)
        for key in original.metadata:
            assert restored[0].metadata[key] == original.metadata[key]

    def test_legacy_checkpoint_redacts_secrets(self) -> None:
        """F-1: cookie/token in metadata must be [REDACTED] after legacy checkpoint roundtrip."""
        original = Task(
            id="secret-rt",
            name="Secret Roundtrip",
            agent_type="Recon",
            action="scan",
            params={"target": "https://example.test"},
            metadata={
                "cookie": "session=abc123; secret=xyz",
                "token": "Bearer eyJhbGciOiJIUzI1NiJ9.xxx",
                "api_key": "sk-1234567890abcdef",
                "password": "supersecret",
                "Authorization": "Basic dXNlcjpwYXNz",
                "session_id": "sess-001",
                "target_key": "https://example.test",
                "origin_key": "https://example.com",
            },
        )

        serialized = serialize_legacy_session_task_queue([original])
        restored, failed = deserialize_legacy_session_task_queue(serialized)

        assert failed == []
        restored_meta = restored[0].metadata

        # Secret-bearing keys must be redacted
        for secret_key in ("cookie", "token", "api_key", "password", "Authorization", "session_id"):
            assert restored_meta.get(secret_key) == "[REDACTED]", (
                f"Secret key '{secret_key}' was not redacted: {restored_meta.get(secret_key)!r}"
            )

        # Non-secret keys must be preserved
        assert restored_meta.get("target_key") == "https://example.test"
        assert restored_meta.get("origin_key") == "https://example.com"

    def test_legacy_checkpoint_redacts_secrets_in_session_dict(self) -> None:
        """F-1: serialized JSON string must contain [REDACTED] not raw secrets."""
        original = Task(
            id="secret-json",
            name="Secret JSON",
            agent_type="Recon",
            action="scan",
            metadata={
                "cookie": "session=topsecret",
                "token": "Bearer xyz",
                "target_key": "https://example.test",
            },
        )

        serialized = serialize_legacy_session_task_queue([original])
        raw_json = serialized[0]

        # Raw JSON string must NOT contain the original secrets
        assert "topsecret" not in raw_json
        assert "Bearer xyz" not in raw_json
        # Raw JSON must contain [REDACTED]
        assert "[REDACTED]" in raw_json


# ===========================================================================
# SGK-2026-0293: Additive review fields in build_async_session_payload
# ===========================================================================

def _build_context() -> SimpleNamespace:
    ctx = SimpleNamespace()
    ctx._total_attempts = 3
    ctx._successful_attempts = 2
    ctx.bypass_methods = ["jwt_bypass"]
    ctx.discovered_assets = [{"url": "https://example.test", "type": "page"}]
    ctx.target_info = {"url": "https://example.test", "domain": "example.test"}
    ctx.success_rate = 0.67
    ctx.total_attempts = 3
    ctx.current_attack_chain = []
    return ctx


def test_build_async_session_payload_stores_session_id_and_run_id() -> None:
    """session_id and run_id passed to builder must appear in the payload root."""
    payload = build_async_session_payload(
        task_queue=[],
        completed_tasks=[],
        context=_build_context(),
        pending_hitl=[],
        coverage_gate={},
        scenario_coverage={},
        timestamp=100.0,
        default_start_time=100.0,
        session_id="sess-abc-123",
        run_id="run-xyz-456",
    )

    assert payload.get("session_id") == "sess-abc-123"
    assert payload.get("run_id") == "run-xyz-456"


def test_build_async_session_payload_preserves_existing_fields() -> None:
    """New fields must not remove or rename any existing top-level keys."""
    task = Task(
        id="task-1", name="Test", agent_type="Recon", action="scan",
        params={"target": "https://example.test"}, priority=10,
        parent_id="parent-1",
    )
    task_comp = Task(
        id="task-2", name="Done", agent_type="Auth", action="verify",
        state=TaskState.SUCCESS, params={}, priority=5,
    )
    ctx = _build_context()

    payload = build_async_session_payload(
        task_queue=[task],
        completed_tasks=[task_comp],
        context=ctx,
        pending_hitl=[],
        coverage_gate={"missing_families": ["xss"]},
        scenario_coverage={"missing_scenarios": ["scn_01"]},
        timestamp=101.0,
        default_start_time=100.0,
        decision_traces=[{"decision_id": "d1", "action": "skip"}],
        task_execution_records=[{"task_id": "task-1", "result": "success"}],
        run_ledger_payload={
            "run_ledger_schema_version": 1,
            "run_ledger": [{"event_id": "e1"}],
            "llm_usage_summary": {"total_tokens": 100},
            "spool_path": "/tmp/spool",
            "spool_sha256": "abc123",
            "spool_event_count": 1,
        },
        session_id="sess-1",
        run_id="run-1",
    )

    # Mandatory existing root keys
    for key in ("task_queue", "completed_tasks", "context", "coverage_gate",
                 "scenario_coverage", "pending_hitl", "start_time", "timestamp",
                 "adjacency_list"):
        assert key in payload, f"Missing required legacy key: {key}"

    # S1 ledger fields
    assert payload.get("decision_traces") == [{"decision_id": "d1", "action": "skip"}]
    assert payload.get("task_execution_records") == [{"task_id": "task-1", "result": "success"}]
    assert payload.get("run_ledger") == [{"event_id": "e1"}]
    assert payload.get("llm_usage_summary") == {"total_tokens": 100}
    assert payload.get("spool_sha256") == "abc123"
    assert payload.get("spool_event_count") == 1


def test_build_async_session_payload_includes_additive_review_fields() -> None:
    """When target_system_profile/attack_review_trail/scenario_candidates are passed,
    they must appear in the payload root."""
    payload = build_async_session_payload(
        task_queue=[],
        completed_tasks=[],
        context=_build_context(),
        pending_hitl=[],
        coverage_gate={},
        scenario_coverage={},
        timestamp=102.0,
        default_start_time=100.0,
        session_id="sess-2",
        run_id="run-2",
        target_system_profile={
            "schema_version": 1,
            "target_host": "example.test",
            "auth_methods": ["JWT"],
        },
        attack_review_trail={
            "schema_version": 1,
            "entries": [{"trail_id": "t1", "phase": "recon", "observation": "page found"}],
        },
        scenario_candidates=[
            {"candidate_id": "c1", "title": "Test scenario", "risk_level": "medium"},
        ],
    )

    assert payload.get("target_system_profile") == {
        "schema_version": 1, "target_host": "example.test", "auth_methods": ["JWT"],
    }
    assert payload.get("attack_review_trail") == {
        "schema_version": 1,
        "entries": [{"trail_id": "t1", "phase": "recon", "observation": "page found"}],
    }
    assert payload.get("scenario_candidates") == [
        {"candidate_id": "c1", "title": "Test scenario", "risk_level": "medium"},
    ]


def test_build_async_session_payload_backward_compatible_without_new_args() -> None:
    """Callers that omit session_id, run_id, and additive review fields must not crash."""
    payload = build_async_session_payload(
        task_queue=[],
        completed_tasks=[],
        context=_build_context(),
        pending_hitl=[],
        coverage_gate={},
        scenario_coverage={},
        timestamp=103.0,
        default_start_time=100.0,
    )

    # Old callers still work
    assert "task_queue" in payload
    assert "completed_tasks" in payload
    # New fields default when not provided
    assert payload.get("session_id") is None
    assert payload.get("run_id") is None
    # target_system_profile is auto-generated from context (target_info present)
    assert payload.get("target_system_profile") is not None
    assert payload.get("target_system_profile")["schema_version"] == 1
    # No execution data → trail/candidates remain None
    assert payload.get("attack_review_trail") is None
    assert payload.get("scenario_candidates") is None


def test_build_async_session_payload_auto_builds_review_fields() -> None:
    """When review fields are not explicitly passed, they are auto-built from session data."""
    task = Task(
        id="task-1", name="Test", agent_type="Recon", action="scan",
        params={"target": "https://example.test"}, priority=10,
        parent_id="parent-1",
    )
    task_comp = Task(
        id="task-2", name="Done", agent_type="Auth", action="verify",
        state=TaskState.SUCCESS, params={}, priority=5,
    )
    ctx = _build_context()

    payload = build_async_session_payload(
        task_queue=[task],
        completed_tasks=[task_comp],
        context=ctx,
        pending_hitl=[],
        coverage_gate={"missing_families": ["xss"]},
        scenario_coverage={"missing_scenarios": ["scn_01"]},
        timestamp=101.0,
        default_start_time=100.0,
        decision_traces=[{"decision_id": "d1", "action": "skip", "phase": "recon",
                           "observation": "page found", "rationale": "worth skipping"}],
        task_execution_records=[{"task_id": "task-1", "result": "success",
                                  "phase": "execution", "summary": "task completed"}],
        run_ledger_payload={
            "run_ledger_schema_version": 1,
            "run_ledger": [{"event_id": "e1", "action": "scan"}],
            "llm_usage_summary": {"total_tokens": 100},
            "spool_path": "/tmp/spool",
            "spool_sha256": "abc123",
            "spool_event_count": 1,
        },
        session_id="sess-1",
        run_id="run-1",
    )

    # Auto-generated target_system_profile must not be None
    target_profile = payload.get("target_system_profile")
    assert target_profile is not None, "target_system_profile should be auto-generated"
    assert target_profile.get("session_id") == "sess-1"
    assert target_profile.get("run_id") == "run-1"

    # Auto-generated attack_review_trail must not be None
    review_trail = payload.get("attack_review_trail")
    assert review_trail is not None, "attack_review_trail should be auto-generated"
    assert review_trail.get("session_id") == "sess-1"
    assert review_trail.get("run_id") == "run-1"
    assert len(review_trail.get("entries", [])) > 0

    # Auto-generated scenario_candidates must not be None
    candidates = payload.get("scenario_candidates")
    assert candidates is not None, "scenario_candidates should be auto-generated"
    assert len(candidates) > 0
    assert candidates[0].get("session_id") == "sess-1"
    assert candidates[0].get("run_id") == "run-1"

    # Explicit values take precedence over auto-generated ones
    explicit_profile = {"schema_version": 1, "explicit": True}
    explicit_trail = {"schema_version": 1, "entries": []}
    explicit_candidates = [{"candidate_id": "explicit-1"}]

    payload2 = build_async_session_payload(
        task_queue=[task],
        completed_tasks=[task_comp],
        context=ctx,
        pending_hitl=[],
        coverage_gate={"missing_families": []},
        scenario_coverage={"missing_scenarios": []},
        timestamp=102.0,
        default_start_time=100.0,
        decision_traces=[],
        task_execution_records=[],
        session_id="sess-2",
        run_id="run-2",
        target_system_profile=explicit_profile,
        attack_review_trail=explicit_trail,
        scenario_candidates=explicit_candidates,
    )

    assert payload2["target_system_profile"] is explicit_profile
    assert payload2["attack_review_trail"] is explicit_trail
    assert payload2["scenario_candidates"] is explicit_candidates
