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
