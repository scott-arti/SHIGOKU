from src.core.domain.model.task import TaskState
from src.core.engine.master_conductor_state_snapshot import restore_pending_hitl_from_session_payload
from src.core.engine.master_conductor import ExecutionContext
from src.core.engine.master_conductor_state_snapshot import (
    restore_task_queue_from_session_payload,
    restore_completed_tasks_from_session_payload,
    restore_context_from_session_payload,
)


def test_restore_pending_hitl_from_session_payload_uses_top_level_value_first() -> None:
    payload = {
        "pending_hitl": [{"ticket_id": "top", "status": "approved"}],
        "context": {"pending_hitl": [{"ticket_id": "ctx", "status": "pending"}]},
    }

    restored = restore_pending_hitl_from_session_payload(payload)

    assert restored == [{"ticket_id": "top", "status": "approved"}]


def test_restore_pending_hitl_from_session_payload_falls_back_to_context_value() -> None:
    payload = {
        "context": {"pending_hitl": [{"ticket_id": "ctx", "status": "pending"}]},
    }

    restored = restore_pending_hitl_from_session_payload(payload)

    assert restored == [{"ticket_id": "ctx", "status": "pending"}]


def test_restore_pending_hitl_from_session_payload_returns_deep_copy() -> None:
    payload = {
        "pending_hitl": [{"ticket_id": "top", "task": {"params": {"nested": {"value": 1}}}}],
    }

    restored = restore_pending_hitl_from_session_payload(payload)
    payload["pending_hitl"][0]["task"]["params"]["nested"]["value"] = 99

    assert restored[0]["task"]["params"]["nested"]["value"] == 1


def test_restore_context_from_session_payload_sets_expected_fields() -> None:
    context = ExecutionContext()
    payload = {
        "context": {
            "total_attempts": 9,
            "successful_attempts": 4,
            "bypass_methods": ["jwt_bypass"],
            "discovered_assets": ["asset.example.test"],
            "target_info": {"target": "https://example.test"},
        }
    }

    restore_context_from_session_payload(payload, context)

    assert context.total_attempts == 9
    assert context.successful_attempts == 4
    assert context.bypass_methods == ["jwt_bypass"]
    assert context.discovered_assets == ["asset.example.test"]
    assert context.target_info == {"target": "https://example.test"}


def test_restore_context_from_session_payload_defaults_missing_fields() -> None:
    context = ExecutionContext()
    context._total_attempts = 11
    context._successful_attempts = 8
    context.bypass_methods = ["old_method"]
    context.discovered_assets = ["old_asset"]
    context.target_info = {"target": "https://old.example.test"}

    restore_context_from_session_payload({"context": {}}, context)

    assert context.total_attempts == 0
    assert context.successful_attempts == 0
    assert context.bypass_methods == []
    assert context.discovered_assets == []
    assert context.target_info == {}


def test_restore_completed_tasks_from_session_payload_backfills_reason_code() -> None:
    payload = {
        "completed_tasks": [
            {
                "id": "done-1",
                "name": "Done Task",
                "state": "not_a_real_state",
                "failure_phase": "dispatch_result",
                "failure_reason": "phase2_timeout",
                "error": "Phase 2 timed out after 60s",
                "timeout_retry_count": 3,
            }
        ]
    }

    restored = restore_completed_tasks_from_session_payload(
        payload,
        normalize_failure_reason_code=lambda phase, reason, error=None: f"norm:{phase}:{reason}:{error}",
    )

    assert len(restored) == 1
    assert restored[0].state.value == "success"
    assert restored[0].failure_reason_code == "norm:dispatch_result:phase2_timeout:Phase 2 timed out after 60s"
    assert restored[0].timeout_retry_count == 3


def test_restore_completed_tasks_from_session_payload_keeps_present_reason_code() -> None:
    payload = {
        "completed_tasks": [
            {
                "id": "done-2",
                "name": "Done Task",
                "state": "failed",
                "failure_phase": "dispatch_result",
                "failure_reason": "phase2_timeout",
                "failure_reason_code": "TIMEOUT_PHASE2",
            }
        ]
    }

    restored = restore_completed_tasks_from_session_payload(
        payload,
        normalize_failure_reason_code=lambda phase, reason, error=None: "SHOULD_NOT_BE_USED",
    )

    assert len(restored) == 1
    assert restored[0].state.value == "failed"
    assert restored[0].failure_reason_code == "TIMEOUT_PHASE2"


def test_restore_task_queue_from_session_payload_defaults_running_to_pending() -> None:
    payload = {
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
        ]
    }

    restored = restore_task_queue_from_session_payload(payload, should_rerun_running=True)

    assert len(restored) == 2
    assert restored[0].state.value == "pending"
    assert restored[0].phase == "attack"
    assert restored[0].priority == 42
    assert restored[0].parent_id == "parent-queue"
    assert restored[0].replan_depth == 1
    assert restored[1].state.value == "pending"


def test_restore_task_queue_from_session_payload_marks_running_skipped_when_not_rerun() -> None:
    payload = {
        "task_queue": [
            {
                "id": "queue-3",
                "name": "Queued Task",
                "agent_type": "InjectionSwarm",
                "action": "scan",
                "state": "running",
            }
        ]
    }

    restored = restore_task_queue_from_session_payload(payload, should_rerun_running=False)

    assert len(restored) == 1
    assert restored[0].state.value == "skipped"


def test_restore_task_queue_from_session_payload_reports_invalid_state_via_callback() -> None:
    payload = {
        "task_queue": [
            {
                "id": "queue-4",
                "name": "Invalid State Task",
                "agent_type": "AuthSwarm",
                "action": "analyze",
                "state": "not_a_real_state",
            }
        ]
    }
    seen: list[str] = []

    restored = restore_task_queue_from_session_payload(
        payload,
        should_rerun_running=True,
        on_invalid_state=seen.append,
    )

    assert len(restored) == 1
    assert restored[0].state.value == "pending"
    assert seen == ["not_a_real_state"]


# ---------------------------------------------------------------------------
# Phase 1 (SGK-2026-0310): execution contract metadata in state snapshot restore
# ---------------------------------------------------------------------------

class TestStateSnapshotMetadata:
    """restore_task_queue and restore_completed_tasks must preserve metadata."""

    def test_restore_task_queue_preserves_metadata(self) -> None:
        payload = {
            "task_queue": [
                {
                    "id": "queue-meta",
                    "name": "Meta Queue Task",
                    "agent_type": "InjectionSwarm",
                    "action": "scan",
                    "state": "pending",
                    "phase": "attack",
                    "params": {"target": "https://example.test"},
                    "priority": 42,
                    "parent_id": "parent-queue",
                    "replan_depth": 1,
                    "metadata": {
                        "target_key": "https://example.test",
                        "origin_key": "recon://scenario-1",
                        "lifecycle_status": "admitted",
                    },
                }
            ]
        }

        restored = restore_task_queue_from_session_payload(payload, should_rerun_running=True)

        assert len(restored) == 1
        assert restored[0].id == "queue-meta"
        assert restored[0].metadata["target_key"] == "https://example.test"
        assert restored[0].metadata["origin_key"] == "recon://scenario-1"
        assert restored[0].metadata["lifecycle_status"] == "admitted"

    def test_restore_task_queue_without_metadata_defaults_to_empty(self) -> None:
        """Legacy session payload without metadata field must default to empty metadata."""
        payload = {
            "task_queue": [
                {
                    "id": "queue-old",
                    "name": "Old Queue Task",
                    "agent_type": "Recon",
                    "action": "scan",
                    "state": "pending",
                }
            ]
        }

        restored = restore_task_queue_from_session_payload(payload, should_rerun_running=True)

        assert len(restored) == 1
        assert restored[0].id == "queue-old"
        assert restored[0].metadata == {}

    def test_restore_completed_tasks_preserves_metadata(self) -> None:
        payload = {
            "completed_tasks": [
                {
                    "id": "done-meta",
                    "name": "Meta Done Task",
                    "state": "success",
                    "metadata": {
                        "target_key": "https://example.test",
                        "correlation_id": "corr-abc",
                        "evidence_key": "ev-123",
                    },
                }
            ]
        }

        restored = restore_completed_tasks_from_session_payload(
            payload,
            normalize_failure_reason_code=lambda phase, reason, error=None: "unused",
        )

        assert len(restored) == 1
        assert restored[0].id == "done-meta"
        assert restored[0].metadata["target_key"] == "https://example.test"
        assert restored[0].metadata["correlation_id"] == "corr-abc"
        assert restored[0].metadata["evidence_key"] == "ev-123"

    def test_restore_completed_tasks_without_metadata_defaults_to_empty(self) -> None:
        """Legacy completed task without metadata field must default to empty metadata."""
        payload = {
            "completed_tasks": [
                {
                    "id": "done-old",
                    "name": "Old Done Task",
                    "state": "success",
                }
            ]
        }

        restored = restore_completed_tasks_from_session_payload(
            payload,
            normalize_failure_reason_code=lambda phase, reason, error=None: "unused",
        )

        assert len(restored) == 1
        assert restored[0].id == "done-old"
        assert restored[0].metadata == {}

    def test_unknown_lifecycle_metadata_does_not_affect_state_restoration(self) -> None:
        """lifecycle_status in metadata must not change restored TaskState."""
        payload = {
            "task_queue": [
                {
                    "id": "queue-lifecycle",
                    "name": "Lifecycle Task",
                    "agent_type": "Recon",
                    "action": "scan",
                    "state": "pending",
                    "metadata": {
                        "lifecycle_status": "invalidated",
                        "invalidated_by": "recon_update_123",
                    },
                }
            ]
        }

        restored = restore_task_queue_from_session_payload(payload, should_rerun_running=True)

        assert restored[0].state == TaskState.PENDING
        assert restored[0].metadata["lifecycle_status"] == "invalidated"

    def test_state_snapshot_redacts_secrets(self) -> None:
        """F-1: cookie/token in session payload metadata must be [REDACTED] after restore."""
        payload = {
            "task_queue": [
                {
                    "id": "queue-secret",
                    "name": "Secret Task",
                    "agent_type": "Recon",
                    "action": "scan",
                    "state": "pending",
                    "metadata": {
                        "cookie": "session=abc123; secret=xyz",
                        "token": "Bearer eyJhbGciOiJIUzI1NiJ9.xxx",
                        "api_key": "sk-1234567890abcdef",
                        "password": "supersecret",
                        "Authorization": "Basic dXNlcjpwYXNz",
                        "session_id": "sess-001",
                        "target_key": "https://example.test",
                        "origin_key": "https://example.com",
                    },
                }
            ]
        }

        restored = restore_task_queue_from_session_payload(payload, should_rerun_running=True)

        assert len(restored) == 1
        restored_meta = restored[0].metadata

        # Secret-bearing keys must be redacted
        for secret_key in ("cookie", "token", "api_key", "password", "Authorization", "session_id"):
            assert restored_meta.get(secret_key) == "[REDACTED]", (
                f"Secret key '{secret_key}' was not redacted: {restored_meta.get(secret_key)!r}"
            )

        # Non-secret keys must be preserved
        assert restored_meta.get("target_key") == "https://example.test"
        assert restored_meta.get("origin_key") == "https://example.com"

    def test_state_snapshot_redacts_secrets_in_completed_tasks(self) -> None:
        """F-1: completed_tasks restore also redacts secrets at the boundary."""
        payload = {
            "completed_tasks": [
                {
                    "id": "done-secret",
                    "name": "Secret Done Task",
                    "state": "success",
                    "metadata": {
                        "cookie": "session=hackme",
                        "token": "Bearer secret123",
                        "Set-Cookie": "auth=realvalue",
                        "target_key": "https://example.test",
                    },
                }
            ]
        }

        restored = restore_completed_tasks_from_session_payload(
            payload,
            normalize_failure_reason_code=lambda phase, reason, error=None: "unused",
        )

        assert len(restored) == 1
        restored_meta = restored[0].metadata

        assert restored_meta.get("cookie") == "[REDACTED]"
        assert restored_meta.get("token") == "[REDACTED]"
        assert restored_meta.get("Set-Cookie") == "[REDACTED]"
        assert restored_meta.get("target_key") == "https://example.test"
