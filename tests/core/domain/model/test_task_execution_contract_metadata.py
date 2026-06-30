"""
TDD tests for Phase 1: additive execution contract metadata on Task.

Plan reference: SGK-2026-0310 Section 6.8 TDD Checklist
"""

import pytest
from src.core.domain.model.task import Task, TaskState


# ---------------------------------------------------------------------------
# 6.8-1: metadata 未指定 Task が従来通り動作する
# ---------------------------------------------------------------------------

class TestLegacyTaskWithoutMetadata:
    """Task without metadata must behave identically to pre-Phase-1."""

    def test_to_dict_without_metadata_preserves_all_existing_fields(self) -> None:
        task = Task(
            id="task-1",
            name="Test Task",
            agent_type="Recon",
            action="scan",
            phase="init",
            params={"target": "https://example.test"},
            target="https://example.test",
            state=TaskState.PENDING,
            priority=5,
            parent_id="parent-1",
            replan_depth=0,
            tags=["tag-a"],
            is_aggressive=False,
        )

        d = task.to_dict()

        assert d["id"] == "task-1"
        assert d["name"] == "Test Task"
        assert d["agent_type"] == "Recon"
        assert d["action"] == "scan"
        # phase is NOT currently in to_dict() output
        assert "phase" not in d


    def test_to_dict_without_metadata_preserves_existing_fields_exactly(self) -> None:
        """Legacy Task.to_dict() output must not change when metadata is absent."""
        task = Task(
            id="task-1",
            name="Test Task",
            agent_type="Recon",
            action="scan",
            target="https://example.test",
            params={"target": "https://example.test"},
            state=TaskState.PENDING,
            priority=5,
            replan_depth=1,
            tags=["tag-a"],
            is_aggressive=False,
        )

        d = task.to_dict()

        # All existing fields must be present and unchanged
        assert d["id"] == "task-1"
        assert d["name"] == "Test Task"
        assert d["agent_type"] == "Recon"
        assert d["action"] == "scan"
        assert d["target"] == "https://example.test"
        assert d["params"] == {"target": "https://example.test"}
        assert d["state"] == "pending"
        assert d["priority"] == 5
        assert d["replan_depth"] == 1
        assert d["result"] is None
        assert d["error"] is None
        assert d["tags"] == ["tag-a"]
        assert d["is_aggressive"] is False

        # Phase 1: empty metadata dict is always present (additive)
        # All existing fields must still be present and unchanged
        # metadata key is the only new addition
        expected_keys = {
            "id", "name", "agent_type", "target", "action", "params",
            "state", "priority", "replan_depth", "result", "error",
            "tags", "is_aggressive", "metadata",
        }
        assert set(d.keys()) == expected_keys, f"Unexpected keys: {set(d.keys()) - expected_keys}"
        assert d["metadata"] == {}


    def test_task_instantiation_without_metadata_is_valid(self) -> None:
        """Creating a Task without metadata must not raise."""
        task = Task(id="task-1", name="Test Task")
        assert task.id == "task-1"
        assert task.name == "Test Task"
        # metadata should default to empty dict
        assert hasattr(task, "metadata")
        assert task.metadata == {}


# ---------------------------------------------------------------------------
# 6.8-2: metadata 指定時 Task.to_dict() の deep copy / 内部状態保護
# ---------------------------------------------------------------------------

class TestTaskWithMetadata:
    """Task with execution contract metadata must serialize and protect state."""

    def test_to_dict_includes_metadata_when_present(self) -> None:
        task = Task(
            id="task-1",
            name="Test Task",
            metadata={
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "canonical_endpoint_key": "https://example.test/api",
                "schema_version": 1,
                "correlation_id": "corr-abc",
                "lifecycle_status": "admitted",
                "auth_context_version": "v2",
                "recon_snapshot_version": "snap-42",
            },
        )

        d = task.to_dict()

        assert "metadata" in d
        assert d["metadata"]["target_key"] == "https://example.test"
        assert d["metadata"]["origin_key"] == "recon://scenario-1"
        assert d["metadata"]["canonical_endpoint_key"] == "https://example.test/api"
        assert d["metadata"]["schema_version"] == 1
        assert d["metadata"]["correlation_id"] == "corr-abc"
        assert d["metadata"]["lifecycle_status"] == "admitted"
        assert d["metadata"]["auth_context_version"] == "v2"
        assert d["metadata"]["recon_snapshot_version"] == "snap-42"

    def test_to_dict_metadata_is_deep_copied(self) -> None:
        """Mutating the returned metadata dict must not affect the Task."""
        task = Task(
            id="task-1",
            name="Test Task",
            metadata={"target_key": "original"},
        )

        d = task.to_dict()
        d["metadata"]["target_key"] = "mutated"
        d["metadata"]["extra_field"] = "should not persist"

        assert task.metadata["target_key"] == "original"
        assert "extra_field" not in task.metadata

    def test_to_dict_metadata_is_deep_copied_nested(self) -> None:
        """Mutating nested values in the returned metadata must not affect the Task."""
        task = Task(
            id="task-1",
            name="Test Task",
            metadata={"nested": {"value": 1, "list": [1, 2, 3]}},
        )

        d = task.to_dict()
        d["metadata"]["nested"]["value"] = 99
        d["metadata"]["nested"]["list"].append(4)

        assert task.metadata["nested"]["value"] == 1
        assert task.metadata["nested"]["list"] == [1, 2, 3]

    def test_metadata_mutation_on_task_does_not_affect_previous_to_dict_output(self) -> None:
        """Mutating task.metadata after to_dict() must not affect previously returned dict."""
        task = Task(
            id="task-1",
            name="Test Task",
            metadata={"target_key": "original"},
        )

        d1 = task.to_dict()
        task.metadata["target_key"] = "changed"
        d2 = task.to_dict()

        assert d1["metadata"]["target_key"] == "original"
        assert d2["metadata"]["target_key"] == "changed"

    def test_empty_metadata_is_serialized_as_empty_dict(self) -> None:
        """Task with empty metadata dict must output empty dict in to_dict."""
        task = Task(id="task-1", name="Test Task", metadata={})

        d = task.to_dict()

        assert "metadata" in d
        assert d["metadata"] == {}


# ---------------------------------------------------------------------------
# 6.8-2b: from_dict() の backward compatibility
# ---------------------------------------------------------------------------

class TestTaskFromDict:
    """Task.from_dict() must handle metadata present, absent, and partial."""

    def test_from_dict_with_metadata_restores_all_fields(self) -> None:
        d = {
            "id": "task-1",
            "name": "Test Task",
            "agent_type": "Recon",
            "action": "scan",
            "target": "https://example.test",
            "params": {"x": 1},
            "state": "pending",
            "priority": 5,
            "replan_depth": 2,
            "metadata": {
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "schema_version": 1,
                "lifecycle_status": "admitted",
            },
        }

        task = Task.from_dict(d)

        assert task.id == "task-1"
        assert task.name == "Test Task"
        assert task.agent_type == "Recon"
        assert task.metadata["target_key"] == "https://example.test"
        assert task.metadata["origin_key"] == "recon://scenario-1"
        assert task.metadata["schema_version"] == 1
        assert task.metadata["lifecycle_status"] == "admitted"

    def test_from_dict_without_metadata_defaults_to_empty_dict(self) -> None:
        d = {
            "id": "task-2",
            "name": "Legacy Task",
            "agent_type": "Recon",
            "action": "scan",
            "state": "pending",
        }

        task = Task.from_dict(d)

        assert task.id == "task-2"
        assert task.name == "Legacy Task"
        assert task.metadata == {}

    def test_from_dict_roundtrip_preserves_metadata(self) -> None:
        """Task -> to_dict -> from_dict must preserve metadata (schema_version auto-injected)."""
        original = Task(
            id="task-3",
            name="Roundtrip Task",
            metadata={
                "target_key": "https://example.test",
                "origin_key": "recon://scenario-1",
                "correlation_id": "corr-abc",
                "lifecycle_status": "admitted",
                "lifecycle_reason": "scope_verified",
            },
        )

        d = original.to_dict()
        restored = Task.from_dict(d)

        # to_dict auto-injects schema_version when metadata is non-empty
        assert restored.id == original.id
        assert restored.name == original.name
        for key in original.metadata:
            assert restored.metadata[key] == original.metadata[key]
        # schema_version is auto-injected by to_dict()
        assert restored.metadata["schema_version"] == 1

    def test_from_dict_with_partial_metadata_fields(self) -> None:
        """from_dict with only some metadata fields must preserve them."""
        d = {
            "id": "task-4",
            "name": "Partial Metadata Task",
            "agent_type": "Recon",
            "metadata": {
                "target_key": "https://example.test",
                # origin_key intentionally missing
            },
        }

        task = Task.from_dict(d)

        assert task.metadata == {"target_key": "https://example.test"}
        assert "origin_key" not in task.metadata


# ---------------------------------------------------------------------------
# 6.8-4b: lifecycle metadata が TaskState と衝突しない
# ---------------------------------------------------------------------------

class TestLifecycleMetadataTaskStateNonInterference:
    """lifecycle_status/reason must NOT affect TaskState enum or state aggregation."""

    def test_lifecycle_status_in_metadata_does_not_change_task_state(self) -> None:
        task = Task(
            id="task-lifecycle",
            name="Lifecycle Task",
            state=TaskState.PENDING,
            metadata={
                "lifecycle_status": "waiting_dependency",
                "lifecycle_reason": "awaiting_recon",
            },
        )

        d = task.to_dict()

        assert d["state"] == "pending"
        assert task.state == TaskState.PENDING

    def test_lifecycle_status_admitted_does_not_change_state(self) -> None:
        task = Task(
            id="task-lifecycle-2",
            name="Admitted Task",
            state=TaskState.PENDING,
            metadata={"lifecycle_status": "admitted"},
        )

        assert task.state == TaskState.PENDING

    def test_lifecycle_status_invalidated_does_not_change_state(self) -> None:
        task = Task(
            id="task-lifecycle-3",
            name="Invalidated Task",
            state=TaskState.PENDING,
            metadata={
                "lifecycle_status": "invalidated",
                "invalidated_by": "recon_update_123",
            },
        )

        assert task.state == TaskState.PENDING
        d = task.to_dict()
        assert d["state"] == "pending"

    def test_lifecycle_status_retired_does_not_change_state(self) -> None:
        task = Task(
            id="task-lifecycle-4",
            name="Retired Task",
            state=TaskState.PENDING,
            metadata={"lifecycle_status": "retired"},
        )

        assert task.state == TaskState.PENDING

    def test_lifecycle_status_superseded_does_not_change_state(self) -> None:
        task = Task(
            id="task-lifecycle-5",
            name="Superseded Task",
            state=TaskState.PENDING,
            metadata={
                "lifecycle_status": "superseded",
                "superseded_by": "task-999",
            },
        )

        assert task.state == TaskState.PENDING

    def test_unknown_lifecycle_status_values_are_preserved(self) -> None:
        """Unknown lifecycle status values must be preserved as-is in metadata."""
        task = Task(
            id="task-lifecycle-6",
            name="Unknown Lifecycle Task",
            metadata={"lifecycle_status": "custom_future_value"},
        )

        assert task.metadata["lifecycle_status"] == "custom_future_value"
        d = task.to_dict()
        assert d["metadata"]["lifecycle_status"] == "custom_future_value"


# ---------------------------------------------------------------------------
# 6.8-7: 秘密情報境界テスト
# ---------------------------------------------------------------------------

class TestSecretBoundary:
    """Metadata must not expose secrets like cookies, tokens, or header values."""

    def test_from_dict_rejects_cookie_in_metadata_at_boundary(self) -> None:
        """from_dict must redact cookie/token values to [REDACTED]."""
        d = {
            "id": "task-secret-1",
            "name": "Secret Task",
            "metadata": {
                "auth_context_version": "v2",
                "cookie": "session=abc123secret",
                "token": "Bearer xyz789",
            },
        }

        task = Task.from_dict(d)

        # auth_context_version must be preserved
        assert task.metadata.get("auth_context_version") == "v2"
        # cookie and token values must be redacted (keys preserved as audit trail)
        assert task.metadata["cookie"] == "[REDACTED]"
        assert task.metadata["token"] == "[REDACTED]"

    def test_from_dict_rejects_header_values_in_nested_metadata(self) -> None:
        """from_dict must recurse and redact nested secret values."""
        d = {
            "id": "task-secret-2",
            "name": "Nested Secret Task",
            "metadata": {
                "source_refs": [
                    {"cookie": "session=abc"},
                    {"headers": {"Authorization": "Bearer xyz"}},
                ]
            },
        }

        task = Task.from_dict(d)

        md = task.metadata
        assert "source_refs" in md
        # First ref: cookie value redacted
        assert md["source_refs"][0]["cookie"] == "[REDACTED]"
        # Second ref: Authorization header value redacted
        assert md["source_refs"][1]["headers"]["Authorization"] == "[REDACTED]"

    def test_to_dict_never_exposes_secrets(self) -> None:
        """to_dict must redact secrets even if present in metadata."""
        task = Task(
            id="task-secret-3",
            name="Secret Leak Test",
            metadata={
                "auth_context_version": "v2",
                "cookie": "session=abc123",
                "token": "Bearer xyz",
            },
        )

        d = task.to_dict()

        assert d["metadata"].get("auth_context_version") == "v2"
        assert d["metadata"]["cookie"] == "[REDACTED]"
        assert d["metadata"]["token"] == "[REDACTED]"


# ---------------------------------------------------------------------------
# 6.8-5: 未知 lifecycle metadata が TaskState 変換に影響しない
# (covered in TestLifecycleMetadataTaskStateNonInterference above)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Phase 1 execution contract field completeness
# ---------------------------------------------------------------------------

class TestExecutionContractFieldCompleteness:
    """All Phase 1 required metadata fields are storable and retrievable."""

    REQUIRED_CONTRACT_FIELDS = {
        "target_key",
        "origin_key",
        "canonical_endpoint_key",
        "session_key",
        "auth_context_version",
        "recon_snapshot_version",
        "correlation_id",
        "generation_reason",
        "evidence_key",
        "attack_hypothesis_id",
        "request_fingerprint",
        "payload_fingerprint",
        "mutation_chain_id",
        "schema_version",
    }

    LIFECYCLE_FIELDS = {
        "lifecycle_status",
        "lifecycle_reason",
        "superseded_by",
        "invalidated_by",
    }

    def test_all_contract_fields_roundtrip(self) -> None:
        """Every Phase 1 contract field must survive to_dict -> from_dict."""
        full_metadata = {
            "target_key": "https://example.test",
            "origin_key": "recon://scenario-1",
            "canonical_endpoint_key": "https://example.test/api/v1",
            "session_key": "sess-abc",
            "auth_context_version": "v2",
            "recon_snapshot_version": "snap-42",
            "correlation_id": "corr-xyz",
            "generation_reason": "new_target_discovered",
            "evidence_key": "ev-123",
            "attack_hypothesis_id": "hyp-456",
            "request_fingerprint": "fp-req-789",
            "payload_fingerprint": "fp-pay-012",
            "mutation_chain_id": "mut-345",
            "schema_version": 1,
        }

        task = Task(id="task-full", name="Full Contract Task", metadata=full_metadata)

        d = task.to_dict()
        restored = Task.from_dict(d)

        for field in self.REQUIRED_CONTRACT_FIELDS:
            assert field in restored.metadata, f"Missing required field: {field}"
            assert restored.metadata[field] == full_metadata[field], (
                f"Field {field}: expected {full_metadata[field]!r}, "
                f"got {restored.metadata[field]!r}"
            )

    def test_all_lifecycle_fields_roundtrip(self) -> None:
        """Every lifecycle metadata field must survive to_dict -> from_dict."""
        lifecycle_metadata = {
            "lifecycle_status": "admitted",
            "lifecycle_reason": "scope_verified",
            "superseded_by": "task-999",
            "invalidated_by": "recon_update_123",
        }

        task = Task(id="task-lc", name="Lifecycle Task", metadata=lifecycle_metadata)

        d = task.to_dict()
        restored = Task.from_dict(d)

        for field in self.LIFECYCLE_FIELDS:
            assert field in restored.metadata, f"Missing lifecycle field: {field}"
            assert restored.metadata[field] == lifecycle_metadata[field]

    def test_schema_version_defaults_to_1_for_new_metadata(self) -> None:
        """When metadata is present but schema_version is missing, default to 1."""
        task = Task(
            id="task-no-version",
            name="No Version Task",
            metadata={"target_key": "https://example.test"},
        )

        d = task.to_dict()

        assert d["metadata"]["schema_version"] == 1

    def test_schema_version_is_absent_when_metadata_is_empty(self) -> None:
        """When metadata is empty, schema_version should not be injected."""
        task = Task(id="task-empty", name="Empty Metadata Task", metadata={})

        d = task.to_dict()

        # Empty metadata means no contract fields, so no schema_version needed
        assert d["metadata"] == {}
        assert "schema_version" not in d["metadata"]
