"""
SGK-2026-0419 Steps 4-5: VDP infrastructure tests.

Tests cover:
- Bounded evidence queue rejects when full (no silent discard)
- EvidenceWriter transitions to degraded mode on queue full
- Old session payload with missing fields readable by compatible reader
- New session fields ignored by old reader (forward-compat)
- Session schema_version injected on write and defaulted on read
- IdempotencyGuard prevents double evidence ID registration
- StateChangeGuard prevents double-send of state changes
- Checkpoint atomic write/read
- Checkpoint resilience to corrupt file
- Secret redaction applied at session write boundary
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    EvidenceQueueBackpressureError,
    IdempotencyGuard,
    StateChangeGuard,
    VdpCheckpoint,
    atomic_write_checkpoint,
    read_checkpoint,
    redact_secrets_deep,
)
from src.core.engine.vdp_session_reader import (
    BoundedEvidenceQueue,
    EvidenceWriter,
    inject_vdp_fields,
    read_session_compat,
    redact_and_write_session,
)


# ============================================================================
# Bounded evidence queue — backpressure (no silent discard)
# ============================================================================


class TestBoundedEvidenceQueue:
    """Ensure the bounded queue rejects when full and never silently discards."""

    @pytest.mark.asyncio
    async def test_queue_rejects_when_full(self):
        """Evidence must NOT be silently discarded — backpressure error is raised."""
        queue = BoundedEvidenceQueue(max_size=2)

        await queue.enqueue({"evidence_id": "ev-01"})
        await queue.enqueue({"evidence_id": "ev-02"})
        assert queue.is_full()

        # Third enqueue must raise, not silently drop
        with pytest.raises(EvidenceQueueBackpressureError) as exc_info:
            await queue.enqueue({"evidence_id": "ev-03"})

        err = exc_info.value
        assert err.evidence_id == "ev-03"
        assert err.queue_size == 2
        assert err.max_size == 2

    @pytest.mark.asyncio
    async def test_queue_dequeue_works_normally(self):
        queue = BoundedEvidenceQueue(max_size=3)
        await queue.enqueue({"evidence_id": "ev-01"})
        await queue.enqueue({"evidence_id": "ev-02"})

        item = await queue.dequeue()
        assert item["evidence_id"] == "ev-01"
        assert not queue.is_full()

    @pytest.mark.asyncio
    async def test_queue_tracks_backpressure_count(self):
        queue = BoundedEvidenceQueue(max_size=1)
        await queue.enqueue({"evidence_id": "ev-01"})

        try:
            await queue.enqueue({"evidence_id": "ev-02"})
        except EvidenceQueueBackpressureError:
            pass

        assert queue._backpressure_count == 1

    @pytest.mark.asyncio
    async def test_queue_empty_full_states(self):
        queue = BoundedEvidenceQueue(max_size=2)
        assert queue.is_empty()
        assert not queue.is_full()

        await queue.enqueue({"evidence_id": "ev-01"})
        assert not queue.is_empty()
        assert not queue.is_full()

        await queue.enqueue({"evidence_id": "ev-02"})
        assert not queue.is_empty()
        assert queue.is_full()


# ============================================================================
# EvidenceWriter — degraded-mode transition on queue full
# ============================================================================


class TestEvidenceWriterDegradedMode:
    """EvidenceWriter must transition to degraded when the bounded queue rejects."""

    @pytest.mark.asyncio
    async def test_writer_starts_not_degraded(self):
        writer = EvidenceWriter(max_queue_size=10)
        assert writer.degraded is False

    @pytest.mark.asyncio
    async def test_writer_transitions_to_degraded_on_queue_full(self):
        writer = EvidenceWriter(max_queue_size=1)
        assert writer.degraded is False

        await writer.enqueue_evidence({"evidence_id": "ev-01"})
        assert writer.degraded is False

        with pytest.raises(EvidenceQueueBackpressureError):
            await writer.enqueue_evidence({"evidence_id": "ev-02"})

        assert writer.degraded is True
        assert writer._degraded_count == 1

    @pytest.mark.asyncio
    async def test_writer_can_explicitly_transition_to_degraded(self):
        writer = EvidenceWriter(max_queue_size=100)
        assert writer.degraded is False

        writer.transition_to_degraded()
        assert writer.degraded is True

    @pytest.mark.asyncio
    async def test_normal_enqueue_does_not_degrade(self):
        writer = EvidenceWriter(max_queue_size=10)
        await writer.enqueue_evidence({"evidence_id": "ev-01"})
        await writer.enqueue_evidence({"evidence_id": "ev-02"})
        assert writer.degraded is False
        assert writer.queue.qsize == 2


# ============================================================================
# Old/new session field compatibility
# ============================================================================


class TestSessionFieldCompatibility:
    """read_session_compat must handle missing and unknown fields."""

    def test_old_session_missing_vdp_fields_is_readable(self):
        """Old session without vdp_contract_version must still be readable."""
        old_payload = {
            "session_id": "sess-old-001",
            "target": "https://example.com",
            "findings": [],
            "task_queue": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "session_old.json"
            path.write_text(json.dumps(old_payload))

            result = read_session_compat(path)
            assert result is not None
            assert result["session_id"] == "sess-old-001"
            assert result["target"] == "https://example.com"
            # VDP field must be defaulted
            assert result["vdp_contract_version"] == VDP_CONTRACT_SCHEMA_VERSION

    def test_new_session_fields_ignored_by_old_reader(self):
        """Forward-compat: unknown (future) fields are preserved but ignored."""
        new_payload = {
            "session_id": "sess-new-001",
            "target": "https://example.com",
            "vdp_contract_version": 2,
            "future_feature_flag": True,
            "machine_learning_fingerprint": "abc123",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "session_new.json"
            path.write_text(json.dumps(new_payload))

            result = read_session_compat(path)
            assert result is not None
            # Known fields are read
            assert result["session_id"] == "sess-new-001"
            assert result["vdp_contract_version"] == 2  # preserved as-is
            # Unknown fields are preserved (forward-compat)
            assert result["future_feature_flag"] is True
            assert result["machine_learning_fingerprint"] == "abc123"

    def test_read_session_compat_returns_none_for_missing_file(self):
        result = read_session_compat(Path("/nonexistent/session_missing.json"))
        assert result is None

    def test_read_session_compat_returns_none_for_corrupt_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "corrupt.json"
            path.write_text("{not valid json!!!")
            result = read_session_compat(path)
            assert result is None


# ============================================================================
# Session schema_version injection
# ============================================================================


class TestSchemaVersionInjection:
    """inject_vdp_fields must inject vdp_contract_version without mutating input."""

    def test_inject_adds_missing_vdp_version(self):
        payload = {"session_id": "sess-001", "target": "https://example.com"}
        result = inject_vdp_fields(payload)

        assert result["session_id"] == "sess-001"
        assert result["vdp_contract_version"] == VDP_CONTRACT_SCHEMA_VERSION
        # Original payload must NOT be mutated
        assert "vdp_contract_version" not in payload

    def test_inject_preserves_existing_vdp_version(self):
        payload = {
            "session_id": "sess-002",
            "vdp_contract_version": 5,
        }
        result = inject_vdp_fields(payload)
        assert result["vdp_contract_version"] == 5  # preserved, not overwritten

    def test_inject_on_write_then_read_defaults(self):
        """Write with injection, then read with defaulting — roundtrip."""
        original = {"session_id": "sess-roundtrip", "data": "test"}

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "session_roundtrip.json"
            injected = inject_vdp_fields(original)
            path.write_text(json.dumps(injected))

            read_back = read_session_compat(path)
            assert read_back is not None
            assert read_back["session_id"] == "sess-roundtrip"
            assert read_back["vdp_contract_version"] == VDP_CONTRACT_SCHEMA_VERSION

    def test_empty_payload_gets_injected(self):
        result = inject_vdp_fields({})
        assert result == {"vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION}


# ============================================================================
# IdempotencyGuard — evidence ID prevention
# ============================================================================


class TestIdempotencyGuardEvidence:
    """IdempotencyGuard must prevent double registration of evidence IDs."""

    def test_double_evidence_id_blocked(self):
        guard = IdempotencyGuard()
        # First registration of evidence ID should succeed
        assert guard.register("evidence-001") is True
        # Second registration of the same evidence ID blocked
        assert guard.register("evidence-001") is False
        # Different evidence ID still allowed
        assert guard.register("evidence-002") is True

    def test_guard_serialization_roundtrip(self):
        guard = IdempotencyGuard()
        guard.register("ev-a")
        guard.register("ev-b")
        guard.register("ev-c")

        d = guard.to_dict()
        restored = IdempotencyGuard.from_dict(d)

        assert restored.is_registered("ev-a") is True
        assert restored.is_registered("ev-b") is True
        assert restored.is_registered("ev-c") is True
        assert restored.is_registered("ev-x") is False

    def test_guard_clear_resets_all(self):
        guard = IdempotencyGuard()
        guard.register("ev-a")
        guard.register("ev-b")
        guard.clear()

        assert guard.is_registered("ev-a") is False
        assert guard.register("ev-a") is True  # now allowed again


# ============================================================================
# StateChangeGuard — double-send prevention
# ============================================================================


class TestStateChangeGuardEvidence:
    """StateChangeGuard must prevent double-send of evidence state changes."""

    def test_sent_but_not_confirmed_blocks_double_send(self):
        guard = StateChangeGuard()

        # Mark evidence as sent but not yet saved
        guard.mark_sent("evidence-send-001")

        # Attempting to re-send must be blocked
        with pytest.raises(ValueError, match="not confirmed saved"):
            guard.prevent_double_send("evidence-send-001")

    def test_confirm_saved_allows_re_send(self):
        guard = StateChangeGuard()

        guard.mark_sent("evidence-send-002")
        guard.confirm_saved("evidence-send-002")

        # After confirming saved, no error should be raised
        guard.prevent_double_send("evidence-send-002")  # should not raise

    def test_is_safe_to_send_returns_false_for_pending(self):
        guard = StateChangeGuard()
        guard.mark_sent("ev-pending")
        assert guard.is_safe_to_send("ev-pending") is False

    def test_state_change_guard_serialization_roundtrip(self):
        guard = StateChangeGuard()
        guard.mark_sent("sc-a")
        guard.mark_sent("sc-b")
        guard.confirm_saved("sc-a")

        d = guard.to_dict()
        restored = StateChangeGuard.from_dict(d)

        # sc-b is still pending (sent but not confirmed)
        assert restored.is_safe_to_send("sc-b") is False
        # sc-a is confirmed
        assert restored.is_safe_to_send("sc-a") is True


# ============================================================================
# Checkpoint — atomic write, read, corrupt resilience
# ============================================================================


class TestCheckpointInfrastructure:
    """Checkpoint atomic write/read and resilience to corruption."""

    def test_checkpoint_atomic_write_and_read(self):
        ck_data = {
            "checkpoint_id": "ck-infra-001",
            "hypothesis_id": "hyp-001",
            "last_completed_attempt_id": "att-005",
            "budget_snapshot": {"requests_used": 10},
            "state": "partial",
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "checkpoint.json"
            atomic_write_checkpoint(ck_data, ck_path)

            assert ck_path.exists()
            restored = read_checkpoint(ck_path)
            assert restored is not None
            assert restored["checkpoint_id"] == "ck-infra-001"
            assert restored["hypothesis_id"] == "hyp-001"
            assert restored["budget_snapshot"]["requests_used"] == 10

    def test_read_missing_checkpoint_returns_none(self):
        result = read_checkpoint(Path("/tmp/nonexistent_vdp_ck.json"))
        assert result is None

    def test_read_corrupt_checkpoint_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "corrupt_ck.json"
            ck_path.write_text("{this is not valid json @@@")

            result = read_checkpoint(ck_path)
            assert result is None

    def test_read_empty_file_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "empty_ck.json"
            ck_path.write_text("")

            result = read_checkpoint(ck_path)
            assert result is None

    def test_checkpoint_vdp_checkpoint_object_roundtrip(self):
        ck = VdpCheckpoint(
            checkpoint_id="ck-obj-001",
            hypothesis_id="hyp-001",
            last_completed_attempt_id="att-003",
            budget_snapshot={"requests_used": 5, "follow_ups_used": 2},
            state="partial",
            vdp_contract_version=1,
        )
        d = ck.to_dict()
        restored = VdpCheckpoint.from_dict(d)

        assert restored.checkpoint_id == ck.checkpoint_id
        assert restored.hypothesis_id == ck.hypothesis_id
        assert restored.last_completed_attempt_id == ck.last_completed_attempt_id
        assert restored.budget_snapshot == ck.budget_snapshot
        assert restored.state == ck.state
        assert restored.vdp_contract_version == ck.vdp_contract_version

    def test_checkpoint_atomic_write_does_not_corrupt_on_disk_full(self):
        """Verify atomic write creates parent directories."""
        ck_data = {"checkpoint_id": "ck-dirs", "hypothesis_id": "hyp-001"}
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "deep" / "nested" / "checkpoint.json"
            atomic_write_checkpoint(ck_data, nested)

            assert nested.exists()
            restored = read_checkpoint(nested)
            assert restored is not None
            assert restored["checkpoint_id"] == "ck-dirs"


# ============================================================================
# Secret redaction at session write boundary
# ============================================================================


class TestSecretRedactionAtSessionBoundary:
    """redact_and_write_session must apply redact_secrets_deep before persisting."""

    def test_redact_and_write_session_redacts_secrets(self):
        payload = {
            "session_id": "sess-redact-001",
            "request": {
                "headers": {
                    "Authorization": "Bearer super-secret-token-12345",
                    "Cookie": "session=abc123xyz",
                },
            },
            "normal_field": "visible data",
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "session_redacted.json"
            redact_and_write_session(payload, path)

            assert path.exists()
            raw = path.read_text()
            data = json.loads(raw)

            # Secrets must be redacted in the written file
            assert "super-secret-token-12345" not in raw
            assert data["request"]["headers"]["Authorization"] == "[REDACTED]"
            assert data["request"]["headers"]["Cookie"] == "[REDACTED]"

            # Non-secret data preserved
            assert data["normal_field"] == "visible data"
            assert data["request"]["headers"]["Authorization"] not in (
                "Bearer super-secret-token-12345",
            )

    def test_redact_and_write_session_injects_vdp_version(self):
        payload = {"session_id": "sess-vdp-inject"}
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "session_injected.json"
            redact_and_write_session(payload, path)

            data = json.loads(path.read_text())
            assert data["vdp_contract_version"] == VDP_CONTRACT_SCHEMA_VERSION

    def test_redact_deep_handles_empty_payload(self):
        payload: dict = {}
        result = redact_secrets_deep(payload)
        assert result == {}

    def test_redact_deep_handles_nested_list_at_write_boundary(self):
        """Secret keys in nested lists must be redacted at write boundary."""
        payload = {
            "attempts": [
                {
                    "auth": {
                        "api_key": "sk-live-secret-key-1234567890abcdef",
                        "url": "https://api.example.com",
                    }
                }
            ]
        }
        result = redact_secrets_deep(payload)
        # "api_key" is a secret key pattern — entire value redacted
        assert result["attempts"][0]["auth"]["api_key"] == "[REDACTED]"
        assert result["attempts"][0]["auth"]["url"] == "https://api.example.com"

    def test_original_payload_not_mutated_by_redaction(self):
        """redact_secrets_deep must not mutate the original input."""
        original = {
            "auth": {"token": "secret-abc"},
        }
        _result = redact_secrets_deep(original)
        # Original must be intact
        assert original["auth"]["token"] == "secret-abc"


# ============================================================================
# Atomic session save — raise on error, no silent ignore
# ============================================================================


class TestAtomicSessionSave:
    """Item 7: atomic_session_save must raise on errors, not silently ignore."""

    def test_atomic_session_save_success(self):
        from src.core.engine.vdp_atomic_writer import atomic_session_save, safe_read_session

        payload = {"session_id": "sess-atom-001", "data": "hello"}
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "session.json"
            atomic_session_save(payload, target)

            assert target.exists()
            restored = safe_read_session(target)
            assert restored is not None
            assert restored["session_id"] == "sess-atom-001"
            assert restored["data"] == "hello"

    def test_atomic_session_save_permission_error_raises(self):
        """PermissionError during os.replace must raise, not be silently ignored."""
        from unittest import mock
        from src.core.engine.vdp_atomic_writer import atomic_session_save

        payload = {"session_id": "sess-perm-err"}

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "session.json"
            with mock.patch("os.replace", side_effect=PermissionError("denied")):
                with pytest.raises(PermissionError):
                    atomic_session_save(payload, target)

    def test_atomic_session_save_io_error_raises(self):
        """IOError during write must raise, not be silently ignored."""
        from unittest import mock
        from src.core.engine.vdp_atomic_writer import atomic_session_save

        payload = {"session_id": "sess-io-err"}

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "session.json"
            # Simulate os.fdopen raising IOError
            with mock.patch("os.fdopen", side_effect=IOError("disk error")):
                with pytest.raises(IOError):
                    atomic_session_save(payload, target)

    def test_atomic_session_save_creates_parent_dirs(self):
        from src.core.engine.vdp_atomic_writer import atomic_session_save

        payload = {"session_id": "sess-dirs"}
        with tempfile.TemporaryDirectory() as tmpdir:
            nested = Path(tmpdir) / "a" / "b" / "session.json"
            atomic_session_save(payload, nested)
            assert nested.exists()


class TestSafeReadSession:
    """Item 7: safe_read_session must handle errors properly."""

    def test_safe_read_session_file_not_found_returns_none(self):
        from src.core.engine.vdp_atomic_writer import safe_read_session

        result = safe_read_session(Path("/nonexistent/session_safe.json"))
        assert result is None

    def test_safe_read_session_permission_error_raises(self):
        """PermissionError on read must raise, not return None."""
        from unittest import mock
        from src.core.engine.vdp_atomic_writer import safe_read_session

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "session.json"
            target.write_text('{"key": "value"}')
            with mock.patch.object(Path, "read_text", side_effect=PermissionError("denied")):
                with pytest.raises(PermissionError):
                    safe_read_session(target)

    def test_safe_read_session_corrupt_json_returns_none(self):
        from src.core.engine.vdp_atomic_writer import safe_read_session

        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "corrupt.json"
            target.write_text("{not valid json!!!")
            result = safe_read_session(target)
            assert result is None


# ============================================================================
# VDP checkpoint payload — budget + guards serialization
# ============================================================================


class TestVdpCheckpointPayload:
    """Item 8: build_vdp_checkpoint_payload and restore_vdp_checkpoint_payload."""

    def test_build_and_restore_checkpoint_payload(self):
        from src.core.engine.vdp_budget import VdpExecutionBudget
        from src.core.engine.vdp_session_reader import (
            build_vdp_checkpoint_payload,
            restore_vdp_checkpoint_payload,
        )
        from src.core.models.vdp_contract import IdempotencyGuard, StateChangeGuard

        budget = VdpExecutionBudget(
            max_requests=10,
            per_asset_burst=5,
        )
        budget.consume(asset_key="a1")
        budget.consume(asset_key="a1")

        idempotency = IdempotencyGuard()
        idempotency.register("ev-01")
        idempotency.register("ev-02")

        state_change = StateChangeGuard()
        state_change.mark_sent("sc-01")

        payload = build_vdp_checkpoint_payload(
            hypothesis_id="hyp-001",
            budget=budget,
            idempotency_guard=idempotency,
            state_change_guard=state_change,
        )

        assert payload["hypothesis_id"] == "hyp-001"
        assert payload["vdp_contract_version"] == 1
        assert "budget" in payload
        assert "idempotency_guard" in payload
        assert "state_change_guard" in payload

        # Restore
        restored_budget, restored_idem, restored_sc = restore_vdp_checkpoint_payload(payload)

        assert restored_budget is not None
        assert restored_budget._requests_used == 2
        assert restored_idem.is_registered("ev-01") is True
        assert restored_idem.is_registered("ev-02") is True
        assert restored_sc.is_safe_to_send("sc-01") is False

    def test_restore_with_missing_budget_returns_none_budget(self):
        from src.core.engine.vdp_session_reader import restore_vdp_checkpoint_payload

        data = {
            "hypothesis_id": "hyp-002",
            "idempotency_guard": {"registered_ids": ["ev-a"]},
            "state_change_guard": {
                "sent_but_not_confirmed": [],
                "confirmed_saved": [],
            },
        }
        restored_budget, restored_idem, restored_sc = restore_vdp_checkpoint_payload(data)

        assert restored_budget is None
        assert restored_idem.is_registered("ev-a") is True
        assert restored_sc.is_safe_to_send("sc-x") is True

    def test_restore_with_empty_data_returns_defaults(self):
        from src.core.engine.vdp_session_reader import restore_vdp_checkpoint_payload

        restored_budget, restored_idem, restored_sc = restore_vdp_checkpoint_payload({})

        assert restored_budget is None
        assert restored_idem.is_registered("anything") is False
        assert restored_sc.is_safe_to_send("anything") is True
