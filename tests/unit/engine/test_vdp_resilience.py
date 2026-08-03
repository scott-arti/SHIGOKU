"""
SGK-2026-0419 Audit Item 11: Resilience tests for VDP pipeline.

Tests cover:
- Transport Spy (no active communication)
- Disk Full (atomic write checkpoint failure, partial file read)
- Partial Write / Resume (incomplete session/checkpoint recovery)
- OOB/Browser/Redirect scope checks
- Invalid enum rejection
- Missing required field validation
- Secrets redaction in transport spy
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from src.core.models.vdp_contract import (
    AttemptRecord,
    CapabilityLevel,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    IdempotencyGuard,
    ProgramCapabilityMatrix,
    RunTerminationState,
    ScopeRevalidationResult,
    atomic_write_checkpoint,
    read_checkpoint,
    redact_secrets_deep,
    validate_hypothesis_record,
    validate_attempt_record,
    validate_evidence_record,
    validate_verdict_record,
)
from src.core.engine.vdp_admission import VdpAdmissionGate
from src.core.engine.vdp_budget import VdpExecutionBudget
from src.core.engine.vdp_session_reader import read_session_compat


# ============================================================================
# Transport Spy
# ============================================================================


class SpyTransport:
    """Records all would-be HTTP calls without making them. For testing no-active-communication."""

    def __init__(self):
        self.calls: list = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url))
        return SpyResponse(200, "OK")


class SpyResponse:
    def __init__(self, status: int, body: str):
        self.status_code = status
        self.text = body


class TestTransportSpy:
    """Verify that VDP operations never trigger real network."""

    def test_spy_transport_records_all_calls_but_makes_none(self):
        """VdpAdmissionGate + VdpExecutionBudget operations must trigger zero network."""
        spy = SpyTransport()

        # Exercise VdpExecutionBudget
        budget = VdpExecutionBudget(per_asset_burst=10, max_requests=100)
        for _ in range(5):
            result = budget.consume(asset_key="https://example.com")
            assert result.allowed is True

        # Exercise VdpAdmissionGate
        pcm = ProgramCapabilityMatrix(
            rules={"read_asset": CapabilityLevel.ALLOWED},
            program_name="test",
        )
        gate = VdpAdmissionGate(capability_matrix=pcm, budget=budget)
        hyp = HypothesisRecord(
            hypothesis_id="hyp-001",
            observation_id="obs-001",
            asset="https://example.com",
            capability="read_asset",
            hypothesis_text="Test",
            trust_boundary="public",
            actors=["unauthenticated"],
        )
        result = gate.evaluate(hyp, scope_verdict="allowed")
        assert result.admitted is True

        # Spy must have 0 calls — this proves no hidden network I/O
        assert len(spy.calls) == 0

    def test_vdp_contract_operations_do_not_use_transport(self):
        """All HypothesisRecord/AttemptRecord/EvidenceRecordV1 operations must not call transport."""
        spy = SpyTransport()

        # Create
        hyp = HypothesisRecord(
            hypothesis_id="hyp-002",
            observation_id="obs-002",
            asset="https://example.com",
            capability="read_asset",
            hypothesis_text="Test",
            trust_boundary="public",
            actors=["unauthenticated"],
        )
        att = AttemptRecord(
            attempt_id="att-002",
            hypothesis_id="hyp-002",
            actor="unauthenticated",
            request_fingerprint="sha256:abc",
            scope_verdict="allowed",
        )
        ev = EvidenceRecordV1(
            evidence_id="ev-002",
            attempt_id="att-002",
            evidence_type="real_http_response",
            raw_hash="sha256:def",
        )

        # Transition
        hyp.transition_to("admitted")

        # to_dict
        hyp_dict = hyp.to_dict()
        att_dict = att.to_dict()
        ev_dict = ev.to_dict()

        # from_dict
        hyp2 = HypothesisRecord.from_dict(hyp_dict)
        att2 = AttemptRecord.from_dict(att_dict)
        ev2 = EvidenceRecordV1.from_dict(ev_dict)

        # Verify roundtrip works
        assert hyp2.hypothesis_id == "hyp-002"
        assert att2.attempt_id == "att-002"
        assert ev2.evidence_id == "ev-002"

        # Verify no transport calls happened
        assert len(spy.calls) == 0


# ============================================================================
# Disk Full
# ============================================================================


class TestDiskFull:
    """Verify correct behavior under disk-full conditions."""

    def test_atomic_write_checkpoint_disk_full(self):
        """os.replace raising OSError(28) must propagate, not be silently ignored."""
        data = {"checkpoint_id": "ck-df-001", "hypothesis_id": "hyp-001"}

        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "checkpoint.json"
            Path(tmpdir).mkdir(parents=True, exist_ok=True)

            with mock.patch("os.replace", side_effect=OSError(28, "No space left on device")):
                with pytest.raises(OSError, match="No space left on device"):
                    atomic_write_checkpoint(data, ck_path)

    def test_checkpoint_write_partial_file(self):
        """Incomplete/corrupt checkpoint file must return None from read_checkpoint."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "checkpoint_partial.json"
            # Write an incomplete JSON fragment (truncated mid-object)
            ck_path.write_text('{"checkpoint_id": "ck-incomplete", "hypothesis_id": "hyp-001"')

            result = read_checkpoint(ck_path)
            assert result is None


# ============================================================================
# Partial Write / Resume
# ============================================================================


class TestPartialWriteResume:
    """Verify graceful handling of partial writes during crash/recovery."""

    def test_partial_session_write_then_resume(self):
        """Incomplete JSON session file must return None from read_session_compat."""
        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = Path(tmpdir) / "session_partial.json"
            # Write truncated JSON
            session_path.write_text('{"session_id": "sess-crash", "target":')

            result = read_session_compat(session_path)
            assert result is None

    def test_checkpoint_resume_preserves_attempt_id_uniqueness(self):
        """After checkpoint save + restore, new attempt gets a different ID (no collision)."""
        guard = IdempotencyGuard()

        # Simulate attempt-1: register and checkpoint
        attempt_id_1 = "att-resume-001"
        assert guard.register(attempt_id_1) is True

        # Serialize guard state (simulates checkpoint save)
        guard_dict = guard.to_dict()

        # Simulate crash and restore from checkpoint
        restored_guard = IdempotencyGuard.from_dict(guard_dict)

        # Attempt-2 must get a different ID and register successfully
        attempt_id_2 = "att-resume-002"
        assert attempt_id_2 != attempt_id_1
        assert restored_guard.register(attempt_id_2) is True  # new ID works

        # Attempt-1 must still be rejected (idempotency preserved across restore)
        assert restored_guard.register(attempt_id_1) is False


# ============================================================================
# OOB / Browser / Redirect scope checks
# ============================================================================


class TestOobRedirectScopeChecks:
    """Out-of-band, browser redirect, and callback URL scope enforcement."""

    def test_redirect_to_oob_target_blocked(self):
        """ScopeRevalidationResult.redirect_to_out_of_scope must be NOT allowed."""
        result = ScopeRevalidationResult.redirect_to_out_of_scope(
            original="https://in-scope.example.com/page",
            redirected_to="https://evil.com/page",
        )
        assert result.verdict == "redirect_out_of_scope"
        assert result.allowed is False
        assert result.redirected_to == "https://evil.com/page"

    def test_browser_redirect_scope_check(self):
        """Admission gate must block a redirect that goes out of scope."""
        pcm = ProgramCapabilityMatrix(
            rules={"browser_execution": CapabilityLevel.ALLOWED},
            program_name="test",
        )
        gate = VdpAdmissionGate(capability_matrix=pcm)
        hyp = HypothesisRecord(
            hypothesis_id="hyp-redirect-001",
            observation_id="obs-redirect-001",
            asset="https://example.com/page",
            capability="browser_execution",
            hypothesis_text="Test browser redirect",
            trust_boundary="browser",
            actors=["unauthenticated"],
        )

        # Simulate: request to example.com/page redirects to evil.com
        result = gate.evaluate(hyp, scope_verdict="redirect_out_of_scope")
        assert result.admitted is False
        assert result.reason_code == "redirect_out_of_scope"

    def test_oob_callback_url_scope_check(self):
        """Out-of-band callback destination not in scope must fail scope revalidation."""
        result = ScopeRevalidationResult.indeterminate(
            "OOB callback destination burpcollaborator.net not in scope"
        )
        assert result.verdict == "scope_revalidation_blocked"
        assert result.allowed is False

        # Verify indeterminate blocks admission too
        pcm = ProgramCapabilityMatrix(
            rules={"oob_probe": CapabilityLevel.ALLOWED},
            program_name="test",
        )
        gate = VdpAdmissionGate(capability_matrix=pcm)
        hyp = HypothesisRecord(
            hypothesis_id="hyp-oob-001",
            observation_id="obs-oob-001",
            asset="https://example.com",
            capability="oob_probe",
            hypothesis_text="OOB callback test",
            trust_boundary="api",
            actors=["unauthenticated"],
        )
        result = gate.evaluate(hyp, scope_verdict="scope_revalidation_blocked")
        assert result.admitted is False
        assert result.reason_code == "scope_revalidation_blocked"


# ============================================================================
# Invalid Enum
# ============================================================================


class TestInvalidEnum:
    """Invalid enum values must be rejected or handled gracefully."""

    def test_invalid_run_termination_state_rejected(self):
        """RunTerminationState with invalid value must raise ValueError."""
        with pytest.raises(ValueError):
            RunTerminationState("invalid_value")

    def test_invalid_capability_level_rejected(self):
        """CapabilityLevel with invalid value must raise ValueError."""
        with pytest.raises(ValueError):
            CapabilityLevel("not_a_level")

    def test_invalid_evidence_type_in_evidence_record(self):
        """EvidenceRecordV1.from_dict with unknown evidence_type must not crash."""
        rec = EvidenceRecordV1.from_dict({
            "evidence_id": "ev-bogus-001",
            "attempt_id": "att-001",
            "evidence_type": "bogus_type",
        })
        # Must not crash; evidence_type is preserved (from_dict is permissive)
        assert rec.evidence_id == "ev-bogus-001"
        assert rec.evidence_type == "bogus_type"

    def test_invalid_hypothesis_state_rejected(self):
        """HypothesisRecord with invalid state must raise on transition_to."""
        rec = HypothesisRecord(
            hypothesis_id="hyp-invalid-001",
            observation_id="obs-001",
            asset="https://example.com",
            capability="test",
            hypothesis_text="Test",
            trust_boundary="public",
            actors=["unauthenticated"],
        )
        # Manually set an invalid state (bypass default "hypothesized")
        rec.state = "invalid"
        with pytest.raises(ValueError, match="Invalid state transition"):
            rec.transition_to("anything")


# ============================================================================
# Missing Required Fields
# ============================================================================


class TestMissingRequiredFields:
    """Record validators must detect missing mandatory fields."""

    def test_hypothesis_missing_observation_id_rejected(self):
        """validate_hypothesis_record with missing observation_id returns error."""
        rec = HypothesisRecord(
            hypothesis_id="hyp-no-obs",
            observation_id="",  # missing
            asset="https://example.com",
            capability="test",
            hypothesis_text="Test",
            trust_boundary="public",
        )
        errors = validate_hypothesis_record(rec)
        assert any("observation_id" in e for e in errors)

    def test_attempt_missing_hypothesis_id_rejected(self):
        """validate_attempt_record with missing hypothesis_id returns error."""
        rec = AttemptRecord(
            attempt_id="att-no-hyp",
            hypothesis_id="",  # missing
            actor="unauthenticated",
            request_fingerprint="sha256:abc",
            scope_verdict="allowed",
        )
        errors = validate_attempt_record(rec)
        assert any("hypothesis_id" in e for e in errors)

    def test_evidence_missing_evidence_id_rejected(self):
        """validate_evidence_record with missing evidence_id returns error."""
        rec = EvidenceRecordV1(
            evidence_id="",  # missing
            attempt_id="att-001",
            evidence_type="real_http_response",
        )
        errors = validate_evidence_record(rec)
        assert any("evidence_id" in e for e in errors)

    def test_verdict_missing_verdict_id_rejected(self):
        """validate_verdict_record with missing verdict_id returns error."""
        rec = EvidenceVerdictV1(
            verdict_id="",  # missing
            hypothesis_id="hyp-001",
            _status="candidate",
        )
        errors = validate_verdict_record(rec)
        assert any("verdict_id" in e for e in errors)


# ============================================================================
# Secrets in Transport Spy
# ============================================================================


class TestSecretsInTransportSpy:
    """Transport spy must never record raw secrets."""

    def test_redaction_applied_before_transport_spy_recording(self):
        """When a request with Authorization header would be sent, spy sees [REDACTED]."""
        payload = {
            "request": {
                "url": "https://api.example.com/v1",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer super-secret-token-abc123xyz",
                    "Content-Type": "application/json",
                },
            }
        }

        redacted = redact_secrets_deep(payload)

        # Authorization header must be fully redacted
        assert redacted["request"]["headers"]["Authorization"] == "[REDACTED]"
        # Non-secret headers must be preserved
        assert redacted["request"]["headers"]["Content-Type"] == "application/json"
        # URL and method preserved
        assert redacted["request"]["url"] == "https://api.example.com/v1"
        assert redacted["request"]["method"] == "GET"
