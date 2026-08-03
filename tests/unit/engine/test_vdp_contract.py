"""
SGK-2026-0419: VDP canonical data contract tests.

TDD: Write failing tests first, then implement.
Tests cover:
- Schema version compatibility
- Invalid state transition rejection
- ID series tracing
- Budget exhaustion
- Scope indeterminate / out-of-scope blocking
- Secret redaction
- Large evidence truncation
- Queue backpressure
- Checkpoint / idempotency / resume
- Old session reading
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest


# ---------------------------------------------------------------------------
# Import the module under test (will fail on first run — expected TDD red)
# ---------------------------------------------------------------------------
def test_vdp_contract_module_importable():
    """T-0419-01: The vdp_contract module must be importable."""
    from src.core.models import vdp_contract  # noqa: F401


# ============================================================================
# T-0419-02: Schema version and contract definitions
# ============================================================================

class TestSchemaVersionContracts:
    """Each record type must carry schema_version and serialize/deserialize correctly."""

    def test_hypothesis_record_v1_schema_version(self):
        from src.core.models.vdp_contract import HypothesisRecord

        rec = HypothesisRecord(
            hypothesis_id="hyp-001",
            observation_id="obs-001",
            asset="https://example.com",
            capability="sql_injection_detector",
            hypothesis_text="Parameter 'id' may be injectable",
            trust_boundary="input_parameter",
            actors=["unauthenticated"],
            success_condition="SQL error in response",
            falsification_condition="No error with safe input",
            required_evidence=["error_based_response"],
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["hypothesis_id"] == "hyp-001"
        assert d["observation_id"] == "obs-001"
        assert d["state"] == "hypothesized"

    def test_hypothesis_record_roundtrip(self):
        from src.core.models.vdp_contract import HypothesisRecord

        original = HypothesisRecord(
            hypothesis_id="hyp-002",
            observation_id="obs-002",
            asset="https://api.example.com/users",
            capability="idor_detector",
            hypothesis_text="User ID can be changed to access other user data",
            trust_boundary="api_endpoint",
            actors=["authenticated_user_a"],
            preconditions={"auth_level": "user"},
            controls=["access_control"],
            success_condition="Response includes other user data",
            falsification_condition="Access denied for other users",
            required_evidence=["response_body_comparison"],
        )
        d = original.to_dict()
        restored = HypothesisRecord.from_dict(d)
        assert restored.hypothesis_id == original.hypothesis_id
        assert restored.observation_id == original.observation_id
        assert restored.asset == original.asset
        assert restored.state == original.state
        assert restored.actors == original.actors
        assert restored.preconditions == original.preconditions

    def test_attempt_record_v1_schema_version(self):
        from src.core.models.vdp_contract import AttemptRecord

        rec = AttemptRecord(
            attempt_id="att-001",
            hypothesis_id="hyp-001",
            actor="unauthenticated",
            request_fingerprint="sha256:abc123",
            scope_verdict="allowed",
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["attempt_id"] == "att-001"
        assert d["scope_verdict"] == "allowed"
        assert d["state"] == "attempted"

    def test_evidence_record_v1_schema_version(self):
        from src.core.models.vdp_contract import EvidenceRecordV1

        rec = EvidenceRecordV1(
            evidence_id="ev-001",
            attempt_id="att-001",
            evidence_type="real_http_response",
            raw_hash="sha256:def456",
            redacted_excerpt="HTTP/1.1 500 Internal Server Error...",
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["evidence_type"] == "real_http_response"

    def test_evidence_verdict_v1_schema_version(self):
        from src.core.models.vdp_contract import EvidenceVerdictV1

        rec = EvidenceVerdictV1(
            verdict_id="ver-001",
            hypothesis_id="hyp-001",
            _status="candidate",
            reason_codes=["payload_request_mismatch"],
            evaluated_evidence_ids=["ev-001"],
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["status"] == "candidate"

    def test_next_action_record_v1_schema_version(self):
        from src.core.models.vdp_contract import NextActionRecord

        rec = NextActionRecord(
            next_action_id="na-001",
            verdict_id="ver-001",
            evidence_gap="Missing second account verification",
            action_class="follow_up_probe",
            risk_class="read_only",
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["risk_class"] == "read_only"

    def test_program_capability_matrix_v1(self):
        from src.core.models.vdp_contract import ProgramCapabilityMatrix, CapabilityLevel

        pcm = ProgramCapabilityMatrix(
            matrix_version=1,
            rules={
                "sql_injection_detector": CapabilityLevel.CONFIRMATION_REQUIRED,
                "idor_detector": CapabilityLevel.ALLOWED,
                "remote_code_execution": CapabilityLevel.PROHIBITED,
                "ddos_testing": CapabilityLevel.UNAVAILABLE,
            },
        )
        d = pcm.to_dict()
        assert d["schema_version"] == 1
        assert d["matrix_version"] == 1

        # Test lookup
        assert pcm.get_level("idor_detector") == CapabilityLevel.ALLOWED
        assert pcm.get_level("sql_injection_detector") == CapabilityLevel.CONFIRMATION_REQUIRED
        assert pcm.get_level("remote_code_execution") == CapabilityLevel.PROHIBITED
        assert pcm.get_level("ddos_testing") == CapabilityLevel.UNAVAILABLE
        # Unknown capabilities default to PROHIBITED (fail-closed)
        assert pcm.get_level("unknown_attack") == CapabilityLevel.PROHIBITED

    def test_execution_budget_v1(self):
        from src.core.models.vdp_contract import ExecutionBudgetV1

        budget = ExecutionBudgetV1(
            max_requests=100,
            max_follow_ups=10,
            max_retries=3,
            max_concurrency=5,
            max_runtime_seconds=3600,
            max_artifact_bytes=10 * 1024 * 1024,
            per_asset_burst=20,
            per_asset_cooldown_seconds=60.0,
        )
        d = budget.to_dict()
        assert d["schema_version"] == 1
        assert d["max_requests"] == 100

    def test_run_health_record_v1(self):
        from src.core.models.vdp_contract import RunHealthRecord, RunTerminationState

        rec = RunHealthRecord(
            health_id="health-001",
            run_state=RunTerminationState.SUCCEEDED,
            reason="All checks passed",
        )
        d = rec.to_dict()
        assert d["schema_version"] == 1
        assert d["run_state"] == "succeeded"

    def test_all_termination_states_defined(self):
        from src.core.models.vdp_contract import RunTerminationState

        states = {e.value for e in RunTerminationState}
        assert "succeeded" in states
        assert "partial" in states
        assert "degraded" in states
        assert "safety_blocked" in states
        assert "failed" in states

    def test_all_capability_levels_defined(self):
        from src.core.models.vdp_contract import CapabilityLevel

        levels = {e.value for e in CapabilityLevel}
        assert "allowed" in levels
        assert "confirmation_required" in levels
        assert "prohibited" in levels
        assert "unavailable" in levels


# ============================================================================
# T-0419-03: Invalid state transition rejection
# ============================================================================

class TestStateTransitions:
    """Ensure invalid state transitions are rejected."""

    def test_hypothesis_must_not_go_directly_to_confirmed(self):
        from src.core.models.vdp_contract import HypothesisRecord

        rec = HypothesisRecord(
            hypothesis_id="hyp-003",
            observation_id="obs-003",
            asset="https://example.com",
            capability="xss_detector",
            hypothesis_text="XSS in search param",
            trust_boundary="query_parameter",
            actors=["unauthenticated"],
            success_condition="Alert box in response",
            falsification_condition="No script execution",
            required_evidence=["browser_execution"],
        )
        with pytest.raises(ValueError, match="Invalid state transition"):
            rec.transition_to("confirmed")

    def test_hypothesis_valid_transition_to_admitted(self):
        from src.core.models.vdp_contract import HypothesisRecord

        rec = HypothesisRecord(
            hypothesis_id="hyp-004",
            observation_id="obs-004",
            asset="https://example.com",
            capability="xss_detector",
            hypothesis_text="XSS in search param",
            trust_boundary="query_parameter",
            actors=["unauthenticated"],
            success_condition="Alert box in response",
            falsification_condition="No script execution",
            required_evidence=["browser_execution"],
        )
        rec.transition_to("admitted")
        assert rec.state == "admitted"

    def test_full_valid_state_chain(self):
        from src.core.models.vdp_contract import (
            HypothesisRecord,
            AttemptRecord,
            EvidenceRecordV1,
            EvidenceVerdictV1,
            NextActionRecord,
        )

        # observed -> hypothesized (constructor)
        hyp = HypothesisRecord(
            hypothesis_id="hyp-005",
            observation_id="obs-005",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="IDOR in user endpoint",
            trust_boundary="api_endpoint",
            actors=["authenticated_user"],
            success_condition="Other user data returned",
            falsification_condition="403 for other users",
            required_evidence=["response_comparison"],
        )
        # hypothesized -> admitted
        hyp.transition_to("admitted")

        # admitted -> attempted (AttemptRecord)
        att = AttemptRecord(
            attempt_id="att-005",
            hypothesis_id="hyp-005",
            actor="authenticated_user",
            request_fingerprint="sha256:xyz789",
            scope_verdict="allowed",
        )
        assert att.hypothesis_id == hyp.hypothesis_id

        # attempted -> evidence
        ev = EvidenceRecordV1(
            evidence_id="ev-005",
            attempt_id="att-005",
            evidence_type="real_http_response",
            raw_hash="sha256:raw123",
            redacted_excerpt="HTTP/1.1 200 OK...",
        )
        assert ev.attempt_id == att.attempt_id

        # evidence -> candidate verdict
        verdict = EvidenceVerdictV1(
            verdict_id="ver-005",
            hypothesis_id="hyp-005",
            _status="candidate",
            reason_codes=["insufficient_evidence"],
            evaluated_evidence_ids=["ev-005"],
        )
        assert verdict.hypothesis_id == hyp.hypothesis_id

        # verdict -> next_action
        na = NextActionRecord(
            next_action_id="na-005",
            verdict_id="ver-005",
            evidence_gap="Need response from second account",
            action_class="follow_up_probe",
            risk_class="read_only",
        )
        assert na.verdict_id == verdict.verdict_id


# ============================================================================
# T-0419-04: ID series traceability
# ============================================================================

class TestIdSeriesTraceability:
    """observation_id -> hypothesis_id -> attempt_id -> evidence_id -> verdict_id -> next_action_id"""

    def test_full_traceable_id_chain(self):
        from src.core.models.vdp_contract import HypothesisRecord, AttemptRecord, EvidenceRecordV1, EvidenceVerdictV1, NextActionRecord

        obs_id = "obs-trace-001"
        hyp = HypothesisRecord(hypothesis_id="hyp-trace-001", observation_id=obs_id,
                              asset="https://example.com", capability="test",
                              hypothesis_text="Test hypothesis", trust_boundary="test",
                              actors=["test"], success_condition="test",
                              falsification_condition="test", required_evidence=["test"])
        att = AttemptRecord(attempt_id="att-trace-001", hypothesis_id=hyp.hypothesis_id,
                           actor="test", request_fingerprint="sha256:test", scope_verdict="allowed")
        ev = EvidenceRecordV1(evidence_id="ev-trace-001", attempt_id=att.attempt_id,
                             evidence_type="real_http_response", raw_hash="sha256:test",
                             redacted_excerpt="test")
        verdict = EvidenceVerdictV1(verdict_id="ver-trace-001", hypothesis_id=hyp.hypothesis_id,
                                    _status="candidate", reason_codes=["test"],
                                    evaluated_evidence_ids=[ev.evidence_id])
        na = NextActionRecord(next_action_id="na-trace-001", verdict_id=verdict.verdict_id,
                             evidence_gap="test", action_class="test", risk_class="read_only")

        # Build trace chain
        chain = {
            "observation_id": obs_id,
            "hypothesis_id": hyp.hypothesis_id,
            "attempt_id": att.attempt_id,
            "evidence_id": ev.evidence_id,
            "verdict_id": verdict.verdict_id,
            "next_action_id": na.next_action_id,
        }
        # Verify chain integrity
        assert hyp.observation_id == chain["observation_id"]
        assert att.hypothesis_id == chain["hypothesis_id"]
        assert ev.attempt_id == chain["attempt_id"]
        assert verdict.hypothesis_id == chain["hypothesis_id"]
        assert ev.evidence_id in verdict.evaluated_evidence_ids
        assert na.verdict_id == chain["verdict_id"]


# ============================================================================
# T-0419-05: Scope re-evaluation blocking
# ============================================================================

class TestScopeRevalidation:
    """Scope indeterminate, out-of-scope, and redirect target changes must block communication."""

    def test_scope_indeterminate_fails_closed(self):
        from src.core.models.vdp_contract import ScopeRevalidationResult

        result = ScopeRevalidationResult.indeterminate("scope file not parseable")
        assert result.verdict == "scope_revalidation_blocked"
        assert result.allowed is False

    def test_scope_out_of_scope_fails_closed(self):
        from src.core.models.vdp_contract import ScopeRevalidationResult

        result = ScopeRevalidationResult.out_of_scope("target not in scope rules")
        assert result.verdict == "out_of_scope"
        assert result.allowed is False

    def test_scope_redirect_target_changes_fails(self):
        from src.core.models.vdp_contract import ScopeRevalidationResult

        result = ScopeRevalidationResult.redirect_to_out_of_scope(
            original="https://example.com/test",
            redirected_to="https://other.com/test"
        )
        assert result.verdict == "redirect_out_of_scope"
        assert result.allowed is False

    def test_scope_allowed_passes(self):
        from src.core.models.vdp_contract import ScopeRevalidationResult

        result = ScopeRevalidationResult.allow()
        assert result.verdict == "allowed"
        assert result.allowed is True


# ============================================================================
# T-0419-06: ProgramCapabilityMatrix HITL requirement
# ============================================================================

class TestHITLRequirement:
    """confirmation_required must not proceed without HITL ticket ID."""

    def test_confirmation_required_without_ticket_rejected(self):
        from src.core.models.vdp_contract import ProgramCapabilityMatrix, CapabilityLevel

        pcm = ProgramCapabilityMatrix(
            matrix_version=1,
            rules={"idor_detector": CapabilityLevel.CONFIRMATION_REQUIRED},
        )
        from src.core.models.vdp_contract import check_admission

        result = check_admission(
            capability="idor_detector",
            capability_matrix=pcm,
            scope_verdict="allowed",
            hitl_ticket_id=None,
        )
        assert result.admitted is False
        assert result.reason_code == "hitl_required"

    def test_confirmation_required_with_ticket_allowed(self):
        from src.core.models.vdp_contract import ProgramCapabilityMatrix, CapabilityLevel, check_admission

        pcm = ProgramCapabilityMatrix(
            matrix_version=1,
            rules={"idor_detector": CapabilityLevel.CONFIRMATION_REQUIRED},
        )
        result = check_admission(
            capability="idor_detector",
            capability_matrix=pcm,
            scope_verdict="allowed",
            hitl_ticket_id="ticket-123",
        )
        assert result.admitted is True

    def test_prohibited_always_rejected(self):
        from src.core.models.vdp_contract import ProgramCapabilityMatrix, CapabilityLevel, check_admission

        pcm = ProgramCapabilityMatrix(
            matrix_version=1,
            rules={"rce": CapabilityLevel.PROHIBITED},
        )
        result = check_admission(
            capability="rce",
            capability_matrix=pcm,
            scope_verdict="allowed",
            hitl_ticket_id="ticket-456",
        )
        assert result.admitted is False
        assert result.reason_code == "capability_prohibited"


# ============================================================================
# T-0419-07: Recursive secret redaction (depth >= 2)
# ============================================================================

class TestDeepSecretRedaction:
    """Secrets nested at depth 2+ in dicts/lists must be redacted."""

    def test_nested_dict_secret_redacted(self):
        from src.core.models.vdp_contract import redact_secrets_deep

        payload = {
            "request": {
                "headers": {
                    "Authorization": "Bearer secret-token-12345",
                    "Cookie": "session=abc123",
                },
                "body": "normal data",
            }
        }
        result = redact_secrets_deep(payload)
        # Assert secrets are redacted at depth 2
        assert result["request"]["headers"]["Authorization"] == "[REDACTED]"
        assert result["request"]["headers"]["Cookie"] == "[REDACTED]"
        assert result["request"]["body"] == "normal data"

    def test_nested_list_secret_redacted(self):
        from src.core.models.vdp_contract import redact_secrets_deep

        payload = {
            "attempts": [
                {"auth": {"token": "secret-abc", "url": "https://example.com"}},
                {"auth": {"token": "secret-def", "url": "https://other.com"}},
            ]
        }
        result = redact_secrets_deep(payload)
        assert result["attempts"][0]["auth"]["token"] == "[REDACTED]"
        assert result["attempts"][1]["auth"]["token"] == "[REDACTED]"
        assert result["attempts"][0]["auth"]["url"] == "https://example.com"

    def test_source_refs_secret_redacted(self):
        from src.core.models.vdp_contract import redact_secrets_deep

        payload = {
            "source_refs": [
                {"credential": {"api_key": "sk-live-abcdef1234567890"}},
            ]
        }
        result = redact_secrets_deep(payload)
        # "credential" key is a secret key, so its entire value is redacted
        assert result["source_refs"][0]["credential"] == "[REDACTED]"

    def test_secret_in_cookies_value(self):
        from src.core.models.vdp_contract import redact_secrets_deep

        payload = {
            "response": {
                "set_cookie": "session_id=xyz789secure; HttpOnly; Secure",
            }
        }
        result = redact_secrets_deep(payload)
        assert "xyz789secure" not in str(result)
        assert "[REDACTED]" in result["response"]["set_cookie"]

    def test_session_id_preserved_not_redacted(self):
        """session_id must NOT be redacted — needed for session resume."""
        from src.core.models.vdp_contract import redact_secrets_deep

        payload = {
            "session_id": "sess-resume-12345",
            "data": "visible",
        }
        result = redact_secrets_deep(payload)
        # session_id must be preserved for resume
        assert result["session_id"] == "sess-resume-12345"
        assert result["data"] == "visible"

    def test_x_api_key_in_headers_redacted(self):
        """X-API-Key header value must be fully removed."""
        from src.core.models.vdp_contract import redact_secrets_deep

        payload = {
            "headers": {
                "X-API-Key": "secret123",
                "Content-Type": "application/json",
            },
        }
        result = redact_secrets_deep(payload)
        # X-API-Key is a secret key, so its entire value is "[REDACTED]"
        assert result["headers"]["X-API-Key"] == "[REDACTED]"
        # Content-Type must be preserved
        assert result["headers"]["Content-Type"] == "application/json"

    def test_redact_http_headers_specific_function(self):
        """redact_http_headers must redact sensitive headers only."""
        from src.core.models.vdp_contract import redact_http_headers

        headers = {
            "Authorization": "Bearer token123",
            "Cookie": "session=abc",
            "X-API-Key": "key-secret",
            "Set-Cookie": "session=xyz",
            "Proxy-Authorization": "Basic creds",
            "Content-Type": "application/json",
            "Accept": "text/html",
            "User-Agent": "Shigoku/1.0",
        }
        result = redact_http_headers(headers)

        # Sensitive headers redacted
        assert result["Authorization"] == "[REDACTED]"
        assert result["Cookie"] == "[REDACTED]"
        assert result["X-API-Key"] == "[REDACTED]"
        assert result["Set-Cookie"] == "[REDACTED]"
        assert result["Proxy-Authorization"] == "[REDACTED]"
        # Non-sensitive headers preserved
        assert result["Content-Type"] == "application/json"
        assert result["Accept"] == "text/html"
        assert result["User-Agent"] == "Shigoku/1.0"

    def test_redact_http_headers_case_insensitive(self):
        """redact_http_headers must be case-insensitive for header names."""
        from src.core.models.vdp_contract import redact_http_headers

        headers = {
            "authorization": "secret1",
            "AUTHORIZATION": "secret2",
            "x-api-key": "secret3",
        }
        result = redact_http_headers(headers)
        assert result["authorization"] == "[REDACTED]"
        assert result["AUTHORIZATION"] == "[REDACTED]"
        assert result["x-api-key"] == "[REDACTED]"

    def test_redact_http_headers_does_not_mutate_original(self):
        """redact_http_headers must not mutate the input dict."""
        from src.core.models.vdp_contract import redact_http_headers

        original = {"Authorization": "secret-token", "Accept": "text/html"}
        _result = redact_http_headers(original)
        assert original["Authorization"] == "secret-token"


# ============================================================================
# T-0419-08: Large evidence truncation with hash/original_size
# ============================================================================

class TestLargeEvidenceTruncation:
    """Large evidence must be truncated with hash and original size preserved."""

    def test_evidence_truncation_preserves_hash_and_size(self):
        from src.core.models.vdp_contract import truncate_evidence_body

        large_body = "A" * (2 * 1024 * 1024)  # 2MB
        result = truncate_evidence_body(large_body, max_bytes=1024 * 1024)  # 1MB limit

        assert len(result["truncated_body"]) <= 1024 * 1024
        assert result["original_size"] == len(large_body)
        assert result["truncated"] is True
        assert "truncation_reason" in result
        # Hash must be of the original body
        expected_hash = "sha256:" + hashlib.sha256(large_body.encode("utf-8")).hexdigest()
        assert result["original_hash"] == expected_hash

    def test_small_evidence_not_truncated(self):
        from src.core.models.vdp_contract import truncate_evidence_body

        small_body = "Small response body"
        result = truncate_evidence_body(small_body, max_bytes=1024 * 1024)

        assert result["truncated"] is False
        assert result["original_size"] == len(small_body)
        assert result["truncated_body"] == small_body


# ============================================================================
# T-0419-09: Bounded queue backpressure
# ============================================================================

class TestBoundedAsyncWriter:
    """Queue saturation must not silently discard evidence."""

    @pytest.mark.asyncio
    async def test_queue_full_transitions_to_degraded(self):
        # This test verifies the bounded-queue contract.
        # Actual async writer implementation is in Step 4.
        from src.core.models.vdp_contract import EvidenceQueueBackpressureError

        # The error type must exist and carry evidence info
        err = EvidenceQueueBackpressureError(
            evidence_id="ev-bp-001",
            queue_size=100,
            max_size=100,
        )
        assert "ev-bp-001" in str(err)
        assert "100" in str(err)


# ============================================================================
# T-0419-10: Checkpoint, atomic save, idempotency
# ============================================================================

class TestCheckpointAndRecovery:
    """Checkpoint integrity, atomic save, idempotent IDs, and resume."""

    def test_checkpoint_serialization_roundtrip(self):
        from src.core.models.vdp_contract import VdpCheckpoint

        ck = VdpCheckpoint(
            checkpoint_id="ck-001",
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
        assert restored.state == ck.state
        assert restored.budget_snapshot == ck.budget_snapshot

    def test_checkpoint_atomic_write_and_read(self):
        from src.core.models.vdp_contract import atomic_write_checkpoint, read_checkpoint

        ck_data = {
            "checkpoint_id": "ck-002",
            "hypothesis_id": "hyp-002",
            "last_completed_attempt_id": "att-005",
            "budget_snapshot": {"requests_used": 10},
            "state": "partial",
            "vdp_contract_version": 1,
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "checkpoint.json"
            atomic_write_checkpoint(ck_data, ck_path)
            assert ck_path.exists()

            restored = read_checkpoint(ck_path)
            assert restored is not None
            assert restored["checkpoint_id"] == "ck-002"
            assert restored["state"] == "partial"

    def test_read_missing_checkpoint_returns_none(self):
        from src.core.models.vdp_contract import read_checkpoint

        result = read_checkpoint(Path("/nonexistent/checkpoint.json"))
        assert result is None

    def test_read_corrupt_checkpoint_returns_none(self):
        from src.core.models.vdp_contract import read_checkpoint, atomic_write_checkpoint

        with tempfile.TemporaryDirectory() as tmpdir:
            ck_path = Path(tmpdir) / "corrupt.json"
            # Write invalid JSON
            ck_path.write_text("{invalid json")

            result = read_checkpoint(ck_path)
            assert result is None

    def test_idempotent_attempt_id_prevention(self):
        """Same attempt_id added twice should not create duplicate."""
        from src.core.models.vdp_contract import IdempotencyGuard

        guard = IdempotencyGuard()
        assert guard.register("att-001") is True  # First time: ok
        assert guard.register("att-001") is False  # Second time: blocked
        assert guard.register("att-002") is True   # Different ID: ok

    def test_double_state_change_prevention(self):
        """State change requests with 'sent-but-not-saved' must not auto-retry."""
        from src.core.models.vdp_contract import StateChangeGuard

        guard = StateChangeGuard()
        # Mark as sent but not yet confirmed saved
        guard.mark_sent("attempt-att-010")
        # On resume, re-request same state change
        with pytest.raises(ValueError, match="not confirmed saved"):
            guard.prevent_double_send("attempt-att-010")

        # After confirming saved, it can proceed
        guard.confirm_saved("attempt-att-010")
        # Now it should be allowed (no error raised)
        guard.prevent_double_send("attempt-att-010")  # should not raise


# ============================================================================
# T-0419-11: Old session compatibility
# ============================================================================

class TestOldSessionCompatibility:
    """Reader must handle missing fields and unknown fields gracefully."""

    def test_hypothesis_record_reader_ignores_unknown_fields(self):
        from src.core.models.vdp_contract import HypothesisRecord

        old_data = {
            "hypothesis_id": "old-hyp-001",
            "observation_id": "old-obs-001",
            "asset": "https://example.com",
            "capability": "test",
            "hypothesis_text": "test",
            "trust_boundary": "test",
            "actors": ["test"],
            "success_condition": "test",
            "falsification_condition": "test",
            "required_evidence": ["test"],
            "state": "hypothesized",
            "schema_version": 1,
            "unknown_legacy_field": "should be ignored",
            "another_new_field": 42,
        }
        rec = HypothesisRecord.from_dict(old_data)
        assert rec.hypothesis_id == "old-hyp-001"
        assert rec.state == "hypothesized"

    def test_hypothesis_record_reader_fills_missing_fields_with_defaults(self):
        from src.core.models.vdp_contract import HypothesisRecord

        minimal_data = {
            "hypothesis_id": "min-hyp-001",
            "observation_id": "min-obs-001",
            "asset": "https://example.com",
            "capability": "test",
            "hypothesis_text": "test",
            "trust_boundary": "test",
            "actors": ["test"],
            "success_condition": "test",
            "falsification_condition": "test",
            "required_evidence": ["test"],
        }
        rec = HypothesisRecord.from_dict(minimal_data)
        assert rec.hypothesis_id == "min-hyp-001"
        assert rec.state == "hypothesized"  # default
        assert rec.preconditions == {}
        assert rec.controls == []

    def test_evidence_verdict_reader_handles_old_format(self):
        from src.core.models.vdp_contract import EvidenceVerdictV1

        old_data = {
            "verdict_id": "old-ver-001",
            "hypothesis_id": "old-hyp-001",
            "status": "confirmed",
            "reason_codes": ["payload_matched"],
            "evaluated_evidence_ids": ["ev-001"],
        }
        # Confirmed status in serialized data is REJECTED — must be re-validated
        with pytest.raises(ValueError, match="confirmed"):
            EvidenceVerdictV1.from_dict(old_data)


# ============================================================================
# T-0419-12: No active communication increase
# ============================================================================

class TestNoActiveCommunication:
    """Verify that SGK-2026-0419 does NOT introduce new active network calls."""

    def test_vdp_contract_has_no_network_calls(self):
        """All contract classes must be pure data models with no network I/O."""
        from src.core.models.vdp_contract import (
            HypothesisRecord, AttemptRecord, EvidenceRecordV1,
            EvidenceVerdictV1, NextActionRecord, ProgramCapabilityMatrix,
            ExecutionBudgetV1, RunHealthRecord,
        )

        # All of these are pure dataclasses with to_dict/from_dict
        # No __init__ or methods should open sockets or make HTTP calls
        import inspect
        forbidden_methods = {"requests.get", "requests.post", "urllib", "socket.", "aiohttp", "httpx"}
        for cls in [HypothesisRecord, AttemptRecord, EvidenceRecordV1, EvidenceVerdictV1,
                     NextActionRecord, ProgramCapabilityMatrix, ExecutionBudgetV1, RunHealthRecord]:
            source = inspect.getsource(cls)
            for forbidden in forbidden_methods:
                assert forbidden not in source, f"{cls.__name__} contains forbidden network call: {forbidden}"


# ============================================================================
# T-0420: SGK-2026-0420 additive hypothesis generation extensions
# ============================================================================

class TestHypothesisRecordV0420Additive:
    """Additive fields on HypothesisRecord for v0420 hypothesis generation."""

    def test_old_0419_dict_reads_with_new_defaults(self):
        """Old-session dict (no new fields) must be readable; new fields get defaults."""
        from src.core.models.vdp_contract import HypothesisRecord

        old_data = {
            "hypothesis_id": "old-hyp-0420",
            "observation_id": "old-obs-0420",
            "asset": "https://example.com",
            "capability": "test",
            "hypothesis_text": "test hypothesis",
            "trust_boundary": "test",
            "actors": ["test"],
            "success_condition": "test",
            "falsification_condition": "test",
            "required_evidence": ["test"],
            "state": "hypothesized",
            "schema_version": 1,
        }
        rec = HypothesisRecord.from_dict(old_data)
        assert rec.hypothesis_id == "old-hyp-0420"
        assert rec.resource_owner == ""
        assert rec.dedup_key == ""
        assert rec.generator_version == ""
        assert rec.risk_class == ""
        assert rec.scope_verdict == ""
        assert rec.budget_estimate == {}
        assert rec.observation_ids == []

    def test_old_record_passes_v1_validator(self):
        """Old 0419 record must pass the v1 validate_hypothesis_record()."""
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record

        rec = HypothesisRecord(
            hypothesis_id="v1-hyp-0420",
            observation_id="v1-obs-0420",
            asset="https://example.com",
            capability="test",
            hypothesis_text="test hypothesis v1",
            trust_boundary="test",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
        )
        errors = validate_hypothesis_record(rec)
        assert errors == []

    def test_new_full_record_passes_v0420_validator(self):
        """Fully populated record must pass validate_hypothesis_record_v0420()."""
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-001",
            observation_id="obs-v0420-001",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="IDOR in user endpoint may leak data",
            trust_boundary="api_endpoint",
            actors=["authenticated_user"],
            controls=["baseline:access_control", "attack:change_user_id", "inverse:restricted_data"],
            success_condition="Other user data returned",
            falsification_condition="403 for other users",
            required_evidence=["response_comparison"],
            priority_trace=["P2"],
            resource_owner="program_x",
            dedup_key="asset:cap:obs-001",
            generator_version="gen-v2.1.0",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 10, "follow_ups": 3},
            observation_ids=["obs-v0420-001"],
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert errors == []

    def test_v0420_missing_resource_owner_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-002",
            observation_id="obs-v0420-002",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            dedup_key="key-1",
            generator_version="gen-v1",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=["obs-v0420-002"],
            resource_owner="",
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("resource_owner" in e.lower() for e in errors)

    def test_v0420_missing_dedup_key_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-003",
            observation_id="obs-v0420-003",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            generator_version="gen-v1",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=["obs-v0420-003"],
            dedup_key="",
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("dedup_key" in e.lower() for e in errors)

    def test_v0420_missing_generator_version_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-004",
            observation_id="obs-v0420-004",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-1",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=["obs-v0420-004"],
            generator_version="",
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("generator_version" in e.lower() for e in errors)

    def test_v0420_invalid_risk_class_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-005",
            observation_id="obs-v0420-005",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-1",
            generator_version="gen-v1",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=["obs-v0420-005"],
            risk_class="invalid_risk",
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("risk_class" in e.lower() for e in errors)

    def test_v0420_invalid_scope_verdict_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-006",
            observation_id="obs-v0420-006",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-1",
            generator_version="gen-v1",
            risk_class="read_only",
            budget_estimate={"requests": 5},
            observation_ids=["obs-v0420-006"],
            scope_verdict="invalid_scope",
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("scope_verdict" in e.lower() for e in errors)

    def test_v0420_empty_budget_estimate_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-007",
            observation_id="obs-v0420-007",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-1",
            generator_version="gen-v1",
            risk_class="read_only",
            scope_verdict="allowed",
            observation_ids=["obs-v0420-007"],
            budget_estimate={},
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("budget_estimate" in e.lower() for e in errors)

    def test_v0420_empty_observation_ids_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-008",
            observation_id="obs-v0420-008",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-1",
            generator_version="gen-v1",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=[],
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("observation_ids" in e.lower() for e in errors)

    def test_v0420_observation_ids_first_mismatch_errors(self):
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-009",
            observation_id="obs-v0420-009",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-1",
            generator_version="gen-v1",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=["different-obs-id", "obs-v0420-009"],
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert any("observation_ids[0]" in e.lower() for e in errors)

    def test_new_fields_roundtrip_in_to_dict(self):
        """New fields must appear in to_dict() output."""
        from src.core.models.vdp_contract import HypothesisRecord

        rec = HypothesisRecord(
            hypothesis_id="hyp-v0420-010",
            observation_id="obs-v0420-010",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="test",
            trust_boundary="api_endpoint",
            actors=["test"],
            success_condition="test",
            falsification_condition="test",
            required_evidence=["test"],
            resource_owner="program_x",
            dedup_key="key-roundtrip",
            generator_version="gen-v1",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 5},
            observation_ids=["obs-v0420-010"],
        )
        d = rec.to_dict()
        assert d["resource_owner"] == "program_x"
        assert d["dedup_key"] == "key-roundtrip"
        assert d["generator_version"] == "gen-v1"
        assert d["risk_class"] == "read_only"
        assert d["scope_verdict"] == "allowed"
        assert d["budget_estimate"] == {"requests": 5}
        assert d["observation_ids"] == ["obs-v0420-010"]

    def test_new_fields_roundtrip_from_dict(self):
        """New fields must survive to_dict -> from_dict roundtrip."""
        from src.core.models.vdp_contract import HypothesisRecord

        data = {
            "hypothesis_id": "hyp-v0420-011",
            "observation_id": "obs-v0420-011",
            "asset": "https://example.com",
            "capability": "idor_detector",
            "hypothesis_text": "test",
            "trust_boundary": "api_endpoint",
            "actors": ["test"],
            "success_condition": "test",
            "falsification_condition": "test",
            "required_evidence": ["test"],
            "schema_version": 1,
            "resource_owner": "program_x",
            "dedup_key": "key-roundtrip",
            "generator_version": "gen-v1",
            "risk_class": "read_only",
            "scope_verdict": "allowed",
            "budget_estimate": {"requests": 5},
            "observation_ids": ["obs-v0420-011"],
        }
        rec = HypothesisRecord.from_dict(data)
        assert rec.resource_owner == "program_x"
        assert rec.dedup_key == "key-roundtrip"
        assert rec.generator_version == "gen-v1"
        assert rec.risk_class == "read_only"
        assert rec.scope_verdict == "allowed"
        assert rec.budget_estimate == {"requests": 5}
        assert rec.observation_ids == ["obs-v0420-011"]

    def test_v0420_valid_scope_verdicts(self):
        """All valid scope_verdict values pass v0420 validation."""
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        for verdict in ["allowed", "out_of_scope", "redirect_out_of_scope", "scope_revalidation_blocked"]:
            rec = HypothesisRecord(
                hypothesis_id=f"hyp-{verdict}",
                observation_id=f"obs-{verdict}",
                asset="https://example.com",
                capability="test",
                hypothesis_text="test",
                trust_boundary="test",
                actors=["test"],
                controls=["baseline:test", "attack:test", "inverse:test"],
                success_condition="test",
                falsification_condition="test",
                required_evidence=["test"],
                priority_trace=["P1"],
                resource_owner="program_x",
                dedup_key=f"key-{verdict}",
                generator_version="gen-v1",
                risk_class="read_only",
                scope_verdict=verdict,
                budget_estimate={"requests": 1},
                observation_ids=[f"obs-{verdict}"],
            )
            errors = validate_hypothesis_record_v0420(rec)
            assert errors == [], f"Failed for scope_verdict={verdict}: {errors}"

    def test_v0420_valid_risk_classes(self):
        """All valid risk_class values pass v0420 validation."""
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        for rc in ["read_only", "state_changing", "out_of_band"]:
            rec = HypothesisRecord(
                hypothesis_id=f"hyp-{rc}",
                observation_id=f"obs-{rc}",
                asset="https://example.com",
                capability="test",
                hypothesis_text="test",
                trust_boundary="test",
                actors=["test"],
                controls=["baseline:test", "attack:test", "inverse:test"],
                success_condition="test",
                falsification_condition="test",
                required_evidence=["test"],
                priority_trace=["P1"],
                resource_owner="program_x",
                dedup_key=f"key-{rc}",
                generator_version="gen-v1",
                risk_class=rc,
                scope_verdict="allowed",
                budget_estimate={"requests": 1},
                observation_ids=[f"obs-{rc}"],
            )
            errors = validate_hypothesis_record_v0420(rec)
            assert errors == [], f"Failed for risk_class={rc}: {errors}"

    # ── SGK-2026-0420 I-06: mandatory-field validation tests ──────────────────

    @pytest.mark.parametrize(
        "override,expected_substr",
        [
            # controls checks
            ({"controls": []}, "controls"),
            ({"controls": ["attack:test", "inverse:test"]}, "controls_missing_baseline"),
            ({"controls": ["baseline:test", "inverse:test"]}, "controls_missing_attack"),
            ({"controls": ["baseline:test", "attack:test"]}, "controls_missing_inverse"),
            # success / falsification conditions
            ({"success_condition": ""}, "success_condition_missing"),
            ({"falsification_condition": ""}, "falsification_condition_missing"),
            # list fields
            ({"required_evidence": []}, "required_evidence_missing"),
            ({"actors": []}, "actors_missing"),
            ({"priority_trace": []}, "priority_trace_missing"),
        ],
    )
    def test_v0420_mandatory_field_errors(self, override, expected_substr):
        """Each mandatory field missing should produce a specific error."""
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        base: dict[str, Any] = {
            "hypothesis_id": "hyp-i06",
            "observation_id": "obs-i06",
            "asset": "https://example.com",
            "capability": "idor_detector",
            "hypothesis_text": "test hypothesis",
            "trust_boundary": "api_endpoint",
            "actors": ["authenticated_user"],
            "controls": ["baseline:test", "attack:test", "inverse:test"],
            "success_condition": "Other user data returned",
            "falsification_condition": "403 for other users",
            "required_evidence": ["response_comparison"],
            "priority_trace": ["P2"],
            "resource_owner": "program_x",
            "dedup_key": "key-i06",
            "generator_version": "gen-v1",
            "risk_class": "read_only",
            "scope_verdict": "allowed",
            "budget_estimate": {"requests": 5},
            "observation_ids": ["obs-i06"],
        }
        base.update(override)
        rec = HypothesisRecord(**base)
        errors = validate_hypothesis_record_v0420(rec)
        assert any(expected_substr in e for e in errors), (
            f"Expected error containing '{expected_substr}', got: {errors}"
        )

    def test_v0420_full_record_passes_with_controls(self):
        """A complete record with all mandatory v1 fields + 3 controls passes."""
        from src.core.models.vdp_contract import HypothesisRecord, validate_hypothesis_record_v0420

        rec = HypothesisRecord(
            hypothesis_id="hyp-i06-full",
            observation_id="obs-i06-full",
            asset="https://example.com",
            capability="idor_detector",
            hypothesis_text="IDOR in user endpoint may leak data",
            trust_boundary="api_endpoint",
            actors=["authenticated_user"],
            controls=["baseline:access_control", "attack:change_user_id", "inverse:restricted_data"],
            success_condition="Other user data returned",
            falsification_condition="403 for other users",
            required_evidence=["response_comparison"],
            priority_trace=["P2"],
            resource_owner="program_x",
            dedup_key="asset:cap:obs-i06",
            generator_version="gen-v2.1.0",
            risk_class="read_only",
            scope_verdict="allowed",
            budget_estimate={"requests": 10, "follow_ups": 3},
            observation_ids=["obs-i06-full"],
        )
        errors = validate_hypothesis_record_v0420(rec)
        assert errors == [], f"Unexpected errors: {errors}"


class TestCanonicalJsonHelpers:
    """canonical_json_bytes and deterministic_id helper functions."""

    def test_canonical_json_bytes_sorted_keys(self):
        from src.core.models.vdp_contract import canonical_json_bytes

        a = {"b": 1, "a": 2}
        b = {"a": 2, "b": 1}
        assert canonical_json_bytes(a) == canonical_json_bytes(b)

    def test_canonical_json_bytes_nested_sorted(self):
        from src.core.models.vdp_contract import canonical_json_bytes

        a = {"outer": {"z": 9, "a": 1}}
        b = {"outer": {"a": 1, "z": 9}}
        assert canonical_json_bytes(a) == canonical_json_bytes(b)

    def test_canonical_json_bytes_no_whitespace(self):
        from src.core.models.vdp_contract import canonical_json_bytes
        import json as _json

        payload = {"key": "value", "nested": {"inner": 1}}
        result = canonical_json_bytes(payload)
        decoded = result.decode("utf-8")
        assert " " not in decoded
        assert "\n" not in decoded

    def test_deterministic_id_same_input_same_output(self):
        from src.core.models.vdp_contract import deterministic_id

        payload = {"key": "value", "nested": 42}
        id1 = deterministic_id("HYP", payload)
        id2 = deterministic_id("HYP", payload)
        assert id1 == id2

    def test_deterministic_id_different_input_different_output(self):
        from src.core.models.vdp_contract import deterministic_id

        id1 = deterministic_id("HYP", {"key": "a"})
        id2 = deterministic_id("HYP", {"key": "b"})
        assert id1 != id2

    def test_deterministic_id_has_prefix(self):
        from src.core.models.vdp_contract import deterministic_id

        result = deterministic_id("SGK", {"test": 1})
        assert result.startswith("SGK-")

    def test_deterministic_id_custom_length(self):
        from src.core.models.vdp_contract import deterministic_id

        result = deterministic_id("H", {}, length=8)
        assert result.startswith("H-")
        assert len(result) == len("H-") + 8
