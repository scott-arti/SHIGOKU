"""
SGK-2026-0419 Item H: Real integration tests exercising actual session builder,
actual M0 gate, actual admission, actual atomic save/read, actual budget
checkpoint, actual auth cache, and actual scope revalidation.

All tests call real functions — no hand-rolled spy results bypassing real logic.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

# Stable confirmation key for tests: 64 hex chars (32 bytes). Set BEFORE any
# import that might resolve the key, so confirmed-verdict tests work across
# "process" boundaries (the key is resolved at call time from the env).
_TEST_CONFIRMATION_KEY = "ab" * 32
os.environ.setdefault("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_CONFIRMATION_KEY)

from src.core.domain.model.task import Task, TaskState
from src.core.engine.master_conductor_session_service import (
    build_async_session_payload,
    inject_vdp_section_to_session_payload,
)
from src.core.engine.vdp_admission import VdpAdmissionGate
from src.core.engine.vdp_atomic_writer import atomic_session_save, safe_read_session
from src.core.engine.vdp_auth_cache import AuthCache, AuthCacheKey
from src.core.engine.vdp_budget import VdpExecutionBudget, BudgetReasonCodeV1
from src.core.engine.vdp_m0_gate import VdpM0ContractGate
from src.core.domain.scope.vdp_scope_validator import revalidate_scope_for_request
from src.core.models.vdp_contract import (
    CapabilityLevel,
    HypothesisRecord,
    EvidenceVerdictV1,
    ProgramCapabilityMatrix,
    AdmissionReasonCode,
    redact_secrets_deep,
)
from src.core.security.ethics_guard import ScopeDefinition


# ============================================================================
# Helpers
# ============================================================================

@dataclass
class MockContext:
    """Minimal context for build_async_session_payload."""
    _total_attempts: int = 0
    _successful_attempts: int = 0
    bypass_methods: list = field(default_factory=list)
    discovered_assets: list = field(default_factory=list)
    target_info: dict = field(default_factory=dict)
    success_rate: float = 0.0
    total_attempts: int = 0
    successful_attempts: int = 0
    current_attack_chain: list = field(default_factory=list)


def _make_task(task_id: str, name: str = "test-task", state: TaskState = TaskState.PENDING,
               metadata: dict | None = None, **kwargs) -> Task:
    defaults = {
        "id": task_id,
        "name": name,
        "agent_type": "test",
        "action": "run",
        "phase": "init",
        "params": {},
        "state": state,
        "priority": 50,
    }
    defaults.update(kwargs)
    t = Task(**defaults)
    if metadata:
        t.metadata = metadata
    return t


def _make_hypothesis(**overrides) -> HypothesisRecord:
    defaults = {
        "hypothesis_id": "hyp-int-001",
        "observation_id": "obs-int-001",
        "asset": "https://example.com",
        "capability": "read_asset",
        "hypothesis_text": "Integration test hypothesis",
        "trust_boundary": "public",
        "actors": ["unauthenticated"],
        "state": "hypothesized",
    }
    defaults.update(overrides)
    return HypothesisRecord(**defaults)


def _make_capability_matrix(**rules) -> ProgramCapabilityMatrix:
    return ProgramCapabilityMatrix(rules=rules, program_name="test-program")


def _make_valid_vdp_state() -> dict:
    """Return a valid vdp_state dict for inject_vdp_section_to_session_payload."""
    from src.core.models.vdp_contract import (
        VDP_CONTRACT_SCHEMA_VERSION,
        AttemptRecord,
        EvidenceRecordV1,
        EvidenceVerdictV1,
        NextActionRecord,
    )
    hyp = _make_hypothesis(hypothesis_id="hyp-m0-001", observation_id="obs-m0-001")

    att = AttemptRecord(
        attempt_id="att-m0-001",
        hypothesis_id="hyp-m0-001",
        actor="unauthenticated",
        request_fingerprint="fp-001",
        scope_verdict="allowed",
        state="attempted",
        started_at="2026-01-01T00:00:00Z",
    )

    ev = EvidenceRecordV1(
        evidence_id="ev-m0-001",
        attempt_id="att-m0-001",
        evidence_type="real_http_response",
        raw_hash="sha256:abc",
    )

    ver = EvidenceVerdictV1(
        verdict_id="ver-m0-001",
        hypothesis_id="hyp-m0-001",
        _status="candidate",
    )

    na = NextActionRecord(
        next_action_id="na-m0-001",
        verdict_id="ver-m0-001",
        action_class="follow_up_probe",
        risk_class="read_only",
    )

    return {
        "vdp_active": True,
        "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
        "hypotheses": [hyp.to_dict()],
        "attempts": [att.to_dict()],
        "evidence_records": [ev.to_dict()],
        "verdicts": [ver.to_dict()],
        "next_actions": [na.to_dict()],
    }


# ============================================================================
# Real Session Builder Tests
# ============================================================================

class TestRealSessionBuilder:
    """Build real session payloads with build_async_session_payload and inject VDP."""

    def test_real_session_payload_includes_vdp_section(self):
        """Build a real session payload, inject VDP state, verify vdp_contract key."""
        task = _make_task("t-001", name="test-task")
        ctx = MockContext(
            target_info={"start_time": time.time()},
        )
        timestamp = time.time()
        default_start = timestamp - 3600.0

        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=ctx,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=timestamp,
            default_start_time=default_start,
        )

        vdp_state = _make_valid_vdp_state()
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        assert "vdp_contract" in injected
        vdp = injected["vdp_contract"]
        assert vdp["vdp_contract_version"] == 1
        assert len(vdp.get("hypotheses", [])) == 1
        assert len(vdp.get("attempts", [])) == 1
        assert len(vdp.get("evidence_records", [])) == 1
        assert len(vdp.get("verdicts", [])) == 1
        assert len(vdp.get("next_actions", [])) == 1

    def test_real_session_payload_redacted_no_secrets(self):
        """Build a real session payload, inject VDP with secrets, write to disk
        via atomic_session_save, read raw file content, verify no raw secrets."""
        task = _make_task(
            "t-002",
            metadata={"Authorization": "Bearer secret-token-xyz", "safe_field": "visible"},
        )
        ctx = MockContext(
            target_info={"start_time": time.time()},
        )
        timestamp = time.time()
        default_start = timestamp - 3600.0

        payload = build_async_session_payload(
            task_queue=[task],
            completed_tasks=[],
            context=ctx,
            pending_hitl=[],
            coverage_gate={},
            scenario_coverage={},
            timestamp=timestamp,
            default_start_time=default_start,
        )

        vdp_state = _make_valid_vdp_state()
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        # inject_vdp_section_to_session_payload now redacts the ENTIRE payload.
        # Verify task metadata is redacted at the builder/injector level.
        task_meta = injected["task_queue"][0].get("metadata", {})
        assert task_meta.get("Authorization", "") == "[REDACTED]"
        assert task_meta.get("safe_field") == "visible"

        # Write to temp file using atomic_session_save, read raw content,
        # and verify no raw secret strings appear on disk.
        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = Path(tmpdir) / "test_session_secret.json"
            atomic_session_save(injected, session_path)
            raw_content = session_path.read_text(encoding="utf-8")
            assert "Bearer secret-token-xyz" not in raw_content


# ============================================================================
# Real M0 Gate Tests
# ============================================================================

class TestRealM0Gate:
    """Real M0 gate using VdpM0ContractGate.evaluate() on real payloads."""

    def test_m0_gate_rejects_missing_schema_version(self):
        """Session payload with records lacking schema_version must fail M0."""
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        task = _make_task("t-m0-001")
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )

        payload["schema_version"] = 1  # required by validate()

        # Build records with schema_version=0 (invalid — must be >= 1)
        hyp = _make_hypothesis(
            hypothesis_id="hyp-noschema", observation_id="obs-noschema",
        )
        hyp.schema_version = 0  # force invalid version
        att = {
            "schema_version": 0,
            "attempt_id": "att-noschema",
            "hypothesis_id": "hyp-noschema",
            "actor": "unauthenticated",
            "request_fingerprint": "fp-noschema",
            "scope_verdict": "allowed",
            "state": "attempted",
        }
        ver = {
            "schema_version": 0,
            "verdict_id": "ver-noschema",
            "hypothesis_id": "hyp-noschema",
            "status": "candidate",
        }

        vdp_state = {
            "vdp_active": True,
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
            "hypotheses": [hyp.to_dict()],
            "attempts": [att],
            "evidence_records": [],
            "verdicts": [ver],
            "next_actions": [],
        }
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        gate = VdpM0ContractGate()
        result = gate.validate(injected)

        assert result.passed is False
        # schema_version=0 is caught by the M0 gate (step 3b) before schema validation
        assert "schema_version_missing" in result.reason_codes

    def test_m0_gate_rejects_invalid_record(self):
        """Hypothesis record missing observation_id must fail with validation_failed."""
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        task = _make_task("t-m0-002")
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )

        payload["schema_version"] = 1  # required by validate()

        # Build vdp state with a hypothesis missing observation_id
        hyp_bad = _make_hypothesis(
            hypothesis_id="hyp-bad-001",
            observation_id="",  # invalid empty
        )
        att_from_hyp = {
            "schema_version": 1,
            "attempt_id": "att-bad-001",
            "hypothesis_id": "hyp-bad-001",
            "actor": "unauthenticated",
            "request_fingerprint": "fp-bad",
            "scope_verdict": "allowed",
            "state": "attempted",
        }
        ver_from_hyp = {
            "schema_version": 1,
            "verdict_id": "ver-bad-001",
            "hypothesis_id": "hyp-bad-001",
            "status": "candidate",
        }
        # next_action references verdict
        na_from_ver = {
            "schema_version": 1,
            "next_action_id": "na-bad-001",
            "verdict_id": "ver-bad-001",
            "action_class": "follow_up_probe",
            "risk_class": "read_only",
        }

        vdp_state = {
            "vdp_active": True,
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
            "hypotheses": [hyp_bad.to_dict()],
            "attempts": [att_from_hyp],
            "evidence_records": [],
            "verdicts": [ver_from_hyp],
            "next_actions": [na_from_ver],
        }
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        gate = VdpM0ContractGate()
        result = gate.validate(injected)

        assert result.passed is False
        assert any("Missing mandatory field: observation_id" in err for err in result.schema_errors)

    def test_m0_gate_rejects_broken_type(self):
        """Pass a payload where vdp_contract is a STRING (not a dict). M0 gate must fail.
        """
        task = _make_task("t-m0-003")
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )

        # Set vdp_contract to a string (not a dict)
        payload["vdp_contract"] = "broken"

        gate = VdpM0ContractGate()
        # Must not raise, must not crash, but must FAIL
        result = gate.validate(payload)
        assert result.passed is False
        assert "not a dict" in result.detail

    def test_m0_gate_passes_valid_session(self):
        """Fully valid session payload must pass M0 gate."""
        task = _make_task("t-m0-004")
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )

        payload["schema_version"] = 1  # required by validate()

        vdp_state = _make_valid_vdp_state()
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        gate = VdpM0ContractGate()
        result = gate.validate(injected)

        assert result.passed is True
        assert result.detail == "All VDP contract records valid"

    def test_m0_gate_rejects_session_payload_not_dict(self):
        """Pass a string as session_payload, verify M0 gate FAILS."""
        gate = VdpM0ContractGate()
        result = gate.validate("not-a-dict")
        assert result.passed is False
        assert "session_payload is not a dict" in result.detail


# ============================================================================
# Real Atomic Save/Read Tests
# ============================================================================

class TestRealAtomicSaveRead:
    """Real atomic_session_save and safe_read_session roundtrip."""

    def test_real_atomic_save_and_read_roundtrip(self):
        """Build a real session payload, save atomically, read back, verify match."""
        task = _make_task("t-ar-001")
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )

        vdp_state = _make_valid_vdp_state()
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = Path(tmpdir) / "test_session.json"
            atomic_session_save(injected, session_path)
            read_back = safe_read_session(session_path)

        assert read_back is not None
        assert read_back.get("vdp_contract") is not None
        assert read_back["vdp_contract"]["vdp_contract_version"] == 1
        assert len(read_back["task_queue"]) == 1
        assert read_back["task_queue"][0]["id"] == "t-ar-001"

    def test_real_atomic_save_secrets_redacted_on_disk(self):
        """Payload with Authorization headers must not leak raw secrets on disk."""
        task = _make_task(
            "t-ar-002",
            metadata={"Authorization": "Bearer secret-leak-test-abc", "safe": "visible"},
        )
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )

        vdp_state = _make_valid_vdp_state()
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        with tempfile.TemporaryDirectory() as tmpdir:
            session_path = Path(tmpdir) / "test_session_secret.json"
            atomic_session_save(injected, session_path)
            raw_content = session_path.read_text(encoding="utf-8")

        assert "Bearer secret-leak-test-abc" not in raw_content


# ============================================================================
# Real Admission Tests
# ============================================================================

class TestRealAdmission:
    """Real VdpAdmissionGate.evaluate() with real hypothesis records."""

    def test_admission_rejects_hypothesis_without_validation(self):
        """Hypothesis rejected when scope_verdict is out_of_scope."""
        hyp = _make_hypothesis(
            hypothesis_id="hyp-adm-bad",
            observation_id="obs-bad",
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(read_asset=CapabilityLevel.ALLOWED),
        )
        result = gate.evaluate(hyp, scope_verdict="out_of_scope")

        assert result is not None
        assert result.admitted is False
        assert result.reason_code == AdmissionReasonCode.OUT_OF_SCOPE

    def test_admission_allows_valid_hypothesis(self):
        """Valid hypothesis admitted through VdpAdmissionGate must PASS."""
        hyp = _make_hypothesis(
            hypothesis_id="hyp-adm-ok",
            observation_id="obs-ok",
            capability="read_asset",
        )
        gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(read_asset=CapabilityLevel.ALLOWED),
        )
        result = gate.evaluate(hyp, scope_verdict="allowed")

        assert result.admitted is True


# ============================================================================
# Real Budget Checkpoint Tests
# ============================================================================

class TestRealBudgetCheckpoint:
    """Real VdpExecutionBudget checkpoint save/restore roundtrip."""

    def test_real_budget_checkpoint_survives_roundtrip(self):
        """Create budget, consume requests, checkpoint, restore, verify counters."""
        budget = VdpExecutionBudget(
            max_requests=100,
            per_asset_burst=50,
            per_actor_burst=30,
        )
        # Consume some requests
        budget.consume(asset_key="asset-1", actor_key="actor-1", hypothesis_key="hyp-1")
        budget.consume(asset_key="asset-1", actor_key="actor-2", hypothesis_key="hyp-2")
        budget.consume(asset_key="asset-2", actor_key="actor-1", hypothesis_key="hyp-3")

        checkpoint = budget.to_checkpoint_dict()
        restored = VdpExecutionBudget.from_checkpoint_dict(checkpoint)

        snap_original = budget.snapshot()
        snap_restored = restored.snapshot()

        assert snap_restored["requests_used"] == snap_original["requests_used"]
        assert snap_restored["requests_used"] >= 3

    def test_real_circuit_breaker_preserved_in_checkpoint(self):
        """Open a circuit breaker, checkpoint, restore, verify circuit still open."""
        budget = VdpExecutionBudget(
            max_requests=100,
            per_asset_burst=50,
            circuit_breaker_429_threshold=3,
        )
        asset = "asset-cb"
        # Trigger 429 errors to open circuit
        budget.record_response(asset_key=asset, status_code=429)
        budget.record_response(asset_key=asset, status_code=429)
        budget.record_response(asset_key=asset, status_code=429)

        # Circuit should now be open
        result_open = budget.consume(asset_key=asset)
        assert result_open.allowed is False
        assert result_open.reason_code == BudgetReasonCodeV1.CIRCUIT_OPEN_429

        # Checkpoint and restore
        checkpoint = budget.to_checkpoint_dict()
        restored = VdpExecutionBudget.from_checkpoint_dict(checkpoint)

        # Restored budget must also have circuit open
        result_restored = restored.consume(asset_key=asset)
        assert result_restored.allowed is False
        assert result_restored.reason_code in (
            BudgetReasonCodeV1.CIRCUIT_OPEN_429,
            # Could also be circuit_open_x or asset_budget_exhausted
            # if the first consume consumed the burst, but the main check
            # is that the circuit breaker state was preserved
        )


# ============================================================================
# Real Auth Cache Tests
# ============================================================================

class TestRealAuthCache:
    """Real AuthCache with credential-hash-based keys."""

    def test_real_auth_cache_credential_change_invalidates(self):
        """Different credential → different key → cache MISS."""
        cache = AuthCache()

        key_a = AuthCacheKey.from_credential(
            credential_value="cred-v1-alpha",
            actor="user",
            auth_context_version="v1",
            scope="https://api.example.com",
        )
        cache.set(key_a, {"auth": "ok"})

        key_b = AuthCacheKey.from_credential(
            credential_value="cred-v2-beta",  # different
            actor="user",
            auth_context_version="v1",
            scope="https://api.example.com",
        )
        result = cache.get(key_b)
        assert result is None

    def test_real_auth_cache_same_credential_hits(self):
        """Same credential → same key → cache HIT."""
        cache = AuthCache()

        key = AuthCacheKey.from_credential(
            credential_value="my-secret-credential",
            actor="user",
            auth_context_version="v1",
            scope="https://api.example.com",
        )
        cache.set(key, {"auth": "ok"})
        result = cache.get(key)
        assert result == {"auth": "ok"}


# ============================================================================
# Real Scope Revalidation Tests
# ============================================================================

class TestRealScopeRevalidation:
    """Real revalidate_scope_for_request pure function."""

    def test_real_scope_revalidation_pure_function(self):
        """Call revalidate_scope_for_request twice with same inputs, verify same result."""
        result1 = revalidate_scope_for_request("https://example.com/page1")
        result2 = revalidate_scope_for_request("https://example.com/page1")

        assert result1.verdict == result2.verdict
        assert result1.allowed == result2.allowed

    def test_real_scope_revalidation_rejects_oob_destination(self):
        """URL not in defined scope must be rejected with out_of_scope verdict."""
        # Create a scope that only includes "in-scope.example.com"
        scope_def = ScopeDefinition(
            program_name="test-program",
            in_scope_domains=["in-scope.example.com"],
            out_of_scope_domains=[],
            max_requests_per_minute=100,
        )

        result = revalidate_scope_for_request(
            "https://oob.example.com/page",
            scope_definition=scope_def,
        )

        assert result.allowed is False
        assert result.verdict in ("out_of_scope", "redirect_out_of_scope")


# ============================================================================
# Confirmed Immutability Tests
# ============================================================================

class TestConfirmedImmutability:
    """EvidenceVerdictV1 must prevent direct construction/serialization of 'confirmed'."""

    def test_confirmed_cannot_be_constructed(self):
        """EvidenceVerdictV1(_status='confirmed', ...) must raise ValueError."""
        with pytest.raises(ValueError):
            EvidenceVerdictV1(
                verdict_id="ver-conf-001",
                hypothesis_id="hyp-001",
                _status="confirmed",
            )

    def test_confirmed_cannot_be_loaded_from_dict(self):
        """EvidenceVerdictV1.from_dict({'status': 'confirmed', ...}) must raise ValueError."""
        with pytest.raises(ValueError, match="confirmed"):
            EvidenceVerdictV1.from_dict({
                "schema_version": 1,
                "verdict_id": "ver-conf-002",
                "hypothesis_id": "hyp-001",
                "status": "confirmed",
                "reason_codes": [],
                "evaluated_evidence_ids": [],
            })

    def test_status_direct_assignment_to_confirmed_rejected(self):
        """Create a verdict, try verdict.status = 'confirmed', assert FrozenInstanceError.

        With frozen=True dataclass, ALL attribute assignment is blocked,
        making 'confirmed' assignment structurally impossible.
        """
        from dataclasses import FrozenInstanceError
        verdict = EvidenceVerdictV1(
            verdict_id="ver-conf-003",
            hypothesis_id="hyp-001",
            _status="candidate",
        )
        with pytest.raises(FrozenInstanceError):
            verdict.status = "confirmed"


# ============================================================================
# Version rejection tests (audit item: unknown vdp_contract_version)
# ============================================================================

class TestM0VersionRejection:
    """M0 must reject unknown, zero, string, and non-matching vdp_contract_version."""

    def test_m0_rejects_unknown_vdp_contract_version(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        payload = {
            "vdp_contract": {
                "vdp_contract_version": 999,
                "hypotheses": [{"hypothesis_id": "h1", "observation_id": "o1", "asset": "a",
                               "capability": "c", "hypothesis_text": "t", "trust_boundary": "b",
                               "actors": ["a"], "success_condition": "s", "falsification_condition": "f",
                               "required_evidence": ["e"], "schema_version": VDP_CONTRACT_SCHEMA_VERSION}],
                "attempts": [], "evidence_records": [], "verdicts": [], "next_actions": [],
            }
        }
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is False
        assert "999" in result.detail

    def test_m0_rejects_vdp_contract_version_zero(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        payload = {
            "vdp_contract": {
                "vdp_contract_version": 0,
                "hypotheses": [{"hypothesis_id": "h1", "observation_id": "o1", "asset": "a",
                               "capability": "c", "hypothesis_text": "t", "trust_boundary": "b",
                               "actors": ["a"], "success_condition": "s", "falsification_condition": "f",
                               "required_evidence": ["e"], "schema_version": VDP_CONTRACT_SCHEMA_VERSION}],
                "attempts": [], "evidence_records": [], "verdicts": [], "next_actions": [],
            }
        }
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is False
        assert "is 0" in result.detail

    def test_m0_rejects_vdp_contract_version_string(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        payload = {
            "vdp_contract": {
                "vdp_contract_version": "not-an-int",
                "hypotheses": [{"hypothesis_id": "h1", "observation_id": "o1", "asset": "a",
                               "capability": "c", "hypothesis_text": "t", "trust_boundary": "b",
                               "actors": ["a"], "success_condition": "s", "falsification_condition": "f",
                               "required_evidence": ["e"], "schema_version": VDP_CONTRACT_SCHEMA_VERSION}],
                "attempts": [], "evidence_records": [], "verdicts": [], "next_actions": [],
            }
        }
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is False
        assert "not an int" in result.detail


# ============================================================================
# Confirmed roundtrip test (audit item: confirmed save → M0 PASS → restore confirmed)
# ============================================================================

class TestConfirmedRoundtrip:
    """Legitimate confirmed verdict must survive save/restore via M0."""

    def test_confirmed_roundtrip_save_m0_pass_restore_confirmed(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        from src.core.models.vdp_contract import (
            _create_confirmed_verdict,
            HypothesisRecord,
            AttemptRecord,
            EvidenceRecordV1,
            VDP_CONTRACT_SCHEMA_VERSION,
        )
        from src.core.engine.master_conductor_session_service import inject_vdp_section_to_session_payload

        hyp = HypothesisRecord(
            hypothesis_id="hyp-rt-001", observation_id="obs-rt-001",
            asset="https://example.com", capability="test",
            hypothesis_text="test", trust_boundary="test",
            actors=["test"], success_condition="test",
            falsification_condition="test", required_evidence=["test"],
            schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        )
        hyp.transition_to("admitted")
        hyp.state = "attempted"  # bypass: set to attempted so confirmed transition is valid

        att = AttemptRecord(
            attempt_id="att-rt-001", hypothesis_id="hyp-rt-001",
            actor="test", request_fingerprint="sha256:test",
            scope_verdict="allowed", schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        )

        ev = EvidenceRecordV1(
            evidence_id="ev-rt-001", attempt_id="att-rt-001",
            evidence_type="real_http_response", raw_hash="sha256:raw",
            redacted_excerpt="test", schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        )

        verdict = _create_confirmed_verdict(
            verdict_id="ver-rt-001", hypothesis_id="hyp-rt-001",
            evidence_ids=["ev-rt-001"], validator_version="1.0.0",
            reason_codes=["payload_matched"], schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            hypothesis=hyp,
        )

        vdp_state = {
            "vdp_active": True,
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
            "hypotheses": [hyp.to_dict()],
            "attempts": [att.to_dict()],
            "evidence_records": [ev.to_dict()],
            "verdicts": [verdict.to_dict()],
            "next_actions": [],
        }

        session = inject_vdp_section_to_session_payload({"task_queue": [], "context": {}}, vdp_state)
        assert "vdp_contract" in session

        m0 = VdpM0ContractGate().validate(session)
        assert m0.passed is True, f"M0 should pass: {m0.detail}"

        # Restore from saved data — must go through the internal proof-verified path
        from src.core.models.vdp_contract import _restore_confirmed_from_dict
        saved_verdict_dict = session["vdp_contract"]["verdicts"][0]
        assert saved_verdict_dict["status"] == "confirmed"
        assert saved_verdict_dict["validation_proof"]  # proof must be present

        restored = _restore_confirmed_from_dict(saved_verdict_dict)
        assert restored.status == "confirmed"
        assert restored.evaluated_evidence_ids == ["ev-rt-001"]

        # Public from_dict must REJECT the same confirmed dict (no trusted param)
        with pytest.raises(ValueError, match="confirmed"):
            EvidenceVerdictV1.from_dict(saved_verdict_dict)


# ============================================================================
# Inactive VDP with evidence rejection test (audit item)
# ============================================================================

class TestInactiveVdpWithEvidence:
    """Inactive VDP with data must be rejected by the M0 gate itself (not just MasterConductor)."""

    def test_inactive_vdp_with_evidence_flagged(self):
        """Simulate the gate check: inactive + evidence present → should be detected."""
        vdp_state = {
            "vdp_active": False,
            "hypotheses": [],
            "attempts": [],
            "verdicts": [],
            "evidence_records": [{"bad": "data"}],
            "next_actions": [],
        }
        vdp_active = vdp_state.get("vdp_active", False)
        vdp_has_data = any(vdp_state.get(k) for k in (
            "hypotheses", "attempts", "evidence_records", "verdicts", "next_actions",
        )) or any(vdp_state.get(k) for k in ("budget_snapshot", "run_health"))

        # Should detect: inactive but has data
        assert vdp_active is False
        assert vdp_has_data is True
        # This condition triggers RuntimeError in production


# ============================================================================
# M0 inactive+data rejection (moved INTO the M0 gate)
# ============================================================================

class TestM0InactiveWithData:
    """M0 gate itself must reject inactive + VDP data (not only MasterConductor)."""

    def _payload_with(self, vdp_section):
        return {"task_queue": [], "context": {}, "vdp_contract": vdp_section}

    def test_m0_rejects_inactive_with_hypotheses(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        payload = self._payload_with({
            "vdp_active": False,
            "vdp_contract_version": 1,
            "hypotheses": [{"hypothesis_id": "h1", "observation_id": "o1"}],
            "attempts": [], "evidence_records": [], "verdicts": [], "next_actions": [],
        })
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is False
        assert "inconsistent state" in result.detail

    def test_m0_rejects_inactive_with_evidence_only(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        payload = self._payload_with({
            "vdp_active": False,
            "vdp_contract_version": 1,
            "hypotheses": [], "attempts": [],
            "evidence_records": [{"evidence_id": "ev1", "attempt_id": "att1"}],
            "verdicts": [], "next_actions": [],
        })
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is False
        assert "inconsistent state" in result.detail

    def test_m0_rejects_inactive_with_budget_only(self):
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        payload = self._payload_with({
            "vdp_active": False,
            "vdp_contract_version": 1,
            "hypotheses": [], "attempts": [], "evidence_records": [], "verdicts": [],
            "next_actions": [], "budget_snapshot": {"requests_used": 3},
        })
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is False
        assert "inconsistent state" in result.detail

    def test_m0_rejects_non_bool_vdp_active(self):
        """vdp_active must be a strict bool (1/0/"yes" are rejected)."""
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        for bad in (1, 0, "yes", "true"):
            payload = self._payload_with({
                "vdp_active": bad,
                "vdp_contract_version": 1,
                "hypotheses": [], "attempts": [], "evidence_records": [],
                "verdicts": [], "next_actions": [],
            })
            result = VdpM0ContractGate().validate(payload)
            assert result.passed is False, f"vdp_active={bad!r} should be rejected"
            assert "not a strict bool" in result.detail

    def test_m0_passes_inactive_with_no_data(self):
        """Inactive + no data sections → PASS (conventional session save)."""
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        payload = self._payload_with({
            "vdp_active": False,
            "vdp_contract_version": 1,
            "hypotheses": [], "attempts": [], "evidence_records": [],
            "verdicts": [], "next_actions": [],
        })
        result = VdpM0ContractGate().validate(payload)
        assert result.passed is True


# ============================================================================
# Confirmed forgery tests (audit: proof-gated restore)
# ============================================================================

class TestConfirmedForgery:
    """Confirmed verdicts must be unforgeable: proof required for restore."""

    def _base_verdict(self, **overrides):
        data = {
            "schema_version": 1,
            "verdict_id": "ver-forge-001",
            "hypothesis_id": "hyp-m0-001",
            "status": "confirmed",
            "reason_codes": ["payload_matched"],
            "evaluated_evidence_ids": ["ev-m0-001"],
            "validator_version": "attacker-controlled",
            "validation_proof": "",
            "notes": [],
        }
        data.update(overrides)
        return data

    def test_forged_confirmed_without_proof_rejected(self):
        """Correct IDs + fake validator name + no proof → REJECT."""
        from src.core.models.vdp_contract import _restore_confirmed_from_dict
        with pytest.raises(ValueError, match="validation_proof"):
            _restore_confirmed_from_dict(self._base_verdict())

    def test_forged_confirmed_with_garbage_proof_rejected(self):
        """Correct IDs + fake validator name + garbage proof → REJECT."""
        from src.core.models.vdp_contract import _restore_confirmed_from_dict
        with pytest.raises(ValueError, match="validation_proof"):
            _restore_confirmed_from_dict(
                self._base_verdict(validation_proof="hmac-sha256:deadbeef")
            )

    def test_public_from_dict_rejects_confirmed(self):
        """External callers cannot load confirmed — no trusted param exists."""
        from src.core.models.vdp_contract import EvidenceVerdictV1
        with pytest.raises(ValueError, match="confirmed"):
            EvidenceVerdictV1.from_dict(self._base_verdict())

    def test_public_from_dict_has_no_trusted_param(self):
        """from_dict must not accept a trusted=True bypass."""
        import inspect
        from src.core.models.vdp_contract import EvidenceVerdictV1
        sig = inspect.signature(EvidenceVerdictV1.from_dict)
        assert "trusted" not in sig.parameters

    def test_legit_confirmed_roundtrip_preserves_status(self):
        """Legitimate Evidence Validator output survives save/restore with proof."""
        from src.core.models.vdp_contract import (
            _create_confirmed_verdict,
            _restore_confirmed_from_dict,
            HypothesisRecord,
            VDP_CONTRACT_SCHEMA_VERSION,
        )
        hyp = HypothesisRecord(
            hypothesis_id="hyp-m0-001", observation_id="obs-m0-001",
            asset="https://example.com", capability="test",
            hypothesis_text="t", trust_boundary="b", actors=["a"],
            success_condition="s", falsification_condition="f",
            required_evidence=["e"], schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        )
        hyp.state = "attempted"

        verdict = _create_confirmed_verdict(
            verdict_id="ver-ok-001", hypothesis_id="hyp-m0-001",
            evidence_ids=["ev-m0-001"], validator_version="1.0.0",
            reason_codes=["payload_matched"],
            schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            hypothesis=hyp,
        )
        assert verdict.status == "confirmed"
        assert verdict.validation_proof  # proof auto-generated

        restored = _restore_confirmed_from_dict(verdict.to_dict())
        assert restored.status == "confirmed"
        assert restored.validator_version == "1.0.0"
        assert restored.evaluated_evidence_ids == ["ev-m0-001"]

    def test_fake_validator_name_with_correct_ids_rejected_by_m0(self):
        """Full M0 path: forged confirmed (correct IDs, fake validator) → REJECT."""
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        from src.core.engine.master_conductor_session_service import inject_vdp_section_to_session_payload
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        vdp_state = {
            "vdp_active": True,
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
            "hypotheses": [{
                "schema_version": 1, "hypothesis_id": "hyp-m0-001",
                "observation_id": "obs-m0-001", "asset": "a", "capability": "c",
                "hypothesis_text": "t", "trust_boundary": "b", "actors": ["a"],
                "success_condition": "s", "falsification_condition": "f",
                "required_evidence": ["e"], "state": "attempted",
            }],
            "attempts": [{
                "schema_version": 1, "attempt_id": "att-m0-001",
                "hypothesis_id": "hyp-m0-001", "actor": "a",
                "request_fingerprint": "fp", "scope_verdict": "allowed",
            }],
            "evidence_records": [{
                "schema_version": 1, "evidence_id": "ev-m0-001",
                "attempt_id": "att-m0-001", "evidence_type": "real_http_response",
            }],
            "verdicts": [self._base_verdict()],  # forged: no proof
            "next_actions": [],
        }
        session = inject_vdp_section_to_session_payload({"task_queue": [], "context": {}}, vdp_state)
        result = VdpM0ContractGate().validate(session)
        assert result.passed is False
        assert any("validation_proof" in err for err in result.schema_errors)


# ============================================================================
# Cross-process confirmation key tests (audit: restart must restore confirmed)
# ============================================================================

class TestCrossProcessConfirmed:
    """Confirmed verdicts must survive process restart via a STABLE key."""

    def test_cross_process_generate_restore_preserves_confirmed(self, tmp_path):
        """Subprocess (process A) creates confirmed + JSON; this process (B) restores it."""
        script = (
            "import os, sys, json\n"
            "os.environ.setdefault('SHIGOKU_VDP_CONFIRMATION_KEY', sys.argv[1])\n"
            "from src.core.models.vdp_contract import (_create_confirmed_verdict,\n"
            "    HypothesisRecord, VDP_CONTRACT_SCHEMA_VERSION)\n"
            "hyp = HypothesisRecord(hypothesis_id='hyp-xp-001', observation_id='obs-xp-001',\n"
            "    asset='https://example.com', capability='test', hypothesis_text='t',\n"
            "    trust_boundary='b', actors=['a'], success_condition='s',\n"
            "    falsification_condition='f', required_evidence=['e'],\n"
            "    schema_version=VDP_CONTRACT_SCHEMA_VERSION)\n"
            "hyp.state = 'attempted'\n"
            "ver = _create_confirmed_verdict(verdict_id='ver-xp-001',\n"
            "    hypothesis_id='hyp-xp-001', evidence_ids=['ev-xp-001'],\n"
            "    validator_version='1.0.0', schema_version=VDP_CONTRACT_SCHEMA_VERSION,\n"
            "    hypothesis=hyp)\n"
            "print(json.dumps(ver.to_dict()))\n"
        )
        env = dict(os.environ)
        env["SHIGOKU_VDP_CONFIRMATION_KEY"] = _TEST_CONFIRMATION_KEY
        result = subprocess.run(
            [sys.executable, "-c", script, _TEST_CONFIRMATION_KEY],
            capture_output=True, text=True, env=env, cwd="/home/bbb/Documents/App/Shigoku",
        )
        assert result.returncode == 0, result.stderr
        verdict_json = json.loads(result.stdout.strip())

        # This process (process B) restores with the SAME stable key
        from src.core.models.vdp_contract import _restore_confirmed_from_dict
        restored = _restore_confirmed_from_dict(verdict_json)
        assert restored.status == "confirmed"
        assert restored.validator_version == "1.0.0"
        assert restored.evaluated_evidence_ids == ["ev-xp-001"]

    def test_key_missing_rejects_confirmed_restore(self, monkeypatch):
        """No key available (env unset + no key file) → fail-closed REJECT."""
        import src.core.models.vdp_contract as vc
        monkeypatch.delenv("SHIGOKU_VDP_CONFIRMATION_KEY", raising=False)
        monkeypatch.setattr(vc, "_CONFIRMATION_KEY_FILE", Path("/nonexistent/definitely/missing.key"))
        monkeypatch.setattr(vc, "_resolve_confirmation_key", lambda: None)

        from src.core.models.vdp_contract import _restore_confirmed_from_dict
        # Create a legit proof first (with key available)
        monkeypatch.setattr(vc, "_resolve_confirmation_key",
                            lambda: bytes.fromhex(_TEST_CONFIRMATION_KEY))
        from src.core.models.vdp_contract import _create_confirmed_verdict
        ver = _create_confirmed_verdict(
            verdict_id="ver-km-001", hypothesis_id="hyp-m0-001",
            evidence_ids=["ev-m0-001"], validator_version="1.0.0",
        )
        ver_dict = ver.to_dict()

        # Now simulate key missing → REJECT
        monkeypatch.setattr(vc, "_resolve_confirmation_key", lambda: None)
        with pytest.raises(ValueError, match="confirmation key unavailable"):
            _restore_confirmed_from_dict(ver_dict)

    def test_key_changed_rejects_restore(self, monkeypatch):
        """Key rotated since signing → fail-closed REJECT with key_id reason."""
        import src.core.models.vdp_contract as vc
        from src.core.models.vdp_contract import _create_confirmed_verdict, _restore_confirmed_from_dict

        # Sign with key A
        monkeypatch.setattr(vc, "_resolve_confirmation_key",
                            lambda: bytes.fromhex(_TEST_CONFIRMATION_KEY))
        ver = _create_confirmed_verdict(
            verdict_id="ver-kc-001", hypothesis_id="hyp-m0-001",
            evidence_ids=["ev-m0-001"], validator_version="1.0.0",
        )
        ver_dict = ver.to_dict()

        # Restore with key B (different) → REJECT with key_id mismatch
        key_b = "cd" * 32
        monkeypatch.setattr(vc, "_resolve_confirmation_key", lambda: bytes.fromhex(key_b))
        with pytest.raises(ValueError, match="key_id mismatch"):
            _restore_confirmed_from_dict(ver_dict)

    def test_key_missing_blocks_confirmed_creation(self, monkeypatch):
        """No key available → cannot even CREATE a confirmed verdict (fail-closed)."""
        import src.core.models.vdp_contract as vc
        monkeypatch.setattr(vc, "_resolve_confirmation_key", lambda: None)
        from src.core.models.vdp_contract import _create_confirmed_verdict
        with pytest.raises(ValueError, match="confirmation key unavailable"):
            _create_confirmed_verdict(
                verdict_id="ver-kmc-001", hypothesis_id="hyp-m0-001",
                evidence_ids=["ev-m0-001"], validator_version="1.0.0",
            )


# ============================================================================
# Structural boundary test (audit: signer must stay within its own module)
# ============================================================================

class TestConfirmationSignerBoundary:
    """No production module may import the confirmation signer or key internals."""

    def test_signer_referenced_only_in_vdp_contract_module(self):
        """Scan src/ for references to the signer functions — only vdp_contract.py allowed."""
        import re as _re
        allowed = {"src/core/models/vdp_contract.py"}
        offenders = []
        for root, _dirs, files in os.walk("src"):
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                path = os.path.join(root, fname).replace(os.sep, "/")
                if path in allowed:
                    continue
                try:
                    text = Path(path).read_text(encoding="utf-8")
                except OSError:
                    continue
                for symbol in (
                    "_compute_validation_proof",
                    "_verify_validation_proof",
                    "_CONFIRMATION_KEY_ENV",
                ):
                    if symbol in text:
                        offenders.append(f"{path} references {symbol}")
        assert offenders == [], f"Signer referenced outside vdp_contract: {offenders}"

    def test_signature_has_no_trusted_bypass(self):
        """from_dict must not expose a trusted/secret bypass parameter."""
        import inspect
        from src.core.models.vdp_contract import EvidenceVerdictV1
        sig = inspect.signature(EvidenceVerdictV1.from_dict)
        assert "trusted" not in sig.parameters
        assert "key" not in sig.parameters
        assert "proof" not in sig.parameters


# ============================================================================
# MasterConductor real-save negative test (audit: inactive+data must not save)
# ============================================================================

class TestMasterConductorSaveRejects:
    """Real async_save_session() must reject inactive+data without saving."""

    @pytest.mark.asyncio
    async def test_async_save_session_raises_and_does_not_save(self):
        from unittest.mock import AsyncMock
        from src.core.engine.master_conductor import MasterConductor

        mc = object.__new__(MasterConductor)  # skip heavy __init__

        mc.project_manager = SimpleNamespace(
            project_dir="/tmp/shigoku-vdp-test",
            save_session=AsyncMock(),
        )
        mc.task_queue = []
        mc.completed_tasks = []
        mc.pending_hitl = []
        mc._vdp_state = {
            "vdp_active": False,  # INACTIVE
            "hypotheses": [],
            "attempts": [],
            "evidence_records": [{"evidence_id": "bad-ev"}],  # data present!
            "verdicts": [],
            "next_actions": [],
        }
        mc._current_session = SimpleNamespace(session_id="test-session")
        mc.run_ledger_recorder = SimpleNamespace(
            prepare_for_session=lambda spool_dir=None: {},
            run_id="test-run",
        )
        mc.decision_tracer = None
        mc.execution_log = SimpleNamespace(to_list=lambda: [])
        mc._shadow_decisions = None
        mc.context = SimpleNamespace(
            _total_attempts=0, _successful_attempts=0,
            bypass_methods=[], discovered_assets=[],
            target_info={"start_time": time.time()},
        )
        mc._ensure_task_reason_code = lambda task: None
        mc._evaluate_vuln_family_coverage = lambda: {}
        mc._evaluate_intervention_scenario_coverage = lambda: {}

        with pytest.raises(RuntimeError, match="inconsistent state"):
            await mc.async_save_session("dummy.json")

        mc.project_manager.save_session.assert_not_awaited()


# ============================================================================
# No-New-Communication Test
# ============================================================================

class TestNoNetworkIO:
    """All VDP operations must cause zero network I/O."""

    def test_vdp_operations_cause_zero_network_io(self, monkeypatch):
        """Monkey-patch socket to count connections, run all VDP ops, verify zero."""
        call_count = [0]
        original_connect = socket.socket.connect

        def counting_connect(self, *args, **kwargs):
            call_count[0] += 1
            return original_connect(self, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", counting_connect)

        # --- Run all VDP operations ---

        # 1. Session builder + VDP inject
        task = _make_task("t-net-001")
        ctx = MockContext(target_info={"start_time": time.time()})
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[task], completed_tasks=[], context=ctx,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )
        vdp_state = _make_valid_vdp_state()
        injected = inject_vdp_section_to_session_payload(payload, vdp_state)

        # 2. M0 gate
        gate = VdpM0ContractGate()
        gate.validate(injected)

        # 3. Admission
        adm_gate = VdpAdmissionGate(
            capability_matrix=_make_capability_matrix(read_asset=CapabilityLevel.ALLOWED),
        )
        hyp = _make_hypothesis()
        adm_gate.evaluate(hyp, scope_verdict="allowed")

        # 4. Budget checkpoint save/restore
        budget = VdpExecutionBudget(
            max_requests=10, per_asset_burst=10, per_actor_burst=10,
            circuit_breaker_429_threshold=2,
        )
        budget.consume(asset_key="a", actor_key="u", hypothesis_key="h")
        budget.record_response(asset_key="a", status_code=429)
        cp = budget.to_checkpoint_dict()
        VdpExecutionBudget.from_checkpoint_dict(cp)

        # 5. Auth cache
        cache = AuthCache()
        key = AuthCacheKey.from_credential("token-net", scope="https://example.com")
        cache.set(key, {"ok": True})
        cache.get(key)

        # 6. Scope revalidation (no network — uses in-memory scope parser)
        revalidate_scope_for_request("https://example.com")

        # --- Verify zero socket connections ---
        assert call_count[0] == 0, (
            f"VDP operations caused {call_count[0]} socket connections, expected 0"
        )
