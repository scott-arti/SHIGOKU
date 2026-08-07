"""
SGK-2026-0422 — legacy HMAC proof verifier tests (engine layer).

Covers the plan §4.4 legacy policy:
- legacy HMAC proofs are read explicitly as ``legacy`` (verification only)
- no NEW HMAC proof generation path exists
- fail-closed: no legacy key -> legacy_proof_unverifiable; key changed ->
  legacy_proof_key_changed; tag mismatch -> legacy_proof_tampered
- legacy confirmed verdicts restore only when the legacy proof verifies
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from src.core.engine.vdp_legacy_proof_verifier import (
    resolve_legacy_confirmation_key,
    verify_legacy_proof,
    restore_legacy_confirmed_verdict,
)
from src.core.models.vdp_contract import EvidenceVerdictV1

_TEST_LEGACY_KEY = "ab" * 32


def _legacy_proof(
    verdict_id: str = "ver-leg-001",
    hypothesis_id: str = "hyp-leg-001",
    evidence_ids=None,
    validator_version: str = "1.0.0",
    key: bytes | None = None,
) -> str:
    """Build a legacy hmac-sha256 proof exactly as the pre-0422 signer did."""
    import hashlib
    import hmac

    secret = key if key is not None else bytes.fromhex(_TEST_LEGACY_KEY)
    payload = "|".join(
        [
            verdict_id,
            hypothesis_id,
            ",".join(sorted(evidence_ids or ["ev-leg-001"])),
            validator_version,
        ]
    )
    tag = hmac.new(secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    key_id = hashlib.sha256(secret).hexdigest()[:8]
    return f"hmac-sha256:{key_id}:{tag}"


def _base_verdict(**overrides) -> dict:
    data = {
        "schema_version": 1,
        "verdict_id": "ver-leg-001",
        "hypothesis_id": "hyp-leg-001",
        "status": "confirmed",
        "reason_codes": ["payload_matched"],
        "evaluated_evidence_ids": ["ev-leg-001"],
        "validator_version": "1.0.0",
        "validation_proof": _legacy_proof(),
        "notes": [],
    }
    data.update(overrides)
    return data


class TestLegacyVerifierBasics:
    def test_module_has_no_generation_path(self):
        """verify_legacy_proof must be verification-only; no sign function."""
        import inspect

        import src.core.engine.vdp_legacy_proof_verifier as lv
        names = [n for n in dir(lv) if not n.startswith("__")]
        for forbidden in (
            "create",
            "sign",
            "compute_new",
            "generate",
        ):
            assert not any(forbidden in n for n in names), (
                f"legacy verifier must not expose a generation-like symbol: {forbidden}"
            )

    def test_legacy_key_resolution_from_env(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        assert resolve_legacy_confirmation_key() == bytes.fromhex(_TEST_LEGACY_KEY)

    def test_legacy_key_resolution_missing_fail_closed(self, monkeypatch):
        monkeypatch.delenv("SHIGOKU_VDP_CONFIRMATION_KEY", raising=False)
        monkeypatch.setattr(
            "src.core.engine.vdp_legacy_proof_verifier._CONFIRMATION_KEY_FILE",
            Path("/nonexistent/definitely/missing.key"),
        )
        assert resolve_legacy_confirmation_key() is None

    def test_legacy_proof_verified_with_key(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        result = verify_legacy_proof(
            "ver-leg-001", "hyp-leg-001", ["ev-leg-001"], "1.0.0", _legacy_proof()
        )
        assert result["verified"] is True
        assert result["reason_code"] == "legacy_proof_verified"

    def test_legacy_proof_unverifiable_without_key(self, monkeypatch):
        monkeypatch.delenv("SHIGOKU_VDP_CONFIRMATION_KEY", raising=False)
        monkeypatch.setattr(
            "src.core.engine.vdp_legacy_proof_verifier._CONFIRMATION_KEY_FILE",
            Path("/nonexistent/definitely/missing.key"),
        )
        result = verify_legacy_proof(
            "ver-leg-001", "hyp-leg-001", ["ev-leg-001"], "1.0.0", _legacy_proof()
        )
        assert result["verified"] is False
        assert result["reason_code"] == "legacy_proof_unverifiable"

    def test_legacy_proof_malformed_rejected(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        result = verify_legacy_proof(
            "v", "h", ["e"], "1.0.0", "ed25519:deadbeef:abc"
        )
        assert result["verified"] is False
        assert result["reason_code"] == "legacy_proof_malformed"

    def test_legacy_proof_key_changed_rejected(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        other_key = bytes.fromhex("cd" * 32)
        # Proof signed with a different key, verified against current key.
        proof = _legacy_proof(key=other_key)
        result = verify_legacy_proof("ver-leg-001", "hyp-leg-001", ["ev-leg-001"], "1.0.0", proof)
        assert result["verified"] is False
        assert result["reason_code"] == "legacy_proof_key_changed"

    def test_legacy_proof_tampered_rejected(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        proof = _legacy_proof()
        parts = proof.split(":")
        parts[2] = "0" * 64  # tamper the tag
        result = verify_legacy_proof("ver-leg-001", "hyp-leg-001", ["ev-leg-001"], "1.0.0", ":".join(parts))
        assert result["verified"] is False
        assert result["reason_code"] == "legacy_proof_tampered"


class TestLegacyRestore:
    def test_legacy_confirmed_restores_with_key(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        verdict = restore_legacy_confirmed_verdict(_base_verdict())
        assert isinstance(verdict, EvidenceVerdictV1)
        assert verdict.status == "confirmed"
        assert verdict.evaluated_evidence_ids == ["ev-leg-001"]

    def test_legacy_confirmed_unverifiable_fail_closed(self, monkeypatch):
        monkeypatch.delenv("SHIGOKU_VDP_CONFIRMATION_KEY", raising=False)
        monkeypatch.setattr(
            "src.core.engine.vdp_legacy_proof_verifier._CONFIRMATION_KEY_FILE",
            Path("/nonexistent/definitely/missing.key"),
        )
        with pytest.raises(ValueError, match="legacy_proof_unverifiable"):
            restore_legacy_confirmed_verdict(_base_verdict())

    def test_legacy_confirmed_tampered_fail_closed(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        d = _base_verdict()
        # Tamper a field that IS bound by the legacy tag (evidence_ids).
        d["evaluated_evidence_ids"] = ["ev-other"]
        with pytest.raises(ValueError, match="legacy_proof_tampered|legacy_proof"):
            restore_legacy_confirmed_verdict(d)

    def test_non_confirmed_passes_through_from_dict(self, monkeypatch):
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        d = _base_verdict(status="candidate", validation_proof="")
        verdict = restore_legacy_confirmed_verdict(d)
        assert verdict.status == "candidate"


class TestLegacyNoNewProofGeneration:
    def test_new_signer_never_emits_hmac(self):
        """The Ed25519 signer must never produce hmac-sha256 proofs."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("77" * 32))
        ev = {
            "schema_version": 1, "evidence_id": "ev-new", "attempt_id": "att-new",
            "evidence_type": "real_http_response", "raw_hash": "sha256:raw",
            "redacted_excerpt": "ok", "normalization_rule_version": "v1",
            "auth_context_version": "none", "captured_at": "", "original_size": 2,
            "truncated": False, "truncation_reason": "",
        }
        verdict = signer.create_confirmed_verdict(
            verdict_id="ver-new", hypothesis_id="hyp-new",
            reason_codes=["evidence_contract_satisfied"], validator_version="1.0.0", evidence_records=[ev],
        )
        assert verdict.validation_proof.startswith("ed25519:")
        assert "hmac-sha256" not in verdict.validation_proof

    def test_m0_gate_routes_legacy_proof_to_legacy_verifier(self, monkeypatch):
        """M0 gate restores legacy-hmac confirmed verdicts via the engine-side
        legacy verifier; without the legacy key it fails closed."""
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        from src.core.engine.master_conductor_session_service import inject_vdp_section_to_session_payload
        from src.core.models.vdp_contract import VDP_CONTRACT_SCHEMA_VERSION

        vdp_state = {
            "vdp_active": True,
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
            "hypotheses": [{
                "schema_version": 1, "hypothesis_id": "hyp-leg-001",
                "observation_id": "obs-leg-001", "asset": "a", "capability": "c",
                "hypothesis_text": "t", "trust_boundary": "b", "actors": ["a"],
                "success_condition": "s", "falsification_condition": "f",
                "required_evidence": ["e"], "state": "attempted",
            }],
            "attempts": [{
                "schema_version": 1, "attempt_id": "att-leg-001",
                "hypothesis_id": "hyp-leg-001", "actor": "a",
                "request_fingerprint": "fp", "scope_verdict": "allowed",
            }],
            "evidence_records": [{
                "schema_version": 1, "evidence_id": "ev-leg-001",
                "attempt_id": "att-leg-001", "evidence_type": "real_http_response",
            }],
            "verdicts": [_base_verdict()],
            "next_actions": [],
        }
        session = inject_vdp_section_to_session_payload({"task_queue": [], "context": {}}, vdp_state)

        # With the legacy key → M0 passes (legacy proof verified).
        monkeypatch.setenv("SHIGOKU_VDP_CONFIRMATION_KEY", _TEST_LEGACY_KEY)
        ok = VdpM0ContractGate().validate(session)
        assert ok.passed is True, ok.detail

        # Without the legacy key → M0 fails closed.
        monkeypatch.delenv("SHIGOKU_VDP_CONFIRMATION_KEY", raising=False)
        monkeypatch.setattr(
            "src.core.engine.vdp_legacy_proof_verifier._CONFIRMATION_KEY_FILE",
            Path("/nonexistent/definitely/missing.key"),
        )
        blocked = VdpM0ContractGate().validate(session)
        assert blocked.passed is False
        assert any("legacy_proof_unverifiable" in err for err in blocked.schema_errors)
