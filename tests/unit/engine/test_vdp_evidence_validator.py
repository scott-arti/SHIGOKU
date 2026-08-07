"""
SGK-2026-0422 — canonical Evidence Validator tests (T3).

Covers:
- confirmed ONLY when: real evidence present, attempt linkage, hypothesis
  contract complete (success/falsification/required_evidence), signer
  available
- a single EvidenceRecord alone is NOT enough (no contract, no real type,
  no raw_hash -> candidate/untested)
- timeout / auth loss / WAF / dependency stop / scope block / budget
  exhaustion are NEVER converted to refuted
- refuted ONLY on explicit falsification_met evidence
- signer unavailable -> candidate + hold reason (never confirmed)
- production wiring: _dispatch_vdp_follow_up -> Attempt/Evidence saved ->
  canonical validator -> proof verdict -> _vdp_state -> async_save_session ->
  M0 gate (integration tests)
"""
from __future__ import annotations

import pytest

from src.core.engine.vdp_evidence_validator import (
    REASON_EVIDENCE_MISSING,
    REASON_FALSIFICATION_MET,
    REASON_HYPOTHESIS_CONTRACT_INCOMPLETE,
    REASON_NO_REAL_RESPONSE,
    REASON_SIGNER_UNAVAILABLE,
    REASON_SYNTHETIC_ONLY,
    VdpEvidenceValidator,
)
from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
)


def _hypothesis(hypothesis_id: str = "hyp-001", *, complete: bool = True) -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        observation_id="obs-001",
        asset="https://example.com/items",
        capability="idor_detector",
        hypothesis_text="object read by another actor",
        trust_boundary="api_endpoint",
        actors=["authA", "authB"],
        success_condition="owner-only field visible to authB" if complete else "",
        falsification_condition="no owner/permission difference" if complete else "",
        required_evidence=["real_http_response", "authz_impact_not_proven"] if complete else [],
        state="attempted",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    )


def _attempt(
    attempt_id: str = "att-001",
    hypothesis_id: str = "hyp-001",
    *,
    scope_verdict: str = "allowed",
) -> AttemptRecord:
    return AttemptRecord(
        attempt_id=attempt_id,
        hypothesis_id=hypothesis_id,
        actor="authB",
        request_fingerprint="fp-001",
        scope_verdict=scope_verdict,
        state="evidence_saved",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        trigger_next_action_id="nxt-001",
    )


def _evidence(
    evidence_id: str = "ev-001",
    attempt_id: str = "att-001",
    *,
    evidence_type: str = "real_http_response",
    raw_hash: str = "sha256:" + "a" * 64,
    execution_result: dict | None = None,
    markers: dict | None = None,
) -> EvidenceRecordV1:
    result = dict(execution_result or {})
    if markers:
        result.update(markers)
    return EvidenceRecordV1(
        evidence_id=evidence_id,
        attempt_id=attempt_id,
        evidence_type=evidence_type,
        raw_hash=raw_hash,
        redacted_excerpt="HTTP/1.1 200 OK",
        normalization_rule_version="v1",
        auth_context_version="none",
        captured_at="2026-08-03T00:00:00Z",
        original_size=20,
        truncated=False,
        truncation_reason="",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        execution_result=result,
    )


class TestConfirmedConditions:
    def test_confirmed_with_complete_contract_and_signer(self):
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("21" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "confirmed"
        assert verdict.validation_proof.startswith("ed25519:")
        assert verdict.evaluated_evidence_ids == ["ev-001"]
        assert verdict.validator_version == validator.validator_version
        # D6: confirmed must carry a non-empty canonical reason code.
        assert verdict.reason_codes == ["evidence_contract_satisfied"]

    def test_success_condition_not_proven_stays_candidate(self):
        """A raw response without structured success markers must NOT be
        confirmed — the gap token authz_impact_not_proven stays unsatisfied
        (audit I-07: production 200 responses must not be promoted)."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("24" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence()],
        )
        assert verdict.status == "candidate"
        assert "success_condition_not_proven" in verdict.reason_codes
        assert verdict.validation_proof == ""

    def test_blanket_success_condition_met_field_not_accepted(self):
        """The legacy blanket execution_result.success_condition_met marker
        is NOT part of the structured marker vocabulary — a plain response
        carrying only that field must stay candidate (audit I-07 repro:
        ordinary_http_response_marker {'success_condition_met': 'true'})."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("26" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(execution_result={"success_condition_met": "true"})],
        )
        assert verdict.status == "candidate"
        assert "success_condition_not_proven" in verdict.reason_codes
        assert verdict.validation_proof == ""

    def test_gap_token_requires_its_own_structured_marker(self):
        """A marker for a DIFFERENT requirement must not satisfy
        authz_impact_not_proven (audit I-07)."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("27" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"state_change_verified": "true"})],
        )
        assert verdict.status == "candidate"
        assert "success_condition_not_proven" in verdict.reason_codes

    def test_unknown_requirement_token_fails_closed(self):
        """An unrecognized required_evidence token can never be satisfied —
        fail-closed candidate (audit I-07)."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("28" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        hyp = _hypothesis()
        hyp.required_evidence = ["mystery_requirement_token"]
        verdict = validator.evaluate(
            hyp,
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "candidate"
        assert "success_condition_not_proven" in verdict.reason_codes

    def test_required_evidence_type_mismatch_not_confirmed(self):
        """required_evidence=browser_execution with real_http_response
        evidence must stay candidate (audit I-01)."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("25" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        hyp = _hypothesis()
        hyp.required_evidence = ["browser_execution"]
        verdict = validator.evaluate(
            hyp,
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "candidate"
        assert "required_evidence_type_not_met" in verdict.reason_codes

    def test_single_evidence_without_contract_not_confirmed(self):
        """EvidenceRecord present but hypothesis contract incomplete -> candidate."""
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(
            _hypothesis(complete=False),
            [_attempt()],
            [_evidence()],
        )
        assert verdict.status == "candidate"
        assert REASON_HYPOTHESIS_CONTRACT_INCOMPLETE in verdict.reason_codes
        assert verdict.validation_proof == ""

    def test_synthetic_evidence_only_not_confirmed(self):
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(evidence_type="synthetic_detector_note")],
        )
        assert verdict.status == "candidate"
        assert REASON_NO_REAL_RESPONSE in verdict.reason_codes

    def test_evidence_without_raw_hash_not_confirmed(self):
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(raw_hash="")],
        )
        assert verdict.status == "candidate"
        assert REASON_NO_REAL_RESPONSE in verdict.reason_codes

    def test_no_evidence_untested(self):
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(_hypothesis(), [_attempt()], [])
        assert verdict.status == "untested"
        assert REASON_EVIDENCE_MISSING in verdict.reason_codes

    def test_evidence_of_other_hypothesis_not_counted(self):
        """Evidence belonging to a different hypothesis must not confirm."""
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(attempt_id="att-other")],
        )
        assert verdict.status == "untested"
        assert REASON_EVIDENCE_MISSING in verdict.reason_codes


class TestFailClosedSigner:
    def test_signer_unavailable_never_confirmed(self):
        """All evidence requirements satisfied but no signer → candidate with
        signer_unavailable_hold (never confirmed, never proof)."""
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "candidate"
        assert REASON_SIGNER_UNAVAILABLE in verdict.reason_codes
        assert verdict.validation_proof == ""

    def test_signer_unavailable_public_key_provider_none(self):
        validator = VdpEvidenceValidator(signer=None)
        assert validator.public_key_provider() is None

    def test_signer_available_public_key_provider(self):
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("22" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        provider = validator.public_key_provider()
        assert provider is not None
        assert signer.key_id in provider


class TestRefutedNeverFromInfra:
    def test_budget_exhaustion_not_refuted(self):
        """Budget exhaustion recorded on the attempt must never become refuted."""
        validator = VdpEvidenceValidator(signer=None)
        attempt = _attempt()
        attempt.execution_result = {"status": "budget_exhausted"}
        verdict = validator.evaluate(_hypothesis(), [attempt], [])
        assert verdict.status != "refuted"
        assert verdict.status in {"candidate", "untested"}

    def test_dependency_stop_not_refuted(self):
        validator = VdpEvidenceValidator(signer=None)
        attempt = _attempt()
        attempt.execution_result = {"status": "dependency_unavailable"}
        verdict = validator.evaluate(_hypothesis(), [attempt], [])
        assert verdict.status != "refuted"
        assert verdict.status in {"candidate", "untested"}

    def test_timeout_not_refuted(self):
        validator = VdpEvidenceValidator(signer=None)
        attempt = _attempt()
        attempt.execution_result = {"status": "timeout"}
        verdict = validator.evaluate(_hypothesis(), [attempt], [])
        assert verdict.status != "refuted"

    def test_scope_block_not_refuted(self):
        validator = VdpEvidenceValidator(signer=None)
        attempt = _attempt(scope_verdict="out_of_scope")
        verdict = validator.evaluate(_hypothesis(), [attempt], [])
        assert verdict.status != "refuted"

    def test_refuted_only_on_explicit_falsification(self):
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(execution_result={"falsification_met": "true"})],
        )
        assert verdict.status == "refuted"
        assert REASON_FALSIFICATION_MET in verdict.reason_codes


class TestUpsertSemantics:
    def test_same_hypothesis_no_duplicate_verdict_ids(self):
        """The validator produces one verdict per hypothesis evaluation; the
        MasterConductor upsert must never append duplicates (verified at the
        wiring layer). Here we assert the deterministic verdict_id."""
        from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("23" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        v1 = validator.evaluate(_hypothesis(), [_attempt()], [_evidence()])
        v2 = validator.evaluate(_hypothesis(), [_attempt()], [_evidence()])
        assert v1.verdict_id == v2.verdict_id == "ver-hyp-001"
        assert v1.validation_proof == v2.validation_proof
