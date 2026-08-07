"""
SGK-2026-0425 M1 part 2: diagnostic telemetry hooks in VdpEvidenceValidator.

- collector=None (default) → verdicts unchanged, no events.
- collector enabled → S11 reached after a normal verdict
  (status in source_refs), S11 blocked on the signer-unavailable hold
  (dependency_unavailable) and on the KeyRegistryError hold
  (proof_unverifiable).
- The signing/proof boundaries are never touched (read-only facts only).
"""
from __future__ import annotations

from src.core.engine.vdp_diagnostic_trace import DiagnosticCollector
from src.core.engine.vdp_evidence_validator import (
    Ed25519EvidenceSigner,
    VdpEvidenceValidator,
)
from src.core.engine.vdp_key_registry import VdpKeyRegistry

from tests.unit.engine.test_vdp_evidence_validator import (
    _attempt,
    _evidence,
    _hypothesis,
)


def _collector(**kwargs) -> DiagnosticCollector:
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("run_id", "test")
    return DiagnosticCollector(**kwargs)


def _events(collector: DiagnosticCollector) -> list:
    section = collector.to_section()
    assert section is not None, "collector disabled?"
    return section["events"]


def _assert_event(collector, stage_id, outcome, *, reason_codes=None, source_refs=None):
    evs = [
        ev
        for ev in _events(collector)
        if ev["stage_id"] == stage_id and ev["outcome"] == outcome
    ]
    assert evs, f"expected event {stage_id}/{outcome}; got {_events(collector)}"
    ev = evs[0]
    if reason_codes is not None:
        assert ev["reason_codes"] == list(reason_codes), ev
    if source_refs is not None:
        assert ev["source_refs"] == list(source_refs), ev
    return ev


class TestNoneCollectorNoOp:
    def test_none_collector_verdict_unchanged(self):
        validator = VdpEvidenceValidator(signer=None)
        verdict = validator.evaluate(_hypothesis(), [_attempt()], [])
        assert verdict.status == "untested"
        assert "evidence_channel_lost" in verdict.reason_codes

    def test_none_collector_confirmed_unchanged(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("41" * 32))
        validator = VdpEvidenceValidator(signer=signer)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "confirmed"
        assert verdict.validation_proof.startswith("ed25519:")


class TestS11Reached:
    """Normal verdicts emit S11 reached with the status in source_refs."""

    def test_untested_emits_s11_reached(self):
        col = _collector()
        validator = VdpEvidenceValidator(signer=None, diagnostic_collector=col)
        verdict = validator.evaluate(_hypothesis(), [_attempt()], [])
        assert verdict.status == "untested"
        _assert_event(col, "S11", "reached", source_refs=["status=untested"])

    def test_candidate_emits_s11_reached(self):
        col = _collector()
        validator = VdpEvidenceValidator(signer=None, diagnostic_collector=col)
        verdict = validator.evaluate(_hypothesis(complete=False), [_attempt()], [_evidence()])
        assert verdict.status == "candidate"
        _assert_event(col, "S11", "reached", source_refs=["status=candidate"])

    def test_refuted_emits_s11_reached(self):
        col = _collector()
        validator = VdpEvidenceValidator(signer=None, diagnostic_collector=col)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(execution_result={"falsification_met": "true"})],
        )
        assert verdict.status == "refuted"
        _assert_event(col, "S11", "reached", source_refs=["status=refuted"])

    def test_confirmed_emits_s11_reached(self):
        col = _collector()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("42" * 32))
        validator = VdpEvidenceValidator(signer=signer, diagnostic_collector=col)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "confirmed"
        _assert_event(col, "S11", "reached", source_refs=["status=confirmed"])


class TestS11Blocked:
    def test_signer_unavailable_emits_s11_blocked_dependency_unavailable(self):
        col = _collector()
        validator = VdpEvidenceValidator(signer=None, diagnostic_collector=col)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "candidate"
        assert "signer_unavailable_hold" in verdict.reason_codes
        _assert_event(
            col, "S11", "blocked",
            reason_codes=["dependency_unavailable"],
            source_refs=["signer_unavailable"],
        )

    def test_key_registry_error_emits_s11_blocked_proof_unverifiable(self):
        col = _collector()
        registry = VdpKeyRegistry()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("43" * 32), registry=registry)
        registry.register(signer.key_id, signer.public_key_bytes())
        registry.revoke(signer.key_id)
        validator = VdpEvidenceValidator(signer=signer, diagnostic_collector=col)
        verdict = validator.evaluate(
            _hypothesis(),
            [_attempt()],
            [_evidence(markers={"authz_impact_proven": "true"})],
        )
        assert verdict.status == "candidate"
        assert "signing_key_not_active" in verdict.reason_codes
        _assert_event(
            col, "S11", "blocked",
            reason_codes=["proof_unverifiable"],
            source_refs=["signing_key_not_active"],
        )


class TestHookFailureNeverBreaksEvaluate:
    def test_raising_emit_hook_does_not_break_evaluate(self):
        col = _collector()

        def _exploding_emit(**kwargs):
            raise RuntimeError("telemetry down")

        col.emit = _exploding_emit
        validator = VdpEvidenceValidator(signer=None, diagnostic_collector=col)
        verdict = validator.evaluate(_hypothesis(), [_attempt()], [])
        assert verdict.status == "untested"
        assert col.hook_failed is True
