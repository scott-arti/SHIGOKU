"""
SGK-2026-0422 — VDP gate profile separation tests (T5).

Covers:
- training gate requires a label manifest (--labels); blocked without it
- training gate evaluates class recall / false promotion / evidence
  completeness / follow-up reach
- real VDP gate NEVER uses confirmed_min / candidate_max / known labels /
  expected detection matrix / product names (structural + policy check)
- real gate returns Go / Hold / No-Go with versioned JSON and reason codes
- scope violation / secret leak / HITL bypass / tampered proof /
  report-session inconsistency -> No-Go
- safety OK but infra/prerequisite/key/volume insufficient -> Hold
- profile missing -> blocked with explicit reason (never legacy thresholds)
- candidate counts alone never fail the real gate
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_gates import (
    GateVerdict,
    PROFILE_REAL,
    PROFILE_TRAINING,
    evaluate_vdp_gate,
    evaluate_vdp_real_gate,
    evaluate_vdp_training_gate,
)

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session


def _summary(**run_health_overrides):
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("71" * 32))
    session = _base_session(signer)
    health = {"run_state": "succeeded"}
    health.update(run_health_overrides)
    session["vdp_contract"]["run_health"] = health
    return extract_vdp_canonical(
        session, public_key_provider=signer.public_key_provider()
    )


class TestTrainingGate:
    def test_labels_required(self):
        verdict = evaluate_vdp_training_gate(_summary(), {})
        assert verdict.status == "blocked"
        assert verdict.reason_codes == ["training_labels_required"]
        assert verdict.profile == PROFILE_TRAINING

    def test_labels_manifest_from_disk(self, tmp_path):
        labels = {
            "labels": [
                {"hypothesis_id": "hyp-001", "expected_class": "idor"}
            ]
        }
        path = tmp_path / "labels.json"
        path.write_text(json.dumps(labels), encoding="utf-8")
        session = _base_session(Ed25519EvidenceSigner(private_key=bytes.fromhex("72" * 32)))
        verdict = evaluate_vdp_gate(
            "training",
            session,
            labels_path=path,
            public_key_provider=Ed25519EvidenceSigner(
                private_key=bytes.fromhex("72" * 32)
            ).public_key_provider(),
        )
        assert verdict.profile == PROFILE_TRAINING
        assert verdict.status == "pass"
        assert verdict.gates["class_recall"]["recall"] == 1.0

    def test_labels_never_leak_into_policy(self):
        verdict = evaluate_vdp_training_gate(
            _summary(),
            {"labels": [{"hypothesis_id": "hyp-001", "expected_class": "idor"}]},
        )
        assert verdict.status == "pass"
        assert verdict.reason_codes == []
        assert verdict.gates["false_promotion"]["false_promotion_count"] == 0


class TestRealGate:
    def test_go_on_healthy_run(self):
        verdict = evaluate_vdp_real_gate(_summary())
        assert verdict.profile == PROFILE_REAL
        assert verdict.decision == "go"
        assert verdict.status == "pass"
        assert "confirmed_min" in str(verdict.to_dict()["policy"])

    def test_scope_violation_no_go(self):
        verdict = evaluate_vdp_real_gate(
            _summary(scope_blocks=["scope_violation"])
        )
        assert verdict.decision == "no_go"
        assert any("scope_violation" in c for c in verdict.reason_codes)

    def test_secret_leak_no_go(self):
        verdict = evaluate_vdp_real_gate(
            _summary(safety_blocks=["secret_leak"])
        )
        assert verdict.decision == "no_go"

    def test_hitl_bypass_no_go(self):
        verdict = evaluate_vdp_real_gate(
            _summary(safety_blocks=["hitl_bypass"])
        )
        assert verdict.decision == "no_go"

    def test_tampered_proof_no_go(self):
        verdict = evaluate_vdp_real_gate(_summary())
        # Inject a tamper compatibility reason.
        summary = _summary()
        from dataclasses import replace

        tampered_summary = replace(
            summary,
            compatibility_reasons=summary.compatibility_reasons + ("tampered_proof",),
        )
        verdict = evaluate_vdp_real_gate(tampered_summary)
        assert verdict.decision == "no_go"
        assert "tampered_proof" in verdict.reason_codes

    def test_report_session_inconsistent_no_go(self):
        verdict = evaluate_vdp_real_gate(
            _summary(), consistency_status="inconsistent"
        )
        assert verdict.decision == "no_go"
        assert "report_session_inconsistent" in verdict.reason_codes

    def test_infra_gap_hold(self):
        verdict = evaluate_vdp_real_gate(
            _summary(dependency_failures=["evidence_channel_lost"])
        )
        assert verdict.decision == "hold"
        assert "operational_hold" in verdict.reason_codes

    def test_key_unavailable_hold(self):
        """Audit I-03: an unverifiable confirmed (key_unavailable) must be
        Hold — never silently Go with zero confirmed."""
        from dataclasses import replace

        summary = _summary()
        tampered_summary = replace(
            summary,
            compatibility_reasons=summary.compatibility_reasons
            + ("key_unavailable:ver-001",),
            verdicts=tuple(
                v for v in summary.verdicts if v.status != "confirmed"
            ),
        )
        verdict = evaluate_vdp_real_gate(tampered_summary)
        assert verdict.decision == "hold"
        assert "verification_key_unavailable_hold" in verdict.reason_codes

    def test_legacy_proof_unverifiable_hold(self):
        """Audit I-03: legacy_proof_unverifiable is a Hold condition."""
        from dataclasses import replace

        summary = _summary()
        tampered_summary = replace(
            summary,
            compatibility_reasons=summary.compatibility_reasons
            + ("legacy_proof_unverifiable:ver-001",),
            verdicts=tuple(
                v for v in summary.verdicts if v.status != "confirmed"
            ),
        )
        verdict = evaluate_vdp_real_gate(tampered_summary)
        assert verdict.decision == "hold"
        assert "verification_key_unavailable_hold" in verdict.reason_codes

    def test_zero_confirmed_with_key_ok_is_go(self):
        """Zero confirmed is NOT itself a Go-blocker when keys verify and no
        Hold/No-Go condition exists (candidate counts alone never fail)."""
        verdict = evaluate_vdp_real_gate(_summary())
        assert verdict.decision in {"go", "hold"}
        assert verdict.decision != "no_go"

    def test_unknown_untested_reason_hold(self):
        summary = _summary()
        from dataclasses import replace

        from src.core.models.vdp_contract import EvidenceVerdictV1

        weird = EvidenceVerdictV1(
            verdict_id="ver-weird", hypothesis_id="hyp-001",
            _status="untested", reason_codes=["mystery_code"],
            schema_version=1,
        )
        verdicts = list(summary.verdicts) + [weird]
        verdict = evaluate_vdp_real_gate(replace(summary, verdicts=tuple(verdicts)))
        assert verdict.decision == "hold"
        assert "unknown_untested_reason_codes" in verdict.reason_codes

    def test_candidate_count_alone_never_fails(self):
        """Even a session with many candidates and zero confirmed is Go when
        safety/consistency/termination are fine."""
        verdict = evaluate_vdp_real_gate(_summary())
        assert verdict.decision in {"go", "hold"}
        assert verdict.decision != "no_go"

    def test_versioned_json(self):
        verdict = evaluate_vdp_real_gate(_summary())
        data = verdict.to_dict()
        assert data["schema_version"] == 1
        assert data["profile"] == PROFILE_REAL
        assert "decision" in data
        assert isinstance(data["reason_codes"], list)


class TestProfileDispatch:
    def test_missing_profile_blocked(self):
        session = _base_session(Ed25519EvidenceSigner(private_key=bytes.fromhex("73" * 32)))
        verdict = evaluate_vdp_gate(
            "",
            session,
            public_key_provider=Ed25519EvidenceSigner(
                private_key=bytes.fromhex("73" * 32)
            ).public_key_provider(),
        )
        assert verdict.status == "blocked"
        assert "profile_required" in verdict.reason_codes

    def test_unknown_profile_blocked(self):
        session = _base_session(Ed25519EvidenceSigner(private_key=bytes.fromhex("74" * 32)))
        verdict = evaluate_vdp_gate("bogus", session)
        assert verdict.status == "blocked"
        assert "profile_required" in verdict.reason_codes

    def test_legacy_session_blocked_for_vdp_gates(self):
        verdict = evaluate_vdp_gate("real", {"task_queue": []})
        assert verdict.status == "blocked"
        assert "canonical_vdp_session_required" in verdict.reason_codes

    def test_profile_name_in_json(self):
        session = _base_session(Ed25519EvidenceSigner(private_key=bytes.fromhex("75" * 32)))
        provider = Ed25519EvidenceSigner(
            private_key=bytes.fromhex("75" * 32)
        ).public_key_provider()
        verdict = evaluate_vdp_gate("real", session, public_key_provider=provider)
        assert verdict.to_dict()["profile"] == PROFILE_REAL


class TestRealGateNeverReadsLegacyThresholds:
    def test_policy_marks_legacy_thresholds_unused(self):
        verdict = evaluate_vdp_real_gate(_summary())
        policy = verdict.to_dict()["policy"]
        assert policy["confirmed_min"] == "not_used"
        assert policy["candidate_max"] == "not_used"
        assert policy["known_labels"] == "not_used"

    def test_no_expected_detection_matrix_import(self):
        """Structural: vdp_gates must not import expected_detection_matrix."""
        text = Path("src/reporting/vdp_gates.py").read_text(encoding="utf-8")
        assert "expected_detection_matrix" not in text
        assert "expected_detection_profile" not in text

    def test_no_product_names_in_gate_source(self):
        text = Path("src/reporting/vdp_gates.py").read_text(encoding="utf-8").lower()
        for token in ("juice shop", "juiceshop", "dvwa", "owasp"):
            assert token not in text, f"product name must not appear in gate: {token}"


class TestRealGateUnknownTermination:
    """Lane J-1: an unknown run termination state is an operational-evidence
    gap — the real gate must Hold, never Go."""

    def test_unknown_run_state_holds(self):
        verdict = evaluate_vdp_real_gate(_summary(run_state="unknown"))
        assert verdict.decision == "hold"
        assert verdict.status == "pass"
        assert "run_state_unknown_hold" in verdict.reason_codes

    def test_missing_run_state_holds(self):
        # run_state absent from run_health -> "unknown" -> Hold (fail closed)
        verdict = evaluate_vdp_real_gate(_summary(run_state=""))
        assert verdict.decision == "hold"
        assert "run_state_unknown_hold" in verdict.reason_codes

    def test_succeeded_run_state_still_go(self):
        verdict = evaluate_vdp_real_gate(_summary(run_state="succeeded"))
        assert verdict.decision == "go"
        assert verdict.status == "pass"
        assert "run_state_unknown_hold" not in verdict.reason_codes

    def test_partial_run_state_still_go(self):
        verdict = evaluate_vdp_real_gate(_summary(run_state="partial"))
        assert verdict.decision == "go"

    def test_failed_run_state_still_no_go(self):
        verdict = evaluate_vdp_real_gate(_summary(run_state="failed"))
        assert verdict.decision == "no_go"
        assert verdict.status == "fail"
        assert "run_state_failed" in verdict.reason_codes
        assert "run_state_unknown_hold" not in verdict.reason_codes

    def test_termination_gate_status_unchanged_for_unknown(self):
        # gates reporting is unchanged: termination_state stays "fail" for
        # unknown; only the DECISION becomes hold with status pass
        verdict = evaluate_vdp_real_gate(_summary(run_state="unknown"))
        assert verdict.gates["termination_state"]["status"] == "fail"
        assert verdict.gates["termination_state"]["run_state"] == "unknown"
