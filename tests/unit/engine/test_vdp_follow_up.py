"""
VDP follow-up reason code mapping — SGK-2026-0421 Step 1.

Every known reason code (sets A-E from the subtask plan) must map
deterministically to a unique NextAction or manual review. Unknown codes
must stop at manual review with the reason attached — never fall through
to a generic scan.
"""
from __future__ import annotations

import pytest

from src.core.engine.recipe_contracts import (
    VDP_ACTION_CLASSES,
    VDP_EVIDENCE_GAP_CODES,
    VDP_INFRA_REASON_CODES,
    VDP_REASON_CODES,
)
from src.core.engine.vdp_follow_up import (
    build_next_action_record,
    classify_reason_code,
    is_known_reason_code,
)
from src.core.models.vdp_contract import (
    AdmissionReasonCode,
    BudgetReasonCodeV1,
    HypothesisRecord,
    NextActionRecord,
    deterministic_id,
    validate_next_action_record,
)


def _enum_values(cls) -> set:
    return {getattr(cls, a) for a in dir(cls) if not a.startswith("_")}


def _all_known_codes() -> set:
    """Union of sets A-E per the subtask plan §3."""
    return (
        set(VDP_EVIDENCE_GAP_CODES)
        | set(VDP_REASON_CODES)
        | _enum_values(AdmissionReasonCode)
        | _enum_values(BudgetReasonCodeV1)
        | set(VDP_INFRA_REASON_CODES)
    )


# ---------------------------------------------------------------------------
# Coverage: every known reason code maps to a unique NextAction or manual review
# ---------------------------------------------------------------------------


class TestReasonCodeCoverage:
    @pytest.mark.parametrize("code", sorted(_all_known_codes()))
    def test_every_known_code_maps(self, code: str):
        assert is_known_reason_code(code), f"{code} must be in the mapping"
        plan = classify_reason_code(code)
        assert plan.category in {
            "follow_up",
            "manual_review",
            "terminal",
            "re_evaluate",
            "delegate_to_gap",
        }, f"{code}: bad category {plan.category}"
        assert plan.action_class in VDP_ACTION_CLASSES, f"{code}: bad action_class"
        assert plan.risk_class in {"read_only", "state_changing", "out_of_band", ""}

    def test_all_evidence_gap_codes_known(self):
        for code in VDP_EVIDENCE_GAP_CODES:
            assert is_known_reason_code(code)

    def test_all_generator_reason_codes_known(self):
        for code in VDP_REASON_CODES:
            assert is_known_reason_code(code)

    def test_all_admission_reason_codes_known(self):
        for code in _enum_values(AdmissionReasonCode):
            assert is_known_reason_code(code)

    def test_all_budget_reason_codes_known(self):
        for code in _enum_values(BudgetReasonCodeV1):
            assert is_known_reason_code(code)

    def test_all_infra_reason_codes_known(self):
        for code in VDP_INFRA_REASON_CODES:
            assert is_known_reason_code(code)

    def test_mapping_is_deterministic(self):
        for code in sorted(_all_known_codes()):
            a = classify_reason_code(code)
            b = classify_reason_code(code)
            assert a == b, f"{code}: mapping not deterministic"

    def test_plan_actions_unique_per_code(self):
        for code in sorted(_all_known_codes()):
            plan = classify_reason_code(code)
            assert plan.reason_code == code


class TestUnknownReasonCode:
    def test_unknown_maps_to_manual_review_with_reason(self):
        plan = classify_reason_code("no_such_reason_code_xyz")
        assert plan.category == "manual_review"
        assert plan.action_class == "manual_review"
        assert "no_such_reason_code_xyz" in plan.notes

    def test_unknown_is_not_known(self):
        assert not is_known_reason_code("no_such_reason_code_xyz")

    def test_unknown_never_produces_follow_up(self):
        plan = classify_reason_code("no_such_reason_code_xyz")
        assert plan.action_class != "follow_up_probe"
        assert plan.m3a_policy in {"none", "manual_review"}


class TestNextActionConstruction:
    def _hypothesis(self) -> HypothesisRecord:
        return HypothesisRecord(
            hypothesis_id="hyp-test-1",
            observation_id="obs-test-1",
            asset="https://example.test/api",
            capability="object_read_write_delete",
            hypothesis_text="test",
            trust_boundary="unauthenticated",
        )

    def test_build_next_action_from_follow_up_gap(self):
        hyp = self._hypothesis()
        na = build_next_action_record(
            verdict_id="vrd-test-1",
            hypothesis=hyp,
            reason_code="payload_request_mismatch",
        )
        assert isinstance(na, NextActionRecord)
        assert na.verdict_id == "vrd-test-1"
        assert na.evidence_gap == "payload_request_mismatch"
        assert na.action_class == "follow_up_probe"
        assert na.risk_class == "read_only"
        assert na.required_preconditions  # scope/budget etc.
        assert validate_next_action_record(na) == []

    def test_build_next_action_deterministic_id(self):
        hyp = self._hypothesis()
        na1 = build_next_action_record("vrd-1", hyp, "payload_request_mismatch")
        na2 = build_next_action_record("vrd-1", hyp, "payload_request_mismatch")
        assert na1.next_action_id == na2.next_action_id

    def test_build_next_action_manual_review_for_unknown(self):
        hyp = self._hypothesis()
        na = build_next_action_record("vrd-1", hyp, "totally_unknown_code")
        assert na.action_class == "manual_review"

    def test_build_next_action_state_changing_is_m3b_gated(self):
        hyp = self._hypothesis()
        na = build_next_action_record("vrd-1", hyp, "state_change_not_verified")
        assert na.risk_class == "state_changing"
        plan = classify_reason_code("state_change_not_verified")
        assert plan.m3a_policy == "m3b_gated"

    def test_build_next_action_generated_candidate_delegates_to_gap(self):
        hyp = self._hypothesis()
        na = build_next_action_record(
            "vrd-1",
            hyp,
            "generated_candidate",
            evidence_gap="payload_request_mismatch",
        )
        assert na.evidence_gap == "payload_request_mismatch"
        assert na.action_class == "follow_up_probe"

    def test_build_next_action_unknown_gap_with_generated_candidate(self):
        hyp = self._hypothesis()
        na = build_next_action_record(
            "vrd-1", hyp, "generated_candidate", evidence_gap="totally_unknown_gap"
        )
        assert na.action_class == "manual_review"


# ---------------------------------------------------------------------------
# Reporting-side coverage comparison (tests may import src.reporting)
# ---------------------------------------------------------------------------


class TestReportingReasonCodeCoverage:
    def test_haddix_reason_codes_covered_by_mapping(self):
        from src.reporting.haddix_evidence_quality import (
            REASON_AUTHZ_IMPACT_NOT_PROVEN,
            REASON_BROWSER_EXECUTION_MISSING,
            REASON_COMMAND_EXECUTION_NOT_VERIFIED,
            REASON_FILE_UPLOAD_IMPACT_NOT_PROVEN,
            REASON_INSUFFICIENT_RESPONSE_DIFFERENCE,
            REASON_INSUFFICIENT_TIMING,
            REASON_PAYLOAD_REQUEST_MISMATCH,
            REASON_PUBLIC_DOCUMENTATION_NOT_AUTHZ_IMPACT,
            REASON_REDIRECT_TARGET_NOT_EXTERNAL,
            REASON_SESSION_TAKEOVER_NOT_VERIFIED,
            REASON_STATE_CHANGE_NOT_VERIFIED,
            REASON_STORED_REVISIT_MISSING,
            REASON_SYNTHETIC_RESPONSE,
            REASON_UNTESTED_NO_SECOND_ACCOUNT,
            REASON_WEAK_SESSION_NOT_STATISTICALLY_VERIFIED,
        )
        haddix_codes = {
            REASON_PAYLOAD_REQUEST_MISMATCH,
            REASON_SYNTHETIC_RESPONSE,
            REASON_INSUFFICIENT_TIMING,
            REASON_BROWSER_EXECUTION_MISSING,
            REASON_STORED_REVISIT_MISSING,
            REASON_STATE_CHANGE_NOT_VERIFIED,
            REASON_AUTHZ_IMPACT_NOT_PROVEN,
            REASON_INSUFFICIENT_RESPONSE_DIFFERENCE,
            REASON_COMMAND_EXECUTION_NOT_VERIFIED,
            REASON_REDIRECT_TARGET_NOT_EXTERNAL,
            REASON_WEAK_SESSION_NOT_STATISTICALLY_VERIFIED,
            REASON_UNTESTED_NO_SECOND_ACCOUNT,
            REASON_FILE_UPLOAD_IMPACT_NOT_PROVEN,
            REASON_PUBLIC_DOCUMENTATION_NOT_AUTHZ_IMPACT,
            REASON_SESSION_TAKEOVER_NOT_VERIFIED,
        }
        for code in haddix_codes:
            assert is_known_reason_code(code), f"haddix reason {code} not mapped"
            plan = classify_reason_code(code)
            assert plan.category in {
                "follow_up",
                "manual_review",
                "terminal",
                "re_evaluate",
            }

    def test_generator_required_evidence_within_public_vocabulary(self):
        # Test-only access to the generator's required-evidence table to prove
        # every gap it produces is part of the public vocabulary.
        from src.core.engine.vdp_hypothesis_generator import (
            _REQUIRED_EVIDENCE_BY_CAPABILITY,
        )

        for gaps in _REQUIRED_EVIDENCE_BY_CAPABILITY.values():
            for gap in gaps:
                assert (
                    gap in VDP_EVIDENCE_GAP_CODES
                ), f"generator gap {gap!r} missing from VDP_EVIDENCE_GAP_CODES"


# ---------------------------------------------------------------------------
# No engine -> reporting production import (structural)
# ---------------------------------------------------------------------------


class TestImportBoundary:
    def test_follow_up_module_does_not_import_reporting(self):
        import src.core.engine.vdp_follow_up as mod

        assert mod.__file__ is not None
        source = open(mod.__file__, encoding="utf-8").read()
        assert "src.reporting" not in source

    def test_evidence_gap_vocabulary_lives_in_public_contract(self):
        assert "payload_request_mismatch" in VDP_EVIDENCE_GAP_CODES
        assert "scope_revalidation_blocked" in VDP_EVIDENCE_GAP_CODES
        assert "follow_up_enqueue_failed" in VDP_INFRA_REASON_CODES
        assert "unknown_reason_code" in VDP_INFRA_REASON_CODES
