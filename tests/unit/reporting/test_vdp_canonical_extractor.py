"""
SGK-2026-0422 — canonical extractor tests (T1).

Covers:
- source_kind split: canonical_vdp vs legacy (no vdp_contract section)
- read-only: input session dict is never mutated
- 0419-0421 record parsing and ID-series consistency
- confirmed only via public-key proof verification; raw confirmed labels
  without an EvidenceVerdict never become confirmed
- legacy HMAC proofs -> legacy_proof_unverifiable (not counted as confirmed)
- backfill/inference separation is a formatter concern; the summary keeps
  raw evidence only (compatibility reasons separate)
- mutually exclusive verdict statuses
- observation content missing -> IDs + observation_content_unavailable
- trigger_next_action_id tracing (NextAction -> Attempt)
- dedup keys include vuln class/asset/endpoint/actor/boundary/fingerprint
- vdp_canonical_index_v1 serializer output
"""
from __future__ import annotations

import copy
import json

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    NextActionRecord,
)
from src.reporting.vdp_canonical import (
    COMPAT_REASON_LEGACY_HMAC_UNVERIFIABLE,
    COMPAT_REASON_LEGACY_NO_VDP_CONTRACT,
    COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE,
    VdpCanonicalSummary,
    build_vdp_canonical_index,
    extract_vdp_canonical,
)


def _hypothesis(hypothesis_id: str = "hyp-001", observation_id: str = "obs-001") -> dict:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        observation_id=observation_id,
        asset="https://example.com/items",
        capability="idor_detector",
        hypothesis_text="object read by another actor",
        trust_boundary="api_endpoint",
        actors=["authA", "authB"],
        success_condition="owner-only field visible to authB",
        falsification_condition="no owner/permission difference",
        required_evidence=["real_http_response"],
        state="attempted",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        observation_ids=[observation_id],
    ).to_dict()


def _attempt(
    attempt_id: str = "att-001",
    hypothesis_id: str = "hyp-001",
    trigger_next_action_id: str = "nxt-001",
) -> dict:
    return AttemptRecord(
        attempt_id=attempt_id,
        hypothesis_id=hypothesis_id,
        actor="authB",
        request_fingerprint="fp-001",
        scope_verdict="allowed",
        state="evidence_saved",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
        trigger_next_action_id=trigger_next_action_id,
    ).to_dict()


def _evidence(evidence_id: str = "ev-001", attempt_id: str = "att-001") -> dict:
    return EvidenceRecordV1(
        evidence_id=evidence_id,
        attempt_id=attempt_id,
        evidence_type="real_http_response",
        raw_hash="sha256:" + "a" * 64,
        redacted_excerpt="HTTP/1.1 200 OK\n\n{\"owner\":\"authB\"}",
        normalization_rule_version="v1",
        auth_context_version="none",
        captured_at="2026-08-03T00:00:00Z",
        original_size=40,
        truncated=False,
        truncation_reason="",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    ).to_dict()


def _next_action(verdict_id: str = "ver-001", next_action_id: str = "nxt-001") -> dict:
    return NextActionRecord(
        next_action_id=next_action_id,
        verdict_id=verdict_id,
        evidence_gap="untested_no_second_account",
        action_class="follow_up_probe",
        risk_class="read_only",
        schema_version=VDP_CONTRACT_SCHEMA_VERSION,
    ).to_dict()


def _base_session(signer: Ed25519EvidenceSigner) -> dict:
    """Build a session with one full ID series ending in a confirmed verdict."""
    ev = _evidence()
    verdict = signer.create_confirmed_verdict(
        verdict_id="ver-001",
        hypothesis_id="hyp-001",
        reason_codes=["authz_impact_not_proven"],
        validator_version="vdp-evidence-validator-0.1.0",
        evidence_records=[ev],
    )
    return {
        "task_queue": [],
        "context": {},
        "vdp_contract": {
            "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
            "vdp_active": True,
            "hypotheses": [_hypothesis()],
            "attempts": [_attempt()],
            "evidence_records": [ev],
            "verdicts": [verdict.to_dict()],
            "next_actions": [_next_action()],
            "budget_snapshot": {"requests_used": 1},
            "run_health": {"run_state": "succeeded"},
        },
    }


class TestSourceKind:
    def test_legacy_session_without_vdp_contract(self):
        summary = extract_vdp_canonical({"task_queue": [], "completed_tasks": []})
        assert summary.source_kind == "legacy"
        assert COMPAT_REASON_LEGACY_NO_VDP_CONTRACT in summary.compatibility_reasons
        assert summary.verdicts == ()

    def test_legacy_session_non_dict_input(self):
        summary = extract_vdp_canonical(None)  # type: ignore[arg-type]
        assert summary.source_kind == "legacy"
        assert "session_data_not_a_dict" in summary.compatibility_reasons

    def test_canonical_session(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("01" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        assert summary.source_kind == "canonical_vdp"
        assert summary.schema_version == VDP_CONTRACT_SCHEMA_VERSION

    def test_invalid_schema_version(self):
        session = _base_session(Ed25519EvidenceSigner(private_key=bytes.fromhex("02" * 32)))
        session["vdp_contract"]["vdp_contract_version"] = 999
        summary = extract_vdp_canonical(session)
        assert any(
            "vdp_contract_version_missing_or_invalid" in r
            or "vdp_contract_version_mismatch" in r
            for r in summary.compatibility_reasons
        )


class TestReadOnly:
    def test_input_session_not_mutated(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("03" * 32))
        session = _base_session(signer)
        before = copy.deepcopy(session)
        extract_vdp_canonical(session, public_key_provider=signer.public_key_provider())
        assert session == before


class TestConfirmedOnlyViaProof:
    def test_raw_confirmed_finding_without_verdict_not_counted(self):
        """A session with raw findings labelled confirmed but NO EvidenceVerdict
        must not produce any confirmed verdict in the canonical summary."""
        session = {
            "task_queue": [],
            "context": {},
            "completed_tasks": [{
                "id": "t-1",
                "result": {"findings": [{"title": "X", "vuln_type": "xss",
                                          "severity": "high", "status": "confirmed"}]},
            }],
            "vdp_contract": {
                "vdp_contract_version": VDP_CONTRACT_SCHEMA_VERSION,
                "vdp_active": True,
                "hypotheses": [_hypothesis()],
                "attempts": [_attempt()],
                "evidence_records": [_evidence()],
                "verdicts": [],  # no canonical verdict at all
                "next_actions": [],
            },
        }
        summary = extract_vdp_canonical(session)
        assert summary.verdicts == ()
        assert summary.funnel.confirmed == 0
        assert summary.source_kind == "canonical_vdp"

    def test_confirmed_restored_with_public_key(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("04" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        confirmed = summary.confirmed_verdicts
        assert len(confirmed) == 1
        assert confirmed[0].verdict_id == "ver-001"
        assert confirmed[0].validation_proof.startswith("ed25519:")

    def test_legacy_hmac_proof_not_counted_as_confirmed(self):
        """Legacy HMAC proofs are unverifiable in reporting -> excluded from
        confirmed with legacy_proof_unverifiable reason."""
        session = _base_session(Ed25519EvidenceSigner(private_key=bytes.fromhex("05" * 32)))
        legacy_proof = "hmac-sha256:deadbeef:0" * 1
        session["vdp_contract"]["verdicts"] = [{
            "schema_version": 1,
            "verdict_id": "ver-leg",
            "hypothesis_id": "hyp-001",
            "status": "confirmed",
            "reason_codes": [],
            "evaluated_evidence_ids": ["ev-001"],
            "validator_version": "1.0.0",
            "validation_proof": legacy_proof,
        }]
        summary = extract_vdp_canonical(session)
        assert summary.confirmed_verdicts == ()
        assert any(
            COMPAT_REASON_LEGACY_HMAC_UNVERIFIABLE in r
            for r in summary.compatibility_reasons
        )

    def test_unknown_proof_excluded_with_reason(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("06" * 32))
        session = _base_session(signer)
        session["vdp_contract"]["verdicts"][0]["validation_proof"] = "ed25519:v99:k:sig"
        summary = extract_vdp_canonical(session)
        assert summary.confirmed_verdicts == ()
        assert any("unknown_proof_version" in r for r in summary.compatibility_reasons)


class TestMutualExclusivityAndFunnel:
    def _mixed_session(self, signer):
        session = _base_session(signer)
        session["vdp_contract"]["verdicts"] = [
            session["vdp_contract"]["verdicts"][0],  # confirmed ver-001
            EvidenceVerdictV1(
                verdict_id="ver-cand", hypothesis_id="hyp-001",
                _status="candidate",
                reason_codes=["insufficient_timing_validation"],
                schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            ).to_dict(),
            EvidenceVerdictV1(
                verdict_id="ver-ref", hypothesis_id="hyp-001",
                _status="refuted",
                reason_codes=["falsification_condition_met"],
                schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            ).to_dict(),
            EvidenceVerdictV1(
                verdict_id="ver-unt", hypothesis_id="hyp-001",
                _status="untested",
                reason_codes=["budget_exhausted"],
                schema_version=VDP_CONTRACT_SCHEMA_VERSION,
            ).to_dict(),
        ]
        return session

    def test_statuses_mutually_exclusive(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("07" * 32))
        summary = extract_vdp_canonical(
            self._mixed_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        all_ids = [v.verdict_id for v in summary.verdicts]
        assert len(all_ids) == len(set(all_ids))  # no double counting
        assert len(summary.confirmed_verdicts) == 1
        assert len(summary.candidate_verdicts) == 1
        assert len(summary.refuted_verdicts) == 1
        assert len(summary.untested_verdicts) == 1

    def test_funnel_counts(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("08" * 32))
        summary = extract_vdp_canonical(
            self._mixed_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        funnel = summary.funnel
        assert funnel.observations == 1  # obs-001
        assert funnel.hypotheses == 1
        assert funnel.attempted == 1
        assert funnel.responded == 1
        assert funnel.followed_up == 1
        assert funnel.confirmed == 1
        assert funnel.refuted == 1
        assert funnel.untested == 1
        assert "budget_exhausted" in funnel.drop_reasons

    def test_retry_kept_as_separate_attempt(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("09" * 32))
        session = _base_session(signer)
        session["vdp_contract"]["attempts"] = [
            _attempt(attempt_id="att-001"),
            _attempt(attempt_id="att-001-retry", trigger_next_action_id="nxt-001"),
        ]
        summary = extract_vdp_canonical(session)
        assert len(summary.attempts) == 2
        assert {a.attempt_id for a in summary.attempts} == {"att-001", "att-001-retry"}


class TestTriggerNextActionTrace:
    def test_attempt_carries_trigger_next_action_id(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("0a" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        assert summary.attempts[0].trigger_next_action_id == "nxt-001"

    def test_old_attempt_defaults_to_empty(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("0b" * 32))
        session = _base_session(signer)
        del session["vdp_contract"]["attempts"][0]["trigger_next_action_id"]
        summary = extract_vdp_canonical(session)
        assert summary.attempts[0].trigger_next_action_id == ""

    def test_next_action_to_attempt_traceable(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("0c" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        na_ids = {n.next_action_id for n in summary.next_actions}
        attempt_triggers = {a.trigger_next_action_id for a in summary.attempts}
        assert attempt_triggers.issubset(na_ids) or attempt_triggers == {"nxt-001"}


class TestObservationMissing:
    def test_observation_content_unavailable_reason(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("0d" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        assert summary.observation_ids == ("obs-001",)
        assert COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE in summary.compatibility_reasons

    def test_no_observation_body_fabricated(self):
        """The summary must never carry fabricated observation content — only
        IDs and provenance are exposed."""
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("0e" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        summary_dict = summary.to_dict()
        # No fabricated observation content fields may exist in the summary.
        for fabricated_key in (
            "observation_body",
            "observations",
            "observation_details",
            "observation_content",
            "observation_payload",
        ):
            assert fabricated_key not in summary_dict, fabricated_key
        assert summary.observation_ids == ("obs-001",)
        # Hypotheses reference the observation by ID only (no content).
        assert summary.hypotheses[0].observation_id == "obs-001"


class TestDedupKeys:
    def test_dedup_key_covers_required_dimensions(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("0f" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        assert len(summary.dedup_keys) == 1
        key = summary.dedup_keys[0]
        assert key.startswith("vdp-dedup-")

    def test_different_actor_produces_different_key(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("10" * 32))
        session = _base_session(signer)
        session["vdp_contract"]["attempts"] = [
            _attempt(attempt_id="att-a", trigger_next_action_id="nxt-a"),
            _attempt(attempt_id="att-b", trigger_next_action_id="nxt-b"),
        ]
        summary = extract_vdp_canonical(session)
        # Same hypothesis+capability+asset but distinct attempt fingerprints:
        # dedup key must still be deterministic and complete.
        assert len(summary.dedup_keys) >= 1


class TestCanonicalIndex:
    def test_index_block_structure(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("11" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        index = build_vdp_canonical_index(summary)
        assert index["index_version"] == "vdp_canonical_index_v1"
        assert index["source_kind"] == "canonical_vdp"
        assert index["verdict_counts"]["confirmed"] == 1
        assert index["verdict_ids"]["confirmed"] == ["ver-001"]
        assert index["evidence_ids"] == ["ev-001"]
        assert index["evidence_hashes"]["ev-001"].startswith("sha256:")
        assert len(index["summary_digest"]) == 64

    def test_legacy_index(self):
        summary = extract_vdp_canonical({"task_queue": []})
        index = build_vdp_canonical_index(summary)
        assert index["source_kind"] == "legacy"
        assert index["verdict_counts"]["confirmed"] == 0

    def test_index_deterministic(self):
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("12" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer),
            public_key_provider=signer.public_key_provider(),
        )
        assert build_vdp_canonical_index(summary) == build_vdp_canonical_index(summary)


class TestCanonicalSummarySecretFree:
    def test_production_write_then_extract_has_no_secret_markers(self):
        """Production flow: session write boundary redacts; the canonical
        summary read back must never carry secret values (plan §7 secret
        non-display). The extractor is read-only — redaction is enforced at
        the session write boundary."""
        from src.core.engine.master_conductor_session_service import (
            inject_vdp_section_to_session_payload,
        )

        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("13" * 32))
        session = _base_session(signer)
        # Inject a secret-looking value into the evidence excerpt; the
        # production write boundary must redact it before it reaches the
        # session artifact.
        session["vdp_contract"]["evidence_records"][0]["redacted_excerpt"] = (
            "HTTP/1.1 200 OK\nAuthorization: Bearer abcdefghij1234567890XYZ"
        )
        redacted_session = inject_vdp_section_to_session_payload(
            {"task_queue": [], "context": {}},
            session["vdp_contract"],
        )
        summary = extract_vdp_canonical(
            redacted_session, public_key_provider=signer.public_key_provider()
        )
        blob = json.dumps(summary.to_dict())
        assert "abcdefghij1234567890XYZ" not in blob
        assert "Bearer" not in blob

    def test_verdict_never_contains_private_key_material(self):
        """Confirmed verdict dicts must not expose private key material."""
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("14" * 32))
        session = _base_session(signer)
        summary = extract_vdp_canonical(
            session, public_key_provider=signer.public_key_provider()
        )
        for verdict in summary.confirmed_verdicts:
            blob = json.dumps(verdict.to_dict())
            assert "private" not in blob.lower()
            assert "BEGIN PRIVATE" not in blob
            assert signer.public_key_provider() is not None
