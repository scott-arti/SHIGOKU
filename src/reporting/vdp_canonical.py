"""
Canonical VDP session extractor — SGK-2026-0422 (reporting layer).

Reads ONLY a ``session_data`` dict and produces an immutable
``VdpCanonicalSummary`` that formatters, gates and the consistency checker
share. The extractor never mutates its input, never generates or infers
evidence, and performs NO re-judgement of confirmed status:

- ``source_kind == "canonical_vdp"``: the session carries a ``vdp_contract``
  section; confirmed verdicts are restored ONLY through public-key proof
  verification (``restore_confirmed_from_dict``).
- ``source_kind == "legacy"``: no ``vdp_contract`` section; the summary is
  empty with an explicit compatibility reason. Legacy report paths keep
  using the existing finding extractor.

Fail-closed rules (plan §8):
- A raw finding labelled ``confirmed`` without an EvidenceVerdict is never
  promoted to confirmed here.
- Legacy HMAC proofs cannot be verified in the reporting layer (no engine
  import, no secret) → ``legacy_proof_unverifiable`` compatibility reason
  and the verdict is NOT counted as confirmed (displayed candidate-equivalent
  with the reason).
- Unknown proof version / unknown key / missing key / tampered evidence →
  ``compatibility_reason`` with the verdict excluded from confirmed.
- backfill / inference are separated from raw/derived evidence sets.
- verdict statuses are mutually exclusive (confirmed / candidate / refuted /
  untested).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.core.models.vdp_contract import (
    VDP_CONTRACT_SCHEMA_VERSION,
    AttemptRecord,
    EvidenceRecordV1,
    EvidenceVerdictV1,
    HypothesisRecord,
    NextActionRecord,
    canonical_json_bytes,
    default_public_key_provider,
    restore_confirmed_from_dict,
    verify_confirmed_verdict,
)

VDP_CANONICAL_INDEX_VERSION = "vdp_canonical_index_v1"
COMPAT_REASON_LEGACY_NO_VDP_CONTRACT = "no_vdp_contract_section"
COMPAT_REASON_LEGACY_HMAC_UNVERIFIABLE = "legacy_proof_unverifiable"
COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE = "observation_content_unavailable"
COMPAT_REASON_UNKNOWN_VERDICT_PROOF = "unknown_proof_version"
COMPAT_REASON_UNKNOWN_KEY = "unknown_key_id"
COMPAT_REASON_KEY_UNAVAILABLE = "key_unavailable"
COMPAT_REASON_TAMPERED = "tampered_proof"
COMPAT_REASON_MISSING_PROOF = "missing_proof"


@dataclass(frozen=True)
class FunnelCounts:
    """Funnel counts for the report (plan §4.1)."""

    observations: int = 0
    hypotheses: int = 0
    attempted: int = 0
    responded: int = 0
    followed_up: int = 0
    confirmed: int = 0
    refuted: int = 0
    untested: int = 0
    drop_reasons: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observations": self.observations,
            "hypotheses": self.hypotheses,
            "attempted": self.attempted,
            "responded": self.responded,
            "followed_up": self.followed_up,
            "confirmed": self.confirmed,
            "refuted": self.refuted,
            "untested": self.untested,
            "drop_reasons": dict(self.drop_reasons),
        }


@dataclass(frozen=True)
class VdpCanonicalSummary:
    """Immutable canonical summary shared by formatter / gate / consistency.

    All record lists are tuples of frozen/immutable dataclass instances.
    Input session dicts are never mutated; record dicts are deep-copied via
    the typed from_dict() readers (unknown fields dropped additively).
    """

    source_kind: str  # "canonical_vdp" | "legacy"
    schema_version: Optional[int]
    compatibility_reasons: Tuple[str, ...] = ()
    observation_ids: Tuple[str, ...] = ()
    hypotheses: Tuple[HypothesisRecord, ...] = ()
    attempts: Tuple[AttemptRecord, ...] = ()
    evidence_records: Tuple[EvidenceRecordV1, ...] = ()
    verdicts: Tuple[EvidenceVerdictV1, ...] = ()
    next_actions: Tuple[NextActionRecord, ...] = ()
    budget_snapshot: Dict[str, Any] = field(default_factory=dict)
    run_health: Dict[str, Any] = field(default_factory=dict)
    funnel: FunnelCounts = field(default_factory=FunnelCounts)
    # evidence fingerprint dedup keys (vuln class + asset + endpoint/action +
    # actor + trust boundary + evidence fingerprint)
    dedup_keys: Tuple[str, ...] = ()
    # SGK-2026-0423 Lane D (additive passthrough): shadow/enforce diff trace
    # recorded by the engine queue/dispatch phases. Read from the session's
    # ``vdp_contract.shadow_diff`` list only; never inferred or generated
    # here. Entries are plain dicts with fixed keys and NO secrets.
    shadow_diff: Tuple[Dict[str, Any], ...] = ()

    @property
    def confirmed_verdicts(self) -> Tuple[EvidenceVerdictV1, ...]:
        return tuple(v for v in self.verdicts if v.status == "confirmed")

    @property
    def candidate_verdicts(self) -> Tuple[EvidenceVerdictV1, ...]:
        return tuple(v for v in self.verdicts if v.status == "candidate")

    @property
    def refuted_verdicts(self) -> Tuple[EvidenceVerdictV1, ...]:
        return tuple(v for v in self.verdicts if v.status == "refuted")

    @property
    def untested_verdicts(self) -> Tuple[EvidenceVerdictV1, ...]:
        return tuple(v for v in self.verdicts if v.status == "untested")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "schema_version": self.schema_version,
            "compatibility_reasons": list(self.compatibility_reasons),
            "observation_ids": list(self.observation_ids),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "attempts": [a.to_dict() for a in self.attempts],
            "evidence_records": [e.to_dict() for e in self.evidence_records],
            "verdicts": [v.to_dict() for v in self.verdicts],
            "next_actions": [n.to_dict() for n in self.next_actions],
            "budget_snapshot": dict(self.budget_snapshot),
            "run_health": dict(self.run_health),
            "funnel": self.funnel.to_dict(),
            "dedup_keys": list(self.dedup_keys),
            "shadow_diff": [dict(e) for e in self.shadow_diff],
        }


def _parse_typed_list(
    raw_items: Any,
    cls: type,
    section: str,
    errors: List[str],
) -> List[Any]:
    results: List[Any] = []
    if not isinstance(raw_items, list):
        errors.append(f"{section}: not a list")
        return results
    for i, item in enumerate(raw_items):
        if not isinstance(item, dict):
            errors.append(f"{section}[{i}]: expected dict, got {type(item).__name__}")
            continue
        try:
            results.append(cls.from_dict(item))
        except (TypeError, ValueError, KeyError) as exc:
            errors.append(f"{section}[{i}]: {type(exc).__name__}: {exc}")
    return results


def _restore_verdict(
    item: Dict[str, Any],
    evidence_dicts: List[Dict[str, Any]],
    public_key_provider: Any,
    compatibility: List[str],
) -> Optional[EvidenceVerdictV1]:
    """Restore a confirmed verdict (public-key proof verification only).

    On verification failure the confirmed verdict is NOT silently kept as
    confirmed and NOT dropped from the ID series — it is demoted to a
    CANDIDATE verdict with the SAME verdict_id/hypothesis_id so the funnel
    and back-references stay intact, and a compatibility reason is recorded
    (fail-closed; audit I-03: key_unavailable must surface as Hold, not Go).
    """
    if item.get("status") != "confirmed":
        return EvidenceVerdictV1.from_dict(item)

    compat_reason: Optional[str] = None
    proof = str(item.get("validation_proof") or "")
    if not proof:
        compat_reason = f"{COMPAT_REASON_MISSING_PROOF}:{item.get('verdict_id', '?')}"
    elif proof.startswith("hmac-sha256"):
        # Reporting cannot verify legacy HMAC (engine-side verifier only).
        compat_reason = f"{COMPAT_REASON_LEGACY_HMAC_UNVERIFIABLE}:{item.get('verdict_id', '?')}"
    else:
        result = verify_confirmed_verdict(
            item, evidence_dicts, public_key_provider=public_key_provider
        )
        if not result.verified:
            reason = result.reason_code
            if reason == "unknown_proof_version":
                compat_reason = f"{COMPAT_REASON_UNKNOWN_VERDICT_PROOF}:{item.get('verdict_id', '?')}"
            elif reason == "unknown_key_id":
                compat_reason = f"{COMPAT_REASON_UNKNOWN_KEY}:{item.get('verdict_id', '?')}"
            elif reason == "key_unavailable":
                compat_reason = f"{COMPAT_REASON_KEY_UNAVAILABLE}:{item.get('verdict_id', '?')}"
            else:
                compat_reason = f"{COMPAT_REASON_TAMPERED}:{item.get('verdict_id', '?')}"

    if compat_reason is not None:
        compatibility.append(compat_reason)
        # Keep the same verdict_id/hypothesis_id as a CANDIDATE so the ID
        # series and NextAction back-references are preserved and the real
        # gate can apply Hold on key_unavailable / legacy unverifiable.
        return EvidenceVerdictV1(
            schema_version=item.get("schema_version", 0),
            verdict_id=str(item.get("verdict_id") or ""),
            hypothesis_id=str(item.get("hypothesis_id") or ""),
            _status="candidate",
            reason_codes=list(item.get("reason_codes") or []) + [compat_reason.split(":")[0]],
            evaluated_evidence_ids=list(item.get("evaluated_evidence_ids") or []),
            validator_version=str(item.get("validator_version") or ""),
            validation_proof="",
            notes=list(item.get("notes") or []),
            proof_schema_version="",
            proof_key_id="",
            evidence_content_sha256={},
        )

    try:
        return restore_confirmed_from_dict(
            item, evidence_dicts, public_key_provider=public_key_provider
        )
    except ValueError as exc:
        compatibility.append(f"{COMPAT_REASON_TAMPERED}:{item.get('verdict_id', '?')}:{exc}")
        return EvidenceVerdictV1(
            schema_version=item.get("schema_version", 0),
            verdict_id=str(item.get("verdict_id") or ""),
            hypothesis_id=str(item.get("hypothesis_id") or ""),
            _status="candidate",
            reason_codes=[COMPAT_REASON_TAMPERED],
            evaluated_evidence_ids=list(item.get("evaluated_evidence_ids") or []),
            validator_version=str(item.get("validator_version") or ""),
            validation_proof="",
            notes=list(item.get("notes") or []),
            proof_schema_version="",
            proof_key_id="",
            evidence_content_sha256={},
        )


def _build_funnel(
    hypotheses: List[HypothesisRecord],
    attempts: List[AttemptRecord],
    evidence_records: List[EvidenceRecordV1],
    verdicts: List[EvidenceVerdictV1],
    next_actions: List[NextActionRecord],
    drop_reasons: Dict[str, int],
) -> FunnelCounts:
    observation_ids = sorted(
        {oid for h in hypotheses for oid in h.observation_ids if oid}
    )
    confirmed = sum(1 for v in verdicts if v.status == "confirmed")
    refuted = sum(1 for v in verdicts if v.status == "refuted")
    untested = sum(1 for v in verdicts if v.status == "untested")
    return FunnelCounts(
        observations=len(observation_ids),
        hypotheses=len(hypotheses),
        attempted=len(attempts),
        responded=len(evidence_records),
        followed_up=len(next_actions),
        confirmed=confirmed,
        refuted=refuted,
        untested=untested,
        drop_reasons=dict(drop_reasons),
    )


def _evidence_fingerprint_dedup_keys(
    hypotheses: List[HypothesisRecord],
    attempts: List[AttemptRecord],
    evidence_records: List[EvidenceRecordV1],
) -> Tuple[str, ...]:
    """Deterministic dedup keys: vulnerability class + asset + endpoint/action
    + actor + trust boundary + evidence fingerprint (plan §4.3)."""
    keys: List[str] = []
    ev_by_attempt = {e.attempt_id: e for e in evidence_records}
    for hyp in hypotheses:
        asset = str(hyp.asset or "").strip().lower()
        vuln_class = str(hyp.capability or "").strip().lower()
        boundary = str(hyp.trust_boundary or "").strip().lower()
        for attempt in attempts:
            if attempt.hypothesis_id != hyp.hypothesis_id:
                continue
            actor = str(attempt.actor or "").strip().lower()
            endpoint = str(attempt.request_fingerprint or "").strip().lower()
            ev = ev_by_attempt.get(attempt.attempt_id)
            ev_fp = str(ev.raw_hash or "").strip() if ev else ""
            payload = {
                "vuln_class": vuln_class,
                "asset": asset,
                "endpoint_action": endpoint,
                "actor": actor,
                "trust_boundary": boundary,
                "evidence_fingerprint": ev_fp,
            }
            digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
            keys.append(f"vdp-dedup-{digest[:16]}")
    return tuple(sorted(set(keys)))


def extract_vdp_canonical(
    session_data: Dict[str, Any],
    *,
    public_key_provider: Any = None,
) -> VdpCanonicalSummary:
    """Build the immutable canonical summary from a session dict (read-only).

    Never mutates ``session_data``. Returns a ``source_kind="legacy"``
    summary with a compatibility reason when the session has no
    ``vdp_contract`` section.
    """
    if not isinstance(session_data, dict):
        return VdpCanonicalSummary(
            source_kind="legacy",
            schema_version=None,
            compatibility_reasons=("session_data_not_a_dict",),
        )

    vdp_section = session_data.get("vdp_contract")
    if not isinstance(vdp_section, dict) or not vdp_section:
        return VdpCanonicalSummary(
            source_kind="legacy",
            schema_version=None,
            compatibility_reasons=(COMPAT_REASON_LEGACY_NO_VDP_CONTRACT,),
        )

    errors: List[str] = []
    compatibility: List[str] = []

    raw_version = vdp_section.get("vdp_contract_version")
    if not isinstance(raw_version, int) or type(raw_version) is not int:
        return VdpCanonicalSummary(
            source_kind="canonical_vdp",
            schema_version=None,
            compatibility_reasons=("vdp_contract_version_missing_or_invalid",),
        )
    if raw_version != VDP_CONTRACT_SCHEMA_VERSION:
        return VdpCanonicalSummary(
            source_kind="canonical_vdp",
            schema_version=raw_version,
            compatibility_reasons=(
                f"vdp_contract_version_mismatch:{raw_version}",
            ),
        )

    raw_hypotheses = vdp_section.get("hypotheses", [])
    raw_attempts = vdp_section.get("attempts", [])
    raw_evidence = vdp_section.get("evidence_records", [])
    raw_verdicts = vdp_section.get("verdicts", [])
    raw_next_actions = vdp_section.get("next_actions", [])

    # SGK-2026-0423 Lane D (additive passthrough): the shadow/enforce diff
    # trace is carried into the summary ONLY when the session stores it as a
    # list of dicts; any other shape is omitted (never guessed).
    raw_shadow_diff = vdp_section.get("shadow_diff")
    shadow_diff = (
        tuple(
            dict(entry)
            for entry in raw_shadow_diff
            if isinstance(entry, dict)
        )
        if isinstance(raw_shadow_diff, list)
        else ()
    )

    hypotheses = _parse_typed_list(raw_hypotheses, HypothesisRecord, "hypotheses", errors)
    attempts = _parse_typed_list(raw_attempts, AttemptRecord, "attempts", errors)
    evidence_records = _parse_typed_list(
        raw_evidence, EvidenceRecordV1, "evidence_records", errors
    )
    next_actions = _parse_typed_list(
        raw_next_actions, NextActionRecord, "next_actions", errors
    )

    provider = public_key_provider if public_key_provider is not None else default_public_key_provider()

    verdicts: List[EvidenceVerdictV1] = []
    if isinstance(raw_verdicts, list):
        evidence_dicts = [e for e in raw_evidence if isinstance(e, dict)]
        for i, item in enumerate(raw_verdicts):
            if not isinstance(item, dict):
                errors.append(f"verdicts[{i}]: expected dict")
                continue
            restored = _restore_verdict(item, evidence_dicts, provider, compatibility)
            if restored is not None:
                verdicts.append(restored)

    # Observation content is NOT stored in the session → only IDs are shown.
    observation_ids = sorted(
        {oid for h in hypotheses for oid in h.observation_ids if oid}
    )
    if observation_ids:
        compatibility.append(COMPAT_REASON_OBSERVATION_CONTENT_UNAVAILABLE)

    drop_reasons: Dict[str, int] = {}
    for verdict in verdicts:
        if verdict.status == "untested":
            for code in verdict.reason_codes:
                drop_reasons[str(code)] = drop_reasons.get(str(code), 0) + 1

    funnel = _build_funnel(
        hypotheses, attempts, evidence_records, verdicts, next_actions, drop_reasons
    )

    if errors:
        compatibility.append(f"parse_errors:{len(errors)}")

    return VdpCanonicalSummary(
        source_kind="canonical_vdp",
        schema_version=int(raw_version),
        compatibility_reasons=tuple(sorted(set(compatibility))),
        observation_ids=tuple(observation_ids),
        hypotheses=tuple(hypotheses),
        attempts=tuple(attempts),
        evidence_records=tuple(evidence_records),
        verdicts=tuple(verdicts),
        next_actions=tuple(next_actions),
        budget_snapshot=dict(vdp_section.get("budget_snapshot", {}) or {}),
        run_health=dict(vdp_section.get("run_health", {}) or {}),
        funnel=funnel,
        dedup_keys=_evidence_fingerprint_dedup_keys(
            hypotheses, attempts, evidence_records
        ),
        shadow_diff=shadow_diff,
    )


def build_vdp_canonical_index(summary: VdpCanonicalSummary) -> Dict[str, Any]:
    """Machine-readable canonical index (plan §9 / T6).

    All formatters emit this block from the SAME serializer so the
    consistency checker can compare report vs session without parsing
    human Markdown regexes. Content: source_kind, verdict sets/counts,
    evidence IDs/hashes and a summary digest.
    """
    evidence_hashes = {
        e.evidence_id: str(e.raw_hash or "") for e in summary.evidence_records
    }
    index = {
        "index_version": VDP_CANONICAL_INDEX_VERSION,
        "source_kind": summary.source_kind,
        "schema_version": summary.schema_version,
        "compatibility_reasons": list(summary.compatibility_reasons),
        "verdict_ids": {
            "confirmed": sorted(v.verdict_id for v in summary.confirmed_verdicts),
            "candidate": sorted(v.verdict_id for v in summary.candidate_verdicts),
            "refuted": sorted(v.verdict_id for v in summary.refuted_verdicts),
            "untested": sorted(v.verdict_id for v in summary.untested_verdicts),
        },
        "verdict_counts": {
            "confirmed": len(summary.confirmed_verdicts),
            "candidate": len(summary.candidate_verdicts),
            "refuted": len(summary.refuted_verdicts),
            "untested": len(summary.untested_verdicts),
        },
        "evidence_ids": sorted(evidence_hashes.keys()),
        "evidence_hashes": evidence_hashes,
        "funnel": summary.funnel.to_dict(),
        "dedup_keys": list(summary.dedup_keys),
        "summary_digest": hashlib.sha256(
            canonical_json_bytes(summary.to_dict())
        ).hexdigest(),
    }
    return index
