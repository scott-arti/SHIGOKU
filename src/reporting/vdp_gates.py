"""
VDP quality gates — SGK-2026-0422 (reporting layer).

Separates the training capability gate from the real VDP run-quality gate
(plan §5). Both consume the SAME immutable ``VdpCanonicalSummary`` produced
by the canonical extractor.

- ``evaluate_vdp_training_gate``: label manifest required (``--labels``).
  Evaluates class recall, false promotion rate, evidence completeness and
  hypothesis→follow-up reach. Labels are read ONLY by this evaluator and
  never reach runtime inputs / prompts / recipes / priorities.
- ``evaluate_vdp_real_gate``: NEVER reads known labels, expected detection
  matrices, product names, known URLs, ``confirmed_min``, ``candidate_max``
  or guessed recall. Evaluates scope/capability application, exploration
  coverage, untested-reason completeness, infra gaps, safety violations,
  HITL bypass, secrets, report/session consistency and run termination.
  Returns Go / Hold / No-Go with versioned JSON and reason codes.
- The legacy initial-release gate (``evaluate_initial_release_gate``) stays
  untouched as the compatibility wrapper for the old CLI.

No gate here auto-selects a profile from target names or known product
information. A missing profile for a canonical VDP artifact is an explicit
error (or Hold), never a silent legacy-threshold application.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.reporting.vdp_canonical import VdpCanonicalSummary, extract_vdp_canonical

VDP_GATE_SCHEMA_VERSION = 1
PROFILE_TRAINING = "training"
PROFILE_REAL = "real"
PROFILE_LEGACY = "legacy"

# Safety-relevant run-health markers that force No-Go.
NO_GO_RUN_HEALTH_MARKERS = (
    "scope_violation",
    "secret_leak",
    "hitl_bypass",
    "unsafe_action_proposed",
    "tampered_proof",
)
# Infra markers that force Hold when present (safety not violated).
HOLD_RUN_HEALTH_MARKERS = (
    "evidence_channel_lost",
    "dependency_unavailable",
    "budget_exhausted",
    "signer_unavailable",
)

_VALID_UNTESTED_REASON_PREFIXES = (
    "untested_",
    "budget_",
    "scope_",
    "evidence_",
    "dependency_",
    "follow_up_",
    "circuit_",
    "payload_",
    "authz_",
    "synthetic_",
    "insufficient_",
    "state_",
    "browser_",
    "stored_",
    "command_",
    "ssrf_",
    "unique_",
    "weak_",
    "file_",
    "public_",
    "session_",
    "redirect_",
    "unknown_",
)


@dataclass(frozen=True)
class GateVerdict:
    """Structured gate verdict (Go/Hold/No-Go or pass/fail + reason codes)."""

    status: str  # pass | fail | blocked
    profile: str
    decision: str = ""  # go | hold | no_go (real profile only)
    reason_codes: List[str] = field(default_factory=list)
    gates: Dict[str, Any] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    actual_values: Dict[str, Any] = field(default_factory=dict)
    schema_version: int = VDP_GATE_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "schema_version": self.schema_version,
            "profile": self.profile,
            "status": self.status,
            "reason_codes": sorted(set(self.reason_codes)),
            "gates": self.gates,
            "policy": self.policy,
            "actual_values": self.actual_values,
        }
        if self.decision:
            result["decision"] = self.decision
        return result


# ---------------------------------------------------------------------------
# Training capability gate
# ---------------------------------------------------------------------------


def _load_labels_manifest(labels_path: Path | str | None) -> Dict[str, Any]:
    """Load a label manifest (training only). Returns {} when missing."""
    if labels_path is None:
        return {}
    path = Path(labels_path)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def evaluate_vdp_training_gate(
    summary: VdpCanonicalSummary,
    labels_manifest: Dict[str, Any],
) -> GateVerdict:
    """Training capability gate — class recall, false promotion, evidence
    completeness, hypothesis→follow-up reach.

    ``labels_manifest`` maps hypothesis_id (or capability) → expected
    vulnerability class. Requires at least one label; without labels the
    gate is blocked (``--labels`` is mandatory for the training profile).
    """
    labels_raw = labels_manifest.get("labels", [])
    labels: Dict[str, str] = {}
    if isinstance(labels_raw, list):
        for item in labels_raw:
            if not isinstance(item, dict):
                continue
            hyp_id = str(item.get("hypothesis_id") or "").strip()
            expected = str(item.get("expected_class") or item.get("vuln_class") or "").strip()
            if hyp_id and expected:
                labels[hyp_id] = expected

    if not labels:
        return GateVerdict(
            status="blocked",
            profile=PROFILE_TRAINING,
            reason_codes=["training_labels_required"],
            policy={"labels_required": True},
            actual_values={"labels_count": 0},
        )

    # Class recall: of the labelled hypotheses, how many produced a
    # confirmed verdict (or at least a candidate with matching capability).
    confirmed_by_class: Dict[str, int] = {}
    candidate_by_class: Dict[str, int] = {}
    expected_by_hypothesis = {
        h.hypothesis_id: labels.get(h.hypothesis_id, "")
        for h in summary.hypotheses
    }
    for verdict in summary.verdicts:
        expected = expected_by_hypothesis.get(verdict.hypothesis_id, "")
        if not expected:
            continue
        if verdict.status == "confirmed":
            confirmed_by_class[expected] = confirmed_by_class.get(expected, 0) + 1
        elif verdict.status == "candidate":
            candidate_by_class[expected] = candidate_by_class.get(expected, 0) + 1

    total_labeled = len(labels)
    total_confirmed = sum(confirmed_by_class.values())
    recall = (total_confirmed / total_labeled) if total_labeled else 0.0

    # False promotion: confirmed verdicts whose hypothesis has NO label
    # (i.e. promotion beyond the labelled set).
    labeled_hyp_ids = set(labels.keys())
    false_promotion = sum(
        1
        for verdict in summary.confirmed_verdicts
        if verdict.hypothesis_id not in labeled_hyp_ids
    )

    # Evidence completeness: every confirmed verdict has evaluated evidence.
    confirmed_verdicts = summary.confirmed_verdicts
    evidence_complete = (
        sum(1 for v in confirmed_verdicts if v.evaluated_evidence_ids) / len(confirmed_verdicts)
        if confirmed_verdicts
        else 0.0
    )

    # Hypothesis -> follow-up reach.
    hypotheses = summary.hypotheses
    reach = (
        (len(summary.next_actions) / len(hypotheses)) if hypotheses else 0.0
    )

    reason_codes: List[str] = []
    if total_confirmed == 0:
        reason_codes.append("no_confirmed_detections")
    if false_promotion > 0:
        reason_codes.append("false_promotion_detected")
    if not confirmed_verdicts:
        reason_codes.append("no_evidence_completeness")

    status = "fail" if reason_codes else "pass"

    return GateVerdict(
        status=status,
        profile=PROFILE_TRAINING,
        reason_codes=reason_codes,
        gates={
            "class_recall": {
                "status": "pass" if recall > 0 else "fail",
                "recall": round(recall, 4),
                "confirmed_by_class": confirmed_by_class,
                "candidate_by_class": candidate_by_class,
                "total_labeled": total_labeled,
            },
            "false_promotion": {
                "status": "pass" if false_promotion == 0 else "fail",
                "false_promotion_count": false_promotion,
            },
            "evidence_completeness": {
                "status": "pass" if evidence_complete == 1.0 else "fail",
                "completeness": round(evidence_complete, 4),
            },
            "follow_up_reach": {
                "status": "pass",
                "reach_rate": round(reach, 4),
            },
        },
        policy={"labels_required": True},
        actual_values={
            "total_labeled": total_labeled,
            "total_confirmed": total_confirmed,
            "recall": round(recall, 4),
            "false_promotion_count": false_promotion,
            "evidence_complete": round(evidence_complete, 4),
            "follow_up_reach": round(reach, 4),
        },
    )


# ---------------------------------------------------------------------------
# Real VDP run-quality gate
# ---------------------------------------------------------------------------


def _real_run_health_flags(run_health: Dict[str, Any]) -> Dict[str, List[str]]:
    """Classify run-health markers into no-go / hold flags."""
    no_go: List[str] = []
    hold: List[str] = []
    for key in ("safety_blocks", "scope_blocks", "dependency_failures", "reason"):
        raw = run_health.get(key, "")
        values: List[str] = []
        if isinstance(raw, str):
            values = [raw]
        elif isinstance(raw, list):
            values = [str(v) for v in raw]
        for value in values:
            lowered = str(value).lower()
            if any(marker in lowered for marker in NO_GO_RUN_HEALTH_MARKERS):
                no_go.append(lowered)
            elif any(marker in lowered for marker in HOLD_RUN_HEALTH_MARKERS):
                hold.append(lowered)
    return {"no_go": sorted(set(no_go)), "hold": sorted(set(hold))}


def _untested_reason_completeness(summary: VdpCanonicalSummary) -> Dict[str, Any]:
    """Untested reasons must be parseable/known; unknown codes → gap."""
    unknown: List[str] = []
    total = 0
    for verdict in summary.untested_verdicts:
        for code in verdict.reason_codes:
            total += 1
            code_lower = str(code or "").lower()
            if not any(code_lower.startswith(prefix) for prefix in _VALID_UNTESTED_REASON_PREFIXES):
                unknown.append(str(code))
    return {
        "untested_count": len(summary.untested_verdicts),
        "reason_code_total": total,
        "unknown_reason_codes": sorted(set(unknown)),
        "complete": not unknown,
    }


def evaluate_vdp_real_gate(
    summary: VdpCanonicalSummary,
    *,
    consistency_status: str = "consistent",
    consistency_reason_codes: Optional[List[str]] = None,
) -> GateVerdict:
    """Real VDP run-quality gate — Go / Hold / No-Go.

    NEVER reads known labels, expected detection matrices, product names,
    known URLs, confirmed_min, candidate_max or guessed recall. Candidate
    counts alone never fail the gate.
    """
    reason_codes: List[str] = []
    gates: Dict[str, Any] = {}

    run_health = summary.run_health or {}
    flags = _real_run_health_flags(run_health)

    # ---- Scope / capability application ----
    scope_blocks = run_health.get("scope_blocks", [])
    if isinstance(scope_blocks, str):
        scope_blocks = [scope_blocks]
    scope_block_count = len(scope_blocks) if isinstance(scope_blocks, list) else 0
    scope_gate = {
        "status": "fail" if flags["no_go"] else "pass",
        "scope_block_count": scope_block_count,
        "no_go_flags": flags["no_go"],
    }
    gates["scope_capability"] = scope_gate
    if flags["no_go"]:
        reason_codes.extend(flags["no_go"])

    # ---- Exploration coverage ----
    funnel = summary.funnel
    exploration_gate = {
        "status": "pass",
        "observations": funnel.observations,
        "hypotheses": funnel.hypotheses,
        "attempted": funnel.attempted,
        "responded": funnel.responded,
        "followed_up": funnel.followed_up,
    }
    gates["exploration_coverage"] = exploration_gate

    # ---- Untested reason completeness ----
    untested = _untested_reason_completeness(summary)
    untested_gate = {
        "status": "pass" if untested["complete"] else "fail",
        **untested,
    }
    gates["untested_reason_completeness"] = untested_gate
    if untested["unknown_reason_codes"]:
        reason_codes.append("unknown_untested_reason_codes")

    # ---- Infra gaps ----
    infra_gate = {
        "status": "pass",
        "hold_flags": flags["hold"],
    }
    gates["infra"] = infra_gate
    if flags["hold"]:
        reason_codes.extend(flags["hold"])

    # ---- Safety / HITL / secret ----
    safety_gate = {
        "status": "pass" if not flags["no_go"] else "fail",
        "no_go_flags": flags["no_go"],
    }
    gates["safety"] = safety_gate

    # ---- Report/session consistency ----
    consistency_gate = {
        "status": "pass" if consistency_status == "consistent" else "fail",
        "consistency_status": consistency_status,
        "consistency_reason_codes": sorted(set(consistency_reason_codes or [])),
    }
    gates["report_session_consistency"] = consistency_gate
    if consistency_status != "consistent":
        reason_codes.append("report_session_inconsistent")

    # ---- Run termination state ----
    run_state = str(run_health.get("run_state", "") or "unknown")
    termination_gate = {
        "status": "pass" if run_state in {"succeeded", "partial"} else "fail",
        "run_state": run_state,
    }
    gates["termination_state"] = termination_gate
    if run_state in {"failed", "safety_blocked"}:
        reason_codes.append(f"run_state_{run_state}")
    elif run_state == "unknown":
        # Lane J-1: unknown termination is an operational-evidence gap, not
        # a safety violation — the DECISION becomes hold (see below), while
        # the termination_gate reporting stays "fail" for unknown.
        reason_codes.append("run_state_unknown_hold")

    # ---- Tampered proof (compatibility reasons) ----
    tampered = [
        r for r in summary.compatibility_reasons
        if "tamper" in r or "unknown_key" in r or "missing_proof" in r
    ]
    if tampered:
        reason_codes.append("tampered_proof")
        gates["proof_integrity"] = {"status": "fail", "compatibility_reasons": tampered}

    # ---- Verification key unavailable / legacy unverifiable -> HOLD ----
    # Audit I-03: an unverifiable confirmed (key_unavailable,
    # legacy_proof_unverifiable) must never silently become Go. These are
    # operational-evidence gaps, not safety violations — Hold.
    unverifiable = [
        r for r in summary.compatibility_reasons
        if "key_unavailable" in r or "legacy_proof_unverifiable" in r
    ]
    if unverifiable:
        reason_codes.append("verification_key_unavailable_hold")
        gates["proof_verifiability"] = {
            "status": "hold",
            "compatibility_reasons": unverifiable,
        }

    # ---- Decision: No-Go > Hold > Go ----
    no_go = (
        bool(flags["no_go"])
        or consistency_status != "consistent"
        or bool(tampered)
        or run_state in {"failed", "safety_blocked"}
    )
    if no_go:
        decision = "no_go"
        status = "fail"
    else:
        hold = (
            bool(flags["hold"])
            or bool(unverifiable)
            or not untested["complete"]
            or run_state == "unknown"  # Lane J-1: unknown termination holds
        )
        if hold:
            decision = "hold"
            status = "pass"  # Hold is not a safety fail; it is an explicit hold
            if not any("operational_hold" in c for c in reason_codes):
                reason_codes.append("operational_hold")
        else:
            decision = "go"
            status = "pass"

    return GateVerdict(
        status=status,
        profile=PROFILE_REAL,
        decision=decision,
        reason_codes=sorted(set(reason_codes)),
        gates=gates,
        policy={
            "confirmed_min": "not_used",
            "candidate_max": "not_used",
            "known_labels": "not_used",
        },
        actual_values={
            "run_state": run_state,
            "untested_count": untested["untested_count"],
            "attempted": funnel.attempted,
            "confirmed": funnel.confirmed,
        },
    )


# ---------------------------------------------------------------------------
# Profile dispatch
# ---------------------------------------------------------------------------


def evaluate_vdp_gate(
    profile: str,
    session_data: Dict[str, Any],
    *,
    labels_path: Optional[Path | str] = None,
    consistency_status: str = "consistent",
    consistency_reason_codes: Optional[List[str]] = None,
    public_key_provider: Any = None,
) -> GateVerdict:
    """Dispatch to the requested gate profile (training | real).

    profile missing/unknown → blocked with an explicit reason (never silent
    legacy-threshold application). ``legacy`` is NOT accepted here — the
    legacy initial-release gate keeps its own entry point.
    """
    profile = str(profile or "").strip().lower()
    summary = extract_vdp_canonical(
        session_data, public_key_provider=public_key_provider
    )
    if summary.source_kind != "canonical_vdp":
        return GateVerdict(
            status="blocked",
            profile=profile or "unknown",
            reason_codes=["canonical_vdp_session_required"],
            actual_values={"source_kind": summary.source_kind},
        )

    if profile == PROFILE_TRAINING:
        return evaluate_vdp_training_gate(
            summary, _load_labels_manifest(labels_path)
        )
    if profile == PROFILE_REAL:
        return evaluate_vdp_real_gate(
            summary,
            consistency_status=consistency_status,
            consistency_reason_codes=consistency_reason_codes,
        )
    return GateVerdict(
        status="blocked",
        profile=profile or "unknown",
        reason_codes=["profile_required"],
        policy={"valid_profiles": [PROFILE_TRAINING, PROFILE_REAL]},
    )
