"""
SGK-2026-0423 Lane B — offline hidden-holdout evaluation runner (reporting).

Consumes ONLY canonical VDP records — ``VdpCanonicalSummary`` (its
``HypothesisRecord`` / ``AttemptRecord`` / ``EvidenceRecordV1`` /
``EvidenceVerdictV1`` / ``NextActionRecord`` tuples) — plus the holdout
label dict and the pre-frozen threshold artifact. It NEVER reads prompts,
recipes, raw config, raw session files, or holdout labels beyond the
passed ``labels`` argument (plan §2.2).

Decision rules (plan §4):
- any leakage hit                    -> outcome "fail" (No-Go, plan §4.1);
- no leakage but a metric below its  -> outcome "hold" (plan §4.2);
  frozen threshold (or a threshold
  name with no computed metric —
  fail-closed)
- otherwise                          -> outcome "pass" (Go, plan §4.3).

Metrics are stored SEPARATELY — no single composite score that could let a
safety violation be offset (plan §6: 単一の総合点で安全違反を相殺しない).

Import boundary (SGK-2026-0422 rule): this module imports ONLY
``src.core.models.vdp_contract`` and ``src.reporting`` modules — never
``src.core.engine``.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

from src.core.models.vdp_contract import canonical_json_bytes
from src.reporting.vdp_canonical import VdpCanonicalSummary
from src.reporting.vdp_dataset import (
    LeakageHit,
    ThresholdArtifact,
    ThresholdMetric,
    normalize_endpoint_structure,
    scan_runtime_inputs_for_leakage,
    thresholds_fingerprint,
)

HOLDOUT_RESULT_SCHEMA_VERSION = 1


class HoldoutEvaluationResult(BaseModel):
    """Hashable, versioned result artifact of one hidden-holdout evaluation.

    ``artifact_hash`` is the sha256 of the canonical JSON of all OTHER
    fields; ``save_evaluation_result`` computes and writes it. Never
    contains secrets: only metric values/formulas and leakage hits are
    stored, never raw runtime texts.
    """

    schema_version: int = HOLDOUT_RESULT_SCHEMA_VERSION
    eval_version: str
    runner_version: str
    threshold_fingerprint: str
    input_session_ref: str
    started_at: str
    finished_at: str
    metrics: Dict[str, Dict[str, Any]]
    leakage_hits: List[LeakageHit]
    outcome: str  # "pass" | "hold" | "fail"
    gaps: List[str] = []  # additive (Lane G): metric-semantics gaps, e.g.
                          # "no_ground_truth" when recall has no labels to
                          # match against
    # Additive metadata (Lane J-1): provenance + operational context of the
    # evaluated run. They are part of the artifact and participate in
    # ``artifact_hash``.
    code_version: str = ""
    config_version: str = ""
    feature_flags: Dict[str, Any] = field(default_factory=dict)
    input_hash: str = ""
    termination_state: str = "unknown"
    artifact_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HoldoutEvaluationResult":
        return cls.model_validate(d)


class EvalVersionMismatch(Exception):
    """Raised when the eval version of a result/threshold pair disagrees."""


# ---------------------------------------------------------------------------
# Metric computation (plan §6)
# ---------------------------------------------------------------------------

_TARGET_SET = "hidden_holdout"


def _put(metrics: Dict[str, Dict[str, Any]], name: str, value: float,
         formula: str) -> None:
    metrics[name] = {
        "value": round(float(value), 6),
        "formula": formula,
        "target_set": _TARGET_SET,
    }


def _threshold_direction(threshold: ThresholdMetric) -> str:
    """Resolve the comparison direction for one frozen threshold.

    An explicit ``direction`` always wins. Legacy artifacts (built before
    the ``direction`` field existed — the field was not set during
    construction/validation) default to "minimum", but the historical
    upper-bound families ``false_promotion_rate:*`` and ``untested_rate``
    keep their maximum semantics so old artifacts bind unchanged.
    """
    direction = threshold.direction
    if direction == "minimum" and "direction" not in threshold.model_fields_set:
        if threshold.name == "untested_rate" or threshold.name.startswith(
            "false_promotion_rate"
        ):
            return "maximum"
    return direction


def _threshold_met(threshold: ThresholdMetric, value: float) -> bool:
    """Direction-aware threshold comparison (Lane J-1).

    - "minimum": met when value >= bound;
    - "maximum": met when value <= bound.
    """
    if _threshold_direction(threshold) == "maximum":
        return bool(value <= threshold.value)
    return bool(value >= threshold.value)


def _compute_metrics(summary: VdpCanonicalSummary,
                     labels: Dict[str, Any],
                     thresholds: ThresholdArtifact,
                     ) -> "tuple[Dict[str, Dict[str, Any]], List[str]]":
    """Compute evaluation metrics.

    Returns ``(metrics, gaps)``. Process metrics (coverage/funnel/untested/
    budget) are unchanged; the quality metrics ``recall:*`` and
    ``false_promotion_rate`` are computed against the product-independent
    ground-truth labels (Lane G):
    - ``recall`` / ``recall:<class>`` — matched ground-truth entries
      (capability + normalized endpoint, host-agnostic) / ground-truth
      entries; overall is 0.0 with gap ``no_ground_truth`` when the label
      artifact carries no ground truth;
    - ``false_promotion_rate`` / ``false_promotion_rate:<class>`` —
      confirmed hypotheses with NO ground-truth match / confirmed
      hypotheses.
    """
    hypotheses = list(summary.hypotheses)
    attempts = list(summary.attempts)
    evidence_records = list(summary.evidence_records)
    verdicts = list(summary.verdicts)
    next_actions = list(summary.next_actions)
    total = len(hypotheses)

    metrics: Dict[str, Dict[str, Any]] = {}
    gaps: List[str] = []

    # Per-class / per-actor / per-trust-boundary hypothesis coverage
    # (process metric, unchanged — plan §6).
    def _groups(key_fn) -> Dict[str, List[Any]]:
        groups: Dict[str, List[Any]] = {}
        for h in hypotheses:
            for group_value in key_fn(h):
                groups.setdefault(group_value, []).append(h)
        return groups

    for prefix, groups in (
        ("class", _groups(lambda h: [h.capability])),
        ("actor", _groups(lambda h: list(h.actors))),
        ("trust_boundary", _groups(lambda h: [h.trust_boundary])),
    ):
        for group_value, members in sorted(groups.items()):
            coverage = len(members) / total if total else 0.0
            _put(metrics, f"coverage:{prefix}:{group_value}", coverage,
                 f"hypotheses({prefix}={group_value}) / total_hypotheses")

    # Label-based recall: fraction of GROUND-TRUTH entries discovered by
    # confirmed verdicts. Match rule: hypothesis capability equals the gt
    # capability AND the normalized endpoint structure equals the gt
    # endpoint structure (host-agnostic). Each gt entry counts once.
    confirmed = [v for v in verdicts if v.status == "confirmed"]
    confirmed_ids = {v.hypothesis_id for v in confirmed}
    hyp_by_id = {h.hypothesis_id: h for h in hypotheses}
    gt_entries = [e for e in (labels.get("ground_truth") or [])
                  if isinstance(e, dict)]

    def _gt_matches(hyp: Any, entry: Dict[str, Any]) -> bool:
        return (
            hyp.capability == str(entry.get("capability") or "")
            and normalize_endpoint_structure(hyp.asset)
            == normalize_endpoint_structure(str(entry.get("endpoint") or ""))
        )

    matched_gt: Dict[int, str] = {}
    for index, entry in enumerate(gt_entries):
        for verdict in confirmed:
            hyp = hyp_by_id.get(verdict.hypothesis_id)
            if hyp is not None and _gt_matches(hyp, entry):
                matched_gt[index] = verdict.hypothesis_id
                break
    hyp_with_match = set(matched_gt.values())

    classes = sorted({str(e.get("class") or "") for e in gt_entries})
    classes = [c for c in classes if c]
    for cls in classes:
        cls_indices = [i for i, e in enumerate(gt_entries)
                       if str(e.get("class") or "") == cls]
        matched_in_cls = sum(1 for i in cls_indices if i in matched_gt)
        _put(metrics, f"recall:{cls}",
             matched_in_cls / len(cls_indices) if cls_indices else 0.0,
             f"matched_ground_truth(class={cls}) / ground_truth(class={cls})")

    if gt_entries:
        _put(metrics, "recall", len(matched_gt) / len(gt_entries),
             "matched_ground_truth_entries / ground_truth_entries")
    else:
        _put(metrics, "recall", 0.0,
             "matched_ground_truth_entries / ground_truth_entries "
             "(0.0 when ground_truth is empty)")
        gaps.append("no_ground_truth")

    # Label-based false promotion rate: confirmed hypotheses with NO
    # ground-truth match / confirmed hypotheses (per gt class via the
    # capability -> class mapping, and overall).
    confirmed_hypotheses = [h for h in hypotheses
                            if h.hypothesis_id in confirmed_ids]
    no_match = [h for h in confirmed_hypotheses
                if h.hypothesis_id not in hyp_with_match]
    _put(metrics, "false_promotion_rate",
         len(no_match) / len(confirmed_hypotheses) if confirmed_hypotheses else 0.0,
         "confirmed_hypotheses_without_gt_match / confirmed_hypotheses")
    capability_class: Dict[str, str] = {}
    for entry in gt_entries:
        capability_class.setdefault(str(entry.get("capability") or ""),
                                    str(entry.get("class") or ""))
    for cls in classes:
        cls_confirmed = [h for h in confirmed_hypotheses
                         if capability_class.get(h.capability) == cls]
        cls_no_match = [h for h in cls_confirmed
                        if h.hypothesis_id not in hyp_with_match]
        _put(metrics, f"false_promotion_rate:{cls}",
             len(cls_no_match) / len(cls_confirmed) if cls_confirmed else 0.0,
             f"confirmed_without_gt_match(class={cls}) / confirmed(class={cls})")

    # Evidence completeness (plan §6).
    evidence_attempt_ids = {e.attempt_id for e in evidence_records}
    hypotheses_with_evidence = {
        a.hypothesis_id for a in attempts if a.attempt_id in evidence_attempt_ids
    }
    _put(metrics, "evidence_completeness",
         len(hypotheses_with_evidence) / total if total else 0.0,
         "hypotheses_with_evidence / total_hypotheses")

    # Funnel reach rates (plan §6: observation -> hypothesis -> attempt ->
    # follow-up -> verdict).
    observation_ids = {oid for h in hypotheses for oid in h.observation_ids if oid}
    _put(metrics, "funnel:observation_to_hypothesis",
         len(hypotheses) / len(observation_ids) if observation_ids else 0.0,
         "hypotheses / observations")
    _put(metrics, "funnel:hypothesis_to_attempt",
         len(attempts) / total if total else 0.0,
         "attempts / hypotheses")
    _put(metrics, "funnel:attempt_to_follow_up",
         len(next_actions) / len(attempts) if attempts else 0.0,
         "next_actions / attempts")
    _put(metrics, "funnel:follow_up_to_verdict",
         len(verdicts) / len(next_actions) if next_actions else 0.0,
         "verdicts / next_actions")

    # Untested rate + reason-code distribution (plan §6: budget/infra/scope/
    # prerequisite別理由分布).
    untested = [v for v in verdicts if v.status == "untested"]
    _put(metrics, "untested_rate",
         len(untested) / len(verdicts) if verdicts else 0.0,
         "untested_verdicts / verdicts")
    distribution: Dict[str, int] = {}
    for verdict in untested:
        for code in verdict.reason_codes:
            distribution[str(code)] = distribution.get(str(code), 0) + 1
    distribution_entry = metrics.setdefault("untested_reason_distribution", {
        "value": 0.0, "formula": "reason_code -> count over untested verdicts",
        "target_set": _TARGET_SET,
    })
    distribution_entry["reasons"] = dict(sorted(distribution.items()))

    # Budget compliance (plan §6): share of budget entries within limits.
    eligible = 0
    compliant = 0
    for key, value in summary.budget_snapshot.items():
        if not isinstance(value, dict) or "used" not in value:
            continue
        limit = value.get("limit")
        if limit is None:
            limit = value.get("max")
        if isinstance(limit, (int, float)) and isinstance(value["used"], (int, float)):
            eligible += 1
            if value["used"] <= limit:
                compliant += 1
    _put(metrics, "budget_compliance",
         compliant / eligible if eligible else 1.0,
         "within-limit budget entries / eligible budget entries "
         "(1.0 when no budget snapshot)")

    # Bind frozen thresholds by their explicit direction (Lane J-1):
    # "minimum" requires value >= bound, "maximum" requires value <= bound.
    # Legacy artifacts without the direction field keep the historical
    # upper-bound semantics for the false_promotion_rate family and
    # untested_rate (see ``_threshold_direction``). A threshold name with
    # no computed metric is unmet (fail-closed).
    for threshold in thresholds.metrics:
        entry = metrics.get(threshold.name)
        if entry is None:
            entry = metrics[threshold.name] = {
                "value": 0.0,
                "formula": "no computed metric (fail-closed)",
                "target_set": threshold.target_set,
            }
            entry["met"] = False
        else:
            entry["threshold"] = threshold.value
            entry["met"] = _threshold_met(threshold, entry["value"])
    return metrics, gaps


def _record_derived_texts(summary: VdpCanonicalSummary) -> List[str]:
    """Runtime-derived texts the runner may legitimately scan for leakage:
    hypothesis texts, attempt request fingerprints and evidence redacted
    excerpts. Index order is fixed: hypotheses, then attempts, then
    evidence (deterministic; recorded via LeakageHit.source_index)."""
    texts: List[str] = []
    texts.extend(h.hypothesis_text for h in summary.hypotheses)
    texts.extend(a.request_fingerprint for a in summary.attempts)
    texts.extend(e.redacted_excerpt for e in summary.evidence_records)
    return texts


def run_holdout_evaluation(
    summary: VdpCanonicalSummary,
    labels: Dict[str, Any],
    thresholds: ThresholdArtifact,
    *,
    eval_version: str,
    runner_version: str,
    session_ref: str = "",
    code_version: str = "",
    config_version: str = "",
    feature_flags: Optional[Dict[str, Any]] = None,
    input_hash: str = "",
    termination_state: str = "unknown",
) -> HoldoutEvaluationResult:
    """Run one hidden-holdout evaluation over canonical records only.

    INPUTS (plan §2.2): the canonical summary (hypotheses/attempts/
    evidence/verdicts/next-actions), the holdout ``labels`` dict and the
    frozen ``thresholds``. ``labels`` may carry an optional
    ``ground_truth`` list (entries: ``class`` / ``capability`` /
    ``method`` / ``endpoint`` with a normalized endpoint structure —
    product-independent); without it, ``recall`` is 0.0 and the result
    carries the ``no_ground_truth`` gap. Never reads prompts, recipes,
    raw config, raw session files, or holdout labels beyond ``labels``.

    Optional additive metadata (Lane J-1): ``code_version``,
    ``config_version``, ``feature_flags``, ``input_hash`` and
    ``termination_state`` are stored on the result and become part of the
    artifact hash.

    Raises ``EvalVersionMismatch`` when ``eval_version`` differs from
    ``thresholds.eval_version`` (a frozen artifact can only judge its own
    evaluation version).
    """
    if eval_version != thresholds.eval_version:
        raise EvalVersionMismatch(
            f"eval_version {eval_version!r} does not match thresholds "
            f"eval_version {thresholds.eval_version!r}"
        )
    started_at = datetime.now(timezone.utc).isoformat()

    metrics, gaps = _compute_metrics(summary, labels, thresholds)
    leakage_hits = scan_runtime_inputs_for_leakage(
        _record_derived_texts(summary), labels
    )
    unmet = [
        name for name, entry in metrics.items()
        if entry.get("met") is False
    ]
    finished_at = datetime.now(timezone.utc).isoformat()

    if leakage_hits:
        outcome = "fail"
    elif unmet:
        outcome = "hold"
    else:
        outcome = "pass"

    return HoldoutEvaluationResult(
        eval_version=eval_version,
        runner_version=runner_version,
        threshold_fingerprint=thresholds_fingerprint(thresholds),
        input_session_ref=session_ref,
        started_at=started_at,
        finished_at=finished_at,
        metrics=metrics,
        leakage_hits=leakage_hits,
        outcome=outcome,
        gaps=gaps,
        code_version=code_version,
        config_version=config_version,
        feature_flags=dict(feature_flags or {}),
        input_hash=input_hash,
        termination_state=termination_state,
    )


def save_evaluation_result(result: HoldoutEvaluationResult,
                           path: str | os.PathLike) -> None:
    """Atomically save a holdout evaluation result (plan §9).

    Computes ``artifact_hash`` over the canonical JSON of every field
    except ``artifact_hash`` itself, then writes via temp file +
    ``os.replace``. NEVER writes secrets: the result contains only metric
    values, formulas and leakage hits (no runtime texts).
    """
    payload = result.to_dict()
    artifact_hash = hashlib.sha256(canonical_json_bytes(
        {k: v for k, v in payload.items() if k != "artifact_hash"}
    )).hexdigest()
    result.artifact_hash = artifact_hash
    final = result.to_dict()

    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(target.parent),
                               prefix=".tmp-holdout-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(final, handle, sort_keys=True,
                      ensure_ascii=False, indent=2)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def assert_thresholds_frozen_for_eval_version(
    result_path: str | os.PathLike,
    thresholds: ThresholdArtifact,
) -> None:
    """Guard: a changed threshold artifact can never re-claim an existing
    eval-version result (plan §2.2).

    Loads the saved result; when it exists AND carries the same
    ``eval_version`` as ``thresholds`` but a different threshold
    fingerprint, raises ``EvalVersionMismatch``. A missing result file is a
    first run and returns normally.
    """
    path = Path(result_path)
    if not path.exists():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    result = HoldoutEvaluationResult.from_dict(data)
    if result.eval_version != thresholds.eval_version:
        return
    if result.threshold_fingerprint != thresholds_fingerprint(thresholds):
        raise EvalVersionMismatch(
            f"eval_version {result.eval_version} already has a saved result "
            f"with a different threshold fingerprint; a changed threshold "
            f"artifact cannot re-claim the same eval_version"
        )


def verify_no_runtime_leakage(result: HoldoutEvaluationResult) -> bool:
    """True when the result carries zero leakage hits (plan §4.3: 漏洩検査
    が0件)."""
    return len(result.leakage_hits) == 0
