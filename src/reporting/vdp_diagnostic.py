"""
SGK-2026-0425 — read-only first-failure analyzer (M2, plan §3.1/§3.3).

Pure module: no network, no LLM, no engine runtime imports, standard library
only. The only shared vocabulary used is the frozen taxonomy constants from
``src.core.engine.vdp_diagnostic_trace`` (STAGE_IDS / OUTCOMES / MECHANISM_CODES).

Responsibilities
----------------
- ``analyze_observed_lineages``: labels-free diagnosis of OBSERVED lineages
  only. Never guesses recall / S01 misses: the output always carries
  ``coverage_not_measurable_without_sealed_labels`` and never emits an
  expected-case recall. If the telemetry is insufficient the analyzer records
  U00 and names the needed artifact fields instead of guessing.
- ``first_failure_for_case`` / ``evaluate_expected_paths``: evaluator-only
  comparison against a sealed ExpectedPathCaseV1 stage DAG. Cases with an
  invalid DAG are excluded from the first-failure denominator with a reason.
- ``evaluate_first_failure_accuracy``: pure metric for the M4 harness.

First-failure rule (taxonomy judgement rules)
--------------------------------------------
The walk advances over stages with reach evidence (event outcome ``reached``
or canonical record presence). The first stage where the run stopped is the
first failure; later retry success never overwrites the earliest cut and the
earliest event_id is kept. Optional/ineligible stages are skipped in the walk
and never become first failures. When predecessor reach evidence is missing,
the analyzer does NOT guess the cut location: it returns U00 with the missing
stage events named in ``missing_artifacts``.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from src.core.engine.vdp_diagnostic_trace import (
    MECHANISM_CODES,
    OUTCOMES,
    STAGE_IDS,
)

ANALYZER_VERSION = "v1"
COVERAGE_NOTE = "coverage_not_measurable_without_sealed_labels"

# Walk order: S00..S12 (U00 is a verdict, never a walk position).
STAGE_ORDER: tuple[str, ...] = tuple(s for s in STAGE_IDS if s != "U00")
FAILURE_OUTCOMES: tuple[str, ...] = tuple(o for o in OUTCOMES if o != "reached")

# Canonical summary presence -> stage reach (labels-free evidence source).
# hypotheses -> S03, attempts -> S07, evidence_records -> S09/S10,
# verdicts -> S11, next_actions -> S04/S05.
CANONICAL_STAGE_MAP: Dict[str, str] = {
    "S03": "hypotheses",
    "S07": "attempts",
    "S09": "evidence_records",
    "S10": "evidence_records",
    "S11": "verdicts",
    "S04": "next_actions",
    "S05": "next_actions",
}

# SGK-2026-0426 W4: evidence-backed stages require attempts > 0. Shadow
# candidate verdicts and evidence records produced WITHOUT any attempt are
# NOT funnel reach — the pipeline demonstrably stopped before execution
# (e.g. the 0427 S05 follow-up-enqueue crash with attempts=0 and
# generated_candidate shadow verdicts must NOT mark S11 reached).
EVIDENCE_BACKED_STAGES: frozenset = frozenset({"S09", "S10", "S11"})


# --- helpers -------------------------------------------------------------------

def _canonical_summary_dict(canonical_summary: Optional[dict]) -> dict:
    if canonical_summary is None:
        return {}
    if isinstance(canonical_summary, dict):
        return canonical_summary
    if hasattr(canonical_summary, "to_dict"):  # VdpCanonicalSummary passthrough
        return canonical_summary.to_dict()
    return {}


def _canonical_reach(canonical_summary: Optional[dict]) -> set[str]:
    summary = _canonical_summary_dict(canonical_summary)
    reach: set[str] = set()
    attempts = summary.get("attempts")
    attempts_present = isinstance(attempts, (list, tuple)) and len(attempts) > 0
    for stage, key in CANONICAL_STAGE_MAP.items():
        items = summary.get(key)
        if not (isinstance(items, (list, tuple)) and len(items) > 0):
            continue
        if stage in EVIDENCE_BACKED_STAGES and not attempts_present:
            # SGK-2026-0426 W4: shadow artifacts without attempts are not
            # stage reach — the demonstrable chain stopped before execution.
            continue
        reach.add(stage)
    return reach


def _iteration_of(event: dict) -> int:
    """Iteration marker from ``source_refs`` ("iteration=N"); 0 when absent."""
    for ref in event.get("source_refs") or []:
        if isinstance(ref, str):
            match = re.search(r"iteration=(\d+)", ref)
            if match:
                return int(match.group(1))
    return 0


def _event_sort_key(event: dict) -> tuple:
    return (_iteration_of(event), str(event.get("event_id") or ""))


def _index_events(events: list) -> Dict[str, Dict[str, list]]:
    index: Dict[str, Dict[str, list]] = {
        s: {"reached": [], "failure": [], "all": []} for s in STAGE_ORDER
    }
    for ev in events:
        if not isinstance(ev, dict):
            continue
        stage = ev.get("stage_id")
        if stage not in index:
            continue
        outcome = ev.get("outcome")
        index[stage]["all"].append(ev)
        if outcome == "reached":
            index[stage]["reached"].append(ev)
        elif outcome in FAILURE_OUTCOMES:
            index[stage]["failure"].append(ev)
    for stage in STAGE_ORDER:
        index[stage]["reached"].sort(key=_event_sort_key)
        index[stage]["failure"].sort(key=_event_sort_key)
        index[stage]["all"].sort(key=_event_sort_key)
    return index


def _compute_reach(index: Dict[str, Dict[str, list]], canonical_reach: set[str]) -> set[str]:
    reach = set(canonical_reach)
    for stage in STAGE_ORDER:
        if index[stage]["reached"]:
            reach.add(stage)
    return reach


def _reason_to_causes(code: str) -> List[str]:
    causes = [c for c in MECHANISM_CODES if code in MECHANISM_CODES[c]]
    # Unknown mechanisms are held as C13, never rounded into existing vocabulary.
    return causes or ["C13"]


def _cause_candidates(reason_codes: list) -> List[str]:
    candidates: List[str] = []
    for code in reason_codes or []:
        for cause in _reason_to_causes(str(code)):
            if cause not in candidates:
                candidates.append(cause)
    return sorted(candidates)


def _missing_stage_artifact(stage: str) -> str:
    return f"{stage} stage event (event_id, outcome, reason_codes)"


def _u00_verdict(reason_codes: List[str], missing_artifacts: List[str], evidence_refs: Optional[List[str]] = None) -> dict:
    codes = sorted(set(reason_codes))
    return {
        "stage_id": "U00",
        "outcome": "unattributable",
        "reason_codes": codes,
        "cause_candidates": _cause_candidates(codes),
        "evidence_refs": sorted(set(evidence_refs or [])),
        "confidence": "unattributable",
        "missing_artifacts": list(missing_artifacts),
    }


def _empty_inputs_verdict() -> dict:
    return _u00_verdict(
        ["producer_trace_missing", "stage_event_missing"],
        [
            "vdp_diagnostics_v1.events (event_id, stage_id, outcome, reason_codes)",
            "canonical_summary.hypotheses",
            "canonical_summary.attempts",
            "canonical_summary.evidence_records",
            "canonical_summary.verdicts",
            "canonical_summary.next_actions",
        ],
    )


def _first_failure(
    events: list,
    canonical_reach: set[str],
    *,
    dag: Optional[dict] = None,
    skipped_stages: Optional[set] = None,
) -> tuple:
    """Return (first_failure_verdict_or_None, reach_set)."""
    skipped = skipped_stages or set()
    index = _index_events(events)
    reach = _compute_reach(index, canonical_reach)

    def deps_of(stage: str) -> List[str]:
        if dag is not None:
            entry = dag.get(stage)
            if isinstance(entry, dict) and "depends_on" in entry:
                return [d for d in entry.get("depends_on", []) if isinstance(d, str)]
        idx = STAGE_ORDER.index(stage)
        return [STAGE_ORDER[idx - 1]] if idx > 0 else []

    def deps_ok(stage: str) -> bool:
        return all(d in reach or d in skipped for d in deps_of(stage))

    def canonical_after(stage: str) -> bool:
        idx = STAGE_ORDER.index(stage)
        return any(s in canonical_reach for s in STAGE_ORDER[idx + 1:])

    def events_after(stage: str) -> bool:
        idx = STAGE_ORDER.index(stage)
        return any(index[s]["all"] for s in STAGE_ORDER[idx + 1:])

    for stage in STAGE_ORDER:
        if stage in skipped:
            continue
        failures = index[stage]["failure"]
        if failures:
            # Retry rule: the earliest cut wins; later success never overwrites it.
            ev = failures[0]
            if deps_ok(stage):
                return (
                    {
                        "stage_id": stage,
                        "outcome": ev.get("outcome"),
                        "reason_codes": sorted(set(ev.get("reason_codes") or [])),
                        "cause_candidates": _cause_candidates(ev.get("reason_codes") or []),
                        "evidence_refs": [ev.get("event_id")],
                        "confidence": "supported",
                        "missing_artifacts": [],
                    },
                    reach,
                )
            missing = [f"{d} stage event" for d in deps_of(stage) if d not in reach]
            return (
                _u00_verdict(["stage_event_missing"], missing, evidence_refs=[ev.get("event_id")]),
                reach,
            )
        if stage in reach:
            continue
        if canonical_after(stage):
            # Telemetry gap with canonical records after it: inconsistency.
            return (
                {
                    "stage_id": stage,
                    "outcome": "unattributable",
                    "reason_codes": ["stage_event_missing"],
                    "cause_candidates": ["C13"],
                    "evidence_refs": [],
                    "confidence": "unattributable",
                    "missing_artifacts": [_missing_stage_artifact(stage)],
                },
                reach,
            )
        if events_after(stage):
            continue  # mid-chain telemetry gap; keep walking
        if deps_ok(stage):
            # End of the demonstrable chain: pipeline stop, no fabricated cause.
            return (
                {
                    "stage_id": stage,
                    "outcome": "failed",
                    "reason_codes": ["stage_event_missing"],
                    "cause_candidates": ["C13"],
                    "evidence_refs": [],
                    "confidence": "suspected",
                    "missing_artifacts": [_missing_stage_artifact(stage)],
                },
                reach,
            )
        missing = [f"{d} stage event" for d in deps_of(stage) if d not in reach]
        return (_u00_verdict(["stage_event_missing"], missing), reach)
    return (None, reach)


def _lineage_entry(root: str, first_failure: Optional[dict], reach: set[str]) -> dict:
    if first_failure is None:
        return {
            "lineage_root": root,
            "first_failure": None,
            "downstream_not_reached": [],
            "missing_artifacts": [],
            "confidence": "supported",
        }
    stage = first_failure.get("stage_id")
    downstream: List[str] = []
    if stage != "U00":
        idx = STAGE_ORDER.index(stage)
        downstream = [s for s in STAGE_ORDER[idx + 1:] if s not in reach]
    return {
        "lineage_root": root,
        "first_failure": first_failure,
        "downstream_not_reached": downstream,
        "missing_artifacts": list(first_failure.get("missing_artifacts") or []),
        "confidence": first_failure.get("confidence", "unattributable"),
    }


# --- public API ----------------------------------------------------------------

def validate_expected_path_dag(case: dict) -> List[str]:
    """Validate an ExpectedPathCaseV1 stage DAG; [] when valid.

    Errors: missing required fields, unknown stage_id in dag/optional/
    ineligible, dependency on an unknown stage, cycle in the dag, stage listed
    in both optional_stages and ineligible_stages.
    """
    if not isinstance(case, dict):
        return ["case_not_a_dict"]
    errors: List[str] = []

    if not isinstance(case.get("opaque_case_id"), str) or not case["opaque_case_id"].strip():
        errors.append("opaque_case_id_missing")
    if not isinstance(case.get("capability_family"), str) or not case["capability_family"].strip():
        errors.append("capability_family_missing")

    dag = case.get("stage_dag")
    if not isinstance(dag, dict):
        errors.append("stage_dag_missing")
        return errors

    for stage, entry in dag.items():
        if stage not in STAGE_IDS:
            errors.append(f"unknown_stage:{stage}")
            continue
        if not isinstance(entry, dict):
            errors.append(f"stage_dag_entry_not_dict:{stage}")
            continue
        for dep in entry.get("depends_on", []) or []:
            if dep not in STAGE_IDS:
                errors.append(f"unknown_dependency:{stage}->{dep}")

    # cycle detection over depends_on edges
    visiting: set = set()
    visited: set = set()

    def _visit(stage: str) -> bool:
        if stage in visiting:
            return True
        if stage in visited:
            return False
        visiting.add(stage)
        entry = dag.get(stage)
        deps = entry.get("depends_on", []) if isinstance(entry, dict) else []
        for dep in deps:
            if dep in dag and _visit(dep):
                return True
        visiting.discard(stage)
        visited.add(stage)
        return False

    for stage in dag:
        if _visit(stage):
            errors.append(f"cycle_detected:{stage}")
            break

    optional = case.get("optional_stages") or []
    if not isinstance(optional, list):
        errors.append("optional_stages_not_list")
        optional = []
    for s in optional:
        if s not in STAGE_IDS:
            errors.append(f"unknown_stage:{s}")

    ineligible = case.get("ineligible_stages") or []
    ineligible_stage_ids: set = set()
    if not isinstance(ineligible, list):
        errors.append("ineligible_stages_not_list")
        ineligible = []
    for e in ineligible:
        if not isinstance(e, dict):
            errors.append("ineligible_stage_not_dict")
            continue
        s = e.get("stage")
        if s not in STAGE_IDS:
            errors.append(f"unknown_stage:{s}")
        else:
            ineligible_stage_ids.add(s)

    for s in sorted(set(optional) & ineligible_stage_ids):
        errors.append(f"stage_optional_and_ineligible:{s}")

    return errors


def stage_reach_evidence(events: list) -> dict:
    """Per-stage evidence: "event:<id>" strings for reached, (outcome, event_id,
    reason_codes) tuples for skipped/blocked/failed events."""
    out: Dict[str, list] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        stage = ev.get("stage_id")
        if stage not in STAGE_IDS:
            continue
        outcome = ev.get("outcome")
        if outcome == "reached":
            entry: Any = f"event:{ev.get('event_id')}"
        elif outcome in FAILURE_OUTCOMES:
            entry = (outcome, ev.get("event_id"), tuple(ev.get("reason_codes") or []))
        else:
            continue
        out.setdefault(stage, []).append(entry)

    def _key(entry: Any) -> tuple:
        if isinstance(entry, str):
            return (0, entry, "")
        return (1, entry[1] or "", "")

    for stage in out:
        out[stage].sort(key=_key)
    return out


def analyze_observed_lineages(events: list, *, canonical_summary: Optional[dict] = None) -> dict:
    """Labels-free diagnosis of OBSERVED lineages only.

    Never outputs expected-case recall; the coverage note is always
    ``coverage_not_measurable_without_sealed_labels``. Grouping is by run_id
    (single fallback group). Each group gets at most ONE first failure.
    """
    canonical_reach = _canonical_reach(canonical_summary)

    if not events and not canonical_reach:
        u00 = _empty_inputs_verdict()
        return {
            "run_id": None,
            "lineages": [
                _lineage_entry("unattributed", u00, set())
            ],
            "coverage_note": COVERAGE_NOTE,
        }

    run_groups: Dict[str, list] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        run_id = ev.get("run_id")
        run_key = run_id if isinstance(run_id, str) and run_id else ""
        run_groups.setdefault(run_key, []).append(ev)
    if not run_groups:
        run_groups = {"": []}

    run_ids = {
        ev.get("run_id")
        for ev in events
        if isinstance(ev, dict) and isinstance(ev.get("run_id"), str) and ev.get("run_id")
    }
    top_run_id = next(iter(run_ids)) if len(run_ids) == 1 else None

    lineages = []
    for run_key in sorted(run_groups):
        group = run_groups[run_key]
        root = run_key if run_key else "unattributed"
        first_failure, reach = _first_failure(group, canonical_reach)
        lineages.append(_lineage_entry(root, first_failure, reach))

    return {
        "run_id": top_run_id,
        "lineages": lineages,
        "coverage_note": COVERAGE_NOTE,
    }


def first_failure_for_case(case: dict, events: list, *, canonical_summary: Optional[dict] = None) -> dict:
    """Evaluator-only first-failure verdict for ONE expected-path case.

    Uses ``case["stage_dag"]`` for dependencies; optional/ineligible stages are
    skipped in the walk, never count as first failure, and are reported in
    ``not_applicable_stages`` / ``ineligible_stages`` with reasons. Invalid
    DAGs return an ``excluded`` entry (excluded from the first-failure
    denominator by ``evaluate_expected_paths``).
    """
    case_id = case.get("opaque_case_id") if isinstance(case, dict) else None
    errors = validate_expected_path_dag(case)
    if errors:
        return {"opaque_case_id": case_id, "excluded": "invalid_dag", "reasons": errors}

    canonical_reach = _canonical_reach(canonical_summary)
    dag = case.get("stage_dag") or {}
    optional_stages = [s for s in case.get("optional_stages") or [] if isinstance(s, str)]
    ineligible = [e for e in case.get("ineligible_stages") or [] if isinstance(e, dict)]
    skipped = set(optional_stages) | {e.get("stage") for e in ineligible}

    first_failure, reach = _first_failure(events, canonical_reach, dag=dag, skipped_stages=skipped)

    not_applicable = [{"stage": s, "reason": "optional"} for s in optional_stages]
    ineligible_out = [{"stage": e.get("stage"), "reason": e.get("reason")} for e in ineligible]

    base = {
        "opaque_case_id": case_id,
        "not_applicable_stages": not_applicable,
        "ineligible_stages": ineligible_out,
        "analyzer_version": ANALYZER_VERSION,
    }
    if first_failure is None:
        return {
            **base,
            "first_failure_stage": None,
            "outcome": None,
            "reason_codes": [],
            "cause_candidates": [],
            "confidence": None,
            "evidence_refs": [],
            "missing_artifacts": [],
            "downstream_not_reached": [],
        }

    stage = first_failure.get("stage_id")
    downstream: List[str] = []
    if stage != "U00":
        idx = STAGE_ORDER.index(stage)
        downstream = [s for s in STAGE_ORDER[idx + 1:] if s not in reach and s not in skipped]

    return {
        **base,
        "first_failure_stage": stage,
        "outcome": first_failure.get("outcome"),
        "reason_codes": first_failure.get("reason_codes"),
        "cause_candidates": first_failure.get("cause_candidates"),
        "confidence": first_failure.get("confidence"),
        "evidence_refs": first_failure.get("evidence_refs"),
        "missing_artifacts": first_failure.get("missing_artifacts"),
        "downstream_not_reached": downstream,
    }


def evaluate_expected_paths(expected_cases: list, events: list, *, canonical_summary: Optional[dict] = None) -> list:
    """Per-case first_failure_for_case; invalid DAGs are excluded with reasons
    and never enter the first-failure denominator."""
    results = []
    for case in expected_cases:
        if not isinstance(case, dict):
            results.append(
                {"opaque_case_id": None, "excluded": "invalid_dag", "reasons": ["case_not_a_dict"]}
            )
            continue
        errors = validate_expected_path_dag(case)
        if errors:
            results.append(
                {
                    "opaque_case_id": case.get("opaque_case_id"),
                    "excluded": "invalid_dag",
                    "reasons": errors,
                }
            )
        else:
            results.append(first_failure_for_case(case, events, canonical_summary=canonical_summary))
    return results


def evaluate_first_failure_accuracy(verdicts: list, expected_stage_by_case: dict) -> dict:
    """M4 harness metric: fraction of verdicts whose first_failure_stage
    matches the sealed expected stage for the same opaque_case_id."""
    correct = 0
    total = 0
    misattributions = []
    for v in verdicts:
        if not isinstance(v, dict):
            continue
        total += 1
        case_id = v.get("opaque_case_id")
        expected = expected_stage_by_case.get(case_id)
        actual = v.get("first_failure_stage")
        if expected == actual:
            correct += 1
        else:
            misattributions.append(
                {"opaque_case_id": case_id, "expected": expected, "actual": actual}
            )
    accuracy = round(correct / total, 6) if total else 0.0
    return {
        "correct": correct,
        "total": total,
        "accuracy": accuracy,
        "misattributions": misattributions,
    }
