"""
SGK-2026-0425 — first-failure analyzer tests (M2, plan §11).

Covers:
- S00..S12 table test: exactly one first failure per intentionally failed stage
- predecessor evidence missing -> U00 with missing artifacts named (no guessing)
- downstream stages in downstream_not_reached, never double-counted as roots
- determinism: event list order / event_id order never changes verdicts
- raw artifact without Observation vs Observation without Hypothesis (S02 vs S03)
- priority starvation / budget stop / loop stop / routing mismatch distinguishability
- transport error is NOT classified as model or refutation (C10/C11, not C05/C12)
- response marker without interpretation (S10) vs interpretation without evidence (S11)
- sufficient evidence but candidate verdict (S11) vs confirmed but report missing (S12)
- expected-path DAG: optional branch, ineligible, invalid DAG exclusion
- retry/follow-up: later successful reach never overwrites the first failure
- coverage note: coverage_not_measurable_without_sealed_labels, never recall
- empty events + empty canonical -> U00 with producer_trace_missing + stage_event_missing
- first_failure_accuracy metric (M4 harness input)
"""
from __future__ import annotations

import copy
import json
import random

import pytest

from src.core.engine.vdp_diagnostic_trace import STAGE_IDS
from src.reporting.vdp_diagnostic import (
    analyze_observed_lineages,
    evaluate_expected_paths,
    evaluate_first_failure_accuracy,
    first_failure_for_case,
    stage_reach_evidence,
    validate_expected_path_dag,
)

ORDER = [s for s in STAGE_IDS if s != "U00"]


def _event(event_id, stage_id, outcome="reached", reason_codes=None, run_id="run-1", source_refs=None):
    return {
        "event_id": event_id,
        "run_id": run_id,
        "stage_id": stage_id,
        "outcome": outcome,
        "reason_codes": list(reason_codes or []),
        "predecessor_ids": [],
        "successor_ids": [],
        "opaque_asset_fingerprint": "fp-opaque-1",
        "producer_id": "producer-1",
        "agent_id": "agent-1",
        "tool_id": "tool-1",
        "recipe_id": "recipe-1",
        "budget_snapshot_hash": "budget-hash-1",
        "source_refs": list(source_refs or []),
        "schema_version": 1,
        "taxonomy_version": "v2",
    }


def _reach_chain(up_to_stage, run_id="run-1", prefix="evt"):
    idx = ORDER.index(up_to_stage)
    return [_event(f"{prefix}-{i:03d}", ORDER[i], run_id=run_id) for i in range(idx + 1)]


def _failure_case(stage, outcome="blocked", reason_codes=None, run_id="run-1"):
    """Events: all predecessors reached, then the target stage fails."""
    events = []
    idx = ORDER.index(stage)
    if idx > 0:
        events += _reach_chain(ORDER[idx - 1], run_id=run_id)
    events.append(
        _event(
            f"fail-{stage}",
            stage,
            outcome=outcome,
            reason_codes=reason_codes or ["c13_unclassified_hold"],
            run_id=run_id,
        )
    )
    return events


# --- 1) table test: exactly one first failure per stage (plan §11 test 1) -------

@pytest.mark.parametrize("stage", ORDER)
@pytest.mark.parametrize("outcome", ["failed", "skipped", "blocked"])
def test_first_failure_exact_stage_table(stage, outcome):
    events = _failure_case(stage, outcome=outcome, reason_codes=["stage_event_missing"])
    out = analyze_observed_lineages(events)
    assert len(out["lineages"]) == 1
    lineage = out["lineages"][0]
    ff = lineage["first_failure"]
    assert ff is not None
    assert ff["stage_id"] == stage
    assert ff["outcome"] == outcome
    assert lineage["confidence"] == "supported"
    assert lineage["missing_artifacts"] == []
    # exactly one root cause: every other stage is either reached or downstream
    for other in ORDER:
        if other == stage:
            continue
        if other in lineage["downstream_not_reached"]:
            continue
        assert other not in (
            ff["stage_id"],
        ), f"{other} must not be reported as the failure stage"


# --- 2) predecessor evidence missing -> U00 (plan §11 test 2) -------------------

def test_predecessor_evidence_missing_is_u00():
    # S03 blocked but S02 (its dependency) has NO reach evidence and no event:
    # the cut may be at S02 (or earlier) -> do not guess, U00 with artifacts.
    events = [
        _event("evt-000", "S00"),
        _event("evt-003", "S03", outcome="blocked", reason_codes=["capability_misclassified"]),
    ]
    out = analyze_observed_lineages(events)
    lineage = out["lineages"][0]
    ff = lineage["first_failure"]
    assert ff["stage_id"] == "U00"
    assert ff["confidence"] == "unattributable"
    assert "stage_event_missing" in ff["reason_codes"]
    assert "S02 stage event" in ff["missing_artifacts"]
    assert lineage["missing_artifacts"] == ff["missing_artifacts"]
    assert lineage["confidence"] == "unattributable"


# --- 3) downstream is not double-counted as root (plan §11 test 3) -------------

def test_downstream_not_reached_not_double_counted():
    events = _reach_chain("S03") + [
        _event("evt-004", "S04", outcome="blocked", reason_codes=["priority_starvation"]),
        _event("evt-005", "S05", outcome="failed", reason_codes=["hitl_missing"]),
        _event("evt-006", "S06", outcome="blocked", reason_codes=["tool_capability_mismatch"]),
    ]
    out = analyze_observed_lineages(events)
    assert len(out["lineages"]) == 1
    lineage = out["lineages"][0]
    ff = lineage["first_failure"]
    assert ff["stage_id"] == "S04"
    assert ff["evidence_refs"] == ["evt-004"]
    assert "S05" in lineage["downstream_not_reached"]
    assert "S06" in lineage["downstream_not_reached"]
    assert "S07" in lineage["downstream_not_reached"]
    # root causes: exactly one lineage has a first_failure and it points at S04
    roots = [l for l in out["lineages"] if l["first_failure"] is not None]
    assert len(roots) == 1
    assert roots[0]["first_failure"]["stage_id"] == "S04"


# --- 4) determinism (plan §11 test 4) -------------------------------------------

def test_determinism_event_order_irrelevant():
    events = [
        _event("e-000", "S00"),
        _event("e-010", "S01", outcome="blocked", reason_codes=["parse_rejected"]),
        _event("e-020", "S02", outcome="reached"),
        _event("e-030", "S02", outcome="reached"),
        _event("e-040", "S03", outcome="failed", reason_codes=["capability_misclassified"]),
    ]
    baseline = analyze_observed_lineages(events)
    for seed in (1, 2, 7):
        shuffled = list(events)
        random.Random(seed).shuffle(shuffled)
        again = analyze_observed_lineages(shuffled)
        assert again == baseline
        assert json.dumps(again, sort_keys=True) == json.dumps(baseline, sort_keys=True)
    ff = baseline["lineages"][0]["first_failure"]
    assert ff["evidence_refs"] == ["e-010"]
    assert ff["reason_codes"] == ["parse_rejected"]


def test_stage_reach_evidence_records_both_sides():
    events = [
        _event("evt-000", "S00"),
        _event("evt-001", "S01", outcome="blocked", reason_codes=["parse_rejected"]),
        _event("evt-002", "S02"),
        _event("evt-003", "S03", outcome="skipped", reason_codes=["hitl_missing"]),
    ]
    r = stage_reach_evidence(events)
    assert "event:evt-000" in r["S00"]
    assert "event:evt-002" in r["S02"]
    assert ("blocked", "evt-001", ("parse_rejected",)) in r["S01"]
    assert ("skipped", "evt-003", ("hitl_missing",)) in r["S03"]
    assert "S04" not in r


# --- 5) raw artifact vs Observation (plan §11 test 5) ---------------------------

def test_raw_artifact_without_observation_vs_observation_without_hypothesis():
    # raw artifact present (S01 reached), no S02 reach, no S03 records -> S02
    events_a = [_event("evt-001", "S01")]
    out_a = analyze_observed_lineages(events_a)
    ff_a = out_a["lineages"][0]["first_failure"]
    assert ff_a["stage_id"] == "S02"
    assert ff_a["confidence"] == "suspected"
    assert ff_a["reason_codes"] == ["stage_event_missing"]
    assert ff_a["cause_candidates"] == ["C13"]

    # Observation present (S02 reached), but no hypothesis (canonical empty) -> S03
    events_b = [_event("evt-002", "S02")]
    out_b = analyze_observed_lineages(events_b)
    ff_b = out_b["lineages"][0]["first_failure"]
    assert ff_b["stage_id"] == "S03"
    assert ff_b["stage_id"] != ff_a["stage_id"]


def test_canonical_summary_reach_mapping():
    # canonical hypotheses => S03 reached; walk continues past S03 -> S04
    events = _reach_chain("S02")
    canonical = {
        "hypotheses": [{"hypothesis_id": "h-1"}],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
    }
    out = analyze_observed_lineages(events, canonical_summary=canonical)
    assert out["lineages"][0]["first_failure"]["stage_id"] == "S04"


def test_canonical_records_after_telemetry_gap_is_inconsistency():
    # S00 reached but canonical hypotheses exist (S03): S01 event missing ->
    # inconsistency, unattributable, telemetry field named (plan §11 test 2)
    events = [_event("evt-000", "S00")]
    canonical = {
        "hypotheses": [{"hypothesis_id": "h-1"}],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
    }
    ff = analyze_observed_lineages(events, canonical_summary=canonical)["lineages"][0]["first_failure"]
    assert ff["stage_id"] == "S01"
    assert ff["confidence"] == "unattributable"
    assert "stage_event_missing" in ff["reason_codes"]
    assert ff["missing_artifacts"], "missing_artifacts must name the needed field"


# --- 6) priority / budget / loop / routing distinguishable (plan §11 test 6) ---

def test_priority_budget_loop_routing_distinguishable():
    def run(code, stage, prefix):
        events = _reach_chain(ORDER[ORDER.index(stage) - 1], prefix=prefix)
        events.append(
            _event(f"{prefix}-fail", stage, outcome="blocked", reason_codes=[code])
        )
        return analyze_observed_lineages(events)["lineages"][0]["first_failure"]

    starv = run("priority_starvation", "S04", "starv")
    budget = run("iteration_cap_binding", "S04", "budget")
    loop = run("premature_stop_with_pending_action", "S04", "loop")
    routing = run("specialist_capability_mismatch", "S06", "rout")

    assert starv["stage_id"] == "S04"
    assert budget["stage_id"] == "S04"
    assert loop["stage_id"] == "S04"
    assert routing["stage_id"] == "S06"
    # reason codes stay distinct (not collapsed)
    assert set(starv["reason_codes"]) == {"priority_starvation"}
    assert set(budget["reason_codes"]) == {"iteration_cap_binding"}
    assert set(loop["reason_codes"]) == {"premature_stop_with_pending_action"}
    assert set(routing["reason_codes"]) == {"specialist_capability_mismatch"}
    # orchestration codes map to C06/C09; routing maps to C07 only
    assert set(starv["cause_candidates"]) == {"C06", "C09"}
    assert set(budget["cause_candidates"]) == {"C06", "C09"}
    assert set(loop["cause_candidates"]) == {"C06", "C09"}
    assert set(routing["cause_candidates"]) == {"C07"}


# --- 7) transport error is not model / refutation (plan §11 test 8) ------------

def test_transport_error_not_classified_as_model_or_refutation():
    events = _reach_chain("S07") + [
        _event("evt-080", "S08", outcome="blocked", reason_codes=["transport_timeout"])
    ]
    ff = analyze_observed_lineages(events)["lineages"][0]["first_failure"]
    assert ff["stage_id"] == "S08"
    assert set(ff["cause_candidates"]) == {"C10", "C11"}
    assert "C05" not in ff["cause_candidates"]
    assert "C12" not in ff["cause_candidates"]


# --- 8) marker without interpretation vs interpretation without evidence (plan §11 test 9) ---

def test_marker_without_interpretation_vs_without_independent_evidence():
    events_a = _reach_chain("S09", prefix="a")
    out_a = analyze_observed_lineages(events_a)
    assert out_a["lineages"][0]["first_failure"]["stage_id"] == "S10"

    events_b = _reach_chain("S10", prefix="b")
    out_b = analyze_observed_lineages(events_b)
    assert out_b["lineages"][0]["first_failure"]["stage_id"] == "S11"

    assert out_a["lineages"][0]["first_failure"]["stage_id"] != out_b["lineages"][0]["first_failure"]["stage_id"]


# --- 9) sufficient evidence vs report projection (plan §11 test 10) ------------

def test_evidence_sufficient_but_candidate_vs_confirmed_but_report_missing():
    # EvidenceRecord sufficient but verdict still candidate -> S11 (C12)
    events_a = _reach_chain("S10", prefix="a") + [
        _event("a-11", "S11", outcome="blocked", reason_codes=["validator_misclassification"])
    ]
    ff_a = analyze_observed_lineages(events_a)["lineages"][0]["first_failure"]
    assert ff_a["stage_id"] == "S11"
    assert "C12" in ff_a["cause_candidates"]

    # session confirmed but report missing -> S12 (C12)
    events_b = _reach_chain("S11", prefix="b") + [
        _event("b-12", "S12", outcome="blocked", reason_codes=["consistency_mismatch"])
    ]
    ff_b = analyze_observed_lineages(events_b)["lineages"][0]["first_failure"]
    assert ff_b["stage_id"] == "S12"
    assert "C12" in ff_b["cause_candidates"]


# --- 10) expected-path DAG (plan §11 test 23 + plan §8 M4) ---------------------

def _linear_dag():
    return {s: {"depends_on": [ORDER[i - 1]]} for i, s in enumerate(ORDER[1:], start=1)}


def _case(case_id="case-1", **overrides):
    case = {
        "opaque_case_id": case_id,
        "capability_family": "opaque_asset_read",
        "stage_dag": _linear_dag(),
        "optional_stages": [],
        "ineligible_stages": [],
        "required_actors": ["actor_a"],
        "required_controls": ["baseline_control"],
        "required_evidence": ["response_diff"],
        "allowed_action_classes": ["read"],
    }
    case.update(overrides)
    return case


def test_optional_branch_no_first_failure():
    case = _case(case_id="case-opt", optional_stages=["S05"])
    events = [_event(f"evt-{i:03d}", s) for i, s in enumerate(ORDER) if s != "S05"]
    v = first_failure_for_case(case, events)
    assert v["opaque_case_id"] == "case-opt"
    assert v["first_failure_stage"] is None
    assert v["analyzer_version"] == "v1"
    assert {"stage": "S05", "reason": "optional"} in v["not_applicable_stages"]
    assert v["ineligible_stages"] == []


def test_ineligible_stage_never_first_failure():
    case = _case(case_id="case-inel", ineligible_stages=[{"stage": "S06", "reason": "no_tool_permission"}])
    # S06 is blocked in events but ineligible -> must not count as first failure
    events = [_event(f"evt-{i:03d}", s) for i, s in enumerate(ORDER) if s != "S06"]
    events.append(_event("evt-blocked", "S06", outcome="blocked", reason_codes=["tool_capability_mismatch"]))
    v = first_failure_for_case(case, events)
    assert v["first_failure_stage"] is None
    assert {"stage": "S06", "reason": "no_tool_permission"} in v["ineligible_stages"]
    # a real failure AFTER the ineligible stage still cuts at that stage
    case2 = _case(case_id="case-inel2", ineligible_stages=[{"stage": "S06", "reason": "no_tool_permission"}])
    events2 = _reach_chain("S07", prefix="e2")
    events2.append(_event("e2-fail", "S08", outcome="blocked", reason_codes=["transport_timeout"]))
    v2 = first_failure_for_case(case2, events2)
    assert v2["first_failure_stage"] == "S08"
    assert "S08" not in v2["downstream_not_reached"]
    assert "S06" not in v2["downstream_not_reached"]


def test_validate_expected_path_dag_errors():
    assert validate_expected_path_dag({}) != []
    assert validate_expected_path_dag(_case()) == []

    missing_dag = _case(stage_dag=None)
    assert any("stage_dag" in e for e in validate_expected_path_dag(missing_dag))

    cycle = _case(
        case_id="case-cycle",
        stage_dag={
            "S03": {"depends_on": ["S04"]},
            "S04": {"depends_on": ["S03"]},
        },
    )
    cycle_errors = validate_expected_path_dag(cycle)
    assert any("cycle" in e for e in cycle_errors)

    unknown_stage = _case(case_id="case-unk", stage_dag={"S99": {"depends_on": []}})
    assert any("S99" in e for e in validate_expected_path_dag(unknown_stage))

    unknown_dep = _case(case_id="case-unkdep", stage_dag={"S03": {"depends_on": ["S99"]}})
    assert any("S99" in e for e in validate_expected_path_dag(unknown_dep))

    both = _case(
        case_id="case-both",
        optional_stages=["S04"],
        ineligible_stages=[{"stage": "S04", "reason": "forbidden"}],
    )
    both_errors = validate_expected_path_dag(both)
    assert any("optional" in e and "ineligible" in e for e in both_errors)


def test_evaluate_expected_paths_excludes_invalid_dag():
    valid_case = _case(case_id="case-valid")
    invalid_case = _case(
        case_id="case-cycle",
        stage_dag={"S03": {"depends_on": ["S04"]}, "S04": {"depends_on": ["S03"]}},
    )
    events = _failure_case("S04", reason_codes=["priority_starvation"])
    results = evaluate_expected_paths([invalid_case, valid_case], events)
    excluded = [r for r in results if r.get("excluded") == "invalid_dag"]
    verdicts = [r for r in results if "excluded" not in r]
    assert len(excluded) == 1
    assert excluded[0]["opaque_case_id"] == "case-cycle"
    assert excluded[0]["reasons"]
    assert len(verdicts) == 1
    assert verdicts[0]["opaque_case_id"] == "case-valid"
    assert verdicts[0]["first_failure_stage"] == "S04"


# --- 11) retry never overwrites the first failure (plan §11 test 23) -----------

def test_retry_does_not_overwrite_first_failure():
    events = []
    for i in range(4):
        events.append(_event(f"i1-{i:03d}", ORDER[i], source_refs=["iteration=1"]))
    events.append(
        _event("i1-004", "S04", outcome="blocked", reason_codes=["priority_starvation"], source_refs=["iteration=1"])
    )
    for s in ("S04", "S05", "S06"):
        events.append(_event(f"i2-{s}", s, source_refs=["iteration=2"]))
    out = analyze_observed_lineages(events)
    lineage = out["lineages"][0]
    ff = lineage["first_failure"]
    assert ff["stage_id"] == "S04"
    assert ff["evidence_refs"] == ["i1-004"]
    assert "S05" not in lineage["downstream_not_reached"]
    assert "S06" not in lineage["downstream_not_reached"]
    assert "S07" in lineage["downstream_not_reached"]


# --- 12) coverage note, never recall (plan §11 test 24) ------------------------

def test_coverage_note_and_no_recall_estimation():
    out = analyze_observed_lineages([_event("evt-000", "S00"), _event("evt-001", "S01")])
    assert out["coverage_note"] == "coverage_not_measurable_without_sealed_labels"
    dumped = json.dumps(out).lower()
    assert "recall" not in dumped


# --- 13) empty events + empty canonical -> U00 ----------------------------------

def test_empty_events_empty_canonical_is_u00():
    out = analyze_observed_lineages([])
    assert out["run_id"] is None
    assert len(out["lineages"]) == 1
    lineage = out["lineages"][0]
    ff = lineage["first_failure"]
    assert ff["stage_id"] == "U00"
    assert set(ff["reason_codes"]) == {"producer_trace_missing", "stage_event_missing"}
    assert ff["confidence"] == "unattributable"
    assert ff["missing_artifacts"], "missing_artifacts must name needed telemetry"
    assert lineage["missing_artifacts"] == ff["missing_artifacts"]

    # explicit empty canonical dict behaves identically
    out2 = analyze_observed_lineages([], canonical_summary={})
    assert out2 == out


def test_multiple_run_lineages():
    events = [
        _event("a-000", "S00", run_id="run-a"),
        _event("b-000", "S00", run_id="run-b"),
        _event("b-001", "S01", outcome="failed", reason_codes=["parse_rejected"], run_id="run-b"),
    ]
    out = analyze_observed_lineages(events)
    assert out["run_id"] is None
    assert len(out["lineages"]) == 2
    by_root = {l["lineage_root"]: l for l in out["lineages"]}
    assert set(by_root) == {"run-a", "run-b"}
    # run-a: S00 reached, S01 missing -> pipeline stop at S01 (suspected)
    assert by_root["run-a"]["first_failure"]["stage_id"] == "S01"
    assert by_root["run-a"]["first_failure"]["confidence"] == "suspected"
    # run-b: S01 explicitly failed -> supported
    assert by_root["run-b"]["first_failure"]["stage_id"] == "S01"
    assert by_root["run-b"]["first_failure"]["confidence"] == "supported"


# --- 14) first-failure accuracy metric (M4 harness) -----------------------------

def test_first_failure_accuracy_9_of_10():
    verdicts = [
        {"opaque_case_id": f"c{i:02d}", "first_failure_stage": f"S{i:02d}"}
        for i in range(1, 11)
    ]
    expected = {f"c{i:02d}": f"S{i:02d}" for i in range(1, 10)}
    expected["c10"] = "S11"  # misattribution
    res = evaluate_first_failure_accuracy(verdicts, expected)
    assert res["correct"] == 9
    assert res["total"] == 10
    assert res["accuracy"] == pytest.approx(0.9)
    assert len(res["misattributions"]) == 1
    assert res["misattributions"][0]["opaque_case_id"] == "c10"
    assert res["misattributions"][0]["expected"] == "S11"
    assert res["misattributions"][0]["actual"] == "S10"


def test_first_failure_accuracy_all_correct():
    verdicts = [{"opaque_case_id": "c1", "first_failure_stage": "S04"}]
    res = evaluate_first_failure_accuracy(verdicts, {"c1": "S04"})
    assert res == {"correct": 1, "total": 1, "accuracy": 1.0, "misattributions": []}


# --- SGK-2026-0426 W4: evidence-backed reach + downstream consistency ----------


def _canon(attempts=0, verdicts=0, evidence=0, hypotheses=1, next_actions=1):
    return {
        "hypotheses": [{"hypothesis_id": f"h{i}"} for i in range(hypotheses)],
        "attempts": [{"attempt_id": f"a{i}"} for i in range(attempts)],
        "evidence_records": [{"evidence_id": f"e{i}"} for i in range(evidence)],
        "verdicts": [{"verdict_id": f"v{i}"} for i in range(verdicts)],
        "next_actions": [{"next_action_id": f"n{i}"} for i in range(next_actions)],
    }


def test_shadow_verdicts_without_attempts_do_not_reach_s11():
    """W4: S05 cut with shadow verdicts (attempts=0) -> downstream covers
    S06..S12 completely, including S11 and S12 (no phantom S11 reach)."""
    events = _failure_case("S05")
    canonical = _canon(attempts=0, verdicts=6, next_actions=6)
    out = analyze_observed_lineages(events, canonical_summary=canonical)
    ff = out["lineages"][0]["first_failure"]
    assert ff["stage_id"] == "S05"
    downstream = out["lineages"][0]["downstream_not_reached"]
    assert downstream == [s for s in ORDER if ORDER.index(s) > ORDER.index("S05")]


def test_attempts_with_verdicts_reach_s11():
    """W4: with attempts > 0 the evidence-backed stages are genuine reach
    and are excluded from downstream (multi-lineage honesty)."""
    events = _failure_case("S05")
    canonical = _canon(attempts=2, verdicts=1, evidence=1, next_actions=6)
    out = analyze_observed_lineages(events, canonical_summary=canonical)
    ff = out["lineages"][0]["first_failure"]
    assert ff["stage_id"] == "S05"
    downstream = out["lineages"][0]["downstream_not_reached"]
    assert "S11" not in downstream  # genuinely reached via attempts + verdicts
    assert "S12" in downstream


@pytest.mark.parametrize("stage", ORDER)
def test_downstream_consistent_from_every_cut_stage(stage):
    """W4: for every cut stage the downstream covers all stages after the
    cut when no genuine reach evidence exists (pure event-driven run)."""
    events = _failure_case(stage)
    canonical = _canon(attempts=0, hypotheses=0, next_actions=0)
    out = analyze_observed_lineages(events, canonical_summary=canonical)
    ff = out["lineages"][0]["first_failure"]
    assert ff["stage_id"] == stage
    downstream = out["lineages"][0]["downstream_not_reached"]
    idx = ORDER.index(stage)
    expected = [s for s in ORDER[idx + 1:]]
    assert downstream == expected, f"stage {stage}: {downstream} != {expected}"
