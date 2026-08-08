"""
SGK-2026-0427 — sealed Juice Shop expected-path DAG + M5 evaluator driver tests.

Covers (plan SGK-2026-0425 §8 M4 DAG-correctness requirement applied to the
sealed cases, and §11 test classes):
- every sealed ExpectedPathCaseV1 passes ``validate_expected_path_dag``
- labels carry no sealed-product denylist tokens (structural isolation)
- a synthetic full-pass event chain produces NO false first failure
- per-stage fault injection cuts exactly the intended stage (table test)
- m3a read-only run classifies state-changing cases as S05 ineligible
  (denominator + reason; never a first failure)
- driver end-to-end outputs: trace_coverage 6/6, first_failure artifact
  schema, external_audit_v2.json is opaque-only (whitelist + denylist scan)
- invalid DAG cases are excluded from the denominator with reasons

These tests are communication-free and never touch the sealed target.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from src.core.engine.vdp_diagnostic_trace import STAGE_IDS
from src.reporting.vdp_diagnostic import validate_expected_path_dag

REPO_ROOT = Path(__file__).parents[3]
LABELS_PATH = (
    REPO_ROOT
    / "tests"
    / "fixtures"
    / "vdp_juiceshop_sealed"
    / "labels"
    / "expected_path_cases_v1.json"
)
DRIVER_PATH = (
    REPO_ROOT / "tests" / "fixtures" / "vdp_juiceshop_sealed" / "evaluate_m5.py"
)
DENYLIST_PATH = REPO_ROOT / "config" / "diagnostics" / "sealed_product_denylist.txt"

ORDER = [s for s in STAGE_IDS if s != "U00"]

READ_ONLY_CASES = ["OPAQUE-XSS-01", "OPAQUE-DATA-01", "OPAQUE-AUTH-02"]
STATE_CHANGING_CASES = ["OPAQUE-AUTH-01", "OPAQUE-IDOR-01", "OPAQUE-PRIV-01"]

_STAGE_REASON = {
    "S01": ["source_not_connected"],
    "S02": ["parse_rejected"],
    "S03": ["capability_misclassified"],
    "S04": ["priority_starvation"],
    "S05": ["scope_block_expected"],
    "S06": ["specialist_capability_mismatch"],
    "S07": ["wrong_actor_owner_pair"],
    "S08": ["transport_timeout"],
    "S09": ["marker_not_extracted"],
    "S10": ["independent_evidence_missing"],
    "S11": ["validator_misclassification"],
    "S12": ["consistency_mismatch"],
}


def _load_driver():
    spec = importlib.util.spec_from_file_location("evaluate_m5", DRIVER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DRIVER = _load_driver()


@pytest.fixture(scope="module")
def labels():
    return DRIVER.load_labels(str(LABELS_PATH))


@pytest.fixture(scope="module")
def cases_by_id(labels):
    return {c["opaque_case_id"]: c for c in labels}


def _event(event_id, stage_id, outcome="reached", reason_codes=None, run_id="run-1"):
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
        "source_refs": [],
        "schema_version": 1,
        "taxonomy_version": "v2",
    }


def _reach_chain(up_to_stage, run_id="run-1"):
    idx = ORDER.index(up_to_stage)
    return [_event(f"evt-{i:03d}", ORDER[i], run_id=run_id) for i in range(idx + 1)]


def _failure_events(stage, run_id="run-1"):
    idx = ORDER.index(stage)
    events = _reach_chain(ORDER[idx - 1], run_id=run_id) if idx > 0 else []
    events.append(
        _event(
            f"fail-{stage}",
            stage,
            outcome="blocked",
            reason_codes=_STAGE_REASON.get(stage, ["c13_unclassified_hold"]),
            run_id=run_id,
        )
    )
    return events


def _synthetic_session(events, run_id="run-1"):
    return {
        "run_id_meta": run_id,
        "vdp_contract": {
            "hypotheses": [],
            "attempts": [],
            "evidence_records": [],
            "verdicts": [],
            "next_actions": [],
        },
        "vdp_diagnostics_v1": {
            "schema_version": 1,
            "taxonomy_version": "v2",
            "run_id": run_id,
            "events": events,
        },
    }


def _denylist_tokens():
    text = DENYLIST_PATH.read_text(encoding="utf-8")
    tokens = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            tokens.append(line)
    return tokens


# --- 1. DAG correctness ------------------------------------------------------


def test_all_sealed_cases_pass_dag_validation(labels):
    assert len(labels) == 6
    for case in labels:
        errors = validate_expected_path_dag(case)
        assert errors == [], f"{case['opaque_case_id']}: {errors}"


def test_sealed_case_ids_unique(labels):
    ids = [c["opaque_case_id"] for c in labels]
    assert len(ids) == len(set(ids))
    for case_id in ids:
        assert case_id.startswith("OPAQUE-")


def test_labels_contain_no_sealed_product_tokens(labels):
    blob = json.dumps(labels).lower()
    for token in _denylist_tokens():
        assert token.lower() not in blob, f"denylist token leaked into labels: {token!r}"


def test_labels_carry_no_external_identifiers(labels):
    blob = json.dumps(labels).lower()
    for marker in ("http://", "https://", "/api/", ".js", ".json?"):
        assert marker not in blob, f"external identifier marker {marker!r} in labels"


# --- 2. Synthetic pass chain: no false first failure -------------------------


@pytest.mark.parametrize("case_id", READ_ONLY_CASES)
def test_full_pass_chain_no_false_first_failure(cases_by_id, case_id):
    events = _reach_chain("S12")
    verdict = DRIVER._evaluated_verdict(
        cases_by_id[case_id], events, canonical_summary={}
    )
    assert verdict["verdict"] == "pass_full_path"
    assert verdict["first_failure_stage"] is None
    assert verdict["denominator_included"] is True


# --- 3. Fault injection: exactly the intended stage cuts ---------------------


@pytest.mark.parametrize("case_id", READ_ONLY_CASES)
@pytest.mark.parametrize("stage", ORDER)
def test_fault_injection_cuts_only_intended_stage(cases_by_id, case_id, stage):
    case = cases_by_id[case_id]
    if stage in (case.get("optional_stages") or []):
        pytest.skip(f"{stage} is optional for {case_id}; skipped in the walk")
    events = _failure_events(stage)
    verdict = DRIVER._evaluated_verdict(case, events, canonical_summary={})
    assert verdict["verdict"] == "first_failure"
    assert verdict["first_failure_stage"] == stage
    if stage != "S12":
        assert verdict["downstream_not_reached"], "downstream stages must be listed"


@pytest.mark.parametrize("case_id", READ_ONLY_CASES)
def test_failure_earliest_cut_wins_retry_never_overwrites(cases_by_id, case_id):
    # S05 blocked first, later S06..S12 reached: first failure stays S05.
    events = _failure_events("S05") + _reach_chain("S12")[ORDER.index("S06"):]
    verdict = DRIVER._evaluated_verdict(
        cases_by_id[case_id], events, canonical_summary={}
    )
    assert verdict["first_failure_stage"] == "S05"


# --- 4. m3a run-config ineligibility -----------------------------------------


def test_m3a_readonly_ineligible_classification(labels):
    ineligible = DRIVER.ineligible_case_ids(labels, "m3a-readonly")
    assert ineligible == set(STATE_CHANGING_CASES)


@pytest.mark.parametrize("case_id", STATE_CHANGING_CASES)
def test_state_changing_cases_recorded_s05_ineligible(cases_by_id, case_id):
    verdict = DRIVER._ineligible_verdict(cases_by_id[case_id])
    assert verdict["verdict"] == "ineligible"
    assert verdict["stage"] == "S05"
    assert verdict["reason"] == DRIVER.S05_INELIGIBLE_REASON
    assert verdict["denominator_included"] is True
    assert "first_failure" not in verdict


# --- 5. Driver end-to-end outputs --------------------------------------------


def test_driver_evaluate_trace_coverage_100_percent(labels, tmp_path):
    session = _synthetic_session(_reach_chain("S12"))
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    result = DRIVER.evaluate(str(LABELS_PATH), str(session_path), "m3a-readonly")
    assert result["trace_coverage"] == {
        "total": 6,
        "with_verdict": 6,
        "excluded": 0,
    }
    by_id = {v["opaque_case_id"]: v for v in result["cases"]}
    for case_id in STATE_CHANGING_CASES:
        assert by_id[case_id]["verdict"] == "ineligible"
        assert by_id[case_id]["stage"] == "S05"
    for case_id in READ_ONLY_CASES:
        assert by_id[case_id]["verdict"] == "pass_full_path"


def test_driver_outputs_opaque_only_and_whitelisted(tmp_path):
    session_path = tmp_path / "session.json"
    session_path.write_text(
        json.dumps(_synthetic_session(_reach_chain("S12"))), encoding="utf-8"
    )
    out_dir = tmp_path / "out"
    result = DRIVER.evaluate(str(LABELS_PATH), str(session_path), "m3a-readonly")
    ff_path, ext_path = DRIVER.write_outputs(
        result,
        str(out_dir),
        eval_version="v1",
        session_path=str(session_path),
    )

    ff = json.loads(Path(ff_path).read_text(encoding="utf-8"))
    assert ff["eval_version"] == "v1"
    assert ff["trace_coverage"]["total"] == 6
    assert len(ff["cases"]) == 6

    ext = json.loads(Path(ext_path).read_text(encoding="utf-8"))
    assert ext["schema_version"] == 1
    cases = ext["targets"][0]["cases"]
    assert len(cases) == 6
    allowed_keys = {"opaque_case_id", "stage", "reason", "confidence"}
    for case in cases:
        assert set(case.keys()) <= allowed_keys

    blob = json.dumps(ext).lower()
    assert "http" not in blob
    for token in _denylist_tokens():
        assert token.lower() not in blob, f"denylist token leaked into external audit: {token!r}"


def test_driver_without_diagnostic_section_yields_early_cut(cases_by_id, tmp_path):
    # No events and no canonical records: the walk demonstrably stops at the
    # first stage (S00) with suspected confidence and C13 — never guessed as
    # a later stage, never reported as a detection failure.
    session = _synthetic_session([])
    session_path = tmp_path / "session.json"
    session_path.write_text(json.dumps(session), encoding="utf-8")
    result = DRIVER.evaluate(str(LABELS_PATH), str(session_path), "m3a-readonly")
    by_id = {v["opaque_case_id"]: v for v in result["cases"]}
    for case_id in READ_ONLY_CASES:
        verdict = by_id[case_id]
        assert verdict["verdict"] == "first_failure"
        assert verdict["first_failure_stage"] == "S00"
        assert verdict["confidence"] == "suspected"
        assert "C13" in verdict["cause_candidates"]


# --- 7. SGK-2026-0434: payload_request_mismatch funnel honesty ----------------

def test_payload_mismatch_blocked_at_s07_is_first_failure(cases_by_id):
    """The funnel for a payload_request_mismatch case whose executor blocks
    at S07 exact_request_material_unavailable must report first_failure S07
    (NOT S08/S10/S11 — the old misleading reach of a payload-less probe)."""
    case = cases_by_id["OPAQUE-XSS-01"]
    events = _reach_chain("S06")
    events.append(
        _event(
            "fail-S07-payload",
            "S07",
            outcome="blocked",
            reason_codes=["exact_request_material_unavailable"],
        )
    )
    verdict = DRIVER._evaluated_verdict(case, events, canonical_summary={})
    assert verdict["verdict"] == "first_failure"
    assert verdict["first_failure_stage"] == "S07"
    assert "exact_request_material_unavailable" in verdict["reason_codes"]
    # downstream stages must NOT be claimed as reached (funnel no longer lies)
    assert verdict["downstream_not_reached"]
    assert "S08" in verdict["downstream_not_reached"]
    assert "S10" in verdict["downstream_not_reached"]
    assert "S11" in verdict["downstream_not_reached"]


# --- 6. Invalid DAG excluded from the denominator ----------------------------


def test_invalid_dag_case_excluded(cases_by_id):
    bad = json.loads(json.dumps(cases_by_id["OPAQUE-XSS-01"]))
    bad["stage_dag"]["S03"]["depends_on"] = ["S09"]  # cycle: S03 -> S09 -> ... -> S03
    assert validate_expected_path_dag(bad)
    verdict = DRIVER._evaluated_verdict(bad, _reach_chain("S12"), canonical_summary={})
    assert verdict["verdict"] == "excluded_invalid_dag"
    assert verdict["denominator_included"] is False
