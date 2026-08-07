"""
SGK-2026-0425 M4 — pure DAG validation tests for ExpectedPathCaseV1.

The isolated harness relies on ``validate_expected_path_dag``: cases with an
invalid stage DAG are excluded from the first-failure denominator with a
reason (plan §8 M4 (b): the DAG itself is a knowledge encoding, and a wrong
DAG shifts first-failure / cause / counterfactual downstream).

Coverage (plan §11 required test 23 + M4 DAG-verification table tests):
- valid linear DAG S00 -> S01 -> ... -> S12;
- valid branching DAG (S03 depends on S02, S04 depends on S02 only);
- valid optional stage and valid ineligible stage with reason;
- invalid: unknown stage in the dag, dependency on an unknown stage,
  cycle (S01 depends on S02 while S02 depends on S01), and a stage listed
  in BOTH optional_stages and ineligible_stages.
"""
from src.reporting.vdp_diagnostic import validate_expected_path_dag

STAGES = [f"S{i:02d}" for i in range(13)]  # S00..S12


def _case(stage_dag, optional=None, ineligible=None, case_id="case-a",
          family="object_id"):
    return {
        "opaque_case_id": case_id,
        "capability_family": family,
        "stage_dag": stage_dag,
        "optional_stages": optional or [],
        "ineligible_stages": ineligible or [],
    }


def _linear_dag(stages=None):
    stages = stages or STAGES
    dag = {}
    for i, stage in enumerate(stages):
        dag[stage] = (
            {"depends_on": [stages[i - 1]]} if i else {"depends_on": []}
        )
    return dag


# ---------------------------------------------------------------------------
# valid DAGs
# ---------------------------------------------------------------------------


def test_valid_linear_dag():
    case = _case(_linear_dag())
    assert validate_expected_path_dag(case) == []


def test_valid_branching_dag():
    # S03 and S04 are siblings: both depend on S02 only.
    dag = {
        "S00": {"depends_on": []},
        "S01": {"depends_on": ["S00"]},
        "S02": {"depends_on": ["S01"]},
        "S03": {"depends_on": ["S02"]},
        "S04": {"depends_on": ["S02"]},
    }
    assert validate_expected_path_dag(_case(dag)) == []


def test_valid_optional_stage():
    case = _case(_linear_dag(), optional=["S09"])
    assert validate_expected_path_dag(case) == []


def test_valid_ineligible_stage_with_reason():
    case = _case(
        _linear_dag(),
        ineligible=[{"stage": "S10", "reason": "oob_not_permitted"}],
    )
    assert validate_expected_path_dag(case) == []


def test_valid_combined_optional_and_ineligible():
    # optional and ineligible on DIFFERENT stages is valid.
    case = _case(
        _linear_dag(),
        optional=["S09"],
        ineligible=[{"stage": "S10", "reason": "oob_not_permitted"}],
    )
    assert validate_expected_path_dag(case) == []


# ---------------------------------------------------------------------------
# invalid DAGs
# ---------------------------------------------------------------------------


def test_unknown_stage_in_dag():
    dag = _linear_dag()
    dag["S99"] = {"depends_on": []}
    errors = validate_expected_path_dag(_case(dag))
    assert errors
    assert any("S99" in e for e in errors)


def test_unknown_dependency():
    dag = _linear_dag()
    dag["S01"] = {"depends_on": ["S99"]}
    errors = validate_expected_path_dag(_case(dag))
    assert errors
    assert any("S99" in e for e in errors)


def test_cycle_detected():
    # S01 depends on S02 while S02 depends on S01.
    dag = {
        "S00": {"depends_on": []},
        "S01": {"depends_on": ["S02"]},
        "S02": {"depends_on": ["S01"]},
    }
    errors = validate_expected_path_dag(_case(dag))
    assert errors
    assert any(e.startswith("cycle_detected") for e in errors)


def test_stage_in_both_optional_and_ineligible():
    case = _case(
        _linear_dag(),
        optional=["S09"],
        ineligible=[{"stage": "S09", "reason": "not_permitted"}],
    )
    errors = validate_expected_path_dag(case)
    assert errors
    assert any("S09" in e for e in errors)
