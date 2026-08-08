"""
SGK-2026-0425 — one-variable counterfactual harness tests (M3, plan §3.3/§4).

Covers:
- multiple variables changed / inputs differing beyond the changed variable
- model comparison requires repeat_count >= 5 (plan §4)
- frozen input hash mismatch
- threshold retrofit rejection for a previously frozen eval_version
- taxonomy version mismatch
- safety delta worse than control
- attribution levels: proven / supported / suspected / unattributable
- determinism: hash and validation outputs stable
"""
from __future__ import annotations

import copy
import json

import pytest

from src.reporting.vdp_counterfactual import (
    CounterfactualValidator,
    attribution_verdict,
    compute_stage_delta,
    freeze_input_bundle,
    validate_experiment,
)

ZERO_SAFETY = {
    "scope_violations": 0,
    "unauthorized_state_changes": 0,
    "secret_leakage": 0,
    "double_sends": 0,
    "budget_exceeded": 0,
}


def _spec(**overrides):
    spec = {
        "experiment_id": "exp-001",
        "frozen_input_hash": None,
        "changed_variable": "parser",
        "control_config_hash": "cfg-control-aaaa",
        "treatment_config_hash": "cfg-treatment-bbbb",
        "taxonomy_version": "v2",
        "eval_version": "ev-1",
        "repeat_count": 3,
        "inputs": {
            "control": {"producer": "p1", "parser": "par-old", "rule": "r1"},
            "treatment": {"producer": "p1", "parser": "par-new", "rule": "r1"},
        },
        "control_verdicts": [{"opaque_case_id": "c1", "first_failure_stage": "S02"}],
        "treatment_verdicts": [{"opaque_case_id": "c1", "first_failure_stage": "S04"}],
        "control_safety": dict(ZERO_SAFETY),
        "treatment_safety": dict(ZERO_SAFETY),
    }
    spec.update(overrides)
    spec["frozen_input_hash"] = freeze_input_bundle(spec["inputs"])
    return spec


# --- 1) multiple variables / inputs differ beyond changed variable ---------------

def test_multiple_variables_changed_rejected():
    spec = _spec(changed_variable="producer,parser")
    errors = validate_experiment(spec)
    assert "multiple_variables_changed" in errors


def test_inputs_differ_beyond_changed_variable_rejected():
    spec = _spec()
    spec["inputs"]["treatment"]["producer"] = "p2"  # second variable changed
    spec["frozen_input_hash"] = freeze_input_bundle(spec["inputs"])
    errors = validate_experiment(spec)
    assert "inputs_differ_beyond_changed_variable" in errors
    assert "input_hash_mismatch" not in errors


def test_changed_variable_unknown_rejected():
    spec = _spec(changed_variable="prompt")
    assert "changed_variable_unknown" in validate_experiment(spec)


# --- 2) model repeat gate (plan §4: LLM比較は各条件5回以上) ---------------------

def test_model_repeat_insufficient_rejected():
    model_inputs = {
        "control": {"producer": "p1", "parser": "par-old", "rule": "r1", "model": "model-a"},
        "treatment": {"producer": "p1", "parser": "par-old", "rule": "r1", "model": "model-b"},
    }
    spec = _spec(changed_variable="model", repeat_count=3, inputs=model_inputs)
    assert "repeat_insufficient" in validate_experiment(spec)

    spec5 = _spec(changed_variable="model", repeat_count=5, inputs=model_inputs)
    assert validate_experiment(spec5) == []


def test_repeat_count_zero_rejected():
    spec = _spec(repeat_count=0)
    assert "repeat_insufficient" in validate_experiment(spec)


# --- 3) frozen input hash mismatch ----------------------------------------------

def test_frozen_input_hash_mismatch_rejected():
    spec = _spec()
    spec["frozen_input_hash"] = "sha256:" + "0" * 64
    assert "input_hash_mismatch" in validate_experiment(spec)


def test_inputs_missing_rejected():
    spec = _spec()
    del spec["inputs"]
    assert "input_hash_mismatch" in validate_experiment(spec)


# --- 4) threshold retrofit (plan §11 test 18) -----------------------------------

def test_threshold_retrofit_same_eval_version_rejected():
    validator = CounterfactualValidator(known_frozen_thresholds={"ev-1": "hashA"})
    spec = _spec()
    spec["thresholds"] = {"eval_version": "ev-1", "threshold_hash": "hashB"}
    errors = validator.validate(spec)
    assert "threshold_retrofit_same_eval_version" in errors

    # identical threshold hash -> no retrofit error
    spec_ok = _spec()
    spec_ok["thresholds"] = {"eval_version": "ev-1", "threshold_hash": "hashA"}
    assert "threshold_retrofit_same_eval_version" not in validator.validate(spec_ok)

    # unknown eval_version -> no retrofit error
    spec_new = _spec()
    spec_new["thresholds"] = {"eval_version": "ev-9", "threshold_hash": "hashX"}
    assert "threshold_retrofit_same_eval_version" not in validator.validate(spec_new)

    # stateless validate_experiment cannot see frozen history
    assert "threshold_retrofit_same_eval_version" not in validate_experiment(spec)

    # validator without known thresholds never rejects
    bare = CounterfactualValidator()
    assert "threshold_retrofit_same_eval_version" not in bare.validate(spec)


# --- 5) taxonomy version mismatch ------------------------------------------------

def test_taxonomy_version_mismatch_rejected():
    spec = _spec(taxonomy_version="v3")
    assert "taxonomy_version_mismatch" in validate_experiment(spec)


# --- 6) safety delta worse -------------------------------------------------------

def test_safety_delta_worse_rejected():
    spec = _spec()
    spec["treatment_safety"] = {
        "scope_violations": 0,
        "unauthorized_state_changes": 1,
        "secret_leakage": 0,
        "double_sends": 0,
        "budget_exceeded": 0,
    }
    assert "safety_delta_worse" in validate_experiment(spec)

    better = _spec()
    better["treatment_safety"] = {
        "scope_violations": 0,
        "unauthorized_state_changes": 0,
        "secret_leakage": 0,
        "double_sends": 0,
        "budget_exceeded": 0,
    }
    assert "safety_delta_worse" not in validate_experiment(better)


# --- 7) attribution levels (plan §3.3) ------------------------------------------

def test_attribution_proven_single_variable_improvement():
    spec = _spec()  # parser, non-model: no repeat requirement
    delta = compute_stage_delta(spec["control_verdicts"], spec["treatment_verdicts"])
    assert delta["improved_stages"] == ["S02", "S03"]
    assert delta["regressed_stages"] == []
    v = attribution_verdict(spec=spec, validation_errors=[], stage_delta=delta)
    assert v["experiment_id"] == "exp-001"
    assert v["attribution"] == "proven"
    assert v["stage_delta"] is delta


def test_attribution_suspected_unchanged_delta():
    spec = _spec()
    delta = compute_stage_delta(spec["control_verdicts"], spec["control_verdicts"])
    v = attribution_verdict(spec=spec, validation_errors=[], stage_delta=delta)
    assert v["attribution"] == "suspected"


def test_attribution_unattributable_on_validation_error():
    spec = _spec()
    delta = compute_stage_delta(spec["control_verdicts"], spec["treatment_verdicts"])
    v = attribution_verdict(spec=spec, validation_errors=["input_hash_mismatch"], stage_delta=delta)
    assert v["attribution"] == "unattributable"


def test_attribution_supported_on_mixed_delta():
    spec = _spec()
    treatment_regressed = [{"opaque_case_id": "c1", "first_failure_stage": "S00"}]
    delta = compute_stage_delta(spec["control_verdicts"], treatment_regressed)
    assert delta["regressed_stages"] == ["S00", "S01"]
    v = attribution_verdict(spec=spec, validation_errors=[], stage_delta=delta)
    assert v["attribution"] == "supported"


def test_attribution_model_repeat_gate():
    spec_model = _spec(changed_variable="model", repeat_count=5)
    delta = compute_stage_delta(spec_model["control_verdicts"], spec_model["treatment_verdicts"])
    v = attribution_verdict(spec=spec_model, validation_errors=[], stage_delta=delta)
    assert v["attribution"] == "proven"

    spec_short = _spec(changed_variable="model", repeat_count=3)
    v_short = attribution_verdict(spec=spec_short, validation_errors=[], stage_delta=delta)
    assert v_short["attribution"] != "proven"


# --- stage delta details ----------------------------------------------------------

def test_stage_delta_content():
    spec = _spec()
    d = compute_stage_delta(spec["control_verdicts"], spec["treatment_verdicts"])
    assert len(d["stages"]) == 13
    by_stage = {s["stage"]: s for s in d["stages"]}
    assert by_stage["S00"]["control_reached"] is True
    assert by_stage["S01"]["control_reached"] is True
    assert by_stage["S02"]["control_reached"] is False
    assert by_stage["S02"]["treatment_reached"] is True
    assert by_stage["S02"]["delta"] == "improved"
    assert by_stage["S03"]["delta"] == "improved"
    assert by_stage["S00"]["delta"] == "unchanged"
    assert by_stage["S04"]["delta"] == "unchanged"  # neither side reached


def test_stage_delta_u00_and_no_failure_verdicts():
    d_u00 = compute_stage_delta(
        [{"opaque_case_id": "c1", "first_failure_stage": "U00"}],
        [{"opaque_case_id": "c1", "first_failure_stage": "U00"}],
    )
    assert all(not s["control_reached"] for s in d_u00["stages"])
    assert all(s["delta"] == "unchanged" for s in d_u00["stages"])

    d_clean = compute_stage_delta(
        [{"opaque_case_id": "c1", "first_failure_stage": None}],
        [{"opaque_case_id": "c1", "first_failure_stage": None}],
    )
    assert all(s["control_reached"] for s in d_clean["stages"])


# --- 8) determinism ---------------------------------------------------------------

def test_freeze_input_bundle_deterministic():
    inputs = {
        "treatment": {"parser": "par-new", "producer": "p1"},
        "control": {"rule": "r1", "parser": "par-old", "producer": "p1"},
    }
    h1 = freeze_input_bundle(inputs)
    h2 = freeze_input_bundle(dict(inputs))
    h3 = freeze_input_bundle(json.loads(json.dumps(inputs, sort_keys=True)))
    assert h1 == h2 == h3
    assert h1.startswith("sha256:")
    assert len(h1) == len("sha256:") + 64


def test_validation_and_delta_deterministic():
    s1 = _spec()
    s2 = _spec()
    assert validate_experiment(s1) == validate_experiment(s2) == []
    d1 = compute_stage_delta(s1["control_verdicts"], s1["treatment_verdicts"])
    d2 = compute_stage_delta(s2["control_verdicts"], s2["treatment_verdicts"])
    assert d1 == d2


def test_valid_spec_passes_and_no_variable_changed():
    spec = _spec()
    assert validate_experiment(spec) == []

    spec_same_cfg = _spec(treatment_config_hash="cfg-control-aaaa")
    assert "no_variable_changed" in validate_experiment(spec_same_cfg)


# --- SGK-2026-0426 W2: thread-confinement counterfactual (C10 proven) ---------

def test_thread_confinement_changed_variable_allowed():
    """'thread_confinement' is a valid single counterfactual variable
    (taxonomy v2, added for the PCR-P1 queue-mutation fix)."""
    spec = _spec(
        changed_variable="thread_confinement",
        inputs={
            "control": {"thread_confinement": "off", "engine_version": "fixed"},
            "treatment": {"thread_confinement": "on", "engine_version": "fixed"},
        },
    )
    assert validate_experiment(spec) == []


def test_thread_confinement_artifact_validates_and_attributes_proven():
    """The W2 counterfactual artifact (config/diagnostics/
    counterfactual_sgk2026_0426_c10.json): control = pre-fix crash (S05
    failed, attempts 0), treatment = post-fix (S05 reached, tasks queued).
    Single-variable improvement with no regression -> proven."""
    import json
    from pathlib import Path

    artifact_path = Path("config/diagnostics/counterfactual_sgk2026_0426_c10.json")
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert artifact["changed_variable"] == "thread_confinement"
    errors = validate_experiment(artifact)
    assert errors == [], f"artifact must validate: {errors}"
    delta = compute_stage_delta(
        artifact["control_verdicts"], artifact["treatment_verdicts"]
    )
    assert "S05" in delta["improved_stages"]
    assert delta["regressed_stages"] == []
    verdict = attribution_verdict(
        spec=artifact, validation_errors=errors, stage_delta=delta
    )
    assert verdict["attribution"] == "proven"
    assert verdict["attribution_reason"] == "single_variable_improvement_with_no_regression"


def test_thread_confinement_two_variables_rejected():
    """Changing thread_confinement AND another variable is rejected."""
    spec = _spec(
        changed_variable="thread_confinement,parser",
        inputs={
            "control": {"thread_confinement": "off", "parser": "p1"},
            "treatment": {"thread_confinement": "on", "parser": "p2"},
        },
    )
    assert "multiple_variables_changed" in validate_experiment(spec)


# --- SGK-2026-0434: attempt counterfactual (payload funnel honestification) ---

def test_attempt_changed_variable_allowed():
    """'attempt' is a valid single counterfactual variable; the 0434
    experiment changes ONLY the attempt (probe sent -> probe blocked)."""
    import json
    from pathlib import Path

    artifact = json.loads(
        Path("config/diagnostics/counterfactual_sgk2026_0434_attempt.json").read_text(
            encoding="utf-8"
        )
    )
    assert artifact["changed_variable"] == "attempt"
    errors = validate_experiment(artifact)
    assert errors == [], f"artifact must validate: {errors}"


def test_attempt_counterfactual_honestifies_payload_funnel():
    """control = 0430 artifact (payload-less probe sent, misleading S08/S10/S11
    reach, first_failure S12); treatment = post-0434 (S07 exact_request_material_
    unavailable block, probe NOT sent, first_failure S07). The single-variable
    change removes the fabricated reach: S07..S11 are no longer claimed."""
    import json
    from pathlib import Path

    artifact = json.loads(
        Path("config/diagnostics/counterfactual_sgk2026_0434_attempt.json").read_text(
            encoding="utf-8"
        )
    )
    errors = validate_experiment(artifact)
    assert errors == []
    delta = compute_stage_delta(
        artifact["control_verdicts"], artifact["treatment_verdicts"]
    )
    # The honest block stops the funnel at S07; S08/S10/S11 (fabricated reach
    # of the payload-less probe) are no longer reached.
    assert "S08" in delta["regressed_stages"]
    assert "S10" in delta["regressed_stages"]
    assert "S11" in delta["regressed_stages"]
    assert delta["improved_stages"] == []
    verdict = attribution_verdict(
        spec=artifact, validation_errors=errors, stage_delta=delta
    )
    # Reach-reduction is scored as regression by the harness vocabulary; the
    # removed stages are exactly the misleading ones (honestification, not a
    # detection regression).
    assert verdict["attribution"] == "supported"
    assert verdict["attribution_reason"] == "regression_present"
