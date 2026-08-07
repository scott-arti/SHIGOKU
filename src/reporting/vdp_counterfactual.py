"""
SGK-2026-0425 — one-variable counterfactual harness (M3, plan §3.3/§4).

Pure module: NO communication, no network, no LLM, standard library only.
Every output is a deterministic JSON-serializable dict (no timestamps/UUIDs).

Attribution is fail-closed:
- two or more variables changed, input hash mismatch, taxonomy mismatch,
  identical control/treatment config, repeat insufficiency (model < 5),
  worse safety delta and threshold retrofits for a frozen eval_version all
  reject attribution ("unattributable").
- "proven" is only emitted for a single-variable experiment with >= 1
  improved stage, 0 regressed stages and (for model) repeat_count >= 5.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from src.core.engine.vdp_diagnostic_trace import STAGE_IDS

TAXONOMY_VERSION_V1 = "v2"
ANALYZER_VERSION_V1 = "v1"

ALLOWED_CHANGED_VARIABLES: tuple[str, ...] = (
    "producer",
    "parser",
    "rule",
    "model",
    "priority",
    "routing",
    "attempt",
    "interpretation",
    "evidence",
    "report",
    # SGK-2026-0426 W2 (taxonomy v2): queue-mutation thread confinement
    # (PCR-P1) fix as a single counterfactual variable.
    "thread_confinement",
)

SAFETY_KEYS: tuple[str, ...] = (
    "scope_violations",
    "unauthorized_state_changes",
    "secret_leakage",
    "double_sends",
    "budget_exceeded",
)

MODEL_MIN_REPEAT = 5

REQUIRED_SPEC_KEYS: tuple[str, ...] = (
    "experiment_id",
    "frozen_input_hash",
    "changed_variable",
    "control_config_hash",
    "treatment_config_hash",
    "taxonomy_version",
    "eval_version",
    "repeat_count",
    "control_verdicts",
    "treatment_verdicts",
    "control_safety",
    "treatment_safety",
)

STAGE_ORDER: tuple[str, ...] = tuple(s for s in STAGE_IDS if s != "U00")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def freeze_input_bundle(inputs: dict) -> str:
    """sha256 of canonical JSON (sort_keys, ensure_ascii=False), "sha256:" prefixed."""
    digest = hashlib.sha256(_canonical_json(inputs).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _dedupe(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items:
        if item not in out:
            out.append(item)
    return out


def validate_experiment(spec: dict) -> List[str]:
    """Fail-closed spec validation; every error code rejects attribution.

    Error codes: spec_key_missing, changed_variable_missing,
    changed_variable_unknown, multiple_variables_changed, repeat_insufficient,
    input_hash_mismatch, inputs_differ_beyond_changed_variable,
    taxonomy_version_mismatch, no_variable_changed, safety_delta_worse.
    (threshold_retrofit_same_eval_version is emitted by
    ``CounterfactualValidator`` which owns the frozen threshold history.)
    """
    if not isinstance(spec, dict):
        return ["spec_not_a_dict"]
    errors: List[str] = []

    for key in REQUIRED_SPEC_KEYS:
        if key not in spec:
            errors.append("spec_key_missing")

    changed = spec.get("changed_variable")
    if not isinstance(changed, str) or not changed.strip():
        errors.append("changed_variable_missing")
    elif "," in changed:
        errors.append("multiple_variables_changed")
    elif changed not in ALLOWED_CHANGED_VARIABLES:
        errors.append("changed_variable_unknown")

    repeat = spec.get("repeat_count")
    if not isinstance(repeat, int) or isinstance(repeat, bool) or repeat < 1:
        errors.append("repeat_insufficient")
    elif changed == "model" and repeat < MODEL_MIN_REPEAT:
        errors.append("repeat_insufficient")

    inputs = spec.get("inputs")
    if not isinstance(inputs, dict):
        errors.append("input_hash_mismatch")
    else:
        if freeze_input_bundle(inputs) != spec.get("frozen_input_hash"):
            errors.append("input_hash_mismatch")
        control = inputs.get("control")
        treatment = inputs.get("treatment")
        if not isinstance(control, dict) or not isinstance(treatment, dict):
            errors.append("inputs_differ_beyond_changed_variable")
        elif isinstance(changed, str) and changed in ALLOWED_CHANGED_VARIABLES:
            for key in sorted(set(control) | set(treatment)):
                if key == changed:
                    continue
                if _canonical_json(control.get(key)) != _canonical_json(treatment.get(key)):
                    errors.append("inputs_differ_beyond_changed_variable")
                    break

    if spec.get("taxonomy_version") != TAXONOMY_VERSION_V1:
        errors.append("taxonomy_version_mismatch")

    if spec.get("control_config_hash") == spec.get("treatment_config_hash"):
        errors.append("no_variable_changed")

    control_safety = spec.get("control_safety")
    treatment_safety = spec.get("treatment_safety")
    if not isinstance(control_safety, dict) or not isinstance(treatment_safety, dict):
        errors.append("safety_delta_worse")
    else:
        for key in SAFETY_KEYS:
            c_val = control_safety.get(key, 0)
            t_val = treatment_safety.get(key, 0)
            if (
                isinstance(c_val, (int, float))
                and isinstance(t_val, (int, float))
                and t_val > c_val
            ):
                errors.append("safety_delta_worse")
                break

    return _dedupe(errors)


class CounterfactualValidator:
    """validate_experiment + threshold-retrofit guard.

    ``known_frozen_thresholds`` maps eval_version -> threshold_hash. Re-freezing
    the same eval_version with a different threshold hash is a retrofit and is
    rejected (plan §11 test 18).
    """

    def __init__(self, known_frozen_thresholds: Optional[Dict[str, str]] = None):
        self._known_frozen_thresholds: Dict[str, str] = dict(known_frozen_thresholds or {})

    def validate(self, spec: dict) -> List[str]:
        errors = validate_experiment(spec)
        if not isinstance(spec, dict):
            return errors
        thresholds = spec.get("thresholds")
        if isinstance(thresholds, dict):
            eval_version = thresholds.get("eval_version")
            threshold_hash = thresholds.get("threshold_hash")
            if isinstance(eval_version, str) and eval_version in self._known_frozen_thresholds:
                if self._known_frozen_thresholds[eval_version] != threshold_hash:
                    errors.append("threshold_retrofit_same_eval_version")
        return _dedupe(errors)


def _reached_stages(verdict: dict) -> set:
    """Stages reached before a first-failure verdict (linear order).

    first_failure_stage == None (pass case) -> all stages reached;
    "U00" (undeterminable) -> nothing is claimed reached.
    """
    stage = verdict.get("first_failure_stage")
    if stage is None:
        return set(STAGE_ORDER)
    if stage == "U00" or stage not in STAGE_ORDER:
        return set()
    return set(STAGE_ORDER[: STAGE_ORDER.index(stage)])


def compute_stage_delta(control_verdicts: list, treatment_verdicts: list) -> dict:
    """Per-stage reach comparison between control and treatment verdicts.

    Returns {"stages": [...], "improved_stages": [...], "regressed_stages": [...]}.
    A stage is reached when ANY verdict in the list implies it was reached.
    """
    control_reach: set = set()
    for v in control_verdicts or []:
        if isinstance(v, dict):
            control_reach |= _reached_stages(v)
    treatment_reach: set = set()
    for v in treatment_verdicts or []:
        if isinstance(v, dict):
            treatment_reach |= _reached_stages(v)

    stages: List[Dict[str, Any]] = []
    for stage in STAGE_ORDER:
        c_reached = stage in control_reach
        t_reached = stage in treatment_reach
        if t_reached and not c_reached:
            delta = "improved"
        elif c_reached and not t_reached:
            delta = "regressed"
        else:
            delta = "unchanged"
        stages.append(
            {"stage": stage, "control_reached": c_reached, "treatment_reached": t_reached, "delta": delta}
        )

    return {
        "stages": stages,
        "improved_stages": [s["stage"] for s in stages if s["delta"] == "improved"],
        "regressed_stages": [s["stage"] for s in stages if s["delta"] == "regressed"],
    }


def attribution_verdict(*, spec: dict, validation_errors: List[str], stage_delta: dict) -> dict:
    """Attribution level per plan §3.3.

    - proven: no validation errors, single-variable (model requires
      repeat_count >= 5), >= 1 improved stage, 0 regressed stages.
    - suspected: no validation errors, delta fully unchanged.
    - supported: no validation errors but the delta is mixed, regressed, or
      not reproducible under the repeat gate.
    - unattributable: any validation error present (fail-closed).
    """
    experiment_id = spec.get("experiment_id") if isinstance(spec, dict) else None

    if validation_errors:
        return {
            "experiment_id": experiment_id,
            "attribution": "unattributable",
            "attribution_reason": "validation_error",
            "stage_delta": stage_delta,
        }

    changed = spec.get("changed_variable")
    repeat = spec.get("repeat_count")
    repeat_ok = isinstance(repeat, int) and (changed != "model" or repeat >= MODEL_MIN_REPEAT)
    improved = list(stage_delta.get("improved_stages") or [])
    regressed = list(stage_delta.get("regressed_stages") or [])

    if improved and not regressed and repeat_ok:
        attribution = "proven"
        reason = "single_variable_improvement_with_no_regression"
    elif not improved and not regressed:
        attribution = "suspected"
        reason = "stage_delta_unchanged"
    elif improved and regressed:
        attribution = "supported"
        reason = "mixed_stage_delta"
    elif regressed:
        attribution = "supported"
        reason = "regression_present"
    elif not repeat_ok:
        attribution = "supported"
        reason = "model_repeat_insufficient"
    else:
        attribution = "supported"
        reason = "no_improvement_observed"

    return {
        "experiment_id": experiment_id,
        "attribution": attribution,
        "attribution_reason": reason,
        "stage_delta": stage_delta,
    }
