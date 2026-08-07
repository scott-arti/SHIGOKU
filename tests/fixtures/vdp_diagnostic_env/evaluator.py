"""
SGK-2026-0425 M4 — isolated diagnostic evaluator (privileged reader).

One-shot evaluation job that runs with ``network_mode: none`` (reads local
files only). It consumes:

- ``MANIFEST_PATH``        — sealed case manifest (opaque case ids + route
                             map + fingerprints) from the private dir;
- ``LABELS_PATH``          — sealed ExpectedPathCaseV1 labels per case
                             (written by the fixture, no product info);
- ``RUNTIME_EVENTS_PATH``  — the event list to EVALUATE (simulated full
                             list until the M1 hooks land, or the genuine
                             runtime events for S02/S03 faults);
- ``SIMULATED_EVENTS_PATH``/``GENUINE_EVENTS_PATH`` — the two event files
                             cross-checked against each other (the simulator
                             must agree with the real pipeline on the
                             S00..S03 prefix it can observe);
- ``SUMMARY_PATH``         — canonical-ish runtime summary (reach evidence);
- ``RESULT_PATH``          — writable output for the evaluation result.

Steps: validate the event list against the frozen diagnostic section
contract, join events to cases via manifest fingerprints, validate every
expected-path DAG (invalid DAGs are excluded from the first-failure
denominator with reasons), run the REAL analyzer
(``validate_expected_path_dag`` / ``first_failure_for_case`` /
``evaluate_expected_paths`` / ``evaluate_first_failure_accuracy``), compare
per-case first failures against the injected fault stage (env
``DIAG_FAULT_STAGE`` as ground truth; S00 = pass-through = no failure
expected), and print the anonymized ``evaluator_result:<json>`` line.

Event matching contract: events carry ``opaque_asset_fingerprint`` only
(never case ids / routes); the evaluator attaches ``opaque_case_id`` from
the manifest before handing events to the analyzer.

Expected-stage rule: a case whose DAG marks the injected fault stage as
optional/ineligible expects NO first failure (the cut does not apply).
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from src.core.engine.vdp_diagnostic_trace import validate_diagnostic_section
from src.reporting.vdp_diagnostic import (
    evaluate_expected_paths,
    evaluate_first_failure_accuracy,
    first_failure_for_case,
    validate_expected_path_dag,
)

EVALUATOR_VERSION = "vdp-diagnostic-evaluator-0.1.0"


def _require_env(name: str) -> Path:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} environment variable is required")
    return Path(value)


def _load_json(path: Path, what: str) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{what} unreadable: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{what} malformed: not a dict")
    return data


def _load_events(path: Path) -> list:
    events = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RuntimeError(f"events unreadable: {type(exc).__name__}") from exc
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"events malformed line: {exc}") from exc
    return events


def _skipped_stages(case: dict) -> set:
    skipped = set(case.get("optional_stages") or [])
    skipped |= {
        e.get("stage") for e in (case.get("ineligible_stages") or [])
        if isinstance(e, dict)
    }
    return skipped


def _cross_check(genuine: list, simulated: list, fp_to_case: dict) -> dict:
    """Simulator-vs-real-pipeline agreement on the observable prefix."""
    simulated_by_key = {}
    for ev in simulated:
        case_id = fp_to_case.get(ev.get("opaque_asset_fingerprint"))
        if case_id is None:
            continue
        simulated_by_key[(case_id, ev.get("stage_id"))] = ev.get("outcome")
    checked = 0
    mismatches = []
    unmatched = 0
    for ev in genuine:
        case_id = fp_to_case.get(ev.get("opaque_asset_fingerprint"))
        if case_id is None:
            unmatched += 1
            continue
        expected = simulated_by_key.get((case_id, ev.get("stage_id")))
        if expected is None:
            continue
        checked += 1
        if expected != ev.get("outcome"):
            mismatches.append({
                "opaque_case_id": case_id,
                "stage_id": ev.get("stage_id"),
                "genuine": ev.get("outcome"),
                "simulated": expected,
            })
    return {
        "checked": checked,
        "unmatched_genuine_events": unmatched,
        "mismatches": mismatches,
    }


def main() -> int:
    manifest_path = _require_env("MANIFEST_PATH")
    labels_path = _require_env("LABELS_PATH")
    events_path = _require_env("RUNTIME_EVENTS_PATH")
    summary_path = _require_env("SUMMARY_PATH")
    result_path = _require_env("RESULT_PATH")
    simulated_path = os.environ.get("SIMULATED_EVENTS_PATH", "")
    genuine_path = os.environ.get("GENUINE_EVENTS_PATH", "")
    fault_stage = os.environ.get("DIAG_FAULT_STAGE", "S00")
    run_id = os.environ.get("DIAG_RUN_ID", "diag-run")

    try:
        manifest = _load_json(manifest_path, "manifest")
        labels = _load_json(labels_path, "labels")
        summary = _load_json(summary_path, "canonical summary")
        events = _load_events(events_path)
        cases = labels.get("cases") or []

        # --- frozen section contract check (fail-closed) ---
        section = {
            "schema_version": 1,
            "taxonomy_version": "v2",
            "diagnostic_active": True,
            "run_id": run_id,
            "events": events,
        }
        section_validation = validate_diagnostic_section(section)

        # --- join events to sealed cases via fingerprints ---
        fp_to_case = {
            c["fingerprint"]: c["opaque_case_id"]
            for c in (manifest.get("cases") or [])
        }
        enriched = []
        unknown_fingerprint = 0
        for ev in events:
            case_id = fp_to_case.get(ev.get("opaque_asset_fingerprint"))
            if case_id is None:
                unknown_fingerprint += 1
                continue
            enriched.append({**ev, "opaque_case_id": case_id})

        # --- per-case first failures (real analyzer; invalid DAGs excluded) ---
        per_case_verdicts = []
        dag_excluded = []
        for case in cases:
            case_id = case.get("opaque_case_id")
            errors = validate_expected_path_dag(case)
            if errors:
                dag_excluded.append({"opaque_case_id": case_id, "reasons": errors})
                continue
            case_events = [
                ev for ev in enriched if ev["opaque_case_id"] == case_id
            ]
            per_case_verdicts.append(
                first_failure_for_case(case, case_events, canonical_summary=summary)
            )

        # --- aggregate (the frozen batch API; DAG exclusions preserved) ---
        aggregate = evaluate_expected_paths(cases, enriched, canonical_summary=summary)
        aggregate_excluded = [
            r for r in aggregate if isinstance(r, dict) and r.get("excluded")
        ]

        # --- ground truth: injected fault stage vs per-case expectations ---
        expected_by_case = {}
        for case in cases:
            skipped = _skipped_stages(case)
            if fault_stage == "S00" or fault_stage in skipped:
                expected_by_case[case["opaque_case_id"]] = None
            else:
                expected_by_case[case["opaque_case_id"]] = fault_stage

        accuracy = evaluate_first_failure_accuracy(per_case_verdicts, expected_by_case)

        per_case_out = []
        for verdict in per_case_verdicts:
            case_id = verdict.get("opaque_case_id")
            expected = expected_by_case.get(case_id)
            actual = verdict.get("first_failure_stage")
            per_case_out.append({
                "opaque_case_id": case_id,
                "first_failure_stage": actual,
                "expected": expected,
                "match": expected == actual,
                "outcome": verdict.get("outcome"),
                "reason_codes": verdict.get("reason_codes"),
                "confidence": verdict.get("confidence"),
            })

        # --- simulator vs real pipeline agreement (when both files exist) ---
        cross_check = {"checked": 0, "unmatched_genuine_events": 0, "mismatches": []}
        if simulated_path and genuine_path:
            try:
                cross_check = _cross_check(
                    _load_events(Path(genuine_path)),
                    _load_events(Path(simulated_path)),
                    fp_to_case,
                )
            except RuntimeError as exc:
                cross_check = {"error": str(exc)}

        result = {
            "run_id": run_id,
            "fault_stage": fault_stage,
            "evaluator_version": EVALUATOR_VERSION,
            "analyzer": "src.reporting.vdp_diagnostic",
            "cases_total": len(cases),
            "cases_included": len(per_case_verdicts),
            "dag_excluded": dag_excluded,
            "aggregate_excluded": aggregate_excluded,
            "per_case": per_case_out,
            "accuracy": accuracy,
            "trace_coverage": round(
                len(per_case_verdicts) / len(cases), 6
            ) if cases else 0.0,
            "events_evaluated": len(enriched),
            "events_unknown_fingerprint": unknown_fingerprint,
            "section_valid": section_validation.passed,
            "section_reason_codes": section_validation.reason_codes,
            "cross_check": cross_check,
        }
        result_path.parent.mkdir(parents=True, exist_ok=True)
        result_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        print(f"evaluator_result:{json.dumps(result, sort_keys=True)}")
        return 0
    except Exception as exc:  # unexpected failure: surface, do not swallow
        print(
            f"evaluator_result:{{\"fatal\":\"{type(exc).__name__}: {exc}\"}}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
