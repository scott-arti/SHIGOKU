#!/usr/bin/env python3
"""SGK-2026-0427 — M5 sealed-audit evaluator post-binding driver (evaluator-only).

Binds sealed ExpectedPathCaseV1 labels + a fresh instrumented session
(``vdp_diagnostics_v1`` events + canonical summary) through the pure analyzer
``src.reporting.vdp_diagnostic`` and emits per-opaque-case first-failure
verdicts.

Isolation contract
------------------
- EVALUATOR-ONLY: never imported by runtime code; imports only pure
  ``src.reporting.vdp_diagnostic`` (no engine runtime, no network, no LLM).
- OPAQUE-ONLY: outputs carry ``opaque_case_id`` / stage / reason / confidence
  only. Product identifiers, endpoints, payloads and challenge names are
  never emitted. ``first_failure_juiceshop_<eval_version>.json`` holds the
  full per-case verdicts; ``external_audit_v2.json`` holds the opaque
  projection (plan SGK-2026-0425 §12, §13 opaque-ref style).
- RUN-CONFIG INELIGIBILITY: an m3a read-only run may not execute
  ``state_changing`` actions. Such cases are recorded as S05 ineligible with
  denominator + reason (plan §3.1: a legitimate capability-gate denial is
  NOT a detection defect), never as a first failure. Ineligibility is
  decided declaratively from the run mode + ``allowed_action_classes`` — it
  is not fabricated from events.

Usage
-----
    .venv/bin/python tests/fixtures/vdp_juiceshop_sealed/evaluate_m5.py \
        --session <session.json> \
        --labels tests/fixtures/vdp_juiceshop_sealed/labels/expected_path_cases_v1.json \
        --output-dir <dir> \
        --eval-version v1 \
        --run-mode m3a-readonly
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.reporting.vdp_diagnostic import (
    ANALYZER_VERSION,
    first_failure_for_case,
    validate_expected_path_dag,
)

# Run modes known to the driver. Each mode maps to a set of permitted action
# classes; anything a case requires outside the set is recorded as
# ineligible at the admission stage (S05).
RUN_MODES: Dict[str, List[str]] = {
    "m3a-readonly": ["read_only"],
}

S05_INELIGIBLE_REASON = "state_changing_not_allowed_m3a_readonly"
S05_INELIGIBLE_NOTE = (
    "legitimate capability-gate denial under an m3a read-only run; "
    "recorded with denominator and reason, not counted as a detection defect"
)


def load_labels(path: str) -> List[dict]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    cases = data.get("cases")
    if not isinstance(cases, list):
        raise ValueError("labels: 'cases' must be a list")
    return [c for c in cases if isinstance(c, dict)]


def load_session(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("session: top-level JSON must be an object")
    return data


def extract_events(session: dict) -> List[dict]:
    """``vdp_diagnostics_v1.events``; [] when the section is absent."""
    section = session.get("vdp_diagnostics_v1")
    events = section.get("events") if isinstance(section, dict) else None
    if not isinstance(events, list):
        return []
    return [e for e in events if isinstance(e, dict)]


def extract_canonical_summary(session: dict) -> dict:
    """Canonical presence dict accepted by the analyzer (plan §3.1 map)."""
    section = session.get("vdp_contract")
    if not isinstance(section, dict):
        return {}
    out: Dict[str, list] = {}
    for key in (
        "hypotheses",
        "attempts",
        "evidence_records",
        "verdicts",
        "next_actions",
    ):
        items = section.get(key)
        out[key] = items if isinstance(items, list) else []
    return out


def run_id_from_session(session: dict) -> Optional[str]:
    section = session.get("vdp_diagnostics_v1")
    run_id = section.get("run_id") if isinstance(section, dict) else None
    return str(run_id) if run_id else None


def ineligible_case_ids(cases: List[dict], run_mode: str) -> set:
    """Opaque case ids whose required action classes are not permitted."""
    allowed = set(RUN_MODES.get(run_mode, RUN_MODES["m3a-readonly"]))
    out: set = set()
    for case in cases:
        classes = case.get("allowed_action_classes") or []
        if any(str(c) not in allowed for c in classes):
            out.add(str(case.get("opaque_case_id")))
    return out


def _ineligible_verdict(case: dict) -> dict:
    return {
        "opaque_case_id": case.get("opaque_case_id"),
        "capability_family": case.get("capability_family"),
        "verdict": "ineligible",
        "stage": "S05",
        "reason": S05_INELIGIBLE_REASON,
        "confidence": "not_applicable",
        "note": S05_INELIGIBLE_NOTE,
        "denominator_included": True,
        "not_applicable_stages": [],
        "ineligible_stages": [{"stage": "S05", "reason": S05_INELIGIBLE_REASON}],
        "downstream_not_reached": [],
        "evidence_refs": [],
        "missing_artifacts": [],
    }


def _evaluated_verdict(case: dict, events: List[dict], canonical_summary: dict) -> dict:
    verdict = first_failure_for_case(
        case, events, canonical_summary=canonical_summary
    )
    if verdict.get("excluded") == "invalid_dag":
        return {
            "opaque_case_id": case.get("opaque_case_id"),
            "capability_family": case.get("capability_family"),
            "verdict": "excluded_invalid_dag",
            "reasons": verdict.get("reasons"),
            "denominator_included": False,
        }
    first_failure_stage = verdict.get("first_failure_stage")
    if first_failure_stage is None:
        return {
            **verdict,
            "capability_family": case.get("capability_family"),
            "verdict": "pass_full_path",
            "denominator_included": True,
        }
    return {
        **verdict,
        "capability_family": case.get("capability_family"),
        "verdict": "first_failure",
        "denominator_included": True,
    }


def evaluate(labels_path: str, session_path: str, run_mode: str) -> dict:
    cases = load_labels(labels_path)
    session = load_session(session_path)
    events = extract_events(session)
    canonical_summary = extract_canonical_summary(session)
    ineligible = ineligible_case_ids(cases, run_mode)

    verdicts: List[dict] = []
    for case in cases:
        case_id = str(case.get("opaque_case_id"))
        if case_id in ineligible:
            verdicts.append(_ineligible_verdict(case))
            continue
        dag_errors = validate_expected_path_dag(case)
        if dag_errors:
            verdicts.append(
                {
                    "opaque_case_id": case_id,
                    "capability_family": case.get("capability_family"),
                    "verdict": "excluded_invalid_dag",
                    "reasons": dag_errors,
                    "denominator_included": False,
                }
            )
            continue
        verdicts.append(_evaluated_verdict(case, events, canonical_summary))

    total = len(cases)
    with_verdict = sum(1 for v in verdicts if v.get("denominator_included"))
    excluded = sum(1 for v in verdicts if not v.get("denominator_included"))

    return {
        "eval_version": None,  # filled by caller
        "analyzer_version": ANALYZER_VERSION,
        "run_mode": run_mode,
        "run_id": run_id_from_session(session),
        "generated_at": datetime.date.today().isoformat(),
        "trace_coverage": {
            "total": total,
            "with_verdict": with_verdict,
            "excluded": excluded,
        },
        "cases": verdicts,
    }


def _external_stage(verdict: dict) -> str:
    if verdict.get("verdict") == "ineligible":
        return str(verdict.get("stage") or "S05")
    if verdict.get("verdict") == "pass_full_path":
        return "none"
    return str(verdict.get("first_failure_stage") or "U00")


def _external_reason(verdict: dict) -> str:
    if verdict.get("verdict") == "ineligible":
        return str(verdict.get("reason") or S05_INELIGIBLE_REASON)
    if verdict.get("verdict") == "pass_full_path":
        return "reached_full_path"
    codes = verdict.get("reason_codes") or []
    return ",".join(sorted(str(c) for c in codes)) if codes else "no_reason_code"


def _external_confidence(verdict: dict) -> Optional[str]:
    return verdict.get("confidence")


def build_external_audit(result: dict) -> dict:
    cases = []
    for v in result.get("cases") or []:
        cases.append(
            {
                "opaque_case_id": v.get("opaque_case_id"),
                "stage": _external_stage(v),
                "reason": _external_reason(v),
                "confidence": _external_confidence(v),
            }
        )
    return {
        "schema_version": 1,
        "eval_version": result.get("eval_version"),
        "generated_at": result.get("generated_at"),
        "task": "SGK-2026-0427 M5 sealed audit active rerun (instrumented)",
        "mode": result.get("run_mode"),
        "targets": [
            {
                "label": "sealed_target_A_instrumented",
                "cases": cases,
            }
        ],
    }


def write_outputs(
    result: dict,
    output_dir: str,
    *,
    eval_version: str,
    session_path: str,
) -> tuple:
    result = dict(result)
    result["eval_version"] = eval_version
    # NOTE: the session path is deliberately NOT embedded — it carries the
    # target identity (denylist token) and must never leave the evaluator
    # boundary. The run_id inside the artifact ties it to the session.
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    first_failure_path = out_dir / f"first_failure_juiceshop_{eval_version}.json"
    external_path = out_dir / f"external_audit_v2.json"
    first_failure_path.write_text(
        json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    external_path.write_text(
        json.dumps(
            build_external_audit(result),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return str(first_failure_path), str(external_path)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=(__doc__ or "SGK-2026-0427 sealed-audit evaluator").splitlines()[0]
    )
    parser.add_argument("--session", required=True, help="instrumented session JSON")
    parser.add_argument(
        "--labels",
        required=True,
        help="sealed expected-path cases JSON",
    )
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--eval-version", default="v1")
    parser.add_argument("--run-mode", default="m3a-readonly", choices=sorted(RUN_MODES))
    args = parser.parse_args(argv)

    result = evaluate(args.labels, args.session, args.run_mode)
    ff_path, ext_path = write_outputs(
        result,
        args.output_dir,
        eval_version=args.eval_version,
        session_path=str(Path(args.session).resolve()),
    )
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    print(f"first_failure: {ff_path}")
    print(f"external_audit: {ext_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
