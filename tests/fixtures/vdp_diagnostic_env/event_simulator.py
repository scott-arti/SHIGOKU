"""
SGK-2026-0425 M4 — deterministic diagnostic event simulator.

Standalone, deterministic bridge used until the M1 diagnostic hooks land in
the real runtime: given the sealed case manifest + expected-path labels and
the injected fault stage, it produces the FULL event list (S00..S12) that
the runtime WOULD emit when the funnel is cut at that stage:

- stages before the cut        -> ``reached`` events;
- the cut stage                -> one ``failed`` event with a stage-appropriate
                                   mechanism code from the frozen vocabulary;
- stages after the cut         -> NO events (absent = not reached, implied by
                                   the DAG);
- optional / ineligible stages -> NO events ever (skipped in the analyzer
                                   walk, never a first failure);
- when the injected fault stage is skipped (optional/ineligible) for a
  case, that case shows NO failure at all (the cut does not apply to it).

Event ids are deterministic (sha256 over run_id|case_id|stage) and
predecessor/successor ids reference only emitted events, so the output
always passes ``validate_diagnostic_section`` (fail-closed self-check).

Run (host side, from the repo root with the project venv):
  .venv/bin/python tests/fixtures/vdp_diagnostic_env/event_simulator.py \
    --manifest <case_manifest.json> --labels <expected_path_labels.json> \
    --fault-stage S07 --run-id diag-run-1 --out runtime_events_simulated.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from src.core.engine.vdp_diagnostic_trace import (
    STAGE_IDS,
    validate_diagnostic_section,
)

STAGE_ORDER = tuple(s for s in STAGE_IDS if s != "U00")

# Stage-appropriate mechanism codes (all from the frozen ALL_MECHANISM_CODES
# vocabulary). S00 is never injected: it is the pass-through stage.
FAULT_REASON_BY_STAGE = {
    "S01": ["asset_not_in_inventory"],
    "S02": ["parse_rejected"],
    "S03": ["capability_misclassified"],
    "S04": ["priority_starvation"],
    "S05": ["scope_block_incorrect"],
    "S06": ["specialist_capability_mismatch"],
    "S07": ["wrong_actor_owner_pair"],
    "S08": ["transport_timeout"],
    "S09": ["marker_not_extracted"],
    "S10": ["independent_evidence_missing"],
    "S11": ["validator_misclassification"],
    "S12": ["canonical_projection_missing"],
    "U00": ["stage_event_missing"],
}

_SCHEMA_VERSION = 1
_TAXONOMY_VERSION = "v2"


def _evid(run_id: str, case_id: str, stage: str) -> str:
    digest = hashlib.sha256(
        f"{run_id}|{case_id}|{stage}".encode("utf-8")
    ).hexdigest()
    return f"ev-{digest[:16]}"


def _budget_hash(run_id: str, case_id: str, stage: str) -> str:
    return hashlib.sha256(
        f"{run_id}|{case_id}|{stage}|budget".encode("utf-8")
    ).hexdigest()[:16]


def _simulate_case(case: dict, label: dict, fault_stage: str,
                   run_id: str) -> list:
    """Full event list for ONE case (deterministic)."""
    case_id = case["opaque_case_id"]
    fingerprint = case["fingerprint"]
    dag = label.get("stage_dag") or {}
    skipped = set(label.get("optional_stages") or [])
    skipped |= {
        e.get("stage") for e in (label.get("ineligible_stages") or [])
        if isinstance(e, dict)
    }

    cut = None
    if fault_stage != "S00" and fault_stage not in skipped:
        cut = fault_stage

    emitted: list[tuple] = []  # (stage, outcome, reason_codes)
    failure_emitted = False
    for stage in STAGE_ORDER:
        if stage in skipped:
            continue
        if cut is not None and stage == cut:
            emitted.append((stage, "failed", FAULT_REASON_BY_STAGE[stage]))
            failure_emitted = True
            continue
        if failure_emitted:
            continue  # downstream absent after the cut
        emitted.append((stage, "reached", []))

    emitted_stages = [s for s, _, _ in emitted]
    emitted_ids = {
        s: _evid(run_id, case_id, s) for s in emitted_stages
    }

    events = []
    for i, (stage, outcome, reason_codes) in enumerate(emitted):
        predecessor_ids = []
        entry = dag.get(stage)
        for dep in (entry.get("depends_on") or []) if isinstance(entry, dict) else []:
            if dep in emitted_ids:
                predecessor_ids.append(emitted_ids[dep])
        successor_ids = []
        for later in STAGE_ORDER[STAGE_ORDER.index(stage) + 1:]:
            if later in emitted_ids:
                successor_ids.append(emitted_ids[later])
                break
        events.append({
            "event_id": emitted_ids[stage],
            "run_id": run_id,
            "stage_id": stage,
            "outcome": outcome,
            "reason_codes": list(reason_codes),
            "predecessor_ids": predecessor_ids,
            "successor_ids": successor_ids,
            "opaque_asset_fingerprint": fingerprint,
            "producer_id": "generated-fixture",
            "agent_id": "event-simulator",
            "tool_id": "vdp-diagnostic-env",
            "recipe_id": "",
            "budget_snapshot_hash": _budget_hash(run_id, case_id, stage),
            "source_refs": [],
            "schema_version": _SCHEMA_VERSION,
            "taxonomy_version": _TAXONOMY_VERSION,
        })
    return events


def main() -> int:
    parser = argparse.ArgumentParser(description="Deterministic diagnostic event simulator")
    parser.add_argument("--manifest", required=True, help="sealed case manifest (json)")
    parser.add_argument("--labels", required=True, help="sealed expected-path labels (json)")
    parser.add_argument("--fault-stage", default="S00")
    parser.add_argument("--run-id", default="diag-run")
    parser.add_argument("--out", required=True, help="output jsonl path")
    args = parser.parse_args()

    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"simulator:fatal:{type(exc).__name__}:{exc}", file=sys.stderr)
        return 1

    label_by_case = {
        c["opaque_case_id"]: c for c in (labels.get("cases") or [])
    }

    events = []
    for case in manifest.get("cases") or []:
        label = label_by_case.get(case["opaque_case_id"])
        if label is None:
            print(
                f"simulator:fatal:no_label_for_case:{case['opaque_case_id']}",
                file=sys.stderr,
            )
            return 1
        events.extend(
            _simulate_case(case, label, args.fault_stage, args.run_id)
        )

    # Fail-closed self-check against the frozen section contract.
    section = {
        "schema_version": _SCHEMA_VERSION,
        "taxonomy_version": _TAXONOMY_VERSION,
        "diagnostic_active": True,
        "run_id": args.run_id,
        "events": events,
    }
    validation = validate_diagnostic_section(section)
    if not validation.passed:
        print(
            f"simulator:fatal:section_invalid:{validation.reason_codes}",
            file=sys.stderr,
        )
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        "\n".join(json.dumps(ev, sort_keys=True) for ev in events) + "\n",
        encoding="utf-8",
    )
    print(f"simulated_events:{len(events)}")
    print(f"simulated_section_valid:true")
    return 0


if __name__ == "__main__":
    sys.exit(main())
