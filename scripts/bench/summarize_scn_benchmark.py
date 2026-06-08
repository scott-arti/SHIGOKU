#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

SCN_IDS = [
    "scn_01_idor_bola_object_access",
    "scn_02_mass_assignment_object_update",
    "scn_03_injection_input_tampering",
    "scn_04_endpoint_enumeration_bfla",
    "scn_05_rate_limit_resilience",
    "scn_06_data_exposure_diff",
    "scn_07_token_trust_boundary",
]


def parse_meta(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact-dir", required=True)
    ap.add_argument("--output-csv", required=True)
    ap.add_argument("--output-summary", required=True)
    args = ap.parse_args()

    adir = Path(args.artifact_dir)
    rows: list[dict[str, str]] = []

    for meta_path in sorted(adir.glob("*_meta.env")):
        run_id = meta_path.stem.replace("_meta", "")
        meta = parse_meta(meta_path)
        gate_path = adir / f"{run_id}_gate.json"
        cons_path = adir / f"{run_id}_consistency.json"

        gate = json.loads(gate_path.read_text(encoding="utf-8")) if gate_path.exists() else {}
        cons = json.loads(cons_path.read_text(encoding="utf-8")) if cons_path.exists() else {}

        report_metrics = gate.get("report_metrics", {}) if isinstance(gate, dict) else {}
        findings_summary = report_metrics.get("findings_summary", {}) if isinstance(report_metrics, dict) else {}
        missing = set(report_metrics.get("actual_missing_scenarios", []) or [])

        row: dict[str, str] = {
            "run_id": meta.get("run_id", run_id),
            "profile_id": meta.get("profile_id", ""),
            "seed_set_id": meta.get("seed_set_id", ""),
            "target_url": meta.get("target_url", ""),
            "started_at": meta.get("started_at", ""),
            "ended_at": meta.get("ended_at", ""),
            "report_path": meta.get("report_path", ""),
            "session_path": meta.get("session_path", ""),
            "consistency_status": str(cons.get("status", "")),
            "consistency_reason_codes": "|".join(cons.get("reason_codes", []) or []),
            "confirmed_count": str(findings_summary.get("confirmed_count", "")),
            "candidate_count": str(findings_summary.get("candidate_count", "")),
            "fn_count": "",
            "fp_count": "",
            "gate_status": str(gate.get("status", "")),
            "gate_reason_codes": "|".join(gate.get("reason_codes", []) or []),
            "scan_exit": meta.get("scan_exit", ""),
            "report_exit": meta.get("report_exit", ""),
            "consistency_exit": meta.get("consistency_exit", ""),
            "findings_exit": meta.get("findings_exit", ""),
            "gate_exit": meta.get("gate_exit", ""),
            "notes": "",
        }

        for idx, sid in enumerate(SCN_IDS, start=1):
            row[f"scn_{idx:02d}_detected"] = "true" if sid not in missing else "false"

        rows.append(row)

    fieldnames = [
        "run_id", "profile_id", "seed_set_id", "target_url", "started_at", "ended_at", "report_path", "session_path",
        "consistency_status", "consistency_reason_codes",
        "scn_01_detected", "scn_02_detected", "scn_03_detected", "scn_04_detected", "scn_05_detected", "scn_06_detected", "scn_07_detected",
        "confirmed_count", "candidate_count", "fn_count", "fp_count", "gate_status", "gate_reason_codes",
        "scan_exit", "report_exit", "consistency_exit", "findings_exit", "gate_exit", "notes",
    ]

    out_csv = Path(args.output_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    summary = {
        "artifact_dir": str(adir),
        "runs": len(rows),
        "all_consistent": all(r.get("consistency_status") == "consistent" for r in rows),
        "gate_status_counts": {
            "pass": sum(1 for r in rows if r.get("gate_status") == "pass"),
            "fail": sum(1 for r in rows if r.get("gate_status") == "fail"),
        },
        "avg_confirmed_count": (sum(int(r.get("confirmed_count") or 0) for r in rows) / len(rows)) if rows else 0.0,
        "avg_candidate_count": (sum(int(r.get("candidate_count") or 0) for r in rows) / len(rows)) if rows else 0.0,
        "scn_detection_rate": {
            f"scn_{i:02d}": (sum(1 for r in rows if r.get(f"scn_{i:02d}_detected") == "true") / len(rows) if rows else 0.0)
            for i in range(1, 8)
        },
    }

    out_summary = Path(args.output_summary)
    out_summary.parent.mkdir(parents=True, exist_ok=True)
    out_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Wrote CSV: {out_csv}")
    print(f"Wrote summary: {out_summary}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
