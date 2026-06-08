#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.utils.json_utils import safe_json_loads

JST = timezone(timedelta(hours=9))


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def main() -> int:
    parser = argparse.ArgumentParser(description="Review weekly observability SLO from daily rollup json.")
    parser.add_argument("--daily-json", required=True)
    parser.add_argument("--unknown-rate-max", type=float, default=0.05)
    parser.add_argument("--p95-max-seconds", type=float, default=900.0)
    parser.add_argument("--p99-max-seconds", type=float, default=1200.0)
    parser.add_argument("--min-sample-count", type=int, default=100)
    parser.add_argument("--min-eligible-days", type=int, default=3)
    parser.add_argument("--schema-severity-required", action="store_true")
    parser.add_argument("--schema-severity-warn-only", action="store_true")
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--out-md", default="")
    args = parser.parse_args()

    daily_path = Path(args.daily_json).expanduser().resolve()
    out_path = Path(args.out_json).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    payload = safe_json_loads(
        daily_path.read_text(encoding="utf-8"),
        context=f"review_observability_slo_weekly:{daily_path.name}",
    )
    daily_rows = payload.get("daily", [])
    if not isinstance(daily_rows, list):
        daily_rows = []

    total_failed = 0
    total_unknown = 0
    min_sample = max(1, int(args.min_sample_count))
    eligible_days = 0
    reference_days = 0
    p95_max_observed = 0.0
    p99_max_observed = 0.0
    violations: list[str] = []
    warnings: list[str] = []

    for row in daily_rows:
        if not isinstance(row, dict):
            continue
        failed = _to_int(row.get("failed_tasks"), 0)
        unknown = _to_int(row.get("unknown_failures"), 0)
        total_failed += max(0, failed)
        total_unknown += max(0, unknown)

        slo = row.get("pr_execution_time_slo", {})
        if not isinstance(slo, dict):
            slo = {}
        sample_count = _to_int(slo.get("sample_count"), 0)
        p95 = _to_float(slo.get("observed_p95_seconds"), 0.0)
        p99 = _to_float(slo.get("observed_p99_seconds"), 0.0)
        p95_max_observed = max(p95_max_observed, p95)
        p99_max_observed = max(p99_max_observed, p99)

        if sample_count >= min_sample:
            eligible_days += 1
            if p95 > float(args.p95_max_seconds):
                violations.append(f"{row.get('date')}:p95_exceeded")
            if p99 > float(args.p99_max_seconds):
                violations.append(f"{row.get('date')}:p99_exceeded")
        else:
            reference_days += 1

        findings_total = _to_int(row.get("findings_total"), 0)
        schema_missing = _to_int(row.get("schema_severity_missing"), 0)
        if findings_total > 0 and schema_missing > 0:
            token = f"{row.get('date')}:schema_severity_missing({schema_missing}/{findings_total})"
            if args.schema_severity_required and not args.schema_severity_warn_only:
                violations.append(token)
            else:
                warnings.append(token)

    unknown_rate_week = (total_unknown / total_failed) if total_failed > 0 else 0.0
    if unknown_rate_week > float(args.unknown_rate_max):
        violations.append("unknown_rate_exceeded")

    min_eligible_days = max(1, int(args.min_eligible_days))
    if eligible_days < min_eligible_days:
        status = "provisional"
        decision = "thresholds_fixed_but_not_enforced_for_slo"
    elif violations:
        status = "fail"
        decision = "thresholds_fixed_and_enforced"
    else:
        status = "pass"
        decision = "thresholds_fixed_and_enforced"

    review = {
        "generated_at": datetime.now(JST).isoformat(),
        "status": status,
        "decision": decision,
        "policy": {
            "unknown_rate_max": float(args.unknown_rate_max),
            "p95_max_seconds": float(args.p95_max_seconds),
            "p99_max_seconds": float(args.p99_max_seconds),
            "min_sample_count": min_sample,
            "min_eligible_days": min_eligible_days,
            "schema_severity_required": bool(args.schema_severity_required),
            "schema_severity_warn_only": bool(args.schema_severity_warn_only),
        },
        "window": {
            "days": len(daily_rows),
            "eligible_days": eligible_days,
            "reference_days": reference_days,
        },
        "metrics": {
            "unknown_rate_week": unknown_rate_week,
            "failed_tasks_week": total_failed,
            "unknown_failures_week": total_unknown,
            "p95_max_observed_seconds": p95_max_observed,
            "p99_max_observed_seconds": p99_max_observed,
        },
        "violations": sorted(set(violations)),
        "warnings": sorted(set(warnings)),
        "source_daily_json": str(daily_path),
    }
    out_path.write_text(json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    out_md = str(args.out_md or "").strip()
    if out_md:
        md_path = Path(out_md).expanduser().resolve()
        md_path.parent.mkdir(parents=True, exist_ok=True)
        today = datetime.now(JST).date().isoformat()
        lines = [
            "---",
            "task_id: SGK-2026-0221-S03",
            "doc_type: work_report",
            "status: active",
            "parent_task_id: SGK-2026-0221",
            "related_docs:",
            "- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s03_groupc_regression-observability_subtask_plan.md",
            f"title: 'Weekly SLO Threshold Review ({today})'",
            f"created_at: '{today}'",
            f"updated_at: '{today}'",
            "tags:",
            "- shigoku",
            "- observability",
            "- slo",
            "---",
            "",
            "# Weekly SLO Threshold Review",
            "",
            f"- generated_at: {review['generated_at']}",
            f"- status: {review['status']}",
            f"- decision: {review['decision']}",
            f"- eligible_days: {review['window']['eligible_days']}",
            f"- reference_days: {review['window']['reference_days']}",
            f"- unknown_rate_week: {review['metrics']['unknown_rate_week']:.4f}",
            f"- p95_max_observed_seconds: {review['metrics']['p95_max_observed_seconds']:.2f}",
            f"- p99_max_observed_seconds: {review['metrics']['p99_max_observed_seconds']:.2f}",
            "",
            "## Policy",
            "",
            f"- unknown_rate_max: {review['policy']['unknown_rate_max']}",
            f"- p95_max_seconds: {review['policy']['p95_max_seconds']}",
            f"- p99_max_seconds: {review['policy']['p99_max_seconds']}",
            f"- min_sample_count: {review['policy']['min_sample_count']}",
            f"- min_eligible_days: {review['policy']['min_eligible_days']}",
            f"- schema_severity_required: {review['policy']['schema_severity_required']}",
            f"- schema_severity_warn_only: {review['policy']['schema_severity_warn_only']}",
            "",
            "## Violations",
            "",
        ]
        if review["violations"]:
            for item in review["violations"]:
                lines.append(f"- {item}")
        else:
            lines.append("- none")
        lines.extend(["", "## Warnings", ""])
        if review["warnings"]:
            for item in review["warnings"]:
                lines.append(f"- {item}")
        else:
            lines.append("- none")
        lines.extend(
            [
                "",
                "## deferred_tasks (optional)",
                "",
                "```yaml",
                "deferred_tasks:",
                "  - deferred_id: SGK-YYYY-NNNN-D01",
                '    title: "継続監視: [監視対象]"',
                '    reason: "実装スコープは完了したが、継続監視が必要"',
                "    impact: medium",
                "    tracking_task_id: SGK-YYYY-NNNN",
                '    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"',
                "```",
            ]
        )
        md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(review, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
