#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
import sys

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core.observability.phase2_classification import classify_failure_pattern
from src.core.utils.json_utils import safe_json_loads

JST = timezone(timedelta(hours=9))
SESSION_NAME_RE = re.compile(r"session_(\d{8})_(\d{6})\.json$")


def _iter_session_files(workspace_projects_dir: Path) -> list[Path]:
    return sorted(workspace_projects_dir.glob("*/sessions/session_*.json"))


def _session_timestamp(session_path: Path) -> datetime | None:
    m = SESSION_NAME_RE.search(session_path.name)
    if not m:
        return None
    token = f"{m.group(1)}{m.group(2)}"
    try:
        return datetime.strptime(token, "%Y%m%d%H%M%S").replace(tzinfo=JST)
    except Exception:
        return None


def _extract_duration_seconds(task: dict[str, Any]) -> float | None:
    candidates: list[Any] = []
    if isinstance(task, dict):
        result = task.get("result", {})
        if isinstance(result, dict):
            candidates.extend(
                [
                    result.get("duration_seconds"),
                    result.get("duration"),
                    result.get("elapsed_seconds"),
                ]
            )
            data = result.get("data", {})
            if isinstance(data, dict):
                candidates.extend(
                    [
                        data.get("duration_seconds"),
                        data.get("duration"),
                        data.get("elapsed_seconds"),
                    ]
                )
        context = task.get("context", {})
        if isinstance(context, dict):
            metrics = context.get("metrics", {})
            if isinstance(metrics, dict):
                candidates.append(metrics.get("total_duration"))
    for val in candidates:
        try:
            num = float(val)
            if num >= 0:
                return num
        except Exception:
            continue
    return None


def _percentile(values: list[float], ratio: float) -> float:
    if not values:
        return 0.0
    idx = int(round((len(values) - 1) * ratio))
    idx = max(0, min(idx, len(values) - 1))
    return float(values[idx])


def _daily_rollup(session_files: list[Path], days: int) -> dict[str, Any]:
    cutoff = datetime.now(JST) - timedelta(days=max(1, int(days)))
    grouped: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "sessions": 0,
            "failed_tasks": 0,
            "unknown_failures": 0,
            "schema_severity_counts": defaultdict(int),
            "findings_total": 0,
            "schema_severity_missing": 0,
            "durations": [],
        }
    )

    for session_path in session_files:
        ts = _session_timestamp(session_path)
        if ts is None or ts < cutoff:
            continue
        date_key = ts.date().isoformat()
        bucket = grouped[date_key]
        bucket["sessions"] += 1

        try:
            session_data = safe_json_loads(
                session_path.read_text(encoding="utf-8"),
                context=f"observability_rollup:{session_path.name}",
            )
        except Exception:
            continue

        completed_tasks = session_data.get("completed_tasks", [])
        if not isinstance(completed_tasks, list):
            continue
        for task in completed_tasks:
            if not isinstance(task, dict):
                continue
            state = str(task.get("state", "") or "").strip().lower()
            if state == "failed":
                bucket["failed_tasks"] += 1
                reason_code = str(task.get("failure_reason_code", "") or "")
                error_message = str(task.get("error", "") or "")
                if classify_failure_pattern(reason_code=reason_code, error_message=error_message) == "unknown":
                    bucket["unknown_failures"] += 1

            duration = _extract_duration_seconds(task)
            if duration is not None:
                bucket["durations"].append(duration)

            result = task.get("result", {})
            findings: list[Any] = []
            if isinstance(result, dict):
                raw_findings = result.get("findings")
                if isinstance(raw_findings, list):
                    findings.extend(raw_findings)
                data = result.get("data", {})
                if isinstance(data, dict):
                    nested = data.get("findings")
                    if isinstance(nested, list):
                        findings.extend(nested)
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                bucket["findings_total"] += 1
                additional = finding.get("additional_info", {})
                severity = ""
                if isinstance(additional, dict):
                    severity = str(additional.get("schema_severity", "") or "")
                if not severity:
                    severity = str(finding.get("schema_severity", "") or "")
                sev = severity.strip().lower()
                if sev:
                    bucket["schema_severity_counts"][sev] += 1
                else:
                    bucket["schema_severity_missing"] += 1

    rows: list[dict[str, Any]] = []
    for date_key in sorted(grouped.keys()):
        bucket = grouped[date_key]
        durations = sorted(float(v) for v in bucket["durations"] if v is not None)
        failed_tasks = int(bucket["failed_tasks"])
        unknown_failures = int(bucket["unknown_failures"])
        rows.append(
            {
                "date": date_key,
                "sessions": int(bucket["sessions"]),
                "failed_tasks": failed_tasks,
                "unknown_failures": unknown_failures,
                "unknown_rate": (unknown_failures / failed_tasks) if failed_tasks > 0 else 0.0,
                "schema_severity_counts": dict(sorted(bucket["schema_severity_counts"].items())),
                "findings_total": int(bucket["findings_total"]),
                "schema_severity_missing": int(bucket["schema_severity_missing"]),
                "pr_execution_time_slo": {
                    "observed_p95_seconds": _percentile(durations, 0.95),
                    "observed_p99_seconds": _percentile(durations, 0.99),
                    "sample_count": len(durations),
                    "insufficient_samples": len(durations) < 100,
                    "target_p95_seconds": 900.0,
                    "target_p99_seconds": 1200.0,
                },
            }
        )

    return {
        "generated_at": datetime.now(JST).isoformat(),
        "window_days": max(1, int(days)),
        "daily": rows,
    }


def _weekly_markdown(daily_payload: dict[str, Any], output_path: Path) -> None:
    daily_rows = daily_payload.get("daily", [])
    if not isinstance(daily_rows, list):
        daily_rows = []

    all_unknown_failures = sum(int(r.get("unknown_failures", 0) or 0) for r in daily_rows if isinstance(r, dict))
    all_failed_tasks = sum(int(r.get("failed_tasks", 0) or 0) for r in daily_rows if isinstance(r, dict))
    week_unknown_rate = (all_unknown_failures / all_failed_tasks) if all_failed_tasks > 0 else 0.0

    p95_values: list[float] = []
    p99_values: list[float] = []
    for row in daily_rows:
        if not isinstance(row, dict):
            continue
        slo = row.get("pr_execution_time_slo", {})
        if not isinstance(slo, dict):
            continue
        try:
            p95_values.append(float(slo.get("observed_p95_seconds", 0.0) or 0.0))
            p99_values.append(float(slo.get("observed_p99_seconds", 0.0) or 0.0))
        except Exception:
            continue
    week_p95 = max(p95_values) if p95_values else 0.0
    week_p99 = max(p99_values) if p99_values else 0.0

    today = datetime.now(JST).date().isoformat()
    lines: list[str] = []
    lines.append("---")
    lines.append("task_id: SGK-2026-0221-S03")
    lines.append("doc_type: work_report")
    lines.append("status: active")
    lines.append("parent_task_id: SGK-2026-0221")
    lines.append("related_docs:")
    lines.append("- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s03_groupc_regression-observability_subtask_plan.md")
    lines.append(f"title: 'Weekly Observability SLO Report ({today})'")
    lines.append(f"created_at: '{today}'")
    lines.append(f"updated_at: '{today}'")
    lines.append("tags:")
    lines.append("- shigoku")
    lines.append("- observability")
    lines.append("- slo")
    lines.append("---")
    lines.append("")
    lines.append("# Weekly Observability SLO Report")
    lines.append("")
    lines.append(f"- generated_at: {daily_payload.get('generated_at')}")
    lines.append(f"- window_days: {daily_payload.get('window_days')}")
    lines.append(f"- unknown_rate_week: {week_unknown_rate:.4f}")
    lines.append(f"- pr_execution_p95_week_max_seconds: {week_p95:.2f}")
    lines.append(f"- pr_execution_p99_week_max_seconds: {week_p99:.2f}")
    lines.append("")
    min_sample = int(daily_payload.get("weekly_min_sample_count", 100) or 100)
    lines.append("## Quality Guard")
    lines.append("")
    lines.append(f"- 判定ルール: `sample_count < {min_sample}` の日は **参考値扱い**（SLO判定に使わない推奨）")
    lines.append("- 週次のSLO判断は `sample_count` を必ず併記して実施する")
    lines.append("")
    lines.append("## Schema Severity Coverage")
    lines.append("")
    lines.append("| date | findings_total | schema_missing | schema_coverage_rate |")
    lines.append("|---|---:|---:|---:|")
    for row in daily_rows:
        if not isinstance(row, dict):
            continue
        findings_total = int(row.get("findings_total", 0) or 0)
        schema_missing = int(row.get("schema_severity_missing", 0) or 0)
        coverage = 1.0 if findings_total <= 0 else max(0.0, (findings_total - schema_missing) / findings_total)
        lines.append(f"| {row.get('date')} | {findings_total} | {schema_missing} | {coverage:.4f} |")
    lines.append("")
    lines.append("## Daily Breakdown")
    lines.append("")
    lines.append("| date | sessions | failed_tasks | unknown_rate | sample_count | quality | p95(s) | p99(s) |")
    lines.append("|---|---:|---:|---:|---:|---|---:|---:|")
    for row in daily_rows:
        if not isinstance(row, dict):
            continue
        slo = row.get("pr_execution_time_slo", {})
        if not isinstance(slo, dict):
            slo = {}
        sample_count = int(slo.get("sample_count", 0) or 0)
        quality = "reference" if sample_count < min_sample else "slo-eligible"
        lines.append(
            f"| {row.get('date')} | {int(row.get('sessions', 0) or 0)} | {int(row.get('failed_tasks', 0) or 0)} | "
            f"{float(row.get('unknown_rate', 0.0) or 0.0):.4f} | {sample_count} | {quality} | {float(slo.get('observed_p95_seconds', 0.0) or 0.0):.2f} | "
            f"{float(slo.get('observed_p99_seconds', 0.0) or 0.0):.2f} |"
        )
    lines.append("")
    lines.append("## deferred_tasks (optional)")
    lines.append("")
    lines.append("```yaml")
    lines.append("deferred_tasks:")
    lines.append("  - deferred_id: SGK-YYYY-NNNN-D01")
    lines.append('    title: "継続監視: [監視対象]"')
    lines.append('    reason: "実装スコープは完了したが、継続監視が必要"')
    lines.append("    impact: medium")
    lines.append("    tracking_task_id: SGK-YYYY-NNNN")
    lines.append('    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"')
    lines.append("```")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Daily/weekly observability SLO rollup.")
    parser.add_argument(
        "--workspace-projects-dir",
        default=str(PROJECT_ROOT / "workspace" / "projects"),
        help="Path to workspace/projects.",
    )
    parser.add_argument("--days", type=int, default=7, help="Rolling window days.")
    parser.add_argument("--weekly-min-sample-count", type=int, default=100, help="Weekly SLO quality guard threshold.")
    parser.add_argument("--daily-json-out", required=True, help="Output path for daily rollup JSON.")
    parser.add_argument("--weekly-md-out", required=True, help="Output path for weekly report markdown.")
    args = parser.parse_args()

    workspace_projects_dir = Path(args.workspace_projects_dir).expanduser().resolve()
    daily_json_out = Path(args.daily_json_out).expanduser().resolve()
    weekly_md_out = Path(args.weekly_md_out).expanduser().resolve()
    daily_json_out.parent.mkdir(parents=True, exist_ok=True)
    weekly_md_out.parent.mkdir(parents=True, exist_ok=True)

    session_files = _iter_session_files(workspace_projects_dir)
    payload = _daily_rollup(session_files=session_files, days=max(1, int(args.days)))
    payload["weekly_min_sample_count"] = max(1, int(args.weekly_min_sample_count))
    daily_json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _weekly_markdown(payload, weekly_md_out)
    print(
        json.dumps(
            {
                "status": "ok",
                "session_files_scanned": len(session_files),
                "daily_json_out": str(daily_json_out),
                "weekly_md_out": str(weekly_md_out),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
