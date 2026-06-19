"""Deferred backlog operations: selection, normalization, resolution, and checklist generation."""

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from src.cli.handlers._shared import report_artifact_order_key
from src.commands import print_banner, print_step, print_result
from src.core.project.project_manager import ProjectManager
from src.core.utils.json_utils import safe_json_loads


def select_latest_deferred_backlog_file(reports_dir: Path) -> Path | None:
    if not reports_dir.exists():
        return None
    deferred_files = sorted(
        list(reports_dir.glob("haddix_deferred_*.json")),
        key=lambda p: report_artifact_order_key(p, "haddix_deferred"),
        reverse=True,
    )
    return deferred_files[0] if deferred_files else None


def extract_deferred_scenarios_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    scenarios = payload.get("deferred_scenarios", [])
    if not isinstance(scenarios, list):
        return []
    return [item for item in scenarios if isinstance(item, dict)]


def normalize_deferred_status(value: Any) -> str:
    token = str(value or "").strip().lower()
    if not token:
        return "pending"

    aliases = {
        "pending": "pending",
        "queued": "pending",
        "open": "pending",
        "in_progress": "in_progress",
        "progress": "in_progress",
        "active": "in_progress",
        "running": "in_progress",
        "done": "done",
        "resolved": "done",
        "complete": "done",
        "completed": "done",
        "closed": "done",
        "rejected": "rejected",
        "skip": "rejected",
        "skipped": "rejected",
    }
    return aliases.get(token, "pending")


def summarize_deferred_statuses(scenarios: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "pending": 0,
        "in_progress": 0,
        "done": 0,
        "rejected": 0,
        "total": 0,
    }
    for item in scenarios:
        if not isinstance(item, dict):
            continue
        status = normalize_deferred_status(item.get("status"))
        if status not in summary:
            status = "pending"
        summary[status] += 1
        summary["total"] += 1
    return summary


def resolve_deferred_scenarios(
    *,
    scenarios: list[dict[str, Any]],
    scenario_ids: list[str],
    note: str | None = None,
    resolved_by: str | None = None,
    resolved_at: str | None = None,
) -> tuple[int, list[str]]:
    requested_map: dict[str, str] = {}
    for raw_id in scenario_ids:
        original = str(raw_id or "").strip()
        if not original:
            continue
        requested_map[original.lower()] = original

    if not requested_map:
        return 0, []

    resolved_count = 0
    remaining = set(requested_map.keys())
    resolved_at_value = resolved_at or datetime.now().isoformat(timespec="seconds")
    resolved_by_value = str(resolved_by or "operator").strip() or "operator"
    note_value = str(note or "").strip()

    for item in scenarios:
        if not isinstance(item, dict):
            continue
        scenario_id = str(item.get("scenario_id", "") or "").strip()
        if not scenario_id:
            continue
        key = scenario_id.lower()
        if key not in requested_map:
            continue

        item["status"] = "done"
        item["resolved_at"] = resolved_at_value
        item["resolved_by"] = resolved_by_value
        if note_value:
            item["resolution_note"] = note_value
        resolved_count += 1
        remaining.discard(key)

    unresolved = [requested_map[key] for key in requested_map if key in remaining]
    return resolved_count, unresolved


def default_deferred_checklist_output_path(deferred_file: Path) -> Path:
    match = re.match(r"^haddix_deferred_(\d{8}_\d{6})\.json$", deferred_file.name)
    suffix = match.group(1) if match else datetime.now().strftime("%Y%m%d_%H%M%S")
    return deferred_file.parent / f"haddix_deferred_checklist_{suffix}.md"


def build_deferred_checklist_markdown(
    *,
    deferred_file: Path,
    payload: dict[str, Any],
    scenarios: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_path = str(payload.get("report_path", "") or "-")

    lines.append("# 🗂️ Deferred Scenario Execution Checklist")
    lines.append("")
    lines.append(f"**Generated:** {generated_at}")
    lines.append(f"**Source Deferred Artifact:** {deferred_file}")
    lines.append(f"**Source Report:** {report_path}")
    lines.append(f"**Scenario Count:** {len(scenarios)}")
    lines.append("")

    if not scenarios:
        lines.append("- [ ] Deferred scenario はありません。")
        lines.append("")
        return "\n".join(lines)

    for idx, item in enumerate(scenarios, 1):
        scenario_id = str(item.get("scenario_id", "-") or "-")
        title = str(item.get("title", scenario_id) or scenario_id)
        route = str(item.get("route", "-") or "-")
        trigger = str(item.get("trigger", "-") or "-")
        why_deferred = str(item.get("why_deferred", "-") or "-")
        operator_input = str(item.get("operator_input", "-") or "-")
        success_criteria = str(item.get("success_criteria", "-") or "-")

        lines.append(f"## {idx}. [ ] {scenario_id} - {title}")
        lines.append("")
        lines.append(f"- Route: `{route}`")
        lines.append(f"- Trigger: {trigger}")
        lines.append(f"- Why Deferred: {why_deferred}")
        lines.append(f"- Operator Input: {operator_input}")
        lines.append(f"- Success Criteria: {success_criteria}")
        lines.append("")
        lines.append("### Execution Checklist")
        lines.append("- [ ] 事前条件とテスト境界を確定した")
        lines.append("- [ ] operator_input を具体値で埋めた")
        lines.append("- [ ] 想定攻撃パスを再現した")
        lines.append("- [ ] 証跡（リクエスト/レスポンス/ログ）を保存した")
        lines.append("- [ ] 成否と次アクションを記録した")
        lines.append("")
        lines.append("### Notes")
        lines.append("- ")
        lines.append("")

    return "\n".join(lines)


def run_deferred_backlog_management(args: argparse.Namespace) -> None:
    from src.core.project.project_manager import ProjectManager
    from src.core.utils.json_utils import safe_json_loads

    print_banner()
    print_step("🗂️", "Deferred scenario backlog mode")

    deferred_file: Path | None = None
    if args.deferred_file:
        deferred_file = Path(args.deferred_file).expanduser().resolve()
    elif args.target:
        pm = ProjectManager(args.target)
        reports_dir = pm.get_reports_dir()
        deferred_file = select_latest_deferred_backlog_file(reports_dir)
        if deferred_file is not None:
            print_step("📂", f"Using latest deferred backlog for project: {args.target} ({deferred_file.name})")
    else:
        print_result(
            False,
            "--deferred-* mode requires --target or --deferred-file "
            "(supported: --deferred-list/--deferred-checklist/--deferred-status/--deferred-resolve)",
        )
        return

    if deferred_file is None or not deferred_file.exists():
        print_result(False, "No deferred backlog artifact found.")
        print("Hint: Generate Haddix report first with `--report --format haddix`.")
        return

    try:
        raw_text = deferred_file.read_text(encoding="utf-8")
        payload = safe_json_loads(raw_text, context=f"deferred_backlog:{deferred_file.name}")
        if not isinstance(payload, dict):
            raise ValueError("deferred backlog is not a JSON object")
    except Exception as exc:
        print_result(False, f"Failed to read deferred backlog: {exc}")
        return

    scenarios = extract_deferred_scenarios_from_payload(payload)
    status_summary = summarize_deferred_statuses(scenarios)

    resolve_ids = [str(item).strip() for item in (args.deferred_resolve or []) if str(item).strip()]
    resolved_count = 0
    unresolved_ids: list[str] = []
    if resolve_ids:
        resolved_count, unresolved_ids = resolve_deferred_scenarios(
            scenarios=scenarios,
            scenario_ids=resolve_ids,
            note=args.deferred_note,
            resolved_by=args.deferred_resolved_by,
        )
        payload["deferred_scenarios"] = scenarios
        payload["updated_at"] = datetime.now().isoformat(timespec="seconds")
        try:
            deferred_file.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            print_result(False, f"Failed to update deferred backlog: {exc}")
            return
        status_summary = summarize_deferred_statuses(scenarios)

    checklist_path: Path | None = None
    if args.deferred_checklist:
        explicit_output = bool(args.deferred_checklist_output)
        checklist_path = (
            Path(args.deferred_checklist_output).expanduser().resolve()
            if args.deferred_checklist_output
            else default_deferred_checklist_output_path(deferred_file)
        )
        checklist_markdown = build_deferred_checklist_markdown(
            deferred_file=deferred_file,
            payload=payload,
            scenarios=scenarios,
        )
        try:
            checklist_path.parent.mkdir(parents=True, exist_ok=True)
            checklist_path.write_text(checklist_markdown, encoding="utf-8")
        except PermissionError:
            if explicit_output:
                print_result(False, f"Checklist output path is not writable: {checklist_path}")
                return
            fallback_dir = (Path.cwd() / "reports").resolve()
            fallback_dir.mkdir(parents=True, exist_ok=True)
            fallback_path = fallback_dir / checklist_path.name
            fallback_path.write_text(checklist_markdown, encoding="utf-8")
            checklist_path = fallback_path
            print_step("⚠️", f"Checklist output path not writable, used fallback: {checklist_path}")
        except Exception as exc:
            print_result(False, f"Failed to generate deferred checklist: {exc}")
            return

    if args.json:
        response = {
            "artifact": str(deferred_file),
            "scenario_count": len(scenarios),
            "status_counts": status_summary,
            "deferred_scenarios": scenarios,
        }
        if resolve_ids:
            response["resolved_count"] = resolved_count
            response["unresolved_requested"] = unresolved_ids
        if checklist_path is not None:
            response["checklist_output"] = str(checklist_path)
        print(json.dumps(response, indent=2, ensure_ascii=False))
        return

    print(f"Deferred scenarios: {len(scenarios)}")
    print(
        "Status summary: "
        f"pending={status_summary.get('pending', 0)}, "
        f"in_progress={status_summary.get('in_progress', 0)}, "
        f"done={status_summary.get('done', 0)}, "
        f"rejected={status_summary.get('rejected', 0)}, "
        f"total={status_summary.get('total', 0)}"
    )
    print(f"Artifact: {deferred_file}")
    if resolve_ids:
        print_step("✅", f"Resolved deferred scenarios: {resolved_count}")
        if unresolved_ids:
            preview = ", ".join(unresolved_ids[:5])
            suffix = " ..." if len(unresolved_ids) > 5 else ""
            print_step("⚠️", f"Requested scenario_id not found: {preview}{suffix}")
    if checklist_path is not None:
        print_step("📝", f"Deferred checklist generated: {checklist_path}")
    if not scenarios:
        print("No deferred scenarios in this artifact.")
        return

    for item in scenarios:
        scenario_id = str(item.get("scenario_id", "-") or "-")
        route = str(item.get("route", "-") or "-")
        title = str(item.get("title", scenario_id) or scenario_id)
        status = normalize_deferred_status(item.get("status"))
        trigger = str(item.get("trigger", "-") or "-")
        operator_input = str(item.get("operator_input", "-") or "-")
        success_criteria = str(item.get("success_criteria", "-") or "-")
        resolved_at = str(item.get("resolved_at", "") or "").strip()
        resolved_by = str(item.get("resolved_by", "") or "").strip()
        print(f"- {scenario_id} | status={status} | route={route} | {title}")
        print(f"  trigger: {trigger}")
        print(f"  operator_input: {operator_input}")
        print(f"  success_criteria: {success_criteria}")
        if resolved_at:
            extra = f" by {resolved_by}" if resolved_by else ""
            print(f"  resolved: {resolved_at}{extra}")

    print("")
    print("Next:")
    print("1. 実施対象の deferred scenario を決める")
    print("2. 必要な operator_input を埋めて検証を実施する")
    print("3. 完了した scenario は `--deferred-resolve <scenario_id>` で状態更新する")
    print("4. 追加の HITL タスクがある場合は `--hitl-list` / `--hitl-run` を使う")
