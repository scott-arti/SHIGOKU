import argparse
import re
import json
from pathlib import Path
from typing import Any

from src.cli.handlers._shared import session_order_key, report_artifact_order_key
from src.commands import print_banner, print_step, print_result
from src.core.engine.master_conductor import MasterConductor
from src.core.project.project_manager import ProjectManager
from src.core.models.llm import LLMClient
from src.core.utils.json_utils import safe_json_loads
from src.config import settings


def extract_hitl_tickets_from_session_data(session_data: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(session_data, dict):
        return []
    pending_hitl = session_data.get("pending_hitl")
    if not isinstance(pending_hitl, list):
        context = session_data.get("context", {})
        if isinstance(context, dict):
            pending_hitl = context.get("pending_hitl")
    if not isinstance(pending_hitl, list):
        return []
    return [ticket for ticket in pending_hitl if isinstance(ticket, dict)]


def select_hitl_session(
    parsed_sessions: list[tuple[Path, dict[str, Any]]],
    requested_ticket_ids: set[str] | None = None,
) -> tuple[Path | None, str]:
    actionable_statuses = {"pending", "approved", "queued"}
    requested_ids = {str(tid or "").strip() for tid in (requested_ticket_ids or set()) if str(tid or "").strip()}
    latest_status_by_ticket: dict[str, str] = {}

    # セッションは新しい順で渡される前提。ticketごとの最新状態を先に確定する。
    for _, data in parsed_sessions:
        for ticket in extract_hitl_tickets_from_session_data(data):
            ticket_id = str(ticket.get("ticket_id", "") or "").strip()
            if not ticket_id or ticket_id in latest_status_by_ticket:
                continue
            latest_status_by_ticket[ticket_id] = str(ticket.get("status", "pending") or "pending").strip().lower()

    # ticket_id が指定されている場合は、その ticket を含むセッションを最優先で選ぶ。
    if requested_ids:
        for s_file, data in parsed_sessions:
            tickets = extract_hitl_tickets_from_session_data(data)
            session_ticket_ids = {
                str(ticket.get("ticket_id", "") or "").strip()
                for ticket in tickets
                if str(ticket.get("ticket_id", "") or "").strip()
            }
            if session_ticket_ids.intersection(requested_ids):
                return s_file, "session containing specified HITL ticket(s)"

    # actionable ticket を含む最新セッションを優先。
    for s_file, data in parsed_sessions:
        tickets = extract_hitl_tickets_from_session_data(data)
        for ticket in tickets:
            ticket_id = str(ticket.get("ticket_id", "") or "").strip()
            status = str(ticket.get("status", "pending") or "pending").strip().lower()
            if not ticket_id or status not in actionable_statuses:
                continue
            if latest_status_by_ticket.get(ticket_id, status) in actionable_statuses:
                return s_file, "latest session with actionable HITL tickets"

    # actionable が無い場合は、HITL履歴がある最新セッションを選ぶ。
    for s_file, data in parsed_sessions:
        if extract_hitl_tickets_from_session_data(data):
            return s_file, "latest session with HITL ticket history"

    # 最後に通常の有効セッションへフォールバック。
    for s_file, data in parsed_sessions:
        completed = data.get("completed_tasks")
        queued = data.get("task_queue")
        if isinstance(completed, list) or isinstance(queued, list):
            return s_file, "latest valid session"

    return None, ""


def run_hitl_management(args: argparse.Namespace) -> None:
    from src.core.engine.master_conductor import MasterConductor
    from src.core.project.project_manager import ProjectManager
    from src.core.models.llm import LLMClient

    print_banner()
    print_step("🧩", "HITL ticket management mode")

    session_file = "session_state.json"
    pm = None
    if args.target:
        pm = ProjectManager(args.target)
        sessions_dir = pm.project_dir / "sessions"
        selected_session = None
        selected_reason = ""

        if sessions_dir.exists():
            from src.core.utils.json_utils import safe_json_loads

            all_sessions = sorted(
                list(sessions_dir.glob("session_*.json")),
                key=session_order_key,
                reverse=True,
            )

            parsed_sessions = []
            for s_file in all_sessions:
                try:
                    if s_file.stat().st_size < 10:
                        continue
                    raw_text = s_file.read_text(encoding="utf-8")
                    data = safe_json_loads(raw_text, context=f"hitl_session_select:{s_file.name}")
                    if not isinstance(data, dict):
                        continue
                    parsed_sessions.append((s_file, data))
                except Exception:
                    continue

            requested_ticket_ids = {
                str(ticket_id or "").strip()
                for ticket_id in (args.hitl_approve or []) + (args.hitl_reject or [])
                if str(ticket_id or "").strip()
            }
            selected_session, selected_reason = select_hitl_session(
                parsed_sessions, requested_ticket_ids=requested_ticket_ids
            )

        latest_session = sessions_dir / "latest.json" if pm else None
        if selected_session is None and latest_session is not None and latest_session.exists():
            selected_session = latest_session
            selected_reason = "latest.json fallback"

        if selected_session is not None:
            session_file = str(selected_session)
            print_step(
                "📂",
                f"Using {selected_reason} for project: {args.target} ({selected_session.name})",
            )
        else:
            print_result(False, f"No session found for project {args.target}")
            return

    if not Path(session_file).exists():
        print_result(False, f"No session file found ({session_file})")
        return

    llm_client = LLMClient(
        model=getattr(settings, "model", None)
        or getattr(settings, "model_output", None)
        or "deepseek/deepseek-chat"
    )
    mc = MasterConductor(llm_client=llm_client)
    if pm:
        mc.set_project_manager(pm)

    if not mc.load_session(session_file):
        print_result(False, "Failed to load session")
        return

    approved = 0
    rejected = 0
    unresolved_ticket_ids: list[str] = []
    for ticket_id in args.hitl_approve or []:
        if mc.set_pending_hitl_status(ticket_id, "approved"):
            approved += 1
        else:
            unresolved_ticket_ids.append(str(ticket_id))
    for ticket_id in args.hitl_reject or []:
        if mc.set_pending_hitl_status(ticket_id, "rejected"):
            rejected += 1
        else:
            unresolved_ticket_ids.append(str(ticket_id))

    if approved > 0:
        print_step("✅", f"Approved HITL tickets: {approved}")
    if rejected > 0:
        print_step("⛔", f"Rejected HITL tickets: {rejected}")
    if unresolved_ticket_ids:
        preview = ", ".join(unresolved_ticket_ids[:3])
        suffix = " ..." if len(unresolved_ticket_ids) > 3 else ""
        print_step("⚠️", f"HITL ticket not found in selected session: {preview}{suffix}")

    if args.hitl_list:
        all_tickets = mc.list_pending_hitl_tickets()
        actionable_statuses = {"pending", "approved", "queued"}
        tickets = [
            ticket
            for ticket in all_tickets
            if str(ticket.get("status", "pending") or "pending").strip().lower() in actionable_statuses
        ]
        done_count = sum(
            1
            for ticket in all_tickets
            if str(ticket.get("status", "") or "").strip().lower() == "done"
        )
        rejected_count = sum(
            1
            for ticket in all_tickets
            if str(ticket.get("status", "") or "").strip().lower() == "rejected"
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "actionable_tickets": tickets,
                        "all_tickets": all_tickets,
                        "status_counts": {
                            "actionable": len(tickets),
                            "done": done_count,
                            "rejected": rejected_count,
                            "total": len(all_tickets),
                        },
                    },
                    indent=2,
                    ensure_ascii=False,
                )
            )
        else:
            if not tickets:
                print("No actionable HITL tickets found.")
                route_counts: dict[str, int] = {}
                gate_mode_counts: dict[str, int] = {}
                for task in mc.completed_tasks:
                    params = task.params if isinstance(task.params, dict) else {}
                    intervention = params.get("_intervention", {}) if isinstance(params, dict) else {}
                    decision = intervention.get("decision", {}) if isinstance(intervention, dict) else {}
                    route = str(decision.get("route", "") or "").strip().lower()
                    gate_mode = str(intervention.get("gate_mode", "") or "").strip().lower()
                    if route:
                        route_counts[route] = route_counts.get(route, 0) + 1
                    if gate_mode:
                        gate_mode_counts[gate_mode] = gate_mode_counts.get(gate_mode, 0) + 1
                hitl_route_count = route_counts.get("shigoku_hitl", 0) + route_counts.get("human_preferred", 0)
                observe_count = gate_mode_counts.get("observe", 0)
                if hitl_route_count > 0 and observe_count == len(mc.completed_tasks):
                    print("Hint: This session ran in observe mode, so HITL-route tasks were not queued as tickets.")
                    print("Hint: Re-run mission with --intervention-gate-mode enforce_hitl, then use --hitl-list.")
                elif hitl_route_count <= 0:
                    print("Hint: No HITL-route tasks were generated in this session.")
                if done_count > 0 or rejected_count > 0:
                    print(
                        f"Status summary: done={done_count}, rejected={rejected_count}, total={len(all_tickets)}"
                    )
            else:
                print(
                    "HITL actionable tickets: "
                    f"{len(tickets)} (done={done_count}, rejected={rejected_count}, total={len(all_tickets)})"
                )
                for ticket in tickets:
                    ticket_id = str(ticket.get("ticket_id", "-") or "-")
                    status = str(ticket.get("status", "pending") or "pending")
                    scenario = str(ticket.get("scenario_id", "-") or "-")
                    task_name = str(ticket.get("task_name", "-") or "-")
                    friction_score = ticket.get("friction_score")
                    score_suffix = ""
                    if friction_score is not None and str(friction_score).strip() != "":
                        score_suffix = f" | friction={friction_score}/10"
                    print(f"- {ticket_id} | {status} | {scenario} | {task_name}{score_suffix}")

    if args.hitl_run:
        existing_pending = len(mc.task_queue)
        if existing_pending > 0:
            print_step("⏭️", f"Ignoring {existing_pending} existing pending task(s) in --hitl-run mode")
            mc.task_queue.clear()
        queued = mc.enqueue_approved_hitl_tasks()
        if queued <= 0:
            print_result(True, "No approved HITL tickets to run.")
            mc.save_session(filepath=session_file)
        else:
            print_step("▶️", f"Queued {queued} approved HITL task(s).")
            result = mc.execute_with_replan()
            print_result(True, "HITL resumed tasks completed")
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        mc.save_session(filepath=session_file)
        print_result(True, "HITL ticket updates saved")


def run_resume_session(args: argparse.Namespace) -> None:
    from src.core.engine.master_conductor import MasterConductor
    from src.core.project.project_manager import ProjectManager
    from src.core.models.llm import LLMClient

    print_banner()
    print_step("🔄", "Attempting to resume previous session...")

    session_file = "session_state.json"
    pm = None

    # Project Aware Resume
    if args.target:
        pm = ProjectManager(args.target)
        latest_session = pm.project_dir / "sessions" / "latest.json"
        if latest_session.exists():
            session_file = str(latest_session)
            print_step("📂", f"Using latest session for project: {args.target}")
        else:
            print_result(False, f"No session found for project {args.target}")
            return

    if not Path(session_file).exists():
        print_result(False, f"No session file found ({session_file})")
        print("💡 Tip: Run a normal mission first, then use --resume after interruption")
        return

    # Initialize LLM Client for resumed session
    llm_client = LLMClient(
        model=getattr(settings, "model", None)
        or getattr(settings, "model_output", None)
        or "deepseek/deepseek-chat"
    )
    mc = MasterConductor(llm_client=llm_client)
    if pm:
        mc.set_project_manager(pm)

    if mc.load_session(session_file):
        print_result(True, f"Session restored: {len(mc.task_queue)} tasks in queue")
        print_step("▶️", "Resuming execution...")

        # 実行再開
        result = mc.execute_with_replan()

        print_result(True, "Resumed session completed")

        # 終了サマリー表示
        from src.commands.report import print_execution_summary
        print_execution_summary(mc.completed_tasks, mc.context)

        if args.json:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print_result(False, "Failed to load session")


def run_report_replay_commands(args: argparse.Namespace) -> None:
    from src.core.reporting.platform_integration import (
        create_platform_manager,
        list_report_adapter_replay_queue,
        retry_failed_report_adapter_replay,
    )

    # Report Output
    if args.report_replay_list:
        list_result = list_report_adapter_replay_queue(
            replay_queue_path=Path(args.report_replay_queue).expanduser().resolve()
            if args.report_replay_queue
            else None,
            platform=args.report_replay_platform,
            queue_id=args.report_replay_queue_id,
            status=args.report_replay_status,
            limit=args.report_replay_limit,
        )

        if args.json:
            print(json.dumps(list_result, indent=2, ensure_ascii=False))
            return

        print_banner()
        print_step("📋", "Report replay list mode")
        print_step("🔢", f"count={list_result['count']}")
        print_step("🗂️", f"queue={list_result['queue_path']}")
        for record in list_result["records"]:
            print(
                f"- {record.get('queue_id', '-')}"
                f" | platform={record.get('platform', '-')}"
                f" | status={record.get('replay_status', '-')}"
            )
        return

    if args.report_retry_failed:
        retry_result = retry_failed_report_adapter_replay(
            platform=args.report_replay_platform,
            replay_queue_path=Path(args.report_replay_queue).expanduser().resolve()
            if args.report_replay_queue
            else None,
            limit=args.report_replay_limit,
            queue_id=args.report_replay_queue_id,
        )

        if args.json:
            print(json.dumps(retry_result, indent=2, ensure_ascii=False))
            return

        print_banner()
        print_step("🔁", "Report retry-failed mode")
        print_result(True, f"Failed replay records reset for {retry_result['platform']}")
        print_step("♻️", f"reset={retry_result['reset']}")
        print_step("⏭️", f"skipped={retry_result['skipped']}")
        print_step("🗂️", f"queue={retry_result['queue_path']}")
        return

    if args.report_replay:
        import asyncio
        import os

        if not args.json:
            print_banner()
            print_step("🔁", "Report replay mode")

        hackerone_token = (
            str(getattr(settings, "hackerone_token", "") or "").strip()
            or str(os.environ.get("H1_API_KEY", "")).strip()
            or str(os.environ.get("HACKERONE_TOKEN", "")).strip()
        )
        hackerone_username = (
            str(getattr(settings, "hackerone_username", "") or "").strip()
            or str(os.environ.get("H1_API_USER", "")).strip()
            or str(os.environ.get("HACKERONE_USERNAME", "")).strip()
        )
        bugcrowd_token = (
            str(getattr(settings, "bugcrowd_token", "") or "").strip()
            or str(os.environ.get("BUGCROWD_API_KEY", "")).strip()
            or str(os.environ.get("BUGCROWD_TOKEN", "")).strip()
        )

        manager = asyncio.run(
            create_platform_manager(
                hackerone_token=hackerone_token or None,
                hackerone_username=hackerone_username or None,
                bugcrowd_token=bugcrowd_token or None,
            )
        )
        if not hasattr(manager, "replay_pending_submissions"):
            print_result(False, "Configured platform manager does not support replay.")
            return
        if args.report_replay_platform not in getattr(manager, "_platforms", {}):
            print_result(False, f"Platform is not configured for replay: {args.report_replay_platform}")
            return

        replay_result = asyncio.run(
            manager.replay_pending_submissions(
                args.report_replay_platform,
                component_status={"report_adapter": "healthy"},
                replay_queue_path=Path(args.report_replay_queue).expanduser().resolve()
                if args.report_replay_queue
                else None,
                limit=args.report_replay_limit,
            )
        )

        if args.json:
            print(json.dumps(replay_result, indent=2, ensure_ascii=False))
            return

        print_result(True, f"Replay processed for {replay_result['platform']}")
        print_step("📦", f"processed={replay_result['processed']}")
        print_step("✅", f"replayed={replay_result['replayed']}")
        print_step("⚠️", f"failed={replay_result['failed']}")
        print_step("🗂️", f"queue={replay_result['queue_path']}")
        return
