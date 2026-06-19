#!/usr/bin/env python3
"""
SHIGOKU - Integrated Hunt Runner

全モジュールを統合したCLIツール。
3つのモードでバグハンティングを実行する。

Usage:
    python -m src.main --log <file>     # Hybrid Hunt: Caidoログ解析→自動攻撃
    python -m src.main --watch <repo>   # Sentinel Watch: GitHub監視
    python -m src.main --demo           # Grand Demo: 全機能デモ
"""

import argparse
import asyncio
import os
import sys
from pathlib import Path
import json
from typing import Any
from datetime import datetime

from src.core.factory import AgentFactory
from src.core.models.llm import LLMClient
from src.core.recon.orchestrator import ReconOrchestrator
from src.core.domain.scope.scope_manager import ScopeManager
from src.config import settings

# Phase 4: sys.pathハック削除（pip install -e . でインストール前提）


# ===== Commands Modules Import =====
from src.commands import print_banner, print_step, print_result
from src.commands.rag import run_rag_ingest, run_rag_query, run_rag_stats
from src.commands.intel import run_dns_history, run_takeover_check
from src.commands.watch import run_sentinel_watch
from src.commands.demo import run_grand_demo
from src.commands.attack import run_param_fuzz, run_openapi_test
from src.commands.hunt import run_hybrid_hunt
from src.commands.export import run_export
from src.commands.audit import run_tool_status
from src.core.config_manager import get_config_manager
from src.core.reporting.platform_integration import (
    create_platform_manager,
    list_report_adapter_replay_queue,
    retry_failed_report_adapter_replay,
)

# ===== CLI Handlers Import =====
from src.cli.handlers._shared import (
    FOCUS_TEST_GROUPS,
    DEFAULT_QUALITY_LOOP_GROUPS,
    REPO_ROOT,
    session_order_key,
)
from src.cli.handlers.focus_tests import (
    print_focus_test_groups,
    run_focused_tests,
)
from src.cli.handlers.quality_loop import (
    build_quality_loop_scan_command,
    run_quality_loop,
    write_quality_loop_precheck_artifact,
)
from src.cli.handlers.report_haddix import (
    enable_debug_mode,
    build_scenario_coverage_for_report,
    build_heuristic_findings_from_execution_notes,
    merge_heuristic_candidates_into_findings,
    materialize_haddix_evidence_artifacts,
    run_haddix_report_generation,
)
from src.cli.handlers.report_replay import (
    extract_hitl_tickets_from_session_data,
    run_report_replay_commands,
    run_resume_session,
    select_hitl_session,
    run_hitl_management,
)
from src.cli.handlers.deferred_backlog import (
    select_latest_deferred_backlog_file,
    extract_deferred_scenarios_from_payload,
    normalize_deferred_status,
    summarize_deferred_statuses,
    resolve_deferred_scenarios,
    default_deferred_checklist_output_path,
    build_deferred_checklist_markdown,
    run_deferred_backlog_management,
)


# ===== Main Entry Point =====

def main():
    parser = argparse.ArgumentParser(
        prog="shigoku",
        description="SHIGOKU (至極) - 自律型バグバウンティハンター\n\n"
                    "Caidoログ解析、GitHub監視、RAGナレッジベース検索、DNS履歴取得など、\n"
                    "バグハンティングに必要な機能を統合したCLIツール。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # ハイブリッドハント（Caidoログ解析→自動攻撃）
  %(prog)s --log caido.json              
  %(prog)s --log caido.json --scope scope.yaml --mode vulntest
  
  # GitHub監視（シークレット漏洩検知）
  %(prog)s --watch owner/repo
  
  # RAGナレッジベース操作
  %(prog)s --rag-ingest ./knowledge      # ディレクトリ取り込み
  %(prog)s --rag-ingest ./doc.pdf        # PDF取り込み
  %(prog)s --rag-query "JWT bypass"      # 検索
  %(prog)s --rag-stats                   # 統計表示
  
  # DNS履歴取得
  %(prog)s --dns example.com
  %(prog)s --dns example.com --json
  
  # 偵察フェーズ
  %(prog)s --recon https://target.com
  
  # デモモード
  %(prog)s --demo

モード設定:
  --mode bugbounty  : バグバウンティモード（デフォルト）
                      - 高精度重視、控えめな攻撃
  --mode vulntest   : 脆弱性診断モード
                      - バランス型、網羅的テスト
  --mode ctf        : CTFモード
                      - 積極的攻撃、速度重視

  # プロジェクト一覧表示
  %(prog)s --projects
  
出力フォーマット:
  --json            : JSON形式で出力（スクリプト連携用）
        """
    )
    
    parser.add_argument(
        "--log", "-l",
        metavar="FILE",
        help="Hybrid Hunt: Analyze proxy log and execute attacks"
    )

    parser.add_argument(
        "--sessions-file",
        metavar="FILE",
        help="Optional multi-account session config for cross-session IDOR testing"
    )

    parser.add_argument(
        "--cross-test-approved",
        action="store_true",
        help="Enable approved IDOR cross-session confirmation (requires --sessions-file)"
    )
    
    parser.add_argument(
        "--scope", "-s",
        metavar="FILE",
        help="Scope definition file (YAML)"
    )
    
    parser.add_argument(
        "--watch", "-w",
        metavar="REPO",
        help="Sentinel Watch: Monitor GitHub repo (owner/repo)"
    )
    
    parser.add_argument(
        "--demo", "-d",
        action="store_true",
        help="Grand Demo: Demonstrate all features"
    )
    
    parser.add_argument(
        "--recon", "-r",
        metavar="URL",
        help="Recon Phase: Map site, identify tech, and store in Neo4j"
    )
    
    parser.add_argument(
        "--mode", "-m",
        metavar="MODE",
        choices=["bugbounty", "vulntest", "ctf"],
        help="Hunting mode: bugbounty (default), vulntest, ctf"
    )

    parser.add_argument(
        "--profile",
        metavar="PROFILE",
        choices=["bbpt", "ctf"],
        help="Scan profile: bbpt (report-quality) or ctf (speed/aggressive)"
    )

    parser.add_argument(
        "--target", "-t",
        metavar="URL",
        help="Target: Specify target URL (alias for --recon)"
    )

    parser.add_argument(
        "--skip-initial-recon",
        action="store_true",
        help="Skip the pre-MC initial recon phase (faster dev iteration)"
    )

    parser.add_argument(
        "--recon-start-step",
        type=int,
        metavar="N",
        help="Override recon pipeline start step for recon_master task (1-8)"
    )

    parser.add_argument(
        "--recon-end-step",
        type=int,
        metavar="N",
        help="Override recon pipeline end step for recon_master task (1-8)"
    )

    parser.add_argument(
        "--fast-iterate",
        action="store_true",
        help="Shortcut for fast iteration: --skip-initial-recon --recon-start-step 6 --recon-end-step 8"
    )

    # Recipe (NEW - Phase 8)
    parser.add_argument(
        "--recipe",
        metavar="FILE",
        help="Recipe: Specify a recipe file (YAML) to execute"
    )
    
    # Cookie (NEW)
    parser.add_argument(
        "--cookie",
        metavar="COOKIE",
        help="Pass cookies for authenticated scan (e.g. 'PHPSESSID=...')"
    )

    parser.add_argument(
        "--bearer-token",
        metavar="TOKEN",
        help="Pass bearer token for authenticated scan (raw JWT or 'Bearer <token>')"
    )
    
    # Crawl command (NEW)
    parser.add_argument(
        "--crawl", "-c",
        metavar="URL",
        help="Crawl: Run gospider/katana via Caido proxy"
    )
    
    parser.add_argument(
        "--crawl-depth",
        metavar="DEPTH",
        choices=["quick", "standard", "deep"],
        help="Crawl depth: quick(1), standard(3), deep(5)"
    )
    
    # Analyze command (NEW)
    parser.add_argument(
        "--analyze", "-a",
        metavar="URL",
        help="Analyze: Analyze app functions, type, architecture, vuln score"
    )
    
    # Debug mode (NEW)
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Debug Mode: Enable detailed logging with handoff/decision traces"
    )
    
    # RAG commands
    parser.add_argument(
        "--rag-ingest",
        metavar="PATH",
        help="RAG: Ingest files from path (directory or PDF)"
    )
    
    parser.add_argument(
        "--rag-query",
        metavar="QUESTION",
        help="RAG: Query the knowledge base"
    )
    
    parser.add_argument(
        "--rag-stats",
        action="store_true",
        help="RAG: Show knowledge base statistics"
    )
    
    parser.add_argument(
        "--pdf-only",
        action="store_true",
        help="RAG ingest: Only process PDF files"
    )
    
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="RAG ingest: Reset database before ingesting"
    )
    
    parser.add_argument(
        "-n", "--num-results",
        type=int,
        help="RAG query: Number of results (default: 5)"
    )
    
    # DNS command
    parser.add_argument(
        "--dns",
        metavar="DOMAIN",
        help="DNS History: Get historical DNS records"
    )
    
    # Parameter Fuzzing
    parser.add_argument(
        "--fuzz",
        metavar="URL",
        help="Parameter Fuzzing: Discover hidden params and check reflection"
    )
    
    # OpenAPI Testing
    parser.add_argument(
        "--openapi",
        metavar="URL",
        help="OpenAPI Testing: Auto-test Swagger/OpenAPI endpoints"
    )
    
    # Subdomain Takeover
    parser.add_argument(
        "--takeover",
        metavar="DOMAIN",
        help="Takeover Detection: Check subdomain takeover vulnerability"
    )
    
    # Export
    parser.add_argument(
        "--export",
        metavar="DIR",
        help="Export: Export findings to file"
    )
    
    parser.add_argument(
        "--format",
        metavar="FORMAT",
        choices=["json", "csv", "pdf", "markdown", "html", "haddix"],
        default="json",
        help="Export/Report format: json (default), csv, pdf, markdown, html, haddix"
    )
    
    # Tool Status
    parser.add_argument(
        "--tools",
        action="store_true",
        help="Tool Status: Show all registered tools and their status"
    )

    # Project List (NEW)
    parser.add_argument(
        "--projects",
        action="store_true",
        help="List Projects: Show all available projects"
    )
    
    # Interactive Mode (NEW - Phase 0)
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactive Mode: Start interactive session with Master Conductor"
    )
    
    # Resume Session (NEW - Session Persistence)
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume Session: Continue from previous interrupted session"
    )

    parser.add_argument(
        "--hitl-list",
        action="store_true",
        help="List pending HITL tickets from session"
    )

    parser.add_argument(
        "--deferred-list",
        action="store_true",
        help="List deferred scenario backlog from latest haddix_deferred artifact"
    )

    parser.add_argument(
        "--deferred-checklist",
        action="store_true",
        help="Generate execution checklist markdown from deferred scenario backlog"
    )

    parser.add_argument(
        "--deferred-status",
        action="store_true",
        help="Show deferred scenario status summary"
    )

    parser.add_argument(
        "--deferred-resolve",
        action="append",
        metavar="SCENARIO_ID",
        help="Mark deferred scenario as resolved (repeatable)"
    )

    parser.add_argument(
        "--deferred-note",
        metavar="TEXT",
        help="Resolution note recorded with --deferred-resolve"
    )

    parser.add_argument(
        "--deferred-resolved-by",
        metavar="NAME",
        help="Resolved-by label recorded with --deferred-resolve (default: operator)"
    )

    parser.add_argument(
        "--deferred-file",
        metavar="PATH",
        help="Explicit haddix_deferred_*.json path for --deferred-* mode"
    )

    parser.add_argument(
        "--deferred-checklist-output",
        metavar="PATH",
        help="Output path for --deferred-checklist markdown (default: reports/haddix_deferred_checklist_<timestamp>.md)"
    )

    parser.add_argument(
        "--hitl-run",
        action="store_true",
        help="Queue approved HITL tickets and execute them"
    )

    parser.add_argument(
        "--hitl-approve",
        action="append",
        metavar="TICKET_ID",
        help="Approve HITL ticket (repeatable)"
    )

    parser.add_argument(
        "--hitl-reject",
        action="append",
        metavar="TICKET_ID",
        help="Reject HITL ticket (repeatable)"
    )

    parser.add_argument(
        "--intervention-gate-mode",
        choices=["observe", "enforce_human_preferred", "enforce_hitl"],
        help="Override intervention gate mode for this run"
    )
    
    # Report (NEW)
    parser.add_argument(
        "--report",
        action="store_true",
        help="Show execution report from last session"
    )

    parser.add_argument(
        "--report-replay",
        action="store_true",
        help="Replay pending canonical_report_payload queue after report_adapter recovery"
    )

    parser.add_argument(
        "--report-retry-failed",
        action="store_true",
        help="Reset failed replay queue records back to pending for manual retry"
    )

    parser.add_argument(
        "--report-replay-list",
        action="store_true",
        help="List replay queue records for operator inspection"
    )

    parser.add_argument(
        "--report-replay-platform",
        choices=["hackerone", "bugcrowd"],
        default="hackerone",
        help="Platform to replay pending report queue entries against"
    )

    parser.add_argument(
        "--report-replay-queue",
        metavar="PATH",
        help="Override replay queue path (default: workspace/runtime/report_adapter_replay_queue.jsonl)"
    )

    parser.add_argument(
        "--report-replay-limit",
        type=int,
        metavar="N",
        help="Maximum number of pending replay entries to process"
    )

    parser.add_argument(
        "--report-replay-queue-id",
        metavar="QUEUE_ID",
        help="Filter report retry-failed to a specific replay queue record"
    )

    parser.add_argument(
        "--report-replay-status",
        choices=["pending", "failed", "completed"],
        help="Filter report replay list by replay status"
    )
    
    # Output format
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format"
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry Run: Execute workflow without actual attacks (sets safe_mode=True)"
    )
    
    parser.add_argument(
        "--translate-logs",
        action="store_true",
        help="Experimental: Translate logs to Japanese using local Ollama"
    )
    
    # Phase 5: Live Dashboard (NEW)
    parser.add_argument(
        "--live-dashboard",
        action="store_true",
        help="Phase 5: Enable real-time execution dashboard in terminal"
    )

    parser.add_argument(
        "--focus-list",
        action="store_true",
        help="List focused regression test groups and exit"
    )

    parser.add_argument(
        "--focus-tests",
        action="store_true",
        help="Run focused regression tests (for faster improve->verify iteration)"
    )

    parser.add_argument(
        "--focus-group",
        action="append",
        choices=["density", "report", "hitl", "fast_mc_recon", "all"],
        help="Focused test group to run (repeatable)"
    )

    parser.add_argument(
        "--focus-test",
        action="append",
        metavar="PATH",
        help="Additional pytest test path/nodeid for focused mode (repeatable)"
    )

    parser.add_argument(
        "--focus-fail-fast",
        action="store_true",
        help="Fail fast (-x) when running focused tests"
    )

    parser.add_argument(
        "--quality-loop",
        choices=["short"],
        help=(
            "Run standardized improve->verify loop. "
            "'short' executes focused tests first, then short attack loop."
        ),
    )

    parser.add_argument(
        "--quality-loop-full-scan",
        action="store_true",
        help="When used with --quality-loop short, run an additional full scan after short attack loop.",
    )

    args = parser.parse_args()

    if args.fast_iterate:
        args.skip_initial_recon = True
        if args.recon_start_step is None:
            args.recon_start_step = 6
        if args.recon_end_step is None:
            args.recon_end_step = 8

    if args.recon_start_step is not None and not (1 <= int(args.recon_start_step) <= 8):
        parser.error("--recon-start-step must be between 1 and 8")
    if args.recon_end_step is not None and not (1 <= int(args.recon_end_step) <= 8):
        parser.error("--recon-end-step must be between 1 and 8")
    if (
        args.recon_start_step is not None
        and args.recon_end_step is not None
        and int(args.recon_start_step) > int(args.recon_end_step)
    ):
        parser.error("--recon-start-step must be <= --recon-end-step")
    if args.quality_loop_full_scan and not args.quality_loop:
        parser.error("--quality-loop-full-scan requires --quality-loop")

    if args.focus_list:
        print_focus_test_groups()
        return

    if args.focus_tests:
        raw_groups = [str(g).strip() for g in (args.focus_group or []) if str(g).strip()]
        raw_custom_tests = [str(t).strip() for t in (args.focus_test or []) if str(t).strip()]
        exit_code, _groups, _tests, _cmd = run_focused_tests(
            groups=raw_groups,
            custom_tests=raw_custom_tests,
            fail_fast=bool(args.focus_fail_fast),
            stage_label="focused tests",
        )
        if exit_code == 0:
            return
        raise SystemExit(exit_code)

    if args.quality_loop:
        run_quality_loop(args, parser)
        return
    
    # Initialize Configuration
    cm = get_config_manager()
    config = cm.config
    
    # Experimental: Log Translation
    if args.translate_logs:
        os.environ["SHIGOKU_TRANSLATE_LOGS"] = "true"
        from src.core.utils.log_translator import enable_log_translation
        enable_log_translation()
    
    # Resolve Configuration (CLI > Config File > Default)
    mode = args.mode or config.mode or "bugbounty"
    scope_file = args.scope or config.scope_file
    
    # デバッグモード有効化（他の処理前に）
    if args.debug:
        enable_debug_mode()

    if args.intervention_gate_mode:
        settings.intervention_gate_mode = str(args.intervention_gate_mode)
        print_step("🛂", f"Intervention gate mode: {settings.intervention_gate_mode}")

    # Deferred scenario backlog management
    if args.deferred_list or args.deferred_checklist or args.deferred_status or args.deferred_resolve:
        run_deferred_backlog_management(args)
        return

    # HITL pending tickets management
    if args.hitl_list or args.hitl_run or args.hitl_approve or args.hitl_reject:
        run_hitl_management(args)
        return
    
    # Resume セッション処理
    if args.resume:
        run_resume_session(args)
        return

    # Report Output
    if args.report_replay_list or args.report_retry_failed or args.report_replay:
        run_report_replay_commands(args)
        return

    if args.report:
        from src.core.engine.master_conductor import MasterConductor
        from src.core.project.project_manager import ProjectManager
        from src.core.utils.json_utils import safe_json_loads
        
        session_file = "session_state.json"
        
        if args.target:
            pm = ProjectManager(args.target)
            sessions_dir = pm.project_dir / "sessions"
            
            latest_session = None
            if sessions_dir.exists():
                all_sessions = sorted(
                    list(sessions_dir.glob("session_*.json")),
                    key=session_order_key,
                    reverse=True
                )
                
                # 2. 有効なセッションを探す
                for s_file in all_sessions:
                    try:
                        if s_file.stat().st_size < 10:
                            continue

                        raw_text = s_file.read_text(encoding="utf-8")
                        data = safe_json_loads(raw_text, context=f"report_session_select:{s_file.name}")
                        if not isinstance(data, dict):
                            continue
                        # タスクがあれば有効とみなす
                        if data.get("completed_tasks") or data.get("task_queue"):
                            latest_session = s_file
                            break
                    except Exception:
                        continue
                
                # 有効なものが見つからなければ、latest.json を試すか、一番新しいものを返す
                if not latest_session:
                    latest_symlink = sessions_dir / "latest.json"
                    if latest_symlink.exists():
                        latest_session = latest_symlink
                    elif all_sessions:
                        latest_session = all_sessions[0]

            if latest_session and latest_session.exists():
                session_file = str(latest_session)
                print_step("📂", f"Using latest VALID session for project: {args.target} ({Path(session_file).name})")
            else:
                print_result(False, f"No valid session found for project {args.target}")
                return
        
        path_obj = Path(session_file)
        if not path_obj.exists():
            print_result(False, f"No session file found ({session_file})")
            return
            
        if args.format == "html":
            try:
                from src.reports.html_generator import generate_report_from_file
                output_path = generate_report_from_file(session_file)
                
                abs_path = Path(output_path).resolve()
                print_result(True, f"HTML Report generated: [bold cyan]{abs_path}[/bold cyan]")
                
                # Check if running in Docker
                is_docker = Path("/.dockerenv").exists()
                
                import webbrowser
                try:
                    if not is_docker:
                        print("Opening in browser...")
                        webbrowser.open(f"file://{abs_path}")
                    else:
                        print("💡 Running in Docker. Please open the report path above manually in your host browser.")
                except Exception:
                    print(f"💡 Could not open browser automatically. Please open: file://{abs_path}")
            except Exception as e:
                print_result(False, f"Failed to generate HTML report: {e}")
        
        elif args.format == "haddix":
            run_haddix_report_generation(session_file, args)
        else:
            # Default: Text Summary
            mc = MasterConductor()
            if mc.load_session(session_file):
                from src.commands.report import print_execution_summary
                print_execution_summary(mc.completed_tasks, mc.context)
            else:
                print_result(False, "Failed to load session")
        return

    # モード判定と実行
    if args.demo:
        run_grand_demo()
    elif args.interactive:
        # Phase 1: InteractiveBridge
        from src.core.conductor.interactive_bridge import start_interactive_session
        from src.core.models.llm import LLMClient
        llm_client = LLMClient(
            model=getattr(settings, "model", None)
            or getattr(settings, "model_output", None)
            or "deepseek/deepseek-chat"
        )
        start_interactive_session(
            mode=mode,
            scope_file=scope_file,
            profile=args.profile,
            llm_client=llm_client,
            bearer_token=args.bearer_token,
        )
    elif args.projects:
        from src.core.project.project_manager import ProjectManager
        projects = ProjectManager.list_projects()
        if args.json:
            print(json.dumps(projects, indent=2, ensure_ascii=False))
        else:
            print_banner()
            if not projects:
                print_result(False, "No projects found.")
            else:
                print(f"{'Project Name':<20} | {'Target':<30} | {'Last Scan'}")
                print("-" * 70)
                for p in projects:
                    name = p.get("project_name", "N/A")
                    target = p.get("target_url", "N/A")
                    last_scan = p.get("last_scan_at", "N/A")
                    print(f"{name:<20} | {target:<30} | {last_scan}")
    elif args.crawl:
        # Phase 2: MasterConductor経由 (旧: run_crawl直接呼び出し)
        from src.core.conductor.interactive_bridge import start_interactive_session
        start_interactive_session(
            mode=mode,
            scope_file=scope_file,
            auto_goal="Crawl",
            auto_target=args.crawl,
            profile=args.profile,
            bearer_token=args.bearer_token,
        )
    elif args.analyze:
        # Phase 2: MasterConductor経由 (旧: run_analyze直接呼び出し)
        from src.core.conductor.interactive_bridge import start_interactive_session
        start_interactive_session(
            mode=mode,
            scope_file=scope_file,
            auto_goal="Analyze",
            auto_target=args.analyze,
            profile=args.profile,
            bearer_token=args.bearer_token,
        )
    elif args.recon:
        # Phase 2: MasterConductor経由 (旧: run_recon_phase直接呼び出し)
        from src.core.conductor.interactive_bridge import start_interactive_session
        start_interactive_session(
            mode=mode,
            scope_file=scope_file,
            auto_goal="Reconnaissance",
            auto_target=args.recon,
            profile=args.profile,
            bearer_token=args.bearer_token,
        )
    elif args.target:
        target = args.target
        if target != "pending_fuzz" and not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        # Initialize Shared LLM Client
        from src.core.models.llm import LLMClient
        llm_client = LLMClient(
            model=getattr(settings, "model", None)
            or getattr(settings, "model_output", None)
            or "deepseek/deepseek-chat"
        )
        
        # Phase 2: MasterConductor経由
        from src.core.conductor.interactive_bridge import start_interactive_session
        # --- Phase 3: Adaptive Recon Start ---
        # 1. TargetAsset のロード
        target_assets = ScopeManager.load(scope_file or target)
        if not target_assets and target:
            from src.core.domain.model.target import TargetAsset
            target_assets = [TargetAsset.from_input(target)]

        # 2. Orchestrator の初期化と実行
        # NOTE: ここでは簡略化のため、MCが必要とするKGを取得・生成するロジックが必要
        kg = None # 実際には DataCenter や GraphDB から取得
        
        from src.core.infra.network_client import AsyncNetworkClient
        
        async def run_recon():
            async with AsyncNetworkClient() as network_client:
                orchestrator = ReconOrchestrator(kg, settings, network_client=network_client, llm_client=llm_client)
                await orchestrator.run_pipeline(target_assets)
        
        if args.skip_initial_recon:
            print_step("⏭️", "Skipping Initial Reconnaissance (--skip-initial-recon)")
        else:
            print_step("🔍", "Starting Initial Reconnaissance (Fast Phase)...")
            asyncio.run(run_recon())
            print_step("✅", "Initial Recon Complete. Starting Master Conductor.")
        # --- Phase 3 End ---

        start_interactive_session(
            mode=mode,
            scope_file=scope_file,
            auto_goal="Reconnaissance" if not args.mode == "vulntest" else "Attack", # vulntestならAttackから開始
            auto_target=target,
            dry_run=args.dry_run,
            cookies=args.cookie,
            bearer_token=args.bearer_token,
            live_dashboard=args.live_dashboard,
            recipe_file=args.recipe,
            profile=args.profile,
            llm_client=llm_client,
            recon_start_step=args.recon_start_step,
            recon_end_step=args.recon_end_step,
        )
    elif args.log:
        if args.sessions_file or args.cross_test_approved:
            run_hybrid_hunt(
                log_path=args.log,
                scope_file=scope_file,
                mode=mode,
                sessions_file=args.sessions_file,
                cross_test_approved=args.cross_test_approved,
            )
        else:
            # Phase 3: MasterConductor 経由 (旧：run_hybrid_hunt 直接呼び出し)
            from src.core.conductor.interactive_bridge import start_interactive_session
            from src.core.models.llm import LLMClient
            llm_client = LLMClient(
                model=getattr(settings, "model", None)
                or getattr(settings, "model_output", None)
                or "deepseek/deepseek-chat"
            )
            start_interactive_session(
                mode=mode,
                scope_file=scope_file,
                auto_goal="HybridHunt",
                auto_target=args.log,
                cookies=args.cookie,
                bearer_token=args.bearer_token,
                profile=args.profile,
                llm_client=llm_client
            )
    elif args.rag_ingest:
        if not config.rag_enabled:
            print_result(False, "RAG is disabled in config.")
            return
        run_rag_ingest(args.rag_ingest, pdf_only=args.pdf_only, reset=args.reset_db)
    elif args.rag_query:
        if not config.rag_enabled:
            print_result(False, "RAG is disabled in config.")
            return
        n_results = args.num_results or 5
        run_rag_query(args.rag_query, n_results=n_results, output_json=args.json)
    elif args.rag_stats:
        run_rag_stats(output_json=args.json)
    elif args.dns:
        run_dns_history(args.dns, output_json=args.json)
    elif args.fuzz:
        run_param_fuzz(args.fuzz, output_json=args.json)
    elif args.openapi:
        run_openapi_test(args.openapi, output_json=args.json)
    elif args.takeover:
        run_takeover_check(args.takeover, output_json=args.json)
    elif args.export:
        run_export(args.export, export_format=args.format, output_json=args.json)
    elif args.tools:
        run_tool_status(output_json=args.json)
    else:
        parser.print_help()
        print("\n💡 Try: python -m src.main --demo")
        print("\nAvailable modes: --mode bugbounty (default), vulntest, ctf")


    # Wait for background threads (e.g., ReconWorker)
    import threading
    import time
    
    # メインループ終了後、バックグラウンドスレッドが残っていれば待機
    background_threads = [t for t in threading.enumerate() if t.name.startswith("ReconWorker-")]
    if background_threads:
        print(f"\n⏳ Waiting for {len(background_threads)} background tasks to complete... (Ctrl+C to force exit)")
        try:
            for t in background_threads:
                if t.is_alive():
                    t.join()
        except KeyboardInterrupt:
            print("\n⚠️  Interrupted. Exiting immediately.")

if __name__ == "__main__":
    main()
