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
import logging
import asyncio
import warnings
import re
import os
import shlex
import subprocess
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
from src.core.preflight import EntryGateFacade, PreflightContext, GatePolicy

logger = logging.getLogger(__name__)

# Phase 4: sys.pathハック削除（pip install -e . でインストール前提）


# ===== Commands Modules Import =====
from src.cli.messages import msg
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


FOCUS_TEST_GROUPS: dict[str, list[str]] = {
    "density": [
        "tests/core/engine/test_attack_planner_scope_filter.py",
        "tests/core/engine/test_master_conductor_scenario_probes.py",
        "tests/unit/agents/swarm/test_fuzzing.py",
    ],
    "report": [
        "tests/unit/reporting/test_report_session_consistency.py",
        "tests/unit/main/test_main_report_haddix.py",
    ],
    "hitl": [
        "tests/core/test_main_hitl_session_selection.py",
    ],
    "fast_mc_recon": [
        "tests/core/engine/test_master_conductor_api_candidate_routing.py",
        "tests/core/engine/test_master_conductor_vuln_family_gate.py",
        "tests/core/engine/test_master_conductor_realtime_budget.py",
        "tests/recon/test_tagged_uncategorized_promotion.py",
    ],
}

DEFAULT_QUALITY_LOOP_GROUPS: list[str] = ["density", "report"]
REPO_ROOT = Path(__file__).resolve().parents[1]


def _dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        deduped.append(token)
    return deduped


def _resolve_focus_test_paths(groups: list[str], custom_tests: list[str]) -> tuple[list[str], list[str]]:
    selected_groups = _dedupe_keep_order(groups)
    if not selected_groups and not custom_tests:
        selected_groups = ["density"]

    if "all" in selected_groups:
        selected_groups = list(FOCUS_TEST_GROUPS.keys())

    paths: list[str] = []
    for group in selected_groups:
        paths.extend(FOCUS_TEST_GROUPS.get(group, []))
    paths.extend(custom_tests)
    return selected_groups, _dedupe_keep_order(paths)


def _print_focus_test_groups() -> None:
    print("Focused test groups:")
    for group, tests in FOCUS_TEST_GROUPS.items():
        print(f"- {group} ({len(tests)} tests)")
        for test_path in tests:
            print(f"  - {test_path}")


def _resolve_focus_test_runtime_paths(selected_tests: list[str]) -> tuple[list[str], list[str], int]:
    """
    focused test path を runtime で解決する。

    - CWD で解決できる相対パスはそのまま使う
    - CWD で見つからない場合は repo root 基準で解決する
    """
    resolved_tests: list[str] = []
    missing_tests: list[str] = []
    repo_root_resolved_count = 0

    for raw_path in selected_tests:
        token = str(raw_path or "").strip()
        if not token:
            continue

        candidate = Path(token)
        if candidate.is_absolute():
            if candidate.exists():
                resolved_tests.append(str(candidate))
            else:
                missing_tests.append(token)
            continue

        cwd_candidate = Path.cwd() / candidate
        if cwd_candidate.exists():
            resolved_tests.append(token)
            continue

        repo_candidate = REPO_ROOT / candidate
        if repo_candidate.exists():
            resolved_tests.append(str(repo_candidate))
            repo_root_resolved_count += 1
            continue

        missing_tests.append(token)

    return _dedupe_keep_order(resolved_tests), missing_tests, repo_root_resolved_count


def _run_focused_tests(
    *,
    groups: list[str],
    custom_tests: list[str],
    fail_fast: bool = False,
    stage_label: str = "focused tests",
) -> tuple[int, list[str], list[str], list[str]]:
    """
    focused regression tests を実行して結果を返す。

    Returns:
        (exit_code, selected_groups, selected_tests, cmd)
    """
    selected_groups, selected_tests = _resolve_focus_test_paths(groups, custom_tests)
    if not selected_tests:
        print_result(False, msg("result.focus.no_tests"))
        return 2, selected_groups, selected_tests, []

    selected_tests, missing, repo_root_resolved_count = _resolve_focus_test_runtime_paths(selected_tests)
    if repo_root_resolved_count > 0:
        print_step(
            "📍",
            msg("result.focus.resolved_count", count=repo_root_resolved_count, root=str(REPO_ROOT)),
        )
    if missing:
        preview = ", ".join(missing[:3])
        suffix = " ..." if len(missing) > 3 else ""
        print_step("⚠️", msg("result.focus.skipping_missing", preview=preview, suffix=suffix))

    if not selected_tests:
        print_result(False, msg("result.focus.only_missing"))
        return 2, selected_groups, selected_tests, []

    cmd = [sys.executable or "python3", "-m", "pytest", "-q"]
    if fail_fast:
        cmd.append("-x")
    cmd.extend(selected_tests)

    selected_group_text = ", ".join(selected_groups) if selected_groups else "(custom only)"
    print_step("🧪", msg("result.focus.running", stage=stage_label, groups=selected_group_text, count=len(selected_tests)))
    result = subprocess.run(cmd, check=False)
    if result.returncode == 0:
        print_result(True, msg("result.focus.stage_passed", stage=stage_label))
    else:
        print_result(False, msg("result.focus.stage_failed", stage=stage_label, code=result.returncode))
    return int(result.returncode), selected_groups, selected_tests, cmd


def _build_quality_loop_scan_command(args: argparse.Namespace, *, short_mode: bool) -> list[str]:
    """quality-loop 用に scan 実行コマンドを構築する。"""
    cmd: list[str] = [sys.executable or "python3", "-m", "src.main", "--target", str(args.target)]

    if args.mode:
        cmd.extend(["--mode", str(args.mode)])
    if args.profile:
        cmd.extend(["--profile", str(args.profile)])
    if args.scope:
        cmd.extend(["--scope", str(args.scope)])
    if args.cookie:
        cmd.extend(["--cookie", str(args.cookie)])
    if args.bearer_token:
        cmd.extend(["--bearer-token", str(args.bearer_token)])
    if args.recipe:
        cmd.extend(["--recipe", str(args.recipe)])
    if args.live_dashboard:
        cmd.append("--live-dashboard")
    if args.dry_run:
        cmd.append("--dry-run")
    if args.debug:
        cmd.append("--debug")
    if args.intervention_gate_mode:
        cmd.extend(["--intervention-gate-mode", str(args.intervention_gate_mode)])

    if short_mode:
        start_step = int(args.recon_start_step) if args.recon_start_step is not None else 6
        end_step = int(args.recon_end_step) if args.recon_end_step is not None else 8
        cmd.extend(
            [
                "--skip-initial-recon",
                "--recon-start-step",
                str(start_step),
                "--recon-end-step",
                str(end_step),
            ]
        )
    else:
        if args.skip_initial_recon:
            cmd.append("--skip-initial-recon")
        if args.recon_start_step is not None:
            cmd.extend(["--recon-start-step", str(int(args.recon_start_step))])
        if args.recon_end_step is not None:
            cmd.extend(["--recon-end-step", str(int(args.recon_end_step))])

    return cmd


def _write_quality_loop_precheck_artifact(
    *,
    target: str,
    mode: str,
    selected_groups: list[str],
    selected_tests: list[str],
    focus_cmd: list[str],
    focus_exit_code: int,
) -> Path | None:
    """quality-loop の focused precheck 結果を reports 配下へ保存する。"""
    try:
        from src.core.project.project_manager import ProjectManager

        pm = ProjectManager(target)
        reports_dir = pm.get_reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        artifact_path = reports_dir / f"quality_loop_precheck_{timestamp}.json"
        payload = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "target": str(target),
            "quality_loop_mode": str(mode),
            "focus": {
                "selected_groups": selected_groups,
                "selected_tests": selected_tests,
                "command": focus_cmd,
                "exit_code": int(focus_exit_code),
            },
        }
        artifact_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return artifact_path
    except Exception as exc:
        logger.warning("Failed to write quality-loop precheck artifact: %s", exc)
        return None


def enable_debug_mode():
    """Enable debug logging with UI feedback."""
    try:
        from src.core.utils.debug_logger import enable_debug_mode as _enable
        _enable()
        print_step("🐛", msg("step.debug_enabled"))
    except ImportError as e:
        print_result(False, msg("result.debug_not_available", error=e))


def _extract_scn_number(scenario_id: str) -> int:
    sid = str(scenario_id or "").strip().lower().replace("-", "_")
    if not sid.startswith("scn_"):
        return 0
    tokens = sid.split("_")
    if len(tokens) < 2:
        return 0
    try:
        return int(tokens[1])
    except Exception:
        return 0


def _normalize_scenario_id_for_report(
    *,
    task: dict[str, Any],
    params: dict[str, Any],
    scenario_id: str,
    route: str,
) -> tuple[str, str, str | None]:
    sid = str(scenario_id or "").strip().lower().replace("-", "_")
    normalized_route = str(route or "").strip().lower()
    if sid.startswith("scn_"):
        return sid, normalized_route, None

    category = str(params.get("category", "") or "").strip().lower()
    alias_by_scenario: dict[str, str] = {
        "category_route:admin": "scn_01_idor_bola_object_access",
        "category_route:auth": "scn_07_token_trust_boundary",
        "category_route:jwt_detected": "scn_07_token_trust_boundary",
        "category_route:basket_order": "scn_09_multi_step_state_machine",
        "category_route:realtime": "scn_09_multi_step_state_machine",
        "category_route:csrf_candidate": "scn_09_multi_step_state_machine",
        "category_route:id_param": "scn_03_injection_input_tampering",
        "category_route:redirect_param": "scn_03_injection_input_tampering",
        "category_route:file_param": "scn_03_injection_input_tampering",
        "category_route:product_search": "scn_03_injection_input_tampering",
        "category_route:feedback_review": "scn_03_injection_input_tampering",
        "category_route:api_data": "scn_03_injection_input_tampering",
        "category_route:client_route_dom": "scn_03_injection_input_tampering",
        "category_route:api_candidate": "scn_03_injection_input_tampering",
        "category_route:api_endpoint": "scn_03_injection_input_tampering",
        "category_route:xss_candidate": "scn_03_injection_input_tampering",
        "category_route:file_exposure_upload": "scn_06_data_exposure_diff",
        "category_route:meta_observability": "scn_06_data_exposure_diff",
        "category_route:debug_info": "scn_06_data_exposure_diff",
    }
    alias_by_category: dict[str, str] = {
        "admin": "scn_01_idor_bola_object_access",
        "auth": "scn_07_token_trust_boundary",
        "jwt_detected": "scn_07_token_trust_boundary",
        "basket_order": "scn_09_multi_step_state_machine",
        "realtime": "scn_09_multi_step_state_machine",
        "csrf_candidate": "scn_09_multi_step_state_machine",
        "id_param": "scn_03_injection_input_tampering",
        "redirect_param": "scn_03_injection_input_tampering",
        "file_param": "scn_03_injection_input_tampering",
        "product_search": "scn_03_injection_input_tampering",
        "feedback_review": "scn_03_injection_input_tampering",
        "api_data": "scn_03_injection_input_tampering",
        "client_route_dom": "scn_03_injection_input_tampering",
        "api_candidate": "scn_03_injection_input_tampering",
        "api_endpoint": "scn_03_injection_input_tampering",
        "xss_candidate": "scn_03_injection_input_tampering",
        "file_exposure_upload": "scn_06_data_exposure_diff",
        "meta_observability": "scn_06_data_exposure_diff",
        "debug_info": "scn_06_data_exposure_diff",
    }
    if sid in alias_by_scenario:
        return alias_by_scenario[sid], normalized_route or "shigoku_hitl", "normalized_category_route"
    if category in alias_by_category:
        return alias_by_category[category], normalized_route or "shigoku_hitl", "normalized_category_alias"

    signal_chunks: list[str] = [
        str(task.get("name", "") or ""),
        str(task.get("action", "") or ""),
        str(task.get("agent_type", "") or ""),
        str(params.get("scenario", "") or ""),
        str(params.get("attack_type", "") or ""),
        str(params.get("description", "") or ""),
        category,
    ]
    tags = params.get("tags", [])
    if isinstance(tags, list):
        signal_chunks.extend(str(t or "") for t in tags)
    signal_text = " ".join(signal_chunks).lower()

    if any(
        marker in signal_text
        for marker in (
            "jwt",
            "alg:none",
            "algorithm confusion",
            "kid injection",
            "jwks",
            "token forgery",
            "token trust boundary",
        )
    ):
        return "scn_07_token_trust_boundary", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    if any(
        marker in signal_text
        for marker in (
            "state machine",
            "multi-step flow",
            "workflow abuse",
            "state transition",
            "precondition",
            "chaining",
            "basket",
            "order flow",
            "csrf",
        )
    ):
        return "scn_09_multi_step_state_machine", normalized_route or "shigoku_hitl", "normalized_signal_alias"

    if any(
        marker in signal_text
        for marker in (
            "sqli",
            "sql injection",
            "xss",
            "payload",
            "input tampering",
            "parameter tampering",
            "mass assignment",
            "overposting",
            "prototype pollution",
        )
    ):
        return "scn_03_injection_input_tampering", normalized_route or "shigoku_only", "normalized_signal_alias"

    if any(
        marker in signal_text
        for marker in (
            "data exposure",
            "sensitive field",
            "response diff",
            "schema diff",
            "debug info",
            "observability",
        )
    ):
        return "scn_06_data_exposure_diff", normalized_route or "shigoku_only", "normalized_signal_alias"

    return sid, normalized_route, None


def _resolve_scn_catalog_for_report() -> list[dict[str, Any]]:
    from src.core.engine.intervention_policy import InterventionPolicy

    fallback: tuple[tuple[str, str], ...] = (
        ("scn_01_idor_bola_object_access", "IDOR/BOLA Object Access"),
        ("scn_02_mass_assignment_object_update", "Mass Assignment Object Update"),
        ("scn_03_injection_input_tampering", "Injection Input Tampering"),
        ("scn_04_endpoint_enumeration_bfla", "Endpoint Enumeration / BFLA"),
        ("scn_05_rate_limit_resilience", "Rate Limit Resilience"),
        ("scn_06_data_exposure_diff", "Data Exposure / Response Diff"),
        ("scn_07_token_trust_boundary", "Token Trust Boundary"),
        ("scn_08_oob_external_channel_flow", "Out-of-Band External Channel"),
        ("scn_09_multi_step_state_machine", "Multi-step State Machine"),
        ("scn_10_semantic_business_logic", "Semantic Business Logic"),
        ("scn_11_multi_vector_chain", "Multi-Vector Chain"),
        ("scn_12_advanced_ssrf_internal_topology", "Advanced SSRF Internal Topology"),
    )
    catalog: list[dict[str, Any]] = []
    seen: set[str] = set()

    try:
        policy = InterventionPolicy(settings.get_intervention_scenarios())
        for scenario in getattr(policy, "scenarios", []):
            if not isinstance(scenario, dict):
                continue
            sid = str(scenario.get("id", "") or "").strip().lower().replace("-", "_")
            number = _extract_scn_number(sid)
            if number < 1 or number > 12 or sid in seen:
                continue
            catalog.append(
                {
                    "id": sid,
                    "number": number,
                    "title": str(scenario.get("title") or scenario.get("name") or sid).strip(),
                    "route": str(scenario.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
                }
            )
            seen.add(sid)
    except Exception:
        pass

    if not catalog:
        for sid, title in fallback:
            catalog.append(
                {
                    "id": sid,
                    "number": _extract_scn_number(sid),
                    "title": title,
                    "route": "shigoku_only",
                }
            )
        return catalog

    fallback_map = {sid: title for sid, title in fallback}
    by_number = {int(item["number"]): dict(item) for item in catalog}
    for sid, title in fallback:
        number = _extract_scn_number(sid)
        if number < 1 or number > 12:
            continue
        if number in by_number:
            if not str(by_number[number].get("title", "")).strip():
                by_number[number]["title"] = title
            continue
        by_number[number] = {
            "id": sid,
            "number": number,
            "title": title,
            "route": "shigoku_only",
        }

    normalized: list[dict[str, Any]] = []
    for number in sorted(by_number.keys()):
        item = dict(by_number[number])
        sid = str(item.get("id", "") or "").strip().lower().replace("-", "_")
        normalized.append(
            {
                "id": sid,
                "number": number,
                "title": str(item.get("title", "") or fallback_map.get(sid, sid)).strip(),
                "route": str(item.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
            }
        )
    return normalized


def _extract_findings_and_execution_notes(
    session_data: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract findings and execution notes from session completed_tasks.

    Shared between --format haddix and --format haddix-ja-en.
    """
    all_tasks = session_data.get("completed_tasks", [])
    findings: list[dict[str, Any]] = []
    execution_notes: list[dict[str, Any]] = []

    for task in all_tasks:
        task_result = task.get("result", {}) if isinstance(task, dict) else {}
        task_data = task_result.get("data", {}) if isinstance(task_result, dict) else {}

        task_findings = task_result.get("findings", []) if isinstance(task_result, dict) else []
        if not task_findings and isinstance(task_data, dict):
            task_findings = task_data.get("findings", [])

        if not task_findings and isinstance(task_data, dict):
            single_finding = task_data.get("finding")
            if single_finding:
                task_findings = [single_finding]

        if not task_findings and isinstance(task_result, dict):
            single_finding = task_result.get("finding")
            if single_finding:
                task_findings = [single_finding]

        if not task_findings and isinstance(task_result, dict) and "vulnerability" in task_result:
            task_findings = [task_result.get("vulnerability")]

        for f in task_findings:
            if f:
                findings.append(f)

        task_exec_log = task_data.get("execution_log", []) if isinstance(task_data, dict) else []
        if isinstance(task_exec_log, list):
            for log_entry in task_exec_log:
                if not isinstance(log_entry, dict):
                    continue
                url_results = log_entry.get("url_results", [])
                if not isinstance(url_results, list):
                    continue
                for item in url_results:
                    if not isinstance(item, dict):
                        continue
                    tested_params = item.get("tested_params", [])
                    blind_correlation = item.get("blind_correlation", {})
                    status = str(item.get("status", ""))
                    status_lower = status.lower()
                    retry_count = int(item.get("retry_count", 0) or 0)
                    duration_seconds = item.get("duration_seconds")
                    has_blind_evidence = bool(blind_correlation) and (
                        bool(blind_correlation.get("correlated"))
                        or bool((blind_correlation.get("time_based") or {}).get("confirmed"))
                        or bool((blind_correlation.get("oob") or {}).get("confirmed"))
                    )
                    should_keep_for_kpi = status_lower in {"completed", "cache_hit", "timeout", "error"}
                    if not tested_params and not has_blind_evidence and not should_keep_for_kpi and retry_count <= 0 and duration_seconds is None:
                        continue
                    execution_notes.append({
                        "url": item.get("url", ""),
                        "vuln_type": item.get("vuln_type", ""),
                        "status": status,
                        "duration_seconds": duration_seconds,
                        "retry_count": retry_count,
                        "tested_params": tested_params,
                        "probe_sent": item.get("probe_sent"),
                        "probe_skipped_reason": item.get("probe_skipped_reason", ""),
                        "poc_request": item.get("poc_request", ""),
                        "poc_response": item.get("poc_response", ""),
                        "blind_correlation": blind_correlation,
                    })

    if not findings:
        findings = session_data.get("findings", [])

    if not findings:
        partial_findings = session_data.get("partial_findings", [])
        if isinstance(partial_findings, list):
            findings = [f for f in partial_findings if f]

    return findings, execution_notes


def _build_scenario_coverage_for_report(session_data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(session_data, dict):
        return {}

    existing_coverage: dict[str, Any] | None = None
    existing = session_data.get("scenario_coverage")
    if not isinstance(existing, dict):
        context = session_data.get("context", {})
        if isinstance(context, dict):
            existing = context.get("scenario_coverage")
    if isinstance(existing, dict) and isinstance(existing.get("coverage_items"), list):
        existing_coverage = existing

    from types import SimpleNamespace
    from src.core.engine.intervention_policy import InterventionPolicy

    catalog = _resolve_scn_catalog_for_report()
    required = [str(item.get("id", "")).strip().lower() for item in catalog if str(item.get("id", "")).strip()]
    metadata = {
        str(item.get("id", "")).strip().lower(): {
            "number": int(item.get("number", 0) or 0),
            "title": str(item.get("title", "") or "").strip(),
            "route": str(item.get("route", "shigoku_only") or "shigoku_only").strip().lower(),
        }
        for item in catalog
        if str(item.get("id", "")).strip()
    }

    policy = InterventionPolicy(settings.get_intervention_scenarios())
    scenario_counts: dict[str, int] = {}
    route_counts: dict[str, int] = {}
    route_by_scenario: dict[str, str] = {}
    source_by_scenario: dict[str, str] = {}

    for task in session_data.get("completed_tasks", []):
        if not isinstance(task, dict):
            continue
        task_state = str(task.get("state", "") or "").strip().lower()
        if task_state == "skipped":
            # HITL待ちを含む未実行タスクはシナリオ到達扱いしない
            continue
        params = task.get("params", {})
        params = params if isinstance(params, dict) else {}
        intervention = params.get("_intervention", {})
        decision = intervention.get("decision", {}) if isinstance(intervention, dict) else {}

        scenario_id = str(decision.get("scenario_id", "") or "").strip().lower().replace("-", "_")
        route = str(decision.get("route", "") or "").strip().lower()
        source = "task_decision"

        if not scenario_id:
            scenario_id = str(params.get("scenario_id", "") or params.get("scenario_probe", "")).strip().lower().replace("-", "_")
            source = "task_params" if scenario_id else source

        if not scenario_id:
            inferred = policy.decide(
                SimpleNamespace(
                    name=task.get("name", ""),
                    action=task.get("action", ""),
                    agent_type=task.get("agent_type", ""),
                    target=task.get("target", ""),
                    tags=task.get("tags", []),
                    params=params,
                )
            )
            scenario_id = str(inferred.get("scenario_id", "") or "").strip().lower().replace("-", "_")
            route = str(inferred.get("route", route) or route).strip().lower()
            source = "inferred_by_policy" if scenario_id else source

        scenario_id, route, normalized_source = _normalize_scenario_id_for_report(
            task=task,
            params=params,
            scenario_id=scenario_id,
            route=route,
        )
        if normalized_source:
            source = normalized_source

        if not scenario_id.startswith("scn_"):
            continue

        scenario_counts[scenario_id] = scenario_counts.get(scenario_id, 0) + 1
        if route:
            route_counts[route] = route_counts.get(route, 0) + 1
            route_by_scenario.setdefault(scenario_id, route)
        source_by_scenario.setdefault(scenario_id, source)

    missing = [sid for sid in required if sid not in scenario_counts]
    covered_count = len([sid for sid in required if sid in scenario_counts])
    required_count = len(required)
    coverage_items: list[dict[str, Any]] = []
    for sid in required:
        meta = metadata.get(sid, {})
        coverage_items.append(
            {
                "scenario_id": sid,
                "number": int(meta.get("number", _extract_scn_number(sid)) or 0),
                "title": str(meta.get("title", sid) or sid),
                "route": str(route_by_scenario.get(sid, meta.get("route", "shigoku_only")) or "shigoku_only"),
                "covered": sid in scenario_counts,
                "count": int(scenario_counts.get(sid, 0)),
                "source": str(source_by_scenario.get(sid, "none") or "none"),
            }
        )

    computed = {
        "required_scenarios": required,
        "covered_scenarios": sorted(
            scenario_counts.keys(),
            key=lambda sid: (_extract_scn_number(sid), sid),
        ),
        "missing_scenarios": missing,
        "required_count": required_count,
        "covered_count": covered_count,
        "coverage_rate": (covered_count / required_count) if required_count > 0 else 1.0,
        "gate_passed": len(missing) == 0,
        "coverage_items": coverage_items,
        "route_counts": dict(sorted(route_counts.items())),
    }

    if isinstance(existing_coverage, dict):
        try:
            existing_count = int(existing_coverage.get("covered_count", 0) or 0)
        except Exception:
            existing_count = 0
        if existing_count > int(computed.get("covered_count", 0) or 0):
            return existing_coverage
    return computed


def _build_heuristic_findings_from_execution_notes(
    execution_notes: list[dict[str, Any]],
    *,
    target: str,
    scenario_coverage: dict[str, Any] | None = None,
    max_candidates: int = 6,
    promote_privilege_probe_min: int = 2,
    promote_completed_probe_min: int = 2,
) -> list[dict[str, Any]]:
    """
    report-only fallback:
    既存 findings が 0 件のとき、execution notes から「要検証候補」を合成する。
    """
    if not isinstance(execution_notes, list) or not execution_notes:
        return []
    try:
        promote_privilege_probe_min = max(1, int(promote_privilege_probe_min))
    except Exception:
        promote_privilege_probe_min = 2
    try:
        promote_completed_probe_min = max(1, int(promote_completed_probe_min))
    except Exception:
        promote_completed_probe_min = 2

    def _as_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return default

    def _extract_note_http_artifact(note: dict[str, Any], keys: list[str]) -> str:
        for key in keys:
            token = str(note.get(key, "") or "").strip()
            if token:
                return token
        return ""

    def _infer_heuristic_detection_class(url: str, vuln_type: str) -> str:
        from urllib.parse import urlsplit

        path = urlsplit(str(url or "")).path.lower()
        normalized_vuln_type = str(vuln_type or "").strip().lower()
        if normalized_vuln_type == "mass_assignment":
            return "mass_assignment"
        if normalized_vuln_type == "api":
            return "endpoint_bfla"
        if normalized_vuln_type == "broken_access_control":
            return "access_control"
        if normalized_vuln_type == "unknown" and (
            "/api/" in path or "/rest/" in path or "graphql" in path
        ):
            return "endpoint_bfla"
        return ""

    normalized_target = str(target or "").strip()
    missing_scenarios = set()
    if isinstance(scenario_coverage, dict):
        raw_missing = scenario_coverage.get("missing_scenarios", [])
        if isinstance(raw_missing, list):
            missing_scenarios = {
                str(item or "").strip().lower()
                for item in raw_missing
                if str(item or "").strip()
            }

    candidates: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    repeat_signal_stats: dict[tuple[str, str], dict[str, set[str]]] = {}

    def _repeat_signal_key(note: dict[str, Any], tested_params: list[str], status: str, probe_sent: bool) -> str:
        task_id = str(note.get("task_id", "") or "").strip()
        if task_id:
            return f"task:{task_id}"
        params_norm = ",".join(sorted({str(param or "").strip().lower() for param in tested_params if str(param or "").strip()}))
        duration_norm = f"{_as_float(note.get('duration_seconds'), 0.0):.6f}"
        return f"status:{status}|probe:{1 if probe_sent else 0}|params:{params_norm}|duration:{duration_norm}"

    for note in execution_notes:
        if not isinstance(note, dict):
            continue
        url = str(note.get("url", "") or "").strip()
        if not url:
            continue
        vuln_type = str(note.get("vuln_type", "unknown") or "unknown").strip().lower() or "unknown"
        tested_params_raw = note.get("tested_params", [])
        tested_params: list[str] = []
        if isinstance(tested_params_raw, str):
            token = tested_params_raw.strip()
            if token:
                tested_params = [token]
        elif isinstance(tested_params_raw, list):
            tested_params = [str(p).strip() for p in tested_params_raw if str(p).strip()]
        lower_params = {param.lower() for param in tested_params}
        privilege_sensitive_params = {"role", "is_admin", "admin", "permission", "scope"}
        has_privilege_sensitive_param = bool(lower_params.intersection(privilege_sensitive_params))

        key = (url, vuln_type)
        stats = repeat_signal_stats.setdefault(
            key,
            {
                "total": set(),
                "completed_with_probe": set(),
                "privilege_probe": set(),
            },
        )
        status = str(note.get("status", "") or "").strip().lower()
        probe_sent = bool(note.get("probe_sent"))
        signal_token = _repeat_signal_key(note, tested_params, status, probe_sent)
        stats["total"].add(signal_token)
        if status == "completed" and probe_sent:
            stats["completed_with_probe"].add(signal_token)
        if has_privilege_sensitive_param and status == "completed" and probe_sent:
            stats["privilege_probe"].add(signal_token)

    for note in execution_notes:
        if not isinstance(note, dict):
            continue
        url = str(note.get("url", "") or "").strip()
        if not url:
            continue

        vuln_type = str(note.get("vuln_type", "unknown") or "unknown").strip().lower()
        if not vuln_type:
            vuln_type = "unknown"
        status = str(note.get("status", "") or "").strip().lower()
        duration_seconds = _as_float(note.get("duration_seconds"), 0.0)
        tested_params_raw = note.get("tested_params", [])
        tested_params = []
        if isinstance(tested_params_raw, str):
            token = tested_params_raw.strip()
            if token:
                tested_params = [token]
        elif isinstance(tested_params_raw, list):
            tested_params = [str(p).strip() for p in tested_params_raw if str(p).strip()]

        blind_correlation = note.get("blind_correlation", {})
        blind_correlation = blind_correlation if isinstance(blind_correlation, dict) else {}
        time_based = blind_correlation.get("time_based", {}) if isinstance(blind_correlation.get("time_based"), dict) else {}
        oob = blind_correlation.get("oob", {}) if isinstance(blind_correlation.get("oob"), dict) else {}
        blind_confirmed = bool(blind_correlation.get("correlated")) or bool(time_based.get("confirmed")) or bool(oob.get("confirmed"))
        note_poc_request = _extract_note_http_artifact(
            note,
            ["poc_request", "request", "raw_request", "request_raw"],
        )
        note_poc_response = _extract_note_http_artifact(
            note,
            ["poc_response", "response", "raw_response", "response_raw"],
        )

        confidence = 0.0
        reasons: list[str] = []
        if tested_params:
            confidence += 0.45
            reasons.append("tested_params")
        if blind_confirmed:
            confidence += 0.45
            reasons.append("blind_confirmation")
        if status in {"timeout", "error"}:
            confidence += 0.25
            reasons.append(f"status_{status}")
        if duration_seconds >= 20.0:
            confidence += 0.15
            reasons.append("long_duration")
        if duration_seconds >= 35.0:
            confidence += 0.10
            reasons.append("very_long_duration")
        if vuln_type == "unknown":
            confidence += 0.20
            reasons.append("unknown_path")

        lower_params = {param.lower() for param in tested_params}
        privilege_sensitive_params = {"role", "is_admin", "admin", "permission", "scope"}
        has_privilege_sensitive_param = bool(lower_params.intersection(privilege_sensitive_params))
        if vuln_type == "api" and has_privilege_sensitive_param:
            confidence += 0.20
            reasons.append("privilege_sensitive_param")

        confidence = min(0.95, round(confidence, 2))
        if confidence < 0.50 and not tested_params and not blind_confirmed:
            continue

        severity = "info"
        if blind_confirmed or "privilege_sensitive_param" in reasons:
            severity = "medium"
        elif confidence >= 0.70:
            severity = "low"

        signal_key = (url, "api")
        signal_stats = repeat_signal_stats.get(signal_key, {})
        privilege_probe_count = len(signal_stats.get("privilege_probe", set()))
        completed_probe_count = len(signal_stats.get("completed_with_probe", set()))
        total_signal_count = len(signal_stats.get("total", set()))
        repeated_privilege_probe = (
            privilege_probe_count >= promote_privilege_probe_min
            and completed_probe_count >= promote_completed_probe_min
        )

        if "privilege_sensitive_param" in reasons:
            title = "Potential privilege parameter tampering surface"
            vuln_type = "mass_assignment"
        elif vuln_type == "unknown":
            title = "Potential high-friction unknown attack surface"
        else:
            title = f"Potential {vuln_type.upper()} attack surface"

        scenario_hints: list[str] = []
        ssrf_like_params = {
            "url",
            "uri",
            "target",
            "dest",
            "destination",
            "callback",
            "webhook",
            "redirect",
            "next",
            "return",
            "endpoint",
            "host",
        }
        has_ssrf_like_params = bool(lower_params.intersection(ssrf_like_params))

        if vuln_type in {"api", "unknown", "mass_assignment"} and "scn_11_multi_vector_chain" in missing_scenarios:
            scenario_hints.append("scn_11_multi_vector_chain")
        should_hint_scn12 = (
            vuln_type in {"redirect", "cmd_ssrf"}
            or (
                vuln_type in {"api", "unknown"}
                and has_ssrf_like_params
                and not has_privilege_sensitive_param
            )
        )
        if should_hint_scn12 and "scn_12_advanced_ssrf_internal_topology" in missing_scenarios:
            scenario_hints.append("scn_12_advanced_ssrf_internal_topology")

        key = (url, vuln_type, title)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        if repeated_privilege_probe and "privilege_sensitive_param" in reasons:
            summary_intro = "Auto-verified heuristic signal from repeated successful privilege-parameter probes."
        else:
            summary_intro = "Heuristic candidate generated from execution telemetry; manual verification required."

        summary_parts = [
            summary_intro,
            f"status={status or '-'}",
            f"duration={duration_seconds:.3f}s" if duration_seconds > 0 else "duration=-",
        ]
        if tested_params:
            summary_parts.append(f"tested_params={', '.join(tested_params)}")
        if blind_confirmed:
            summary_parts.append("blind=confirmed")
        if scenario_hints:
            summary_parts.append(f"scenario_hint={', '.join(scenario_hints)}")

        heuristic_candidate = not (repeated_privilege_probe and "privilege_sensitive_param" in reasons)
        detection_mode = "heuristic_promoted" if not heuristic_candidate else "heuristic_fallback"
        detection_class = _infer_heuristic_detection_class(url, vuln_type)
        if heuristic_candidate:
            impact_text = "Potential security impact exists, but this item is not yet confirmed as a valid reportable vulnerability."
        else:
            impact_text = "Repeated successful privilege-parameter probes indicate elevated privilege-tampering risk and this item is promoted for remediation priority."
        candidates.append(
            {
                "title": title,
                "severity": severity,
                "vuln_type": vuln_type,
                "target_url": url,
                "summary": " | ".join(summary_parts),
                "impact": impact_text,
                "confidence": confidence,
                "poc_request": note_poc_request,
                "poc_response": note_poc_response,
                "steps_to_reproduce": [
                    "同じURL・同じ認証状態で再送し、レスポンス差分を記録する。",
                    "対象パラメータを1つずつ改ざんし、権限/状態変化の有無を比較する。",
                    "差分が再現した場合のみ、PoCを確定して正式findingへ昇格する。",
                ],
                "references": [
                    "OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/",
                ],
                "additional_info": {
                    "heuristic_candidate": heuristic_candidate,
                    "verification_required": heuristic_candidate,
                    "heuristic_source": "report_execution_notes",
                    "heuristic_reasons": reasons,
                    "detection_mode": detection_mode,
                    "detection_class": detection_class,
                    "tested_params": tested_params,
                    "blind_correlation": blind_correlation,
                    "status": status,
                    "duration_seconds": duration_seconds,
                    "poc_request": note_poc_request,
                    "poc_response": note_poc_response,
                    "scenario_hints": scenario_hints,
                    "repeat_signal": {
                        "total": int(total_signal_count),
                        "completed_with_probe": int(completed_probe_count),
                        "privilege_probe": int(privilege_probe_count),
                        "privilege_probe_min": int(promote_privilege_probe_min),
                        "completed_with_probe_min": int(promote_completed_probe_min),
                    },
                },
            }
        )

    candidates.sort(key=lambda item: float(item.get("confidence", 0.0) or 0.0), reverse=True)
    if max_candidates > 0:
        candidates = candidates[:max_candidates]

    if not candidates:
        return []

    for item in candidates:
        if not str(item.get("target_url", "") or "").strip():
            item["target_url"] = normalized_target
    return candidates


def _finding_signature_for_merge(entry: Any) -> tuple[str, str, str] | None:
    if not isinstance(entry, dict):
        return None
    target = str(entry.get("target_url", entry.get("target", entry.get("url", ""))) or "").strip().lower()
    vuln_type = str(entry.get("vuln_type", entry.get("type", "")) or "").strip().lower()
    title = str(entry.get("title", "") or "").strip().lower()
    if not target and not vuln_type and not title:
        return None
    return (target, vuln_type, title)


def _merge_heuristic_candidates_into_findings(
    *,
    confirmed_findings: list[Any],
    heuristic_candidates: list[dict[str, Any]],
    max_append: int = 3,
) -> list[Any]:
    """
    confirmed findings を維持したまま、重複しない heuristic candidate を追記する。
    """
    merged: list[Any] = list(confirmed_findings or [])
    if not isinstance(heuristic_candidates, list) or not heuristic_candidates:
        return merged

    seen_signatures: set[tuple[str, str, str]] = set()
    confirmed_targets: set[str] = set()
    confirmed_target_vuln_pairs: set[tuple[str, str]] = set()
    for entry in merged:
        signature = _finding_signature_for_merge(entry)
        if signature is not None:
            seen_signatures.add(signature)
        if isinstance(entry, dict):
            entry_target = str(entry.get("target_url", entry.get("target", entry.get("url", ""))) or "").strip().lower()
            if entry_target:
                confirmed_targets.add(entry_target)
                entry_vuln_type = str(entry.get("vuln_type", entry.get("type", "")) or "").strip().lower()
                if entry_vuln_type:
                    confirmed_target_vuln_pairs.add((entry_target, entry_vuln_type))

    appended = 0
    append_limit = int(max_append)
    for candidate in heuristic_candidates:
        if not isinstance(candidate, dict):
            continue
        if append_limit >= 0 and appended >= append_limit:
            break
        signature = _finding_signature_for_merge(candidate)
        if signature is not None and signature in seen_signatures:
            continue
        candidate_target = str(candidate.get("target_url", candidate.get("target", candidate.get("url", ""))) or "").strip().lower()
        candidate_vuln_type = str(candidate.get("vuln_type", candidate.get("type", "")) or "").strip().lower()
        candidate_info = candidate.get("additional_info", {})
        candidate_info = candidate_info if isinstance(candidate_info, dict) else {}
        candidate_detection_mode = str(candidate_info.get("detection_mode", "") or "").strip().lower()
        candidate_is_promoted = (
            candidate_detection_mode == "heuristic_promoted"
            and not bool(candidate_info.get("heuristic_candidate"))
        )
        if candidate_target and candidate_target in confirmed_targets:
            if not candidate_is_promoted:
                continue
            if candidate_vuln_type and (candidate_target, candidate_vuln_type) in confirmed_target_vuln_pairs:
                continue
        if signature is not None:
            seen_signatures.add(signature)
        merged.append(candidate)
        if candidate_target:
            confirmed_targets.add(candidate_target)
            if candidate_vuln_type:
                confirmed_target_vuln_pairs.add((candidate_target, candidate_vuln_type))
        appended += 1
    return merged


def _coerce_finding_dict(entry: Any) -> dict[str, Any] | None:
    if isinstance(entry, dict):
        return dict(entry)
    to_dict = getattr(entry, "to_dict", None)
    if callable(to_dict):
        try:
            payload = to_dict()
            if isinstance(payload, dict):
                return payload
        except Exception:
            return None
    return None


def _first_non_empty_string(values: list[Any]) -> str:
    for value in values:
        token = str(value or "").strip()
        if token:
            return token
    return ""


def _clip_http_text(raw: Any, *, limit: int = 1200) -> str:
    text = str(raw or "")
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n...[truncated]"


def _synthesize_request_raw_from_evidence(
    *,
    evidence_obj: dict[str, Any],
    target_url: str,
) -> str:
    method = str(
        _first_non_empty_string(
            [
                evidence_obj.get("request_method"),
                evidence_obj.get("method"),
                "GET",
            ]
        )
    ).upper()
    request_url = _first_non_empty_string(
        [
            evidence_obj.get("request_url"),
            evidence_obj.get("url"),
            target_url,
        ]
    )
    if not request_url:
        return ""

    lines = [f"{method} {request_url} HTTP/1.1"]
    request_headers = evidence_obj.get("request_headers")
    if isinstance(request_headers, dict):
        header_count = 0
        for key, value in request_headers.items():
            h_key = str(key or "").strip()
            h_value = str(value or "").strip()
            if not h_key or not h_value:
                continue
            lines.append(f"{h_key}: {h_value}")
            header_count += 1
            if header_count >= 12:
                break

    request_body = evidence_obj.get("request_body")
    if isinstance(request_body, (dict, list)):
        body = json.dumps(request_body, ensure_ascii=False)
    else:
        body = str(request_body or "")
    body = _clip_http_text(body, limit=1000).strip()
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines).strip()


def _synthesize_response_raw_from_evidence(*, evidence_obj: dict[str, Any]) -> str:
    response_status = 0
    try:
        response_status = int(evidence_obj.get("response_status", 0) or 0)
    except Exception:
        response_status = 0

    lines = [f"HTTP/1.1 {response_status}"]
    response_headers = evidence_obj.get("response_headers")
    if isinstance(response_headers, dict):
        header_count = 0
        for key, value in response_headers.items():
            h_key = str(key or "").strip()
            h_value = str(value or "").strip()
            if not h_key or not h_value:
                continue
            lines.append(f"{h_key}: {h_value}")
            header_count += 1
            if header_count >= 12:
                break

    response_body = evidence_obj.get("response_body")
    if isinstance(response_body, (dict, list)):
        body = json.dumps(response_body, ensure_ascii=False)
    else:
        body = str(response_body or "")
    body = _clip_http_text(body, limit=1000).strip()
    if body:
        lines.append("")
        lines.append(body)
    return "\n".join(lines).strip()


def _build_replay_command_for_finding(
    *,
    target_url: str,
    request_raw: str,
    request_headers: dict[str, Any] | None = None,
    request_body: str = "",
) -> str:
    method = "GET"
    replay_url = str(target_url or "").strip()

    first_line = str(request_raw or "").splitlines()[0].strip() if str(request_raw or "").strip() else ""
    if first_line:
        parts = first_line.split()
        if len(parts) >= 2:
            if str(parts[0]).isalpha():
                method = str(parts[0]).upper()
            candidate = str(parts[1]).strip()
            if candidate.startswith("http://") or candidate.startswith("https://"):
                replay_url = candidate
            elif candidate.startswith("/") and replay_url:
                from urllib.parse import urlsplit, urlunsplit

                split = urlsplit(replay_url)
                if split.scheme and split.netloc:
                    replay_url = urlunsplit((split.scheme, split.netloc, candidate, "", ""))

    if not replay_url:
        return ""

    cmd_parts = ["curl", "-i", "-X", method, shlex.quote(replay_url)]
    if isinstance(request_headers, dict):
        header_count = 0
        for key, value in request_headers.items():
            h_key = str(key or "").strip()
            h_value = str(value or "").strip()
            if not h_key or not h_value:
                continue
            cmd_parts.extend(["-H", shlex.quote(f"{h_key}: {h_value}")])
            header_count += 1
            if header_count >= 5:
                break
    body = str(request_body or "").strip()
    if body:
        cmd_parts.extend(["--data-raw", shlex.quote(body)])
    return " ".join(cmd_parts)


def _build_detector_signals(additional_info: dict[str, Any]) -> list[str]:
    if not isinstance(additional_info, dict):
        return []

    signals: list[str] = []
    authz = additional_info.get("authz_differential", {})
    if isinstance(authz, dict):
        raw_signals = authz.get("signals", [])
        if isinstance(raw_signals, list):
            for signal in raw_signals:
                token = str(signal or "").strip()
                if token:
                    signals.append(token)
        scenario = str(authz.get("scenario", "") or "").strip()
        if scenario:
            signals.append(f"authz_scenario:{scenario}")

    heuristic_reasons = additional_info.get("heuristic_reasons", [])
    if isinstance(heuristic_reasons, list):
        for reason in heuristic_reasons:
            token = str(reason or "").strip()
            if token:
                signals.append(f"heuristic:{token}")

    repeat_signal = additional_info.get("repeat_signal", {})
    if isinstance(repeat_signal, dict):
        for key in ("total", "completed_with_probe", "privilege_probe"):
            if key in repeat_signal:
                signals.append(f"repeat:{key}={repeat_signal.get(key)}")

    probe_skip = str(additional_info.get("probe_skipped_reason", "") or "").strip()
    if probe_skip:
        signals.append(f"probe_skip:{probe_skip}")

    return _dedupe_keep_order(signals)


def _materialize_haddix_evidence_artifacts(
    *,
    findings: list[Any],
    evidence_dir: Path,
    captured_at: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    normalized_findings: list[dict[str, Any]] = []
    artifact_paths: list[str] = []
    if not isinstance(findings, list) or not findings:
        return normalized_findings, artifact_paths

    for entry in findings:
        normalized = _coerce_finding_dict(entry)
        if normalized is None:
            continue
        normalized_findings.append(normalized)

    if not normalized_findings:
        return normalized_findings, artifact_paths

    evidence_dir.mkdir(parents=True, exist_ok=True)

    for index, finding in enumerate(normalized_findings, 1):
        additional_info = finding.get("additional_info", {})
        if not isinstance(additional_info, dict):
            additional_info = {}
        finding["additional_info"] = additional_info

        evidence_obj = finding.get("evidence", {})
        if not isinstance(evidence_obj, dict):
            evidence_obj = {}

        request_raw = _first_non_empty_string(
            [
                finding.get("poc_request"),
                finding.get("request"),
                finding.get("raw_request"),
                additional_info.get("poc_request"),
                additional_info.get("request"),
                additional_info.get("request_raw"),
                additional_info.get("raw_request"),
                evidence_obj.get("request"),
                evidence_obj.get("request_raw"),
                evidence_obj.get("raw_request"),
            ]
        )
        response_raw = _first_non_empty_string(
            [
                finding.get("poc_response"),
                finding.get("response"),
                finding.get("raw_response"),
                additional_info.get("poc_response"),
                additional_info.get("response"),
                additional_info.get("response_raw"),
                additional_info.get("raw_response"),
                evidence_obj.get("response"),
                evidence_obj.get("response_raw"),
                evidence_obj.get("raw_response"),
            ]
        )

        if not request_raw:
            request_raw = _synthesize_request_raw_from_evidence(
                evidence_obj=evidence_obj,
                target_url=str(
                    finding.get("target_url", finding.get("target", finding.get("url", ""))) or ""
                ).strip(),
            )
        if not response_raw:
            response_raw = _synthesize_response_raw_from_evidence(evidence_obj=evidence_obj)

        if not str(finding.get("poc_request", "") or "").strip() and request_raw:
            finding["poc_request"] = request_raw
        if not str(finding.get("poc_response", "") or "").strip() and response_raw:
            finding["poc_response"] = response_raw

        target_url = str(
            finding.get("target_url", finding.get("target", finding.get("url", ""))) or ""
        ).strip()
        replay_command = _build_replay_command_for_finding(
            target_url=target_url,
            request_raw=request_raw,
            request_headers=evidence_obj.get("request_headers") if isinstance(evidence_obj, dict) else None,
            request_body=str(evidence_obj.get("request_body", "") or "") if isinstance(evidence_obj, dict) else "",
        )

        vuln_token = re.sub(r"[^A-Z0-9_]+", "_", str(finding.get("vuln_type", "unknown") or "unknown").upper())
        vuln_token = vuln_token.strip("_") or "UNKNOWN"
        artifact_path = evidence_dir / f"EV-{index:03d}-{vuln_token}.json"
        detector_verdict = {
            "detection_mode": str(additional_info.get("detection_mode", "") or "").strip() or "-",
            "heuristic_candidate": bool(additional_info.get("heuristic_candidate", False)),
            "verification_required": bool(additional_info.get("verification_required", False)),
            "authz_differential": additional_info.get("authz_differential", {})
            if isinstance(additional_info.get("authz_differential"), dict)
            else {},
            "blind_correlation": additional_info.get("blind_correlation", {})
            if isinstance(additional_info.get("blind_correlation"), dict)
            else {},
        }
        key_signals = _build_detector_signals(additional_info)

        artifact_payload = {
            "captured_at": captured_at,
            "finding_index": index,
            "title": str(finding.get("title", "") or ""),
            "vuln_type": str(finding.get("vuln_type", finding.get("type", "")) or ""),
            "severity": str(finding.get("severity", "") or ""),
            "target_url": target_url,
            "raw_request": request_raw,
            "raw_response": response_raw,
            "replay_command": replay_command,
            "detector_verdict": detector_verdict,
            "key_signals": key_signals,
        }
        artifact_path.write_text(
            json.dumps(artifact_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        artifact_paths.append(str(artifact_path.resolve()))

        capture_status = "missing"
        if request_raw and response_raw:
            capture_status = "full"
        elif request_raw or response_raw:
            capture_status = "partial"

        additional_info["evidence_artifact_path"] = str(artifact_path.resolve())
        additional_info["replay_command"] = replay_command
        additional_info["evidence_capture_status"] = capture_status

    return normalized_findings, artifact_paths


def _extract_hitl_tickets_from_session_data(session_data: dict[str, Any]) -> list[dict[str, Any]]:
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


def _select_hitl_session(
    parsed_sessions: list[tuple[Path, dict[str, Any]]],
    requested_ticket_ids: set[str] | None = None,
) -> tuple[Path | None, str]:
    actionable_statuses = {"pending", "approved", "queued"}
    requested_ids = {str(tid or "").strip() for tid in (requested_ticket_ids or set()) if str(tid or "").strip()}
    latest_status_by_ticket: dict[str, str] = {}

    # セッションは新しい順で渡される前提。ticketごとの最新状態を先に確定する。
    for _, data in parsed_sessions:
        for ticket in _extract_hitl_tickets_from_session_data(data):
            ticket_id = str(ticket.get("ticket_id", "") or "").strip()
            if not ticket_id or ticket_id in latest_status_by_ticket:
                continue
            latest_status_by_ticket[ticket_id] = str(ticket.get("status", "pending") or "pending").strip().lower()

    # ticket_id が指定されている場合は、その ticket を含むセッションを最優先で選ぶ。
    if requested_ids:
        for s_file, data in parsed_sessions:
            tickets = _extract_hitl_tickets_from_session_data(data)
            session_ticket_ids = {
                str(ticket.get("ticket_id", "") or "").strip()
                for ticket in tickets
                if str(ticket.get("ticket_id", "") or "").strip()
            }
            if session_ticket_ids.intersection(requested_ids):
                return s_file, "session containing specified HITL ticket(s)"

    # actionable ticket を含む最新セッションを優先。
    for s_file, data in parsed_sessions:
        tickets = _extract_hitl_tickets_from_session_data(data)
        for ticket in tickets:
            ticket_id = str(ticket.get("ticket_id", "") or "").strip()
            status = str(ticket.get("status", "pending") or "pending").strip().lower()
            if not ticket_id or status not in actionable_statuses:
                continue
            if latest_status_by_ticket.get(ticket_id, status) in actionable_statuses:
                return s_file, "latest session with actionable HITL tickets"

    # actionable が無い場合は、HITL履歴がある最新セッションを選ぶ。
    for s_file, data in parsed_sessions:
        if _extract_hitl_tickets_from_session_data(data):
            return s_file, "latest session with HITL ticket history"

    # 最後に通常の有効セッションへフォールバック。
    for s_file, data in parsed_sessions:
        completed = data.get("completed_tasks")
        queued = data.get("task_queue")
        if isinstance(completed, list) or isinstance(queued, list):
            return s_file, "latest valid session"

    return None, ""


def _session_order_key(path: Path) -> tuple[int, float]:
    """
    セッション名 `session_YYYYMMDD_HHMMSS.json` の時系列を優先し、
    取得できない場合のみ mtime を補助キーとして使う。
    """
    name = path.name
    match = re.match(r"^session_(\d{8})_(\d{6})\.json$", name)
    seq = int(f"{match.group(1)}{match.group(2)}") if match else -1
    try:
        mtime = float(path.stat().st_mtime)
    except Exception:
        mtime = 0.0
    return (seq, mtime)


def _report_artifact_order_key(path: Path, prefix: str) -> tuple[int, float]:
    """
    レポート成果物 `prefix_YYYYMMDD_HHMMSS.json` の時系列を優先し、
    取得できない場合のみ mtime を補助キーとして使う。
    """
    name = path.name
    match = re.match(rf"^{re.escape(prefix)}_(\d{{8}})_(\d{{6}})\.json$", name)
    seq = int(f"{match.group(1)}{match.group(2)}") if match else -1
    try:
        mtime = float(path.stat().st_mtime)
    except Exception:
        mtime = 0.0
    return (seq, mtime)


def _select_latest_deferred_backlog_file(reports_dir: Path) -> Path | None:
    if not reports_dir.exists():
        return None
    deferred_files = sorted(
        list(reports_dir.glob("haddix_deferred_*.json")),
        key=lambda p: _report_artifact_order_key(p, "haddix_deferred"),
        reverse=True,
    )
    return deferred_files[0] if deferred_files else None


def _extract_deferred_scenarios_from_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    scenarios = payload.get("deferred_scenarios", [])
    if not isinstance(scenarios, list):
        return []
    return [item for item in scenarios if isinstance(item, dict)]


def _normalize_deferred_status(value: Any) -> str:
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


def _summarize_deferred_statuses(scenarios: list[dict[str, Any]]) -> dict[str, int]:
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
        status = _normalize_deferred_status(item.get("status"))
        if status not in summary:
            status = "pending"
        summary[status] += 1
        summary["total"] += 1
    return summary


def _resolve_deferred_scenarios(
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


def _default_deferred_checklist_output_path(deferred_file: Path) -> Path:
    match = re.match(r"^haddix_deferred_(\d{8}_\d{6})\.json$", deferred_file.name)
    suffix = match.group(1) if match else datetime.now().strftime("%Y%m%d_%H%M%S")
    return deferred_file.parent / f"haddix_deferred_checklist_{suffix}.md"


def _build_deferred_checklist_markdown(
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


# ===== Preflight Entry Gate =====

def _parse_cookie_string(cookie_str: str) -> dict[str, str]:
    """Parse a cookie string like 'a=1; b=2' into a dict."""
    if not cookie_str:
        return {}
    cookies: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                cookies[key] = value
    return cookies


def _normalize_target_for_preflight(target: str) -> str:
    """Ensure target has a scheme for preflight checks."""
    if not target:
        return ""
    if "://" not in target:
        return f"https://{target}"
    return target


def _derive_goal_for_preflight(args: argparse.Namespace) -> str:
    """Derive execution goal from CLI action for tool/auth matrix checks."""
    if getattr(args, "recon", None) or getattr(args, "target", None):
        return "recon"
    if getattr(args, "crawl", None):
        return "crawl"
    if getattr(args, "analyze", None):
        return "analyze"
    if getattr(args, "log", None):
        return "hybridhunt"
    if getattr(args, "interactive", None):
        return "interactive"
    if getattr(args, "attack", None):
        return "attack"
    if getattr(args, "auto_goal", None):
        return str(getattr(args, "auto_goal"))
    return "recon"


async def _run_entry_gate(
    *,
    target: str = "",
    mode: str = "bugbounty",
    goal: str = "bugbounty",
    profile: str = "",
    cookies: str = "",
    bearer_token: str = "",
    auth_headers: dict[str, str] | None = None,
    resume_session_id: str = "",
    debug: bool = False,
) -> None:
    """Run the preflight entry gate and exit on failure."""
    normalized_target = _normalize_target_for_preflight(target)
    context = PreflightContext(
        target=normalized_target,
        mode=mode,
        goal=goal,
        profile=profile,
        cookies=_parse_cookie_string(cookies),
        bearer_token=bearer_token or "",
        auth_headers=auth_headers or {},
        resume_session_id=resume_session_id,
        gate_policy=GatePolicy.STRICT_DEV if debug else GatePolicy.STRICT_PROD,
        caido_url=_caido_url_from_settings(),
        caido_token=_caido_token_from_settings(),
    )
    result = await EntryGateFacade().run_once(context)
    if result.failed:
        for failure in result.failures:
            print(f"[GATE] {failure.reason_code}: {failure.remediation}")
        print("Preflight entry gate failed — aborting execution.")
        sys.exit(1)


def _caido_url_from_settings() -> str:
    """Extract caido.url from settings safely."""
    try:
        return getattr(settings, "caido", None).url  # type: ignore[union-attr]
    except Exception:
        return "http://127.0.0.1:8080"


def _caido_token_from_settings() -> str:
    """Extract caido.token from settings safely."""
    try:
        return getattr(settings, "caido", None).token  # type: ignore[union-attr]
    except Exception:
        return ""


# ===== Main Entry Point =====

def main():
    parser = argparse.ArgumentParser(
        prog="shigoku",
        description=msg("argparse.description"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=msg("argparse.epilog"),
    )
    
    parser.add_argument(
        "--log", "-l",
        metavar="FILE",
        help=msg("argparse.log.help")
    )

    parser.add_argument(
        "--sessions-file",
        metavar="FILE",
        help=msg("argparse.sessions_file.help")
    )

    parser.add_argument(
        "--cross-test-approved",
        action="store_true",
        help=msg("argparse.cross_test_approved.help")
    )
    
    parser.add_argument(
        "--scope", "-s",
        metavar="FILE",
        help=msg("argparse.scope.help")
    )
    
    parser.add_argument(
        "--watch", "-w",
        metavar="REPO",
        help=msg("argparse.watch.help")
    )
    
    parser.add_argument(
        "--demo", "-d",
        action="store_true",
        help=msg("argparse.demo.help")
    )
    
    parser.add_argument(
        "--recon", "-r",
        metavar="URL",
        help=msg("argparse.recon.help")
    )
    
    parser.add_argument(
        "--mode", "-m",
        metavar="MODE",
        choices=["bugbounty", "vulntest", "ctf"],
        help=msg("argparse.mode.help")
    )

    parser.add_argument(
        "--profile",
        metavar="PROFILE",
        choices=["bbpt", "ctf"],
        help=msg("argparse.profile.help")
    )

    parser.add_argument(
        "--target", "-t",
        metavar="URL",
        help=msg("argparse.target.help")
    )

    parser.add_argument(
        "--skip-initial-recon",
        action="store_true",
        help=msg("argparse.skip_initial_recon.help")
    )

    parser.add_argument(
        "--recon-start-step",
        type=int,
        metavar="N",
        help=msg("argparse.recon_start_step.help")
    )

    parser.add_argument(
        "--recon-end-step",
        type=int,
        metavar="N",
        help=msg("argparse.recon_end_step.help")
    )

    parser.add_argument(
        "--recon-resume",
        action="store_true",
        help=msg("argparse.recon_resume.help"),
    )

    parser.add_argument(
        "--fast-iterate",
        action="store_true",
        help=msg("argparse.fast_iterate.help")
    )

    # Recipe (NEW - Phase 8)
    parser.add_argument(
        "--recipe",
        metavar="FILE",
        help=msg("argparse.recipe.help")
    )
    
    # Cookie (NEW)
    parser.add_argument(
        "--cookie",
        metavar="COOKIE",
        help=msg("argparse.cookie.help")
    )

    parser.add_argument(
        "--bearer-token",
        metavar="TOKEN",
        help=msg("argparse.bearer_token.help")
    )
    
    # Crawl command (NEW)
    parser.add_argument(
        "--crawl", "-c",
        metavar="URL",
        help=msg("argparse.crawl.help")
    )
    
    parser.add_argument(
        "--crawl-depth",
        metavar="DEPTH",
        choices=["quick", "standard", "deep"],
        help=msg("argparse.crawl_depth.help")
    )
    
    # Analyze command (NEW)
    parser.add_argument(
        "--analyze", "-a",
        metavar="URL",
        help=msg("argparse.analyze.help")
    )
    
    # Debug mode (NEW)
    parser.add_argument(
        "--debug",
        action="store_true",
        help=msg("argparse.debug.help")
    )
    
    # RAG commands
    parser.add_argument(
        "--rag-ingest",
        metavar="PATH",
        help=msg("argparse.rag_ingest.help")
    )
    
    parser.add_argument(
        "--rag-query",
        metavar="QUESTION",
        help=msg("argparse.rag_query.help")
    )
    
    parser.add_argument(
        "--rag-stats",
        action="store_true",
        help=msg("argparse.rag_stats.help")
    )
    
    parser.add_argument(
        "--pdf-only",
        action="store_true",
        help=msg("argparse.pdf_only.help")
    )
    
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help=msg("argparse.reset_db.help")
    )
    
    parser.add_argument(
        "-n", "--num-results",
        type=int,
        help=msg("argparse.num_results.help")
    )
    
    # DNS command
    parser.add_argument(
        "--dns",
        metavar="DOMAIN",
        help=msg("argparse.dns.help")
    )
    
    # Parameter Fuzzing
    parser.add_argument(
        "--fuzz",
        metavar="URL",
        help=msg("argparse.fuzz.help")
    )
    
    # OpenAPI Testing
    parser.add_argument(
        "--openapi",
        metavar="URL",
        help=msg("argparse.openapi.help")
    )
    
    # Subdomain Takeover
    parser.add_argument(
        "--takeover",
        metavar="DOMAIN",
        help=msg("argparse.takeover.help")
    )
    
    # Export
    parser.add_argument(
        "--export",
        metavar="DIR",
        help=msg("argparse.export.help")
    )
    
    parser.add_argument(
        "--format",
        metavar="FORMAT",
        choices=["json", "csv", "pdf", "markdown", "html", "haddix", "haddix-ja-en"],
        default="json",
        help=msg("argparse.format.help")
    )
    
    # Tool Status
    parser.add_argument(
        "--tools",
        action="store_true",
        help=msg("argparse.tools.help")
    )

    # Project List (NEW)
    parser.add_argument(
        "--projects",
        action="store_true",
        help=msg("argparse.projects.help")
    )
    
    # Interactive Mode (NEW - Phase 0)
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help=msg("argparse.interactive.help")
    )
    
    # Resume Session (NEW - Session Persistence)
    parser.add_argument(
        "--resume",
        action="store_true",
        help=msg("argparse.resume.help")
    )

    parser.add_argument(
        "--hitl-list",
        action="store_true",
        help=msg("argparse.hitl_list.help")
    )

    parser.add_argument(
        "--deferred-list",
        action="store_true",
        help=msg("argparse.deferred_list.help")
    )

    parser.add_argument(
        "--deferred-checklist",
        action="store_true",
        help=msg("argparse.deferred_checklist.help")
    )

    parser.add_argument(
        "--deferred-status",
        action="store_true",
        help=msg("argparse.deferred_status.help")
    )

    parser.add_argument(
        "--deferred-resolve",
        action="append",
        metavar="SCENARIO_ID",
        help=msg("argparse.deferred_resolve.help")
    )

    parser.add_argument(
        "--deferred-note",
        metavar="TEXT",
        help=msg("argparse.deferred_note.help")
    )

    parser.add_argument(
        "--deferred-resolved-by",
        metavar="NAME",
        help=msg("argparse.deferred_resolved_by.help")
    )

    parser.add_argument(
        "--deferred-file",
        metavar="PATH",
        help=msg("argparse.deferred_file.help")
    )

    parser.add_argument(
        "--deferred-checklist-output",
        metavar="PATH",
        help=msg("argparse.deferred_checklist_output.help")
    )

    parser.add_argument(
        "--hitl-run",
        action="store_true",
        help=msg("argparse.hitl_run.help")
    )

    parser.add_argument(
        "--hitl-approve",
        action="append",
        metavar="TICKET_ID",
        help=msg("argparse.hitl_approve.help")
    )

    parser.add_argument(
        "--hitl-reject",
        action="append",
        metavar="TICKET_ID",
        help=msg("argparse.hitl_reject.help")
    )

    parser.add_argument(
        "--intervention-gate-mode",
        choices=["observe", "enforce_human_preferred", "enforce_hitl"],
        help=msg("argparse.intervention_gate_mode.help")
    )
    
    # Report (NEW)
    parser.add_argument(
        "--report",
        action="store_true",
        help=msg("argparse.report.help")
    )

    parser.add_argument(
        "--report-replay",
        action="store_true",
        help=msg("argparse.report_replay.help")
    )

    parser.add_argument(
        "--report-retry-failed",
        action="store_true",
        help=msg("argparse.report_retry_failed.help")
    )

    parser.add_argument(
        "--report-replay-list",
        action="store_true",
        help=msg("argparse.report_replay_list.help")
    )

    parser.add_argument(
        "--report-replay-platform",
        choices=["hackerone", "bugcrowd"],
        default="hackerone",
        help=msg("argparse.report_replay_platform.help")
    )

    parser.add_argument(
        "--report-replay-queue",
        metavar="PATH",
        help=msg("argparse.report_replay_queue.help")
    )

    parser.add_argument(
        "--report-replay-limit",
        type=int,
        metavar="N",
        help=msg("argparse.report_replay_limit.help")
    )

    parser.add_argument(
        "--report-replay-queue-id",
        metavar="QUEUE_ID",
        help=msg("argparse.report_replay_queue_id.help")
    )

    parser.add_argument(
        "--report-replay-status",
        choices=["pending", "failed", "completed"],
        help=msg("argparse.report_replay_status.help")
    )
    
    # Output format
    parser.add_argument(
        "--json",
        action="store_true",
        help=msg("argparse.json.help")
    )
    
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=msg("argparse.dry_run.help")
    )
    
    # Phase 5: Live Dashboard (NEW)
    parser.add_argument(
        "--live-dashboard",
        action="store_true",
        help=msg("argparse.live_dashboard.help")
    )

    parser.add_argument(
        "--focus-list",
        action="store_true",
        help=msg("argparse.focus_list.help")
    )

    parser.add_argument(
        "--focus-tests",
        action="store_true",
        help=msg("argparse.focus_tests.help")
    )

    parser.add_argument(
        "--focus-group",
        action="append",
        choices=["density", "report", "hitl", "fast_mc_recon", "all"],
        help=msg("argparse.focus_group.help")
    )

    parser.add_argument(
        "--focus-test",
        action="append",
        metavar="PATH",
        help=msg("argparse.focus_test.help")
    )

    parser.add_argument(
        "--focus-fail-fast",
        action="store_true",
        help=msg("argparse.focus_fail_fast.help")
    )

    parser.add_argument(
        "--import-recon",
        metavar="DIR",
        help=msg("argparse.import_recon.help"),
    )

    parser.add_argument(
        "--quality-loop",
        choices=["short"],
        help=msg("argparse.quality_loop.help")
    )

    parser.add_argument(
        "--quality-loop-full-scan",
        action="store_true",
        help=msg("argparse.quality_loop_full_scan.help"),
    )

    args = parser.parse_args()

    if args.fast_iterate:
        args.skip_initial_recon = True
        if args.recon_start_step is None:
            args.recon_start_step = 6
        if args.recon_end_step is None:
            args.recon_end_step = 8

    if args.recon_start_step is not None and not (1 <= int(args.recon_start_step) <= 8):
        parser.error(msg("parser.error.recon_start_step_range"))
    if args.recon_end_step is not None and not (1 <= int(args.recon_end_step) <= 8):
        parser.error(msg("parser.error.recon_end_step_range"))
    if (
        args.recon_start_step is not None
        and args.recon_end_step is not None
        and int(args.recon_start_step) > int(args.recon_end_step)
    ):
        parser.error(msg("parser.error.recon_step_order"))
    if args.quality_loop_full_scan and not args.quality_loop:
        parser.error(msg("parser.error.quality_loop_requires_full_scan"))

    if args.focus_list:
        _print_focus_test_groups()
        return

    if args.focus_tests:
        raw_groups = [str(g).strip() for g in (args.focus_group or []) if str(g).strip()]
        raw_custom_tests = [str(t).strip() for t in (args.focus_test or []) if str(t).strip()]
        exit_code, _groups, _tests, _cmd = _run_focused_tests(
            groups=raw_groups,
            custom_tests=raw_custom_tests,
            fail_fast=bool(args.focus_fail_fast),
            stage_label="focused tests",
        )
        if exit_code == 0:
            return
        raise SystemExit(exit_code)

    if args.quality_loop:
        if not args.target:
            parser.error(msg("parser.error.quality_loop_requires_target"))

        if args.quality_loop != "short":
            parser.error(f"Unsupported --quality-loop mode: {args.quality_loop}")

        raw_groups = [str(g).strip() for g in (args.focus_group or []) if str(g).strip()]
        raw_custom_tests = [str(t).strip() for t in (args.focus_test or []) if str(t).strip()]
        if not raw_groups and not raw_custom_tests:
            raw_groups = list(DEFAULT_QUALITY_LOOP_GROUPS)

        print_step("🧭", msg("step.quality_loop_1"))
        focus_exit, selected_groups, selected_tests, focus_cmd = _run_focused_tests(
            groups=raw_groups,
            custom_tests=raw_custom_tests,
            fail_fast=bool(args.focus_fail_fast),
            stage_label="quality-loop precheck",
        )

        artifact_path = _write_quality_loop_precheck_artifact(
            target=str(args.target),
            mode=str(args.quality_loop),
            selected_groups=selected_groups,
            selected_tests=selected_tests,
            focus_cmd=focus_cmd,
            focus_exit_code=focus_exit,
        )
        if artifact_path is not None:
            print_step("🗃️", msg("step.quality_loop_precheck_artifact", path=artifact_path))

        if focus_exit != 0:
            if not selected_tests:
                print_step(
                    "⚠️",
                    msg("step.quality_loop_precheck_unavailable"),
                )
            else:
                raise SystemExit(focus_exit)

        print_step("⚡", msg("step.quality_loop_2"))
        short_cmd = _build_quality_loop_scan_command(args, short_mode=True)
        short_result = subprocess.run(short_cmd, check=False)
        if short_result.returncode != 0:
            print_result(False, msg("quality.short_attack_failed", code=short_result.returncode))
            raise SystemExit(int(short_result.returncode))

        if args.quality_loop_full_scan:
            print_step("🧪", msg("step.quality_loop_3"))
            full_cmd = _build_quality_loop_scan_command(args, short_mode=False)
            full_result = subprocess.run(full_cmd, check=False)
            if full_result.returncode != 0:
                print_result(False, msg("quality.full_scan_failed", code=full_result.returncode))
                raise SystemExit(int(full_result.returncode))
            print_result(True, msg("result.quality_loop_completed_full"))
            return

        print_result(True, msg("result.quality_loop_completed_short"))
        print(msg("next_action.after_scan"))
        return
    
    # Initialize Configuration
    cm = get_config_manager()
    config = cm.config
    
    # Resolve Configuration (CLI > Config File > Default)
    mode = args.mode or config.mode or "bugbounty"
    scope_file = args.scope or config.scope_file
    
    # デバッグモード有効化（他の処理前に）
    if args.debug:
        enable_debug_mode()

    if args.intervention_gate_mode:
        settings.intervention_gate_mode = str(args.intervention_gate_mode)
        print_step("🛂", msg("step.intervention_gate_mode", mode=settings.intervention_gate_mode))

    # Deferred scenario backlog management
    if args.deferred_list or args.deferred_checklist or args.deferred_status or args.deferred_resolve:
        from src.core.project.project_manager import ProjectManager
        from src.core.utils.json_utils import safe_json_loads

        print_banner()
        print_step("🗂️", msg("step.deferred_mode"))

        deferred_file: Path | None = None
        if args.deferred_file:
            deferred_file = Path(args.deferred_file).expanduser().resolve()
        elif args.target:
            pm = ProjectManager(args.target)
            reports_dir = pm.get_reports_dir()
            deferred_file = _select_latest_deferred_backlog_file(reports_dir)
            if deferred_file is not None:
                print_step("📂", msg("deferred.using_latest", target=args.target, file=deferred_file.name))
        else:
            print_result(
                False,
                msg("result.deferred.mode_requires_target"),
            )
            return

        if deferred_file is None or not deferred_file.exists():
            print_result(False, msg("result.deferred.no_artifact"))
            print(msg("result.deferred.generate_haddix_hint"))
            return

        try:
            raw_text = deferred_file.read_text(encoding="utf-8")
            payload = safe_json_loads(raw_text, context=f"deferred_backlog:{deferred_file.name}")
            if not isinstance(payload, dict):
                raise ValueError("deferred backlog is not a JSON object")
        except Exception as exc:
            print_result(False, msg("result.deferred.read_failed", error=exc))
            return

        scenarios = _extract_deferred_scenarios_from_payload(payload)
        status_summary = _summarize_deferred_statuses(scenarios)

        resolve_ids = [str(item).strip() for item in (args.deferred_resolve or []) if str(item).strip()]
        resolved_count = 0
        unresolved_ids: list[str] = []
        if resolve_ids:
            resolved_count, unresolved_ids = _resolve_deferred_scenarios(
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
                print_result(False, msg("result.deferred.update_failed", error=exc))
                return
            status_summary = _summarize_deferred_statuses(scenarios)

        checklist_path: Path | None = None
        if args.deferred_checklist:
            explicit_output = bool(args.deferred_checklist_output)
            checklist_path = (
                Path(args.deferred_checklist_output).expanduser().resolve()
                if args.deferred_checklist_output
                else _default_deferred_checklist_output_path(deferred_file)
            )
            checklist_markdown = _build_deferred_checklist_markdown(
                deferred_file=deferred_file,
                payload=payload,
                scenarios=scenarios,
            )
            try:
                checklist_path.parent.mkdir(parents=True, exist_ok=True)
                checklist_path.write_text(checklist_markdown, encoding="utf-8")
            except PermissionError:
                if explicit_output:
                    print_result(False, msg("result.deferred.checklist_unwritable", path=checklist_path))
                    return
                fallback_dir = (Path.cwd() / "reports").resolve()
                fallback_dir.mkdir(parents=True, exist_ok=True)
                fallback_path = fallback_dir / checklist_path.name
                fallback_path.write_text(checklist_markdown, encoding="utf-8")
                checklist_path = fallback_path
                print_step("⚠️", msg("result.deferred.checklist_fallback", path=checklist_path))
            except Exception as exc:
                print_result(False, msg("result.deferred.checklist_failed", error=exc))
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

        print(msg("result.deferred.scenario_count", count=len(scenarios)))
        print(
            msg("deferred.status_summary",
                pending=status_summary.get('pending', 0),
                in_progress=status_summary.get('in_progress', 0),
                done=status_summary.get('done', 0),
                rejected=status_summary.get('rejected', 0),
                total=status_summary.get('total', 0),
            )
        )
        print(msg("deferred.artifact_path", path=deferred_file))
        if resolve_ids:
            print_step("✅", msg("result.deferred.resolved_count", count=resolved_count))
            if unresolved_ids:
                preview = ", ".join(unresolved_ids[:5])
                suffix = " ..." if len(unresolved_ids) > 5 else ""
                print_step("⚠️", msg("result.deferred.scenario_not_found", preview=preview, suffix=suffix))
        if checklist_path is not None:
            print_step("📝", msg("result.deferred.checklist_generated", path=checklist_path))
        if not scenarios:
            print(msg("result.deferred.no_scenarios"))
            return

        for item in scenarios:
            scenario_id = str(item.get("scenario_id", "-") or "-")
            route = str(item.get("route", "-") or "-")
            title = str(item.get("title", scenario_id) or scenario_id)
            status = _normalize_deferred_status(item.get("status"))
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
        return

    # HITL pending tickets management
    if args.hitl_list or args.hitl_run or args.hitl_approve or args.hitl_reject:
        from src.core.engine.master_conductor import MasterConductor
        from src.core.project.project_manager import ProjectManager
        from src.core.models.llm import LLMClient

        print_banner()
        print_step("🧩", msg("step.hitl_mode"))

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
                    key=_session_order_key,
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
                selected_session, selected_reason = _select_hitl_session(
                    parsed_sessions, requested_ticket_ids=requested_ticket_ids
                )

            latest_session = sessions_dir / "latest.json"
            if selected_session is None and latest_session.exists():
                selected_session = latest_session
                selected_reason = "latest.json fallback"

            if selected_session is not None:
                session_file = str(selected_session)
                print_step(
                    "📂",
                    msg("hitl.using_session", reason=selected_reason, target=args.target, session=selected_session.name),
                )
            else:
                print_result(False, msg("result.session.not_found", target=args.target))
                return

        if not Path(session_file).exists():
            print_result(False, msg("result.session.file_not_found", path=session_file))
            return

        llm_client = LLMClient(role="specialist_light")
        mc = MasterConductor(llm_client=llm_client)
        if pm:
            mc.set_project_manager(pm)

        if not mc.load_session(session_file):
            print_result(False, msg("result.session.load_failed"))
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
            print_step("✅", msg("result.hitl.approved_count", count=approved))
        if rejected > 0:
            print_step("⛔", msg("result.hitl.rejected_count", count=rejected))
        if unresolved_ticket_ids:
            preview = ", ".join(unresolved_ticket_ids[:3])
            suffix = " ..." if len(unresolved_ticket_ids) > 3 else ""
            print_step("⚠️", msg("result.hitl.ticket_not_found", preview=preview, suffix=suffix))

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
                    print(msg("result.hitl.no_tickets"))
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
                        print(msg("result.hitl.hint_gate_mode"))
                        print(msg("result.hitl.hint_gate_mode"))
                    elif hitl_route_count <= 0:
                        print(msg("result.hitl.hint_rerun"))
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
                print_step("⏭️", msg("result.hitl.ignoring_pending", count=existing_pending))
                mc.task_queue.clear()
            queued = mc.enqueue_approved_hitl_tasks()
            if queued <= 0:
                print_result(True, msg("result.hitl.no_approved"))
                mc.save_session(filepath=session_file)
            else:
                print_step("▶️", msg("result.hitl.queued", count=queued))
                result = mc.execute_with_replan()
                print_result(True, msg("result.hitl.completed"))
                if args.json:
                    print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            mc.save_session(filepath=session_file)
            print_result(True, msg("result.hitl.saved"))
        return
    
    # Resume セッション処理
    if args.resume:
        from src.core.engine.master_conductor import MasterConductor
        from src.core.project.project_manager import ProjectManager
        from src.core.models.llm import LLMClient

        print_banner()
        print_step("🔄", msg("step.resume_attempting"))

        session_file = "session_state.json"
        pm = None

        # Project Aware Resume
        if args.target:
            pm = ProjectManager(args.target)
            latest_session = pm.project_dir / "sessions" / "latest.json"
            if latest_session.exists():
                session_file = str(latest_session)
                print_step("📂", msg("hitl.resume_using_latest", target=args.target))
            else:
                print_result(False, msg("result.session.not_found", target=args.target))
                return

        if not Path(session_file).exists():
            print_result(False, msg("result.session.file_not_found", path=session_file))
            print(msg("result.resume.tip"))
            return

        # Initialize LLM Client for resumed session
        llm_client = LLMClient(role="specialist_light")
        mc = MasterConductor(llm_client=llm_client)
        if pm:
            mc.set_project_manager(pm)

        if mc.load_session(session_file):
            # Preflight entry gate AFTER session load — uses real session context
            resume_session_id = Path(session_file).stem
            target_info = mc.context.target_info if isinstance(getattr(mc.context, "target_info", {}), dict) else {}
            session_target = str(target_info.get("target", "") or "")
            session_cookies = target_info.get("cookies", {})
            if isinstance(session_cookies, str):
                session_cookies = _parse_cookie_string(session_cookies)
            session_bearer = str(target_info.get("bearer_token", "") or "")
            session_mode = str(target_info.get("mode", "") or mode)

            gate_context = PreflightContext(
                target=_normalize_target_for_preflight(session_target),
                mode=session_mode,
                goal=_derive_goal_for_preflight(args),
                profile=str(args.profile or ""),
                cookies=session_cookies,
                bearer_token=session_bearer,
                resume_session_id=resume_session_id,
                gate_policy=GatePolicy.STRICT_DEV if args.debug else GatePolicy.STRICT_PROD,
            )
            gate_result = asyncio.run(EntryGateFacade().run_once(gate_context))
            if gate_result.failed:
                for failure in gate_result.failures:
                    print(f"[GATE] {failure.reason_code}: {failure.remediation}")
                print("Preflight entry gate failed — aborting execution.")
                sys.exit(1)

            print_result(True, msg("step.resume_restored", count=len(mc.task_queue)))
            print_step("▶️", msg("step.resume_executing"))
             
            # 実行再開
            result = mc.execute_with_replan()
            
            print_result(True, msg("step.resume_completed"))
            
            # 終了サマリー表示
            from src.commands.report import print_execution_summary
            print_execution_summary(mc.completed_tasks, mc.context)
            
            if args.json:
                print(json.dumps(result, indent=2, ensure_ascii=False))
        else:
            print_result(False, msg("result.session.load_failed"))
        return

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
        print_step("📋", msg("step.report_list_mode"))
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
        print_step("🔁", msg("step.report_retry_mode"))
        print_result(True, msg("result.report.replay_reset", platform=retry_result['platform'], count=retry_result['reset']))
        print_step("♻️", f"reset={retry_result['reset']}")
        print_step("⏭️", f"skipped={retry_result['skipped']}")
        print_step("🗂️", f"queue={retry_result['queue_path']}")
        return

    if args.report_replay:
        if not args.json:
            print_banner()
            print_step("🔁", msg("step.report_replay_mode"))

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
            print_result(False, msg("result.report.replay_no_support"))
            return
        if args.report_replay_platform not in getattr(manager, "_platforms", {}):
            print_result(False, msg("result.report.replay_not_configured", platform=args.report_replay_platform))
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

        print_result(True, msg("result.report.replay_processed", platform=replay_result['platform'], count=replay_result['processed']))
        print_step("📦", f"processed={replay_result['processed']}")
        print_step("✅", f"replayed={replay_result['replayed']}")
        print_step("⚠️", f"failed={replay_result['failed']}")
        print_step("🗂️", f"queue={replay_result['queue_path']}")
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
                    key=_session_order_key,
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
                print_step("📂", msg("hitl.resume_valid_session", target=args.target, file=Path(session_file).name))
            else:
                print_result(False, msg("result.session.not_found", target=args.target))
                return
        
        path_obj = Path(session_file)
        if not path_obj.exists():
            print_result(False, msg("result.session.file_not_found", path=session_file))
            return
            
        if args.format == "html":
            try:
                from src.reports.html_generator import generate_report_from_file
                output_path = generate_report_from_file(session_file)
                
                abs_path = Path(output_path).resolve()
                print_result(True, msg("result.report.html_generated", path=abs_path))
                
                # Check if running in Docker
                is_docker = Path("/.dockerenv").exists()
                
                import webbrowser
                try:
                    if not is_docker:
                        print(msg("result.report.open_browser"))
                        webbrowser.open(f"file://{abs_path}")
                    else:
                        print(msg("result.report.docker_hint"))
                except Exception:
                    print(msg("result.report.cannot_open_browser", path=abs_path))
            except Exception as e:
                print_result(False, msg("result.report.html_failed", error=e))
        
        elif args.format == "haddix":
            try:
                from src.reporting.haddix_formatter import generate_haddix_report
                from src.reporting.initial_release_gate import (
                    DEFAULT_ALLOWED_MISSING_SCENARIOS,
                    evaluate_initial_release_gate,
                )
                from src.core.utils.json_utils import safe_json_loads
                
                # セッションデータを読み込み
                raw_text = Path(session_file).read_text(encoding="utf-8")
                session_data = safe_json_loads(raw_text, context="haddix_gen")
                
                # Findingsを抽出 (completed_tasks内の共有ヘルパーを再利用)
                haddix_findings, execution_notes = _extract_findings_and_execution_notes(session_data)

                scenario_coverage = _build_scenario_coverage_for_report(session_data)
                vulnerability_family_coverage: dict[str, Any] = {}
                raw_coverage_gate = session_data.get("coverage_gate")
                if not isinstance(raw_coverage_gate, dict):
                    session_context = session_data.get("context", {})
                    if isinstance(session_context, dict):
                        raw_coverage_gate = session_context.get("coverage_gate") or session_context.get("vulnerability_family_coverage")
                if isinstance(raw_coverage_gate, dict):
                    vulnerability_family_coverage = raw_coverage_gate
                report_target = session_data.get("goal_target", args.target)

                heuristic_budget = int(getattr(settings, "report_heuristic_max_candidates", 6) or 6)
                if haddix_findings:
                    heuristic_budget = min(
                        heuristic_budget,
                        int(getattr(settings, "report_heuristic_append_when_confirmed", 3) or 3),
                    )
                heuristic_promote_privilege_probe_min = max(
                    1,
                    int(getattr(settings, "report_heuristic_promote_privilege_probe_min", 2) or 2),
                )
                heuristic_promote_completed_probe_min = max(
                    1,
                    int(getattr(settings, "report_heuristic_promote_completed_probe_min", 2) or 2),
                )

                heuristic_candidates = _build_heuristic_findings_from_execution_notes(
                    execution_notes,
                    target=report_target,
                    scenario_coverage=scenario_coverage,
                    max_candidates=max(0, heuristic_budget),
                    promote_privilege_probe_min=heuristic_promote_privilege_probe_min,
                    promote_completed_probe_min=heuristic_promote_completed_probe_min,
                )
                if heuristic_candidates:
                    if haddix_findings:
                        before_len = len(haddix_findings)
                        merged = _merge_heuristic_candidates_into_findings(
                            confirmed_findings=haddix_findings,
                            heuristic_candidates=heuristic_candidates,
                            max_append=max(0, heuristic_budget),
                        )
                        appended = max(0, len(merged) - before_len)
                        if appended > 0:
                            haddix_findings = merged
                            print_step(
                                "🧪",
                                msg("finding.appended_heuristics", count=appended),
                            )
                    else:
                        haddix_findings = heuristic_candidates
                        print_step(
                            "🧪",
                            msg("finding.promoted_heuristics", count=len(heuristic_candidates)),
                        )

                # report-only 経路でも重複排除を適用（特に file_upload の大量重複を統合）
                try:
                    from src.core.deduplication.finding_deduplicator import deduplicate_findings
                    from src.core.models.finding import Finding, VulnType, Severity

                    finding_objects = []
                    for raw in haddix_findings:
                        if isinstance(raw, Finding):
                            finding_objects.append(raw)
                            continue
                        if not isinstance(raw, dict):
                            continue

                        vuln_raw = str(raw.get("vuln_type", raw.get("type", "other"))).lower()
                        sev_raw = str(raw.get("severity", "low")).lower()

                        try:
                            vuln_type = VulnType(vuln_raw)
                        except Exception:
                            vuln_type = VulnType.OTHER

                        try:
                            severity = Severity(sev_raw)
                        except Exception:
                            severity = Severity.LOW

                        confidence_raw = raw.get("confidence", 0.0)
                        try:
                            confidence = float(confidence_raw)
                        except Exception:
                            confidence = 0.0

                        finding_objects.append(Finding(
                            vuln_type=vuln_type,
                            severity=severity,
                            title=raw.get("title", "Unknown Vulnerability"),
                            description=raw.get("description", raw.get("summary", "")),
                            target_url=raw.get("target_url", raw.get("target", raw.get("url", report_target))),
                            target_program=raw.get("target_program", session_data.get("program_name", "")),
                            evidence=raw.get("evidence", {}),
                            reproduction_steps=raw.get("reproduction_steps", raw.get("steps_to_reproduce", [])),
                            impact=raw.get("impact", ""),
                            source_agent=raw.get("source_agent", raw.get("discovered_by", "")),
                            confidence=confidence,
                            additional_info=raw.get("additional_info", {}),
                            cwe_id=raw.get("cwe_id"),
                            cvss_score=raw.get("cvss_score"),
                        ))

                    if len(finding_objects) > 1:
                        deduped = deduplicate_findings(finding_objects)
                        if len(deduped) < len(finding_objects):
                            logger.info("Report dedup applied: %d -> %d", len(finding_objects), len(deduped))
                        haddix_findings = [f.to_dict() for f in deduped]
                except Exception as _dedup_error:
                    logger.warning("Report dedup skipped: %s", _dedup_error)

                # 出力パスの決定
                output_dir = Path(session_file).parent.parent / "reports"
                output_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = output_dir / f"haddix_report_{timestamp}.md"
                gate_output_path = output_dir / f"haddix_gate_{timestamp}.json"
                deferred_output_path = output_dir / f"haddix_deferred_{timestamp}.json"
                evidence_output_dir = output_dir / f"haddix_evidence_{timestamp}"

                haddix_findings, evidence_artifact_paths = _materialize_haddix_evidence_artifacts(
                    findings=haddix_findings,
                    evidence_dir=evidence_output_dir,
                    captured_at=datetime.now().isoformat(timespec="seconds"),
                )
                if evidence_artifact_paths:
                    print_step(
                        "🧾",
                        msg("finding.evidence_saved", count=len(evidence_artifact_paths), dir=evidence_output_dir.resolve()),
                    )
                
                generate_haddix_report(
                    findings=haddix_findings,
                    target=report_target,
                    output_path=output_path,
                    program_name=session_data.get("program_name", ""),
                    execution_notes=execution_notes,
                    scenario_coverage=scenario_coverage,
                    vulnerability_family_coverage=vulnerability_family_coverage,
                    initial_release_gate={},
                    source_session=str(Path(session_file).resolve()),
                )

                raw_allowed_missing = getattr(
                    settings,
                    "report_initial_release_allowed_missing_scenarios",
                    ",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS),
                )
                if isinstance(raw_allowed_missing, list):
                    allowed_missing_scenarios = [
                        str(token or "").strip()
                        for token in raw_allowed_missing
                        if str(token or "").strip()
                    ]
                else:
                    allowed_missing_scenarios = [
                        str(token or "").strip()
                        for token in str(raw_allowed_missing or "").split(",")
                        if str(token or "").strip()
                    ]
                if not allowed_missing_scenarios:
                    allowed_missing_scenarios = list(DEFAULT_ALLOWED_MISSING_SCENARIOS)

                raw_required_classes = getattr(
                    settings,
                    "report_initial_release_required_confirmed_classes",
                    "",
                )
                if isinstance(raw_required_classes, list):
                    required_confirmed_classes = [
                        str(token or "").strip()
                        for token in raw_required_classes
                        if str(token or "").strip()
                    ]
                else:
                    required_confirmed_classes = [
                        str(token or "").strip()
                        for token in str(raw_required_classes or "").split(",")
                        if str(token or "").strip()
                    ]

                baseline_report_path_raw = str(
                    getattr(settings, "report_initial_release_baseline_report_path", "") or ""
                ).strip()
                baseline_session_path_raw = str(
                    getattr(settings, "report_initial_release_baseline_session_path", "") or ""
                ).strip()
                baseline_report_path = (
                    Path(baseline_report_path_raw).expanduser().resolve()
                    if baseline_report_path_raw
                    else None
                )
                baseline_session_path = (
                    Path(baseline_session_path_raw).expanduser().resolve()
                    if baseline_session_path_raw
                    else None
                )

                gate_result = evaluate_initial_release_gate(
                    output_path,
                    session_path=Path(session_file),
                    baseline_report_path=baseline_report_path,
                    baseline_session_path=baseline_session_path,
                    allowed_missing_scenarios=allowed_missing_scenarios,
                    confirmed_min=max(
                        0,
                        int(getattr(settings, "report_initial_release_confirmed_min", 3) or 3),
                    ),
                    candidate_max=max(
                        0,
                        int(getattr(settings, "report_initial_release_candidate_max", 2) or 2),
                    ),
                    confirmed_poc_missing_max=max(
                        0,
                        int(getattr(settings, "report_initial_release_confirmed_poc_missing_max", 0) or 0),
                    ),
                    reason_code_missing_max=max(
                        0,
                        int(getattr(settings, "report_initial_release_reason_code_missing_max", 0) or 0),
                    ),
                    required_confirmed_classes=required_confirmed_classes,
                    required_class_confirmed_min=max(
                        0,
                        int(
                            getattr(
                                settings,
                                "report_initial_release_required_class_confirmed_min",
                                1,
                            )
                            or 1
                        ),
                    ),
                )

                generate_haddix_report(
                    findings=haddix_findings,
                    target=report_target,
                    output_path=output_path,
                    program_name=session_data.get("program_name", ""),
                    execution_notes=execution_notes,
                    scenario_coverage=scenario_coverage,
                    vulnerability_family_coverage=vulnerability_family_coverage,
                    initial_release_gate=gate_result,
                    source_session=str(Path(session_file).resolve()),
                )
                gate_output_path.write_text(
                    json.dumps(gate_result, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                deferred_scenarios = gate_result.get("deferred_scenarios", [])
                if isinstance(deferred_scenarios, list) and deferred_scenarios:
                    deferred_payload = {
                        "report_path": str(output_path.resolve()),
                        "gate_path": str(gate_output_path.resolve()),
                        "generated_at": datetime.now().isoformat(timespec="seconds"),
                        "deferred_scenarios": deferred_scenarios,
                    }
                    deferred_output_path.write_text(
                        json.dumps(deferred_payload, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                
                abs_path = output_path.resolve()
                print_result(True, msg("result.report.haddix_generated", path=abs_path))
                print_step("🚦", msg("gate.verdict_saved", path=gate_output_path.resolve()))
                if isinstance(deferred_scenarios, list) and deferred_scenarios:
                    print_step("🗂️", msg("gate.deferred_saved", path=deferred_output_path.resolve()))

                gate_status = str(gate_result.get("status", "") or "").strip().upper() or "UNKNOWN"
                reason_codes = gate_result.get("reason_codes", [])
                reason_codes_text = ", ".join(str(code) for code in reason_codes) if reason_codes else "-"
                print_step("🚦", msg("gate.status", status=gate_status, codes=reason_codes_text))

                recommended_actions = gate_result.get("recommended_actions", [])
                if isinstance(recommended_actions, list) and recommended_actions:
                    for action in recommended_actions[:5]:
                        if not isinstance(action, dict):
                            continue
                        action_id = str(action.get("id", "") or "action")
                        priority = str(action.get("priority", "") or "medium").lower()
                        summary = str(action.get("summary", "") or "").strip()
                        command_hint = str(action.get("command_hint", "") or "").strip()
                        print_step(
                            "🧭",
                            f"[{priority}] {action_id}: {summary}" if summary else f"[{priority}] {action_id}",
                        )
                        if command_hint:
                            print(f"   └─ {command_hint}")
                
                if not Path("/.dockerenv").exists():
                    print(msg("result.report.view_hint", path=abs_path))
                
            except Exception as e:
                print_result(False, msg("result.report.haddix_failed", error=e))
                import traceback
                logger.error(traceback.format_exc())
        
        elif args.format == "haddix-ja-en":
            import tempfile
            import shutil
            try:
                from src.reporting.haddix_ja_en_formatter import generate_haddix_ja_en_report
                from src.core.utils.json_utils import safe_json_loads

                # セッションデータを読み込み
                raw_text = Path(session_file).read_text(encoding="utf-8")
                session_data = safe_json_loads(raw_text, context="haddix_ja_en_gen")

                # 共有抽出ヘルパーで findings + execution_notes を準備
                ja_en_findings, ja_en_exec_notes = _extract_findings_and_execution_notes(session_data)

                # report_target を定義（haddix 分岐と同じ）
                report_target = session_data.get("goal_target", args.target)

                # シナリオカバレッジと脆弱性ファミリーカバレッジを構築
                scenario_coverage = _build_scenario_coverage_for_report(session_data)
                vulnerability_family_coverage: dict[str, Any] = {}
                raw_coverage_gate = session_data.get("coverage_gate")
                if not isinstance(raw_coverage_gate, dict):
                    session_context = session_data.get("context", {})
                    if isinstance(session_context, dict):
                        raw_coverage_gate = session_context.get("coverage_gate") or session_context.get("vulnerability_family_coverage")
                if isinstance(raw_coverage_gate, dict):
                    vulnerability_family_coverage = raw_coverage_gate

                # Heuristic candidate 生成・マージ（haddix 分岐と同一ロジック）
                heuristic_budget = int(getattr(settings, "report_heuristic_max_candidates", 6) or 6)
                if ja_en_findings:
                    heuristic_budget = min(
                        heuristic_budget,
                        int(getattr(settings, "report_heuristic_append_when_confirmed", 3) or 3),
                    )
                heuristic_promote_privilege_probe_min = max(
                    1,
                    int(getattr(settings, "report_heuristic_promote_privilege_probe_min", 2) or 2),
                )
                heuristic_promote_completed_probe_min = max(
                    1,
                    int(getattr(settings, "report_heuristic_promote_completed_probe_min", 2) or 2),
                )

                heuristic_candidates = _build_heuristic_findings_from_execution_notes(
                    ja_en_exec_notes,
                    target=report_target,
                    scenario_coverage=scenario_coverage,
                    max_candidates=max(0, heuristic_budget),
                    promote_privilege_probe_min=heuristic_promote_privilege_probe_min,
                    promote_completed_probe_min=heuristic_promote_completed_probe_min,
                )
                if heuristic_candidates:
                    if ja_en_findings:
                        before_len = len(ja_en_findings)
                        merged = _merge_heuristic_candidates_into_findings(
                            confirmed_findings=ja_en_findings,
                            heuristic_candidates=heuristic_candidates,
                            max_append=max(0, heuristic_budget),
                        )
                        appended = max(0, len(merged) - before_len)
                        if appended > 0:
                            ja_en_findings = merged
                    else:
                        ja_en_findings = heuristic_candidates

                # Deduplication（haddix 分岐と同一ロジック）
                try:
                    from src.core.deduplication.finding_deduplicator import deduplicate_findings
                    from src.core.models.finding import Finding, VulnType, Severity

                    finding_objects = []
                    for raw in ja_en_findings:
                        if isinstance(raw, Finding):
                            finding_objects.append(raw)
                            continue
                        if not isinstance(raw, dict):
                            continue

                        vuln_raw = str(raw.get("vuln_type", raw.get("type", "other"))).lower()
                        sev_raw = str(raw.get("severity", "low")).lower()

                        try:
                            vuln_type = VulnType(vuln_raw)
                        except Exception:
                            vuln_type = VulnType.OTHER

                        try:
                            severity = Severity(sev_raw)
                        except Exception:
                            severity = Severity.LOW

                        confidence_raw = raw.get("confidence", 0.0)
                        try:
                            confidence = float(confidence_raw)
                        except Exception:
                            confidence = 0.0

                        finding_objects.append(Finding(
                            vuln_type=vuln_type,
                            severity=severity,
                            title=raw.get("title", "Unknown Vulnerability"),
                            description=raw.get("description", raw.get("summary", "")),
                            target_url=raw.get("target_url", raw.get("target", raw.get("url", report_target))),
                            target_program=raw.get("target_program", session_data.get("program_name", "")),
                            evidence=raw.get("evidence", {}),
                            reproduction_steps=raw.get("reproduction_steps", raw.get("steps_to_reproduce", [])),
                            impact=raw.get("impact", ""),
                            source_agent=raw.get("source_agent", raw.get("discovered_by", "")),
                            confidence=confidence,
                            additional_info=raw.get("additional_info", {}),
                            cwe_id=raw.get("cwe_id"),
                            cvss_score=raw.get("cvss_score"),
                        ))

                    if len(finding_objects) > 1:
                        deduped = deduplicate_findings(finding_objects)
                        if len(deduped) < len(finding_objects):
                            logger.info("Report dedup applied: %d -> %d", len(finding_objects), len(deduped))
                        ja_en_findings = [f.to_dict() for f in deduped]
                except Exception as _dedup_error:
                    logger.warning("Report dedup skipped: %s", _dedup_error)

                # 出力パスの決定
                output_dir = Path(session_file).parent.parent / "reports"
                output_dir.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = output_dir / f"haddix_report_{timestamp}.md"
                evidence_output_dir = output_dir / f"haddix_evidence_{timestamp}"

                # Evidence artifact materialization（haddix 分岐と同一ロジック）
                ja_en_findings, evidence_artifact_paths = _materialize_haddix_evidence_artifacts(
                    findings=ja_en_findings,
                    evidence_dir=evidence_output_dir,
                    captured_at=datetime.now().isoformat(timespec="seconds"),
                )

                # Gate 評価（haddix 分岐と同一ロジック）
                from src.reporting.initial_release_gate import (
                    DEFAULT_ALLOWED_MISSING_SCENARIOS,
                    evaluate_initial_release_gate,
                )
                raw_allowed_missing = getattr(
                    settings,
                    "report_initial_release_allowed_missing_scenarios",
                    ",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS),
                )
                if isinstance(raw_allowed_missing, list):
                    allowed_missing_scenarios = [
                        str(token or "").strip()
                        for token in raw_allowed_missing
                        if str(token or "").strip()
                    ]
                else:
                    allowed_missing_scenarios = [
                        str(token or "").strip()
                        for token in str(raw_allowed_missing or "").split(",")
                        if str(token or "").strip()
                    ]
                if not allowed_missing_scenarios:
                    allowed_missing_scenarios = list(DEFAULT_ALLOWED_MISSING_SCENARIOS)

                raw_required_classes = getattr(
                    settings,
                    "report_initial_release_required_confirmed_classes",
                    "",
                )
                if isinstance(raw_required_classes, list):
                    required_confirmed_classes = [
                        str(token or "").strip()
                        for token in raw_required_classes
                        if str(token or "").strip()
                    ]
                else:
                    required_confirmed_classes = [
                        str(token or "").strip()
                        for token in str(raw_required_classes or "").split(",")
                        if str(token or "").strip()
                    ]

                baseline_report_path_raw = str(
                    getattr(settings, "report_initial_release_baseline_report_path", "") or ""
                ).strip()
                baseline_session_path_raw = str(
                    getattr(settings, "report_initial_release_baseline_session_path", "") or ""
                ).strip()
                baseline_report_path = (
                    Path(baseline_report_path_raw).expanduser().resolve()
                    if baseline_report_path_raw
                    else None
                )
                baseline_session_path = (
                    Path(baseline_session_path_raw).expanduser().resolve()
                    if baseline_session_path_raw
                    else None
                )

                # Temp file に ja-en レポートを生成（gate 評価前の初回生成）
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix=".md",
                    prefix="haddix_ja_en_tmp_",
                    dir=str(output_dir),
                    encoding="utf-8",
                    delete=False,
                ) as tmp_file:
                    tmp_path = Path(tmp_file.name)

                try:
                    generate_haddix_ja_en_report(
                        findings=ja_en_findings,
                        target=report_target,
                        output_path=tmp_path,
                        program_name=session_data.get("program_name", ""),
                        execution_notes=ja_en_exec_notes,
                        scenario_coverage=scenario_coverage,
                        vulnerability_family_coverage=vulnerability_family_coverage,
                        initial_release_gate={},
                        source_session=str(Path(session_file).resolve()),
                    )

                    if not tmp_path.exists() or tmp_path.stat().st_size == 0:
                        raise RuntimeError("Generated report is empty")

                    content = tmp_path.read_text(encoding="utf-8")
                    if "# SHIGOKU" not in content or "# Submission Report" not in content:
                        raise RuntimeError("Generated report missing required sections")

                except Exception:
                    if tmp_path.exists():
                        tmp_path.unlink(missing_ok=True)
                    raise

                # Gate 評価
                gate_result = evaluate_initial_release_gate(
                    tmp_path,
                    session_path=Path(session_file),
                    baseline_report_path=baseline_report_path,
                    baseline_session_path=baseline_session_path,
                    allowed_missing_scenarios=allowed_missing_scenarios,
                    confirmed_min=max(0, int(getattr(settings, "report_initial_release_confirmed_min", 3) or 3)),
                    candidate_max=max(0, int(getattr(settings, "report_initial_release_candidate_max", 2) or 2)),
                    confirmed_poc_missing_max=max(0, int(getattr(settings, "report_initial_release_confirmed_poc_missing_max", 0) or 0)),
                    reason_code_missing_max=max(0, int(getattr(settings, "report_initial_release_reason_code_missing_max", 0) or 0)),
                    required_confirmed_classes=required_confirmed_classes,
                    required_class_confirmed_min=max(0, int(getattr(settings, "report_initial_release_required_class_confirmed_min", 1) or 1)),
                )

                # Gate 結果を埋め込んだ最終レポートを再生成
                generate_haddix_ja_en_report(
                    findings=ja_en_findings,
                    target=report_target,
                    output_path=tmp_path,
                    program_name=session_data.get("program_name", ""),
                    execution_notes=ja_en_exec_notes,
                    scenario_coverage=scenario_coverage,
                    vulnerability_family_coverage=vulnerability_family_coverage,
                    initial_release_gate=gate_result,
                    source_session=str(Path(session_file).resolve()),
                )

                # Atomic rename to final path
                shutil.move(str(tmp_path), str(output_path))

                abs_path = str(output_path.resolve())
                logger.info(f"ja-en report saved: {abs_path}")

                print_step("📄", f"ja-en report: {abs_path}")
                print_result(True, msg("result.report.haddix_ja_en_generated", path=abs_path))

                gate_status = str(gate_result.get("status", "") or "").strip().upper() or "UNKNOWN"
                reason_codes = gate_result.get("reason_codes", [])
                reason_codes_text = ", ".join(str(code) for code in reason_codes) if reason_codes else "-"
                print_step("🚦", msg("gate.status", status=gate_status, codes=reason_codes_text))

                if not Path("/.dockerenv").exists():
                    print(msg("result.report.view_hint", path=abs_path))

            except Exception as e:
                print_result(False, msg("result.report.haddix_failed", error=e))
                import traceback
                logger.error(traceback.format_exc())
        else:
            # Default: Text Summary
            mc = MasterConductor()
            if mc.load_session(session_file):
                from src.commands.report import print_execution_summary
                print_execution_summary(mc.completed_tasks, mc.context)
            else:
                print_result(False, msg("result.session.load_failed"))
        return

    # Preflight entry gate for heavy-execution paths
    if any([
        args.target,
        args.recon,
        args.log,
        args.crawl,
        args.analyze,
        args.interactive,
    ]):
        asyncio.run(
            _run_entry_gate(
                target=_normalize_target_for_preflight(
                    str(args.target or args.recon or args.log or args.crawl or args.analyze or "")
                ),
                mode=str(mode),
                goal=_derive_goal_for_preflight(args),
                profile=str(args.profile or ""),
                cookies=str(args.cookie or ""),
                bearer_token=str(args.bearer_token or ""),
                debug=bool(args.debug),
            ),
        )

    # モード判定と実行
    if args.demo:
        run_grand_demo()
    elif args.interactive:
        # Phase 1: InteractiveBridge
        from src.core.conductor.interactive_bridge import start_interactive_session
        from src.core.models.llm import LLMClient
        llm_client = LLMClient(role="specialist_light")
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
                print_result(False, msg("result.projects.none"))
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
        
        # Resolve start_step from --recon-resume / --recon-start-step
        resolved_start_step = args.recon_start_step
        resume_state_path = None
        resume_source = None
        if args.recon_resume or args.recon_start_step is None:
            try:
                from src.core.project.project_manager import ProjectManager
                from src.recon.pipeline import resolve_resume_start_step
                pm = ProjectManager(args.recon)
                state_path = pm.project_dir / "recon_state.json"
                _start, _verdict = resolve_resume_start_step(
                    recon_resume=bool(args.recon_resume),
                    recon_start_step=args.recon_start_step,
                    state_path=state_path,
                    target=args.recon,
                )
                if resolved_start_step is None:
                    resolved_start_step = _start
                resume_state_path = _verdict.get("resume_state_path") or ""
                resume_source = _verdict.get("effective_resume_source", "fresh")
                logger.info(
                    "Recon resume verdict: %s start_step=%s resolved_via=%s resume=%s",
                    _verdict.get("resume_verdict", {}).get("reason_code", "n/a"),
                    _start,
                    _verdict.get("resolved_via", "n/a"),
                    resume_source,
                )
            except Exception as e:
                logger.warning("Resume resolver failed, using default start_step: %s", e)
                if resolved_start_step is None:
                    resolved_start_step = 1
        
        start_interactive_session(
            mode=mode,
            scope_file=scope_file,
            auto_goal="Reconnaissance",
            auto_target=args.recon,
            profile=args.profile,
            bearer_token=args.bearer_token,
            recon_start_step=resolved_start_step,
            recon_end_step=args.recon_end_step,
            resume_state_path=resume_state_path,
            resume_source=resume_source,
            import_recon_dir=args.import_recon,
        )
    elif args.target:
        target = args.target
        if target != "pending_fuzz" and not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        # Initialize Shared LLM Client
        from src.core.models.llm import LLMClient
        llm_client = LLMClient(role="specialist_light")
        
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
            print_step("⏭️", msg("step.recon_skip"))
        else:
            print_step("🔍", msg("step.recon_start"))
            asyncio.run(run_recon())
            print_step("✅", msg("step.recon_complete"))
        # --- Phase 3 End ---

        # Resolve start_step from --recon-resume / --recon-start-step
        resolved_target_start_step = args.recon_start_step
        resume_state_path = None
        resume_source = None
        if args.recon_resume or args.recon_start_step is None:
            try:
                from src.core.project.project_manager import ProjectManager
                from src.recon.pipeline import resolve_resume_start_step
                pm = ProjectManager(target)
                state_path = pm.project_dir / "recon_state.json"
                _start, _verdict = resolve_resume_start_step(
                    recon_resume=bool(args.recon_resume),
                    recon_start_step=args.recon_start_step,
                    state_path=state_path,
                    target=target,
                )
                if resolved_target_start_step is None:
                    resolved_target_start_step = _start
                resume_state_path = _verdict.get("resume_state_path") or ""
                resume_source = _verdict.get("effective_resume_source", "fresh")
                logger.info(
                    "Recon resume verdict: %s start_step=%s resolved_via=%s resume=%s",
                    _verdict.get("resume_verdict", {}).get("reason_code", "n/a"),
                    _start,
                    _verdict.get("resolved_via", "n/a"),
                    resume_source,
                )
            except Exception as e:
                logger.warning("Resume resolver failed, using default start_step: %s", e)
                if resolved_target_start_step is None:
                    resolved_target_start_step = 1

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
            recon_start_step=resolved_target_start_step,
            recon_end_step=args.recon_end_step,
            resume_state_path=resume_state_path,
            resume_source=resume_source,
            import_recon_dir=args.import_recon,
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
            llm_client = LLMClient(role="specialist_light")
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
            print_result(False, msg("result.rag.disabled"))
            return
        run_rag_ingest(args.rag_ingest, pdf_only=args.pdf_only, reset=args.reset_db)
    elif args.rag_query:
        if not config.rag_enabled:
            print_result(False, msg("result.rag.disabled"))
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
        print(msg("result.no_args_help_hint"))
        print(msg("result.no_args_modes"))


    # Wait for background threads (e.g., ReconWorker)
    import threading
    import time
    
    # メインループ終了後、バックグラウンドスレッドが残っていれば待機
    background_threads = [t for t in threading.enumerate() if t.name.startswith("ReconWorker-")]
    if background_threads:
        print(msg("result.background_waiting", count=len(background_threads)))
        try:
            for t in background_threads:
                if t.is_alive():
                    t.join()
        except KeyboardInterrupt:
            print(msg("result.interrupted"))

if __name__ == "__main__":
    main()
