"""Quality-loop scan command builder and precheck artifact writer.

Extracted from src/main.py to keep the main module focused on CLI entrypoint wiring.
"""

import sys
import subprocess
import argparse
import json
import logging
from pathlib import Path
from datetime import datetime

from src.cli.handlers._shared import DEFAULT_QUALITY_LOOP_GROUPS
from src.cli.handlers.focus_tests import run_focused_tests
from src.commands import print_step, print_result

# Module-level import alongside lazy import preserved in the function below.
from src.core.project.project_manager import ProjectManager  # noqa: F811

logger = logging.getLogger(__name__)


def build_quality_loop_scan_command(args: argparse.Namespace, *, short_mode: bool) -> list[str]:
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


def write_quality_loop_precheck_artifact(
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


def run_quality_loop(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.target:
        parser.error("--quality-loop requires --target")

    if args.quality_loop != "short":
        parser.error(f"Unsupported --quality-loop mode: {args.quality_loop}")

    raw_groups = [str(g).strip() for g in (args.focus_group or []) if str(g).strip()]
    raw_custom_tests = [str(t).strip() for t in (args.focus_test or []) if str(t).strip()]
    if not raw_groups and not raw_custom_tests:
        raw_groups = list(DEFAULT_QUALITY_LOOP_GROUPS)

    print_step("🧭", "Quality Loop 1/3: focused regression precheck")
    focus_exit, selected_groups, selected_tests, focus_cmd = run_focused_tests(
        groups=raw_groups,
        custom_tests=raw_custom_tests,
        fail_fast=bool(args.focus_fail_fast),
        stage_label="quality-loop precheck",
    )

    artifact_path = write_quality_loop_precheck_artifact(
        target=str(args.target),
        mode=str(args.quality_loop),
        selected_groups=selected_groups,
        selected_tests=selected_tests,
        focus_cmd=focus_cmd,
        focus_exit_code=focus_exit,
    )
    if artifact_path is not None:
        print_step("🗃️", f"Saved precheck artifact: {artifact_path}")

    if focus_exit != 0:
        if not selected_tests:
            print_step(
                "⚠️",
                "Focused precheck tests are unavailable in this runtime. "
                "Continuing with short attack loop.",
            )
        else:
            raise SystemExit(focus_exit)

    print_step("⚡", "Quality Loop 2/3: short attack loop")
    short_cmd = build_quality_loop_scan_command(args, short_mode=True)
    short_result = subprocess.run(short_cmd, check=False)
    if short_result.returncode != 0:
        print_result(False, f"Short attack loop failed (exit={short_result.returncode})")
        raise SystemExit(int(short_result.returncode))

    if args.quality_loop_full_scan:
        print_step("🧪", "Quality Loop 3/3: full scan (explicit)")
        full_cmd = build_quality_loop_scan_command(args, short_mode=False)
        full_result = subprocess.run(full_cmd, check=False)
        if full_result.returncode != 0:
            print_result(False, f"Full scan failed (exit={full_result.returncode})")
            raise SystemExit(int(full_result.returncode))
        print_result(True, "Quality loop completed: focus-tests -> short attack loop -> full scan")
        return

    print_result(True, "Quality loop completed: focus-tests -> short attack loop")
    print("Next: run full scan only if needed.")
