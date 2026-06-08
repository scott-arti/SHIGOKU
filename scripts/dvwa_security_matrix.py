#!/usr/bin/env python3
"""Run DVWA regression scans across security levels and collect summaries."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List
from urllib.parse import urlsplit


@dataclass
class LevelRunResult:
    security_level: str
    scan_exit_code: int
    report_exit_code: int
    duration_seconds: float
    scan_log_path: str
    report_log_path: str


def _project_key_from_target(target: str) -> str:
    parsed = urlsplit(target)
    host = parsed.hostname or "unknown"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}:{port}"


def _run_and_log(cmd: List[str], log_path: Path) -> int:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("w", encoding="utf-8") as log_file:
        process = subprocess.run(cmd, stdout=log_file, stderr=subprocess.STDOUT, check=False)
    return int(process.returncode)


def _build_scan_command(args: argparse.Namespace, level: str) -> List[str]:
    cookie = f"PHPSESSID={args.phpsessid}; security={level}"
    cmd = [
        sys.executable,
        "-m",
        "src.main",
        "--recon",
        args.target,
        "--profile",
        args.profile,
        "--cookie",
        cookie,
    ]
    if args.mode:
        cmd.extend(["--mode", args.mode])
    if args.scope:
        cmd.extend(["--scope", args.scope])
    if args.debug:
        cmd.append("--debug")
    return cmd


def _build_report_command(target: str) -> List[str]:
    return [
        sys.executable,
        "-m",
        "src.main",
        "--report",
        "--target",
        target,
        "--format",
        "haddix",
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DVWA low/medium/high regression runner")
    parser.add_argument("--target", required=True, help="DVWA base URL, e.g. http://localhost:4280")
    parser.add_argument("--phpsessid", required=True, help="Authenticated DVWA PHPSESSID")
    parser.add_argument("--levels", default="low,medium,high", help="Comma-separated security levels")
    parser.add_argument("--profile", default="bbpt", choices=["bbpt", "ctf"], help="SHIGOKU scan profile")
    parser.add_argument("--mode", default="bugbounty", choices=["bugbounty", "vulntest", "ctf"], help="SHIGOKU mode")
    parser.add_argument("--scope", default="", help="Optional scope file path")
    parser.add_argument("--debug", action="store_true", help="Enable SHIGOKU debug mode")
    parser.add_argument(
        "--output-dir",
        default="",
        help="Optional output directory. Defaults to workspace/projects/<host:port>/regression",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    levels = [lvl.strip() for lvl in args.levels.split(",") if lvl.strip()]
    if not levels:
        print("No security levels provided.")
        return 2

    project_key = _project_key_from_target(args.target)
    default_output = Path("workspace") / "projects" / project_key / "regression"
    output_dir = Path(args.output_dir) if args.output_dir else default_output
    output_dir.mkdir(parents=True, exist_ok=True)

    run_results: List[LevelRunResult] = []

    for level in levels:
        started_at = time.time()

        scan_log_path = output_dir / f"scan_{level}.log"
        report_log_path = output_dir / f"report_{level}.log"

        scan_cmd = _build_scan_command(args, level)
        print(f"[dvwa-matrix] running scan: level={level}")
        scan_rc = _run_and_log(scan_cmd, scan_log_path)

        report_cmd = _build_report_command(args.target)
        print(f"[dvwa-matrix] generating report: level={level}")
        report_rc = _run_and_log(report_cmd, report_log_path)

        duration = round(time.time() - started_at, 3)
        run_results.append(
            LevelRunResult(
                security_level=level,
                scan_exit_code=scan_rc,
                report_exit_code=report_rc,
                duration_seconds=duration,
                scan_log_path=str(scan_log_path),
                report_log_path=str(report_log_path),
            )
        )

    summary_path = output_dir / "matrix_summary.json"
    summary_payload = {
        "target": args.target,
        "profile": args.profile,
        "mode": args.mode,
        "levels": levels,
        "runs": [asdict(item) for item in run_results],
    }
    summary_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[dvwa-matrix] summary: {summary_path}")
    failed = [r for r in run_results if r.scan_exit_code != 0 or r.report_exit_code != 0]
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
