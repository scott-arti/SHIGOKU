#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.initial_release_gate import (
    DEFAULT_ALLOWED_MISSING_SCENARIOS,
    DEFAULT_REQUIRED_CONFIRMED_CLASSES,
    evaluate_initial_release_gate,
    set_locked_baseline,
)


def _parse_csv_tokens(raw: str) -> list[str]:
    tokens = [str(token or "").strip() for token in str(raw or "").split(",")]
    return [token for token in tokens if token]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate initial-release quality gate from a haddix report.",
    )
    parser.add_argument(
        "--report",
        required=True,
        help="Absolute or relative path to haddix_report_*.md",
    )
    parser.add_argument(
        "--session",
        help="Optional explicit session file path (session_*.json)",
    )
    parser.add_argument(
        "--sessions-dir",
        help="Optional sessions directory path when --session is not provided",
    )
    parser.add_argument(
        "--baseline-report",
        help="Optional baseline haddix_report_*.md path used as source of truth for delta comparison",
    )
    parser.add_argument(
        "--baseline-session",
        help="Optional baseline session path (session_*.json) paired with --baseline-report",
    )
    parser.add_argument(
        "--allowed-missing",
        default=",".join(DEFAULT_ALLOWED_MISSING_SCENARIOS),
        help=(
            "Comma-separated scenario IDs allowed to remain missing in initial release. "
            "Default: scn_08_oob_external_channel_flow,scn_10_semantic_business_logic,scn_12_advanced_ssrf_internal_topology"
        ),
    )
    parser.add_argument(
        "--confirmed-min",
        type=int,
        default=3,
        help="Minimum required confirmed findings count. Default: 3",
    )
    parser.add_argument(
        "--candidate-max",
        type=int,
        default=2,
        help="Maximum allowed candidate findings count. Default: 2",
    )
    parser.add_argument(
        "--confirmed-poc-missing-max",
        type=int,
        default=0,
        help="Maximum allowed confirmed findings without PoC request/response. Default: 0",
    )
    parser.add_argument(
        "--reason-code-missing-max",
        type=int,
        default=0,
        help="Maximum allowed candidate findings missing reason code. Default: 0",
    )
    parser.add_argument(
        "--required-confirmed-classes",
        default=",".join(DEFAULT_REQUIRED_CONFIRMED_CLASSES),
        help=(
            "Comma-separated detection classes that must reach confirmed threshold "
            "(e.g. access_control,idor_bola,mass_assignment,endpoint_bfla). "
            "Default: disabled"
        ),
    )
    parser.add_argument(
        "--required-class-confirmed-min",
        type=int,
        default=1,
        help="Minimum confirmed count required for each required detection class. Default: 1",
    )
    parser.add_argument("--schema-severity-critical-max", type=int, default=0)
    parser.add_argument("--schema-severity-high-max", type=int, default=0)
    parser.add_argument("--schema-severity-enforcement-mode", default="warn", choices=["warn", "soft-fail", "hard-fail"])
    parser.add_argument("--schema-severity-soft-fail-missing-ratio", type=float, default=0.2)
    parser.add_argument("--schema-severity-soft-fail-missing-count", type=int, default=3)
    parser.add_argument(
        "--set-locked-baseline",
        action="store_true",
        help="Update reports/quality_baseline_lock.json to this report/session pair after consistency verification.",
    )
    args = parser.parse_args()

    if args.set_locked_baseline:
        result = set_locked_baseline(
            Path(args.report),
            session_path=Path(args.session) if args.session else None,
            sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if bool(result.get("updated", False)) else 2

    allowed_missing = _parse_csv_tokens(args.allowed_missing)
    required_confirmed_classes = _parse_csv_tokens(args.required_confirmed_classes)
    verdict = evaluate_initial_release_gate(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        baseline_report_path=Path(args.baseline_report) if args.baseline_report else None,
        baseline_session_path=Path(args.baseline_session) if args.baseline_session else None,
        allowed_missing_scenarios=allowed_missing,
        confirmed_min=max(0, int(args.confirmed_min)),
        candidate_max=max(0, int(args.candidate_max)),
        confirmed_poc_missing_max=max(0, int(args.confirmed_poc_missing_max)),
        reason_code_missing_max=max(0, int(args.reason_code_missing_max)),
        required_confirmed_classes=required_confirmed_classes,
        required_class_confirmed_min=max(0, int(args.required_class_confirmed_min)),
        schema_severity_critical_max=max(0, int(args.schema_severity_critical_max)),
        schema_severity_high_max=max(0, int(args.schema_severity_high_max)),
        schema_severity_enforcement_mode=str(args.schema_severity_enforcement_mode or "warn"),
        schema_severity_soft_fail_missing_ratio=max(0.0, float(args.schema_severity_soft_fail_missing_ratio)),
        schema_severity_soft_fail_missing_count=max(0, int(args.schema_severity_soft_fail_missing_count)),
    )
    print(json.dumps(verdict, ensure_ascii=False, indent=2))

    status = str(verdict.get("status", "") or "").strip().lower()
    if status == "pass":
        return 0
    if status == "fail":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
