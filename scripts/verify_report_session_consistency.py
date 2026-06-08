#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.report_session_consistency import verify_report_session_consistency


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify consistency between a haddix report and its source session.",
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
    args = parser.parse_args()

    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
    )
    print(json.dumps(verdict, ensure_ascii=False, indent=2))

    status = str(verdict.get("status", "") or "").strip().lower()
    if status == "consistent":
        return 0
    if status == "inconsistent":
        return 3
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
