#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.session_finding_inspector import inspect_session_findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inspect canonical findings from a SHIGOKU session without double-counting mirrored result/data lists.",
    )
    parser.add_argument(
        "--session",
        required=True,
        help="Absolute or relative path to session_*.json",
    )
    parser.add_argument(
        "--detection-class",
        help="Optional detection class filter (for example: idor_bola)",
    )
    args = parser.parse_args()

    summary = inspect_session_findings(
        Path(args.session),
        detection_class=args.detection_class,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
