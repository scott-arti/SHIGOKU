#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

REQUIRED_SECTIONS = [
    "Reason:",
    "Expected Impact:",
    "KPI Evidence",
    "Rollback Plan:",
    "Security Approver: @",
]


def _run(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()


def _changed_files(base: str, head: str) -> list[str]:
    out = _run(["git", "diff", "--name-only", f"{base}...{head}"])
    return [line.strip() for line in out.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description="Check PR policy for SSRF quality config changes")
    parser.add_argument("--event-path", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    args = parser.parse_args()

    event = json.loads(Path(args.event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request", {})
    body = str(pr.get("body") or "")

    changed = _changed_files(args.base, args.head)
    changed_features = "config/features.yaml" in changed

    if not changed_features:
        print("No config/features.yaml change detected. Policy check skipped.")
        return 0

    # Only enforce when ssrf_quality block changed.
    diff = _run(["git", "diff", f"{args.base}...{args.head}", "--", "config/features.yaml"])
    if "ssrf_quality" not in diff:
        print("config/features.yaml changed, but ssrf_quality block unchanged. Policy check skipped.")
        return 0

    missing = [s for s in REQUIRED_SECTIONS if s not in body]
    if missing:
        print("Missing required PR sections for SSRF quality change:")
        for m in missing:
            print(f"- {m}")
        return 2

    print("SSRF PR policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
