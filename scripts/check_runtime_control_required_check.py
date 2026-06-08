#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path
from typing import Any


def _api_get(url: str, token: str) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "shigoku-runtime-control-required-check",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=20) as res:  # noqa: S310
        return json.loads(res.read().decode("utf-8"))


def _parse_required_contexts(cli_values: list[str] | None) -> list[str]:
    values = [str(x).strip() for x in (cli_values or []) if str(x).strip()]
    if values:
        return values
    env_raw = str(os.environ.get("SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS", "") or "").strip()
    if env_raw:
        parsed = [token.strip() for token in env_raw.split(",") if token.strip()]
        if parsed:
            return parsed
    return ["runtime-control-governance"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify branch protection required checks include runtime-control-governance.")
    parser.add_argument("--event-path", required=True, help="Path to GitHub event payload JSON.")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument(
        "--required-context",
        action="append",
        default=None,
        help="Required status check context (repeatable).",
    )
    parser.add_argument(
        "--runbook-url",
        default="https://github.com/shigoku/shigoku/blob/main/docs/shigoku/manuals/2026-05-26_runtime-control-fail-open-guard_runbook.md",
        help="Runbook URL shown when validation fails.",
    )
    args = parser.parse_args()

    token = str(os.environ.get("GITHUB_TOKEN", "") or "").strip()
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 2

    event = json.loads(Path(args.event_path).read_text(encoding="utf-8"))
    pr = event.get("pull_request") or {}
    base_ref = str((pr.get("base") or {}).get("ref") or "").strip()
    if not base_ref:
        print("pull_request base ref missing", file=sys.stderr)
        return 2

    repo = str(args.repo).strip()
    protection = _api_get(f"https://api.github.com/repos/{repo}/branches/{base_ref}/protection", token)
    checks = (protection.get("required_status_checks") or {}).get("contexts") or []
    actual = {str(x).strip() for x in checks if str(x).strip()}
    required = set(_parse_required_contexts(args.required_context))
    missing = sorted(required - actual)
    if missing:
        print(
            json.dumps(
                {
                    "status": "fail",
                    "missing_contexts": missing,
                    "actual_contexts": sorted(actual),
                    "runbook_url": str(args.runbook_url),
                    "message": "Required status check is not configured in branch protection. See runbook_url.",
                },
                ensure_ascii=False,
            )
        )
        return 3
    print(
        json.dumps(
            {
                "status": "pass",
                "required_contexts": sorted(required),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
