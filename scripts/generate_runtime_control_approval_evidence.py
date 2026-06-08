#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


def _api_get(url: str, token: str, *, retries: int, initial_backoff_seconds: float) -> Any:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "shigoku-runtime-control-governance",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as res:  # noqa: S310
                return json.loads(res.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt >= retries:
                break
            time.sleep(initial_backoff_seconds * (2**attempt))
    raise RuntimeError(f"api_get_failed: {url}") from last_error


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate runtime control approval evidence from GitHub API.")
    parser.add_argument("--event-path", required=True, help="Path to GitHub event payload JSON.")
    parser.add_argument("--repo", required=True, help="owner/repo")
    parser.add_argument("--output", required=True, help="Output JSON path.")
    parser.add_argument("--retries", type=int, default=2, help="Retry count for GitHub API calls.")
    parser.add_argument("--initial-backoff-seconds", type=float, default=2.0, help="Initial retry backoff seconds.")
    args = parser.parse_args()

    token = str(os.environ.get("GITHUB_TOKEN", "") or "").strip()
    if not token:
        print("GITHUB_TOKEN is required", file=sys.stderr)
        return 2

    event_path = Path(args.event_path).expanduser().resolve()
    if not event_path.exists():
        print(f"event file not found: {event_path}", file=sys.stderr)
        return 2

    event = json.loads(event_path.read_text(encoding="utf-8"))
    pr = event.get("pull_request") or {}
    pull_number = int(pr.get("number") or 0)
    base_ref = str((pr.get("base") or {}).get("ref") or "").strip()
    if pull_number <= 0 or not base_ref:
        print("pull_request context is required", file=sys.stderr)
        return 2

    repo = str(args.repo).strip()
    reviews_url = f"https://api.github.com/repos/{repo}/pulls/{pull_number}/reviews?per_page=100"
    protection_url = f"https://api.github.com/repos/{repo}/branches/{base_ref}/protection"

    reviews = _api_get(
        reviews_url,
        token,
        retries=max(0, int(args.retries)),
        initial_backoff_seconds=max(0.1, float(args.initial_backoff_seconds)),
    )
    protection = _api_get(
        protection_url,
        token,
        retries=max(0, int(args.retries)),
        initial_backoff_seconds=max(0.1, float(args.initial_backoff_seconds)),
    )

    if not isinstance(reviews, list):
        print("invalid reviews response", file=sys.stderr)
        return 2

    approved_review_ids: list[str] = []
    approvers: set[str] = set()
    for review in reviews:
        if str(review.get("state", "") or "").upper() != "APPROVED":
            continue
        review_id = int(review.get("id") or 0)
        login = str((review.get("user") or {}).get("login") or "").strip()
        if review_id <= 0:
            continue
        approved_review_ids.append(f"{repo}#{pull_number}:{review_id}")
        if login:
            approvers.add(login)

    required_reviews = int(
        ((protection.get("required_pull_request_reviews") or {}).get("required_approving_review_count") or 0)
    )
    require_code_owner_reviews = bool(
        ((protection.get("required_pull_request_reviews") or {}).get("require_code_owner_reviews") or False)
    )
    payload = {
        "source": "github_pr_review_api",
        "repo": repo,
        "pull_number": pull_number,
        "base_ref": base_ref,
        "required_approving_review_count": required_reviews,
        "require_code_owner_reviews": require_code_owner_reviews,
        "approved_unique_count": len(approvers),
        "approved_review_ids": sorted(set(approved_review_ids)),
    }
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
