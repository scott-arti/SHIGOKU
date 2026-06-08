#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


def _seed_entry(url: str, method: str = "GET", source: str = "seed_set_v2", evidence: str = "") -> dict[str, Any]:
    return {
        "url": url,
        "method": method,
        "auth_context": {},
        "evidence": evidence,
        "original_id": None,
        "forms": [],
        "source": source,
        "response_status": 0,
        "response_headers": {},
        "response_body_snippet": "",
        "has_form_tag": False,
        "seed_set_id": "scn01-07_seed_v2",
    }


def _load_existing_urls(path: Path) -> set[str]:
    urls: set[str] = set()
    if not path.exists():
        return urls
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            item = json.loads(s)
            if isinstance(item, dict):
                u = str(item.get("url", "") or "").strip()
                if u:
                    urls.add(u)
        except Exception:
            continue
    return urls


def _resolve_target_file(tagged_dir: Path, date_str: str, category: str) -> Path:
    candidates = sorted(tagged_dir.glob(f"{date_str}_*_tagged_{category}.jsonl"))
    if candidates:
        return candidates[0]
    return tagged_dir / f"{date_str}_target_tagged_{category}.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser(description="Apply seed_set_v2 entries to tagged_urls files")
    ap.add_argument(
        "--project-dir",
        default="/home/bbb/Documents/App/Shigoku/tmp/bench_runtime/projects/127.0.0.1:8888",
        help="Project directory containing tagged_urls/",
    )
    ap.add_argument(
        "--date",
        default=datetime.now().strftime("%Y%m%d"),
        help="Date prefix YYYYMMDD (default: today)",
    )
    args = ap.parse_args()

    project_dir = Path(args.project_dir)
    tagged_dir = project_dir / "tagged_urls"
    tagged_dir.mkdir(parents=True, exist_ok=True)
    date_str = str(args.date)

    seed_map: dict[str, list[dict[str, Any]]] = {
        "admin": [
            _seed_entry("http://127.0.0.1:8888/admin", evidence="admin_surface"),
            _seed_entry("http://127.0.0.1:8888/profile?role=admin", evidence="role_param"),
        ],
        "auth": [
            _seed_entry("http://127.0.0.1:8888/profile", evidence="auth_profile"),
            _seed_entry("http://127.0.0.1:8888/login", evidence="auth_login"),
        ],
        "id_param": [
            _seed_entry("http://127.0.0.1:8888/orders/history?order_id=1001", evidence="idor_order_id"),
            _seed_entry("http://127.0.0.1:8888/reviews?user_id=2", evidence="idor_user_id"),
        ],
        "api_data": [
            _seed_entry("http://127.0.0.1:8888/chatbot/genai/state?account_id=2", evidence="api_account_id"),
            _seed_entry("http://127.0.0.1:8888/chatbot/genai/state?user_id=2", evidence="api_user_id"),
        ],
        "feedback_review": [
            _seed_entry("http://127.0.0.1:8888/reviews?review_id=2", evidence="review_id_param"),
            _seed_entry("http://127.0.0.1:8888/reviews?comment_id=3", evidence="comment_id_param"),
        ],
    }

    summary: dict[str, dict[str, Any]] = {}

    for category, entries in seed_map.items():
        target_file = _resolve_target_file(tagged_dir, date_str, category)
        existing_urls = _load_existing_urls(target_file)
        to_add = [e for e in entries if str(e.get("url", "")) not in existing_urls]

        if to_add:
            with target_file.open("a", encoding="utf-8") as f:
                for item in to_add:
                    f.write(json.dumps(item, ensure_ascii=False) + "\n")

        summary[category] = {
            "file": str(target_file),
            "existing": len(existing_urls),
            "added": len(to_add),
            "total_after": len(existing_urls) + len(to_add),
        }

    print(json.dumps({
        "project_dir": str(project_dir),
        "tagged_dir": str(tagged_dir),
        "date": date_str,
        "seed_set_id": "scn01-07_seed_v2",
        "summary": summary,
    }, ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
