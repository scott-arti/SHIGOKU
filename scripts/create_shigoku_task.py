#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import yaml

ALLOWED_DOC_TYPES = ["spec", "roadmap", "plan", "subtask_plan", "work_report", "work_log", "manual"]
ALLOWED_STATUS = ["backlog", "active", "done", "deferred", "archived"]
TASK_DOC_TYPES = ["plan", "subtask_plan"]


@dataclass
class TaskCreateResult:
    task_id: str
    provisional_id: str
    plan_path: Path


def slugify(text: str) -> str:
    text = text.strip().lower()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-")
    return text or "task"


def load_registry(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"registry not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("registry yaml is not a mapping")
    data.setdefault("tasks", [])
    if not isinstance(data["tasks"], list):
        raise ValueError("registry tasks is not a list")
    return data


def next_task_id(tasks: list[dict[str, Any]], year: int) -> str:
    pat = re.compile(rf"^SGK-{year}-(\d{{4}})$")
    max_no = 0
    for t in tasks:
        m = pat.match(str(t.get("task_id", "")))
        if m:
            max_no = max(max_no, int(m.group(1)))
    return f"SGK-{year}-{max_no + 1:04d}"


def next_provisional_id(tasks: list[dict[str, Any]]) -> str:
    pat = re.compile(r"^DOC-(\d{4})$")
    max_no = 0
    for t in tasks:
        m = pat.match(str(t.get("provisional_id", "")))
        if m:
            max_no = max(max_no, int(m.group(1)))
    return f"DOC-{max_no + 1:04d}"


def unique_plan_path(plans_dir: Path, today: str, slug: str, doc_type: str) -> Path:
    suffix = "_subtask_plan.md" if doc_type == "subtask_plan" else "_plan.md"
    base = plans_dir / f"{today}_{slug}{suffix}"
    if not base.exists():
        return base
    i = 2
    while True:
        suffix_v = "_subtask_plan_v" if doc_type == "subtask_plan" else "_plan_v"
        cand = plans_dir / f"{today}_{slug}{suffix_v}{i}.md"
        if not cand.exists():
            return cand
        i += 1


def build_plan_markdown(
    *,
    task_id: str,
    title: str,
    status: str,
    parent_task_id: str | None,
    related_docs: list[str],
    today: str,
    target: str,
    doc_type: str,
) -> str:
    fm = {
        "task_id": task_id,
        "doc_type": doc_type,
        "status": status,
        "parent_task_id": parent_task_id,
        "related_docs": related_docs,
        "title": title,
        "created_at": today,
        "updated_at": today,
        "tags": ["shigoku"],
        "target": target,
    }
    fm_text = yaml.safe_dump(fm, sort_keys=False, allow_unicode=True).rstrip()

    body = f"""# 実装計画書：{title}

## 1. 達成したいゴール（ユーザー視点）
- [ ] [ユーザー操作]を行うと、[期待する結果]が実現されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `[path/to/file]`: （新規/修正）[役割]
- **データの流れ / 依存関係:**
  - [入力元] -> [処理] -> [保存/表示先]

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** [name] ([type]), [name] ([type])
- **出力/結果 (Output):** [成功時の結果], [失敗時の挙動]
- **制約・ルール:**
  - [必須ルール1]
  - [必須ルール2]
  - [品質/型/セキュリティ制約]

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: [変更対象と作業内容]
- [ ] ステップ2: [単体確認・テスト観点]
- [ ] ステップ3: [統合・接続・最終確認]

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:低/中/高] [懸念内容] - [次回対応方針]

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: {task_id}-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
"""
    return f"---\n{fm_text}\n---\n\n{body}"


def write_task_ledger(docs_root: Path, registry: dict[str, Any]) -> None:
    tasks = registry.get("tasks", [])
    ledger_md = docs_root / "registry" / "task_ledger.md"
    ledger_csv = docs_root / "registry" / "task_ledger.csv"

    lines: list[str] = []
    lines.append("# SHIGOKU タスク台帳\n\n")
    lines.append(f"- 更新日: {registry.get('updated_at', date.today().isoformat())}\n")
    lines.append(f"- 総タスク数: {len(tasks)}\n")
    lines.append("- ステータス許可値: backlog / active / done / deferred / archived\n")
    lines.append("- doc_type 許可値: spec / roadmap / plan / subtask_plan / work_report / work_log / manual\n\n")
    lines.append("| Task ID | Task Content | Status | Doc Type | Parent Task | Primary Doc |\n")
    lines.append("|---|---|---|---|---|---|\n")
    for t in tasks:
        parent = t.get("parent_task_id") or ""
        title = str(t.get("task_summary") or t.get("title") or "").replace("|", "\\|")
        lines.append(
            f"| {t.get('task_id','')} | {title} | {t.get('status','')} | {t.get('doc_type','')} | {parent} | {t.get('primary_doc','')} |\n"
        )
    ledger_md.write_text("".join(lines), encoding="utf-8")

    with ledger_csv.open("w", newline="", encoding="utf-8") as fp:
        writer = csv.writer(fp)
        writer.writerow(["task_id", "task_content", "status", "doc_type", "parent_task_id", "primary_doc"])
        for t in tasks:
            writer.writerow(
                [
                    t.get("task_id", ""),
                    t.get("task_summary") or t.get("title") or "",
                    t.get("status", ""),
                    t.get("doc_type", ""),
                    t.get("parent_task_id") or "",
                    t.get("primary_doc", ""),
                ]
            )


def create_task(args: argparse.Namespace) -> TaskCreateResult:
    repo_root = Path(args.repo_root).resolve()
    docs_root = (repo_root / "docs" / "shigoku").resolve()
    if args.plans_dir:
        plans_dir = (repo_root / args.plans_dir).resolve()
    elif args.doc_type == "subtask_plan":
        plans_dir = (repo_root / "docs" / "shigoku" / "subtasks").resolve()
    else:
        plans_dir = (repo_root / "docs" / "shigoku" / "plans").resolve()
    registry_path = (docs_root / "registry" / "task_registry.yaml").resolve()

    if args.status not in ALLOWED_STATUS:
        raise ValueError(f"invalid status: {args.status}")

    plans_dir.mkdir(parents=True, exist_ok=True)

    registry = load_registry(registry_path)
    tasks = registry["tasks"]

    year = args.year or date.today().year
    task_id = next_task_id(tasks, year)
    provisional_id = next_provisional_id(tasks)

    today = date.today().isoformat()
    slug = args.slug or slugify(args.title)
    plan_path = unique_plan_path(plans_dir, today, slug, args.doc_type)

    parent_task_id = args.parent_task_id if args.parent_task_id else None
    related_docs = args.related_docs or []

    rel_plan_path = plan_path.relative_to(repo_root).as_posix()
    plan_content = build_plan_markdown(
        task_id=task_id,
        title=args.title,
        status=args.status,
        parent_task_id=parent_task_id,
        related_docs=related_docs,
        today=today,
        target=args.target,
        doc_type=args.doc_type,
    )

    if not args.dry_run:
        plan_path.write_text(plan_content, encoding="utf-8")

    task_entry = {
        "provisional_id": provisional_id,
        "task_id": task_id,
        "doc_type": args.doc_type,
        "title": args.title,
        "primary_doc": rel_plan_path,
        "status": args.status,
        "provisional": False,
        "task_summary": args.title,
        "parent_task_id": parent_task_id,
        "related_docs": related_docs,
    }

    tasks.append(task_entry)
    registry["updated_at"] = today
    registry["status_allowed_values"] = ALLOWED_STATUS
    registry["doc_type_allowed_values"] = ALLOWED_DOC_TYPES

    if not args.dry_run:
        registry_path.write_text(yaml.safe_dump(registry, sort_keys=False, allow_unicode=True), encoding="utf-8")
        write_task_ledger(docs_root, registry)

    return TaskCreateResult(task_id=task_id, provisional_id=provisional_id, plan_path=plan_path)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Create new SHIGOKU task: assign ID + update registry + scaffold plan")
    p.add_argument("--title", required=True, help="Task title")
    p.add_argument("--doc-type", default="plan", choices=TASK_DOC_TYPES, help="Task document type (plan/subtask_plan)")
    p.add_argument("--slug", help="Slug for plan file name (optional)")
    p.add_argument("--status", default="active", choices=ALLOWED_STATUS, help="Initial status")
    p.add_argument("--parent-task-id", help="Parent task ID (optional)")
    p.add_argument("--related-doc", dest="related_docs", action="append", default=[], help="Related doc path (repeatable)")
    p.add_argument("--target", default="", help="Target system/module (optional)")
    p.add_argument("--year", type=int, help="ID year (default: current year)")
    p.add_argument("--plans-dir", default="", help="Output directory override (default: plans or subtasks by doc-type)")
    p.add_argument("--repo-root", default=".", help="Repository root")
    p.add_argument("--dry-run", action="store_true", help="Preview only, do not write")
    p.add_argument("--run-validate", action="store_true", help="Run docs validator after write")
    p.add_argument(
        "--skip-sync-updated-at",
        action="store_true",
        help="Skip internal updated_at sync (debug/exceptional use only)",
    )
    return p.parse_args()


def run_sync_updated_at(repo_root: Path) -> int:
    cmd = [sys.executable, "scripts/sync_shigoku_updated_at.py", "--repo-root", str(repo_root)]
    completed = subprocess.run(cmd, cwd=repo_root)
    return completed.returncode


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    try:
        result = create_task(args)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    print(f"TASK_ID={result.task_id}")
    print(f"PROVISIONAL_ID={result.provisional_id}")
    print(f"PLAN_PATH={result.plan_path}")
    print(f"DRY_RUN={args.dry_run}")

    if not args.dry_run and not args.skip_sync_updated_at:
        sync_rc = run_sync_updated_at(repo_root)
        if sync_rc != 0:
            return sync_rc

    if args.run_validate and not args.dry_run:
        cmd = [sys.executable, "scripts/validate_shigoku_docs.py", "--repo-root", str(repo_root)]
        completed = subprocess.run(cmd, cwd=repo_root)
        return completed.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
