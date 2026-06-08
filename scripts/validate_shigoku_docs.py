#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, unquote

import yaml

ALLOWED_DOC_TYPES = {
    "spec",
    "roadmap",
    "plan",
    "subtask_plan",
    "work_report",
    "work_log",
    "manual",
}
ALLOWED_STATUS = {"backlog", "active", "done", "deferred", "archived"}

LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
SKIP_SCHEMES = {"http", "https", "mailto", "tel", "data", "obsidian"}
TRACKING_TASK_ID_RE = re.compile(r"^SGK-\d{4}-\d{4}(?:-S\d{2})?$")


def load_md_files(docs_root: Path) -> list[Path]:
    files = sorted(docs_root.rglob("*.md"))
    excluded = {
        (docs_root / "registry" / "task_ledger.md").resolve(),
    }
    return [f for f in files if f.resolve() not in excluded]


def parse_front_matter(text: str) -> dict | None:
    m = re.match(r"^---\n([\s\S]*?)\n---\n", text)
    if not m:
        return None
    try:
        data = yaml.safe_load(m.group(1))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def check_front_matter(md_files: list[Path]) -> list[tuple[str, str]]:
    issues: list[tuple[str, str]] = []
    for f in md_files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        fm = parse_front_matter(text)
        rel = f.as_posix()
        if fm is None:
            issues.append((rel, "missing_or_invalid_front_matter"))
            continue

        if "task_id" not in fm:
            issues.append((rel, "missing_task_id"))
        if "doc_type" not in fm:
            issues.append((rel, "missing_doc_type"))
        else:
            if str(fm["doc_type"]) not in ALLOWED_DOC_TYPES:
                issues.append((rel, f"invalid_doc_type:{fm['doc_type']}"))
        if "status" not in fm:
            issues.append((rel, "missing_status"))
        else:
            if str(fm["status"]) not in ALLOWED_STATUS:
                issues.append((rel, f"invalid_status:{fm['status']}"))
        if "parent_task_id" not in fm:
            issues.append((rel, "missing_parent_task_id"))
        if "related_docs" not in fm:
            issues.append((rel, "missing_related_docs"))
        if "created_at" not in fm:
            issues.append((rel, "missing_created_at"))
        else:
            created = str(fm["created_at"])[:10]
            try:
                datetime.strptime(created, "%Y-%m-%d")
            except ValueError:
                issues.append((rel, f"invalid_created_at:{fm['created_at']}"))
        if "updated_at" not in fm:
            issues.append((rel, "missing_updated_at"))
        else:
            updated = str(fm["updated_at"])[:10]
            try:
                datetime.strptime(updated, "%Y-%m-%d")
            except ValueError:
                issues.append((rel, f"invalid_updated_at:{fm['updated_at']}"))
    return issues


def link_exists(file_path: Path, raw_target: str, repo_root: Path) -> bool:
    target = raw_target.split()[0].strip("<>")
    if not target or target.startswith("#"):
        return True

    parsed = urlparse(target)
    if parsed.scheme in SKIP_SCHEMES:
        return True

    if parsed.scheme == "file":
        return Path(unquote(parsed.path)).exists()

    base = target.split("#", 1)[0].split("?", 1)[0]
    if not base:
        return True
    if base.startswith("/"):
        path = repo_root / base.lstrip("/")
    else:
        path = (file_path.parent / base).resolve()
    return path.exists()


def check_links(md_files: list[Path], repo_root: Path) -> list[tuple[str, str]]:
    broken: list[tuple[str, str]] = []
    for f in md_files:
        text = f.read_text(encoding="utf-8", errors="ignore")
        rel = f.as_posix()
        for m in LINK_RE.finditer(text):
            raw = m.group(1).strip()
            if not link_exists(f, raw, repo_root):
                broken.append((rel, raw))
    return broken


def check_registry(docs_root: Path, repo_root: Path) -> tuple[list[str], int, int]:
    registry_path = docs_root / "registry" / "task_registry.yaml"
    if not registry_path.exists():
        return ([f"missing_registry:{registry_path.as_posix()}"], 0, 0)

    try:
        data = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    except Exception as e:
        return ([f"registry_parse_error:{e}"], 0, 0)

    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    if not isinstance(tasks, list):
        return (["registry_tasks_not_list"], 0, 0)

    issues: list[str] = []
    for i, t in enumerate(tasks, start=1):
        if not isinstance(t, dict):
            issues.append(f"task_{i}_invalid_entry")
            continue
        rel = t.get("primary_doc")
        task_id = t.get("task_id")
        doc_type = t.get("doc_type")
        status = t.get("status")
        if status not in ALLOWED_STATUS:
            issues.append(f"task_{i}_invalid_status:{status}")
        if doc_type not in ALLOWED_DOC_TYPES:
            issues.append(f"task_{i}_invalid_doc_type:{doc_type}")
        if not rel:
            issues.append(f"task_{i}_missing_primary_doc")
            continue
        p = repo_root / str(rel)
        if not p.exists():
            issues.append(f"task_{i}_missing_file:{rel}")
            continue

        text = p.read_text(encoding="utf-8", errors="ignore")
        fm = parse_front_matter(text)
        if fm is None:
            issues.append(f"task_{i}_no_front_matter:{rel}")
            continue

        if str(fm.get("task_id")) != str(task_id):
            issues.append(f"task_{i}_task_id_mismatch:{rel}")
        if str(fm.get("doc_type")) != str(doc_type):
            issues.append(f"task_{i}_doc_type_mismatch:{rel}")
        if str(fm.get("status")) != str(status):
            issues.append(f"task_{i}_status_mismatch:{rel}")

    return issues, len(tasks), len(load_md_files(docs_root))


def check_deferred_task_links(docs_root: Path, repo_root: Path) -> list[str]:
    issues: list[str] = []
    registry_path = docs_root / "registry" / "task_registry.yaml"
    if not registry_path.exists():
        return [f"missing_registry:{registry_path.as_posix()}"]

    try:
        data = yaml.safe_load(registry_path.read_text(encoding="utf-8"))
    except Exception as e:
        return [f"registry_parse_error:{e}"]

    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    if not isinstance(tasks, list):
        return ["registry_tasks_not_list"]

    task_by_id: dict[str, dict] = {}
    for t in tasks:
        if isinstance(t, dict):
            tid = str(t.get("task_id", "")).strip()
            if tid:
                task_by_id[tid] = t

    for f in load_md_files(docs_root):
        text = f.read_text(encoding="utf-8", errors="ignore")
        fm = parse_front_matter(text)
        if not isinstance(fm, dict):
            continue
        if str(fm.get("doc_type", "")) != "work_report":
            continue
        report_task_id = str(fm.get("task_id", "")).strip()
        rel = f.relative_to(repo_root).as_posix()

        try:
            body = text.split("\n---\n", 1)[1]
        except Exception:
            body = text

        fenced = re.search(r"(?ms)```(?:yaml)?\s*\n(deferred_tasks:\s*\n.*?)\n```", body)
        if fenced:
            deferred_yaml = fenced.group(1)
        else:
            inline = re.search(r"(?ms)^deferred_tasks:\s*\n(.*?)(?:\n## |\n# |\Z)", body)
            if not inline:
                continue
            deferred_yaml = "deferred_tasks:\n" + inline.group(1)
        if not deferred_yaml:
            continue
        try:
            deferred_obj = yaml.safe_load(deferred_yaml) or {}
        except Exception as e:
            issues.append(f"deferred_tasks_parse_error:{rel}:{e}")
            continue

        deferred_items = deferred_obj.get("deferred_tasks", [])
        if not isinstance(deferred_items, list):
            issues.append(f"deferred_tasks_not_list:{rel}")
            continue

        for idx, item in enumerate(deferred_items, start=1):
            if not isinstance(item, dict):
                issues.append(f"deferred_item_invalid:{rel}:{idx}")
                continue
            deferred_id = str(item.get("deferred_id", "")).strip()
            if not deferred_id:
                deferred_id = str(item.get("task_id", "")).strip()
            if not deferred_id:
                continue
            if not TRACKING_TASK_ID_RE.match(deferred_id):
                # Backward-compatible: legacy deferred IDs (e.g. SGK-...-D01) are advisory labels.
                continue
            if deferred_id not in task_by_id:
                issues.append(f"deferred_unknown_task_id:{rel}:{deferred_id}")
                continue

            t = task_by_id[deferred_id]
            status = str(t.get("status", "")).strip()
            if status not in {"active", "backlog", "deferred"}:
                issues.append(f"deferred_invalid_status:{rel}:{deferred_id}:{status}")

            primary_doc = str(t.get("primary_doc", "")).strip()
            if primary_doc:
                child_doc_path = (repo_root / primary_doc).resolve()
                if child_doc_path.exists():
                    child_text = child_doc_path.read_text(encoding="utf-8", errors="ignore")
                    child_fm = parse_front_matter(child_text) or {}
                    child_related = child_fm.get("related_docs", [])
                    if isinstance(child_related, list):
                        if rel not in [str(x) for x in child_related]:
                            issues.append(f"deferred_related_docs_missing:{primary_doc}:{report_task_id}")
                    else:
                        issues.append(f"deferred_related_docs_invalid:{primary_doc}")
    return issues


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate docs/shigoku link/frontmatter/registry consistency")
    parser.add_argument("--repo-root", default=".", help="Repository root path")
    parser.add_argument("--docs-root", default="docs/shigoku", help="Docs root path (relative to repo root)")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    docs_root = (repo_root / args.docs_root).resolve()

    md_files = load_md_files(docs_root)
    fm_issues = check_front_matter(md_files)
    broken_links = check_links(md_files, repo_root)
    reg_issues, reg_entries, md_count = check_registry(docs_root, repo_root)
    deferred_issues = check_deferred_task_links(docs_root, repo_root)

    print(f"MD_FILES={len(md_files)}")
    print(f"FRONT_MATTER_ISSUES={len(fm_issues)}")
    print(f"BROKEN_LINKS={len(broken_links)}")
    print(f"REGISTRY_ISSUES={len(reg_issues)}")
    print(f"DEFERRED_LINK_ISSUES={len(deferred_issues)}")
    print(f"REGISTRY_ENTRIES={reg_entries}")
    print(f"REGISTRY_MD_COUNT={md_count}")

    for rel, issue in fm_issues[:50]:
        print(f"FM_ISSUE\t{rel}\t{issue}")
    for rel, link in broken_links[:50]:
        print(f"BROKEN_LINK\t{rel}\t{link}")
    for issue in reg_issues[:50]:
        print(f"REGISTRY_ISSUE\t{issue}")
    for issue in deferred_issues[:50]:
        print(f"DEFERRED_ISSUE\t{issue}")

    total_issues = len(fm_issues) + len(broken_links) + len(reg_issues) + len(deferred_issues)
    return 0 if total_issues == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
