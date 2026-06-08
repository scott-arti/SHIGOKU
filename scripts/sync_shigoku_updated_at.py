#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import date
from pathlib import Path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Sync updated_at=today for docs/shigoku markdown front matter")
    p.add_argument("--repo-root", default=".", help="Repository root path")
    p.add_argument("--docs-root", default="docs/shigoku", help="Docs root path (relative to repo root)")
    p.add_argument("--all", action="store_true", help="Apply to all markdown files under docs root")
    return p.parse_args()


def changed_md_files(repo_root: Path, docs_root_rel: str) -> list[Path]:
    cmd = ["git", "status", "--porcelain", "--", docs_root_rel]
    out = subprocess.run(cmd, cwd=repo_root, check=False, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"git status failed: {out.stderr.strip()}")

    files: list[Path] = []
    for line in out.stdout.splitlines():
        if len(line) < 4:
            continue
        status = line[:2]
        rel = line[3:]
        if "->" in rel:
            rel = rel.split("->", 1)[1].strip()
        if status.strip() == "D":
            continue
        p = (repo_root / rel).resolve()
        if p.suffix.lower() == ".md" and p.exists():
            files.append(p)
    return sorted(set(files))


def all_md_files(docs_root: Path) -> list[Path]:
    return sorted(p.resolve() for p in docs_root.rglob("*.md"))


def update_front_matter_updated_at(md_path: Path, today: str) -> tuple[bool, str]:
    text = md_path.read_text(encoding="utf-8", errors="ignore")
    if not text.startswith("---\n"):
        return False, "no_front_matter"
    end = text.find("\n---\n", 4)
    if end == -1:
        return False, "no_front_matter_end"

    fm = text[4:end]
    body = text[end + 5 :]
    lines = fm.splitlines()

    updated_idx = -1
    created_idx = -1
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("updated_at:"):
            updated_idx = i
        if stripped.startswith("created_at:"):
            created_idx = i

    new_line = f"updated_at: '{today}'"
    changed = False

    if updated_idx >= 0:
        if lines[updated_idx].strip() != new_line:
            lines[updated_idx] = new_line
            changed = True
    else:
        insert_at = created_idx + 1 if created_idx >= 0 else len(lines)
        lines.insert(insert_at, new_line)
        changed = True

    if not changed:
        return False, "already_today"

    new_text = "---\n" + "\n".join(lines) + "\n---\n" + body
    md_path.write_text(new_text, encoding="utf-8")
    return True, "updated"


def main() -> int:
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    docs_root = (repo_root / args.docs_root).resolve()
    today = date.today().isoformat()

    if not docs_root.exists():
        print(f"ERROR: docs root not found: {docs_root}", file=sys.stderr)
        return 1

    if args.all:
        targets = all_md_files(docs_root)
    else:
        targets = changed_md_files(repo_root, args.docs_root)

    updated = 0
    skipped = 0
    for p in targets:
        changed, reason = update_front_matter_updated_at(p, today)
        rel = p.relative_to(repo_root).as_posix()
        if changed:
            updated += 1
            print(f"UPDATED\t{rel}")
        else:
            skipped += 1
            print(f"SKIPPED\t{rel}\t{reason}")

    print(f"TARGETS={len(targets)}")
    print(f"UPDATED={updated}")
    print(f"SKIPPED={skipped}")
    print(f"DATE={today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
