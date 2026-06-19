"""Focused test selection and execution handlers.

Extracted from src.main.py to keep the CLI handler layer cohesive.
"""

import subprocess
import sys
from pathlib import Path
from typing import Any

from src.cli.handlers._shared import dedupe_keep_order, FOCUS_TEST_GROUPS, REPO_ROOT
from src.commands import print_step, print_result


def resolve_focus_test_paths(groups: list[str], custom_tests: list[str]) -> tuple[list[str], list[str]]:
    selected_groups = dedupe_keep_order(groups)
    if not selected_groups and not custom_tests:
        selected_groups = ["density"]

    if "all" in selected_groups:
        selected_groups = list(FOCUS_TEST_GROUPS.keys())

    paths: list[str] = []
    for group in selected_groups:
        paths.extend(FOCUS_TEST_GROUPS.get(group, []))
    paths.extend(custom_tests)
    return selected_groups, dedupe_keep_order(paths)


def print_focus_test_groups() -> None:
    print("Focused test groups:")
    for group, tests in FOCUS_TEST_GROUPS.items():
        print(f"- {group} ({len(tests)} tests)")
        for test_path in tests:
            print(f"  - {test_path}")


def resolve_focus_test_runtime_paths(selected_tests: list[str]) -> tuple[list[str], list[str], int]:
    """
    focused test path を runtime で解決する。

    - CWD で解決できる相対パスはそのまま使う
    - CWD で見つからない場合は repo root 基準で解決する
    """
    resolved_tests: list[str] = []
    missing_tests: list[str] = []
    repo_root_resolved_count = 0

    for raw_path in selected_tests:
        token = str(raw_path or "").strip()
        if not token:
            continue

        candidate = Path(token)
        if candidate.is_absolute():
            if candidate.exists():
                resolved_tests.append(str(candidate))
            else:
                missing_tests.append(token)
            continue

        cwd_candidate = Path.cwd() / candidate
        if cwd_candidate.exists():
            resolved_tests.append(token)
            continue

        repo_candidate = REPO_ROOT / candidate
        if repo_candidate.exists():
            resolved_tests.append(str(repo_candidate))
            repo_root_resolved_count += 1
            continue

        missing_tests.append(token)

    return dedupe_keep_order(resolved_tests), missing_tests, repo_root_resolved_count


def run_focused_tests(
    *,
    groups: list[str],
    custom_tests: list[str],
    fail_fast: bool = False,
    stage_label: str = "focused tests",
) -> tuple[int, list[str], list[str], list[str]]:
    """
    focused regression tests を実行して結果を返す。

    Returns:
        (exit_code, selected_groups, selected_tests, cmd)
    """
    selected_groups, selected_tests = resolve_focus_test_paths(groups, custom_tests)
    if not selected_tests:
        print_result(False, "No tests selected for focused mode.")
        return 2, selected_groups, selected_tests, []

    selected_tests, missing, repo_root_resolved_count = resolve_focus_test_runtime_paths(selected_tests)
    if repo_root_resolved_count > 0:
        print_step(
            "📍",
            f"Resolved {repo_root_resolved_count} focused tests via repo root: {REPO_ROOT}",
        )
    if missing:
        preview = ", ".join(missing[:3])
        suffix = " ..." if len(missing) > 3 else ""
        print_step("⚠️", f"Skipping missing focused tests: {preview}{suffix}")

    if not selected_tests:
        print_result(False, "Focused mode selected only missing tests.")
        return 2, selected_groups, selected_tests, []

    cmd = [sys.executable or "python3", "-m", "pytest", "-q"]
    if fail_fast:
        cmd.append("-x")
    cmd.extend(selected_tests)

    selected_group_text = ", ".join(selected_groups) if selected_groups else "(custom only)"
    print_step("🧪", f"Running {stage_label}: groups={selected_group_text}, tests={len(selected_tests)}")
    result = subprocess.run(cmd, check=False)
    if result.returncode == 0:
        print_result(True, f"{stage_label.capitalize()} passed")
    else:
        print_result(False, f"{stage_label.capitalize()} failed (exit={result.returncode})")
    return int(result.returncode), selected_groups, selected_tests, cmd
