"""Shared utilities and constants for CLI handler modules."""

import re
from pathlib import Path

# ---- Constants ----

FOCUS_TEST_GROUPS: dict[str, list[str]] = {
    "density": [
        "tests/core/engine/test_attack_planner_scope_filter.py",
        "tests/core/engine/test_master_conductor_scenario_probes.py",
        "tests/unit/agents/swarm/test_fuzzing.py",
    ],
    "report": [
        "tests/unit/reporting/test_report_session_consistency.py",
        "tests/unit/main/test_main_report_haddix.py",
    ],
    "hitl": [
        "tests/core/test_main_hitl_session_selection.py",
    ],
    "fast_mc_recon": [
        "tests/core/engine/test_master_conductor_api_candidate_routing.py",
        "tests/core/engine/test_master_conductor_vuln_family_gate.py",
        "tests/core/engine/test_master_conductor_realtime_budget.py",
        "tests/recon/test_tagged_uncategorized_promotion.py",
    ],
}

DEFAULT_QUALITY_LOOP_GROUPS: list[str] = ["density", "report"]
REPO_ROOT = Path(__file__).resolve().parents[3]


# ---- Shared Utilities ----

def dedupe_keep_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        token = str(item or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        deduped.append(token)
    return deduped


def session_order_key(path: Path) -> tuple[int, float]:
    """
    Session name `session_YYYYMMDD_HHMMSS.json` time-series priority,
    with mtime as fallback.
    """
    name = path.name
    match = re.match(r"^session_(\d{8})_(\d{6})\.json$", name)
    seq = int(f"{match.group(1)}{match.group(2)}") if match else -1
    try:
        mtime = float(path.stat().st_mtime)
    except Exception:
        mtime = 0.0
    return (seq, mtime)


def report_artifact_order_key(path: Path, prefix: str) -> tuple[int, float]:
    """
    Report artifact `prefix_YYYYMMDD_HHMMSS.json` time-series priority,
    with mtime as fallback.
    """
    name = path.name
    match = re.match(rf"^{re.escape(prefix)}_(\d{{8}})_(\d{{6}})\.json$", name)
    seq = int(f"{match.group(1)}{match.group(2)}") if match else -1
    try:
        mtime = float(path.stat().st_mtime)
    except Exception:
        mtime = 0.0
    return (seq, mtime)
