"""
AttackReviewBuilder: finalized session data -> additive review fields.

Pure helper: reads from decision_traces, task_execution_records, run_ledger,
context.target_info, completed_tasks, coverage_gate, and scenario_coverage.
Produces target_system_profile, attack_review_trail, and scenario_candidates.

Rules:
- No raw token/cookie/header/prompt/response is ever stored.
- Every entry includes source_refs for traceability.
- Intermediate state (current_context etc.) is never used as the ground truth.
- Existing fields are never removed or renamed.
"""
from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Schema constants
# ---------------------------------------------------------------------------

PROFILE_SCHEMA_VERSION = 1
TRAIL_SCHEMA_VERSION = 1
CANDIDATE_SCHEMA_VERSION = 1

MAX_TRAIL_ENTRIES = 200
MAX_CANDIDATES = 50

# ---------------------------------------------------------------------------
# Secret-bearing key patterns (case-insensitive check)
# ---------------------------------------------------------------------------

_SECRET_KEY_SUBSTRINGS = (
    "cookie", "token", "api_key", "apikey", "password", "secret",
    "authorization", "auth_header", "bearer", "credential", "passwd",
    "private_key", "access_key",
)

_REDACTED = "[REDACTED]"


def _is_secret_key(key: str) -> bool:
    key_lower = key.lower().replace("-", "_").replace(" ", "_")
    return any(s in key_lower for s in _SECRET_KEY_SUBSTRINGS)


def _redact_value(value: Any) -> Any:
    """Recursively redact values under secret-bearing keys."""
    if isinstance(value, dict):
        return {k: _REDACTED if _is_secret_key(k) else _redact_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v) for v in value]
    return value


def _safe_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def _safe_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _make_source_ref(source_type: str, source_id: str, location: str = "") -> str:
    """Build a stable source_ref string."""
    if location:
        return f"{source_type}.{source_id}#{location}"
    return f"{source_type}.{source_id}"


# ===================================================================
# Public API
# ===================================================================


def build_target_system_profile(
    session_data: dict,
    session_id: str | None = None,
    run_id: str | None = None,
) -> dict | None:
    """Build target_system_profile from context.target_info and completed_tasks.

    Returns None when there is no meaningful data to profile.
    """
    context = _safe_dict(session_data.get("context", {}))
    target_info = _safe_dict(context.get("target_info", {}))

    url = _safe_str(target_info.get("url", target_info.get("domain", "")))
    host = _safe_str(target_info.get("domain", target_info.get("host", "")))
    if not url and not host:
        # Check completed_tasks for a target_url
        for t in _safe_list(session_data.get("completed_tasks", [])):
            tu = _safe_str(t.get("target_url", ""))
            if tu:
                url = tu
                break

    if not url and not host:
        return None

    # Auth methods
    auth_methods: List[str] = []
    auth_raw = target_info.get("auth_mechanisms", [])
    if isinstance(auth_raw, list):
        for a in auth_raw:
            if isinstance(a, dict):
                name = _safe_str(a.get("name", a.get("type", "")))
                if name:
                    auth_methods.append(name)
            elif isinstance(a, str):
                auth_methods.append(a)
    elif isinstance(auth_raw, str):
        auth_methods = [auth_raw]

    # Tech stack
    tech_stack: Dict[str, str] = {}
    ts_raw = target_info.get("tech_stack", {})
    if isinstance(ts_raw, dict):
        tech_stack = {_safe_str(k): _safe_str(v) for k, v in ts_raw.items()}
    elif isinstance(ts_raw, list):
        for item in ts_raw:
            if isinstance(item, dict):
                name = _safe_str(item.get("name", item.get("technology", "")))
                ver = _safe_str(item.get("version", ""))
                if name:
                    tech_stack[name] = ver

    # Key features from task types
    completed = _safe_list(session_data.get("completed_tasks", []))
    task_types: set[str] = set()
    for t in completed:
        at = _safe_str(t.get("agent_type", t.get("action", "")))
        if at:
            task_types.add(at)

    # Key endpoints from discovered assets + completed task URLs
    key_endpoints: List[Dict[str, str]] = []
    seen_urls: set[str] = set()
    discovered = _safe_list(context.get("discovered_assets", []))
    for asset in discovered:
        if isinstance(asset, dict):
            u = _safe_str(asset.get("url", ""))
            if u and u not in seen_urls:
                seen_urls.add(u)
                key_endpoints.append({"url": u, "kind": "discovered_asset"})

    for t in completed:
        tu = _safe_str(t.get("target_url", ""))
        tid = _safe_str(t.get("id", ""))
        if tu and tu not in seen_urls:
            seen_urls.add(tu)
            key_endpoints.append({"url": tu, "kind": "task_target", "task_id": tid})

    # Input points (completed task params with action descriptions)
    input_points: List[Dict[str, str]] = []
    for t in completed:
        params = _safe_dict(t.get("params", {}))
        action = _safe_str(t.get("action", ""))
        tid = _safe_str(t.get("id", ""))
        for pk, pv in params.items():
            if _is_secret_key(pk):
                continue
            input_points.append({
                "param": pk,
                "action": action,
                "task_id": tid,
            })

    # Attack surface summary from findings
    findings = _safe_list(session_data.get("findings", []))
    attack_surface: List[Dict[str, str]] = []
    for f in findings[:20]:
        if isinstance(f, dict):
            attack_surface.append({
                "type": _safe_str(f.get("vuln_type", f.get("type", ""))),
                "severity": _safe_str(f.get("severity", "info")),
                "url": _safe_str(f.get("target_url", f.get("url", ""))),
            })

    source_refs: List[str] = []
    if target_info:
        source_refs.append(_make_source_ref("context", "target_info"))
    if completed:
        source_refs.append(_make_source_ref("completed_tasks", str(len(completed))))

    profile: dict = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "run_id": run_id,
        "session_id": session_id,
        "target_scope_id": _safe_str(target_info.get("target_scope_id", run_id or "")),
        "target_host": host or url,
        "in_scope": True,
        "status": "partial",
        "reason_codes": [],
        "redaction_status": "clean",
        "source_refs": source_refs,
        "auth_methods": auth_methods,
        "key_features": sorted(task_types),
        "key_endpoints": key_endpoints,
        "input_points": input_points,
        "state_transitions": [],
        "tech_stack": tech_stack,
        "constraints": {},
        "attack_surface": attack_surface,
    }

    return _redact_value(profile)


def build_attack_review_trail(
    session_data: dict,
    session_id: str | None = None,
    run_id: str | None = None,
) -> dict | None:
    """Build attack_review_trail from decision_traces, task_execution_records, run_ledger."""
    decision_traces = _safe_list(session_data.get("decision_traces", []))
    task_records = _safe_list(session_data.get("task_execution_records", []))
    run_ledger = _safe_list(session_data.get("run_ledger", []))
    completed_tasks = _safe_list(session_data.get("completed_tasks", []))

    entries: List[dict] = []
    reason_codes: List[str] = []

    # From decision_traces
    for i, dt in enumerate(decision_traces[:MAX_TRAIL_ENTRIES]):
        if not isinstance(dt, dict):
            continue
        decision_id = _safe_str(dt.get("decision_id", dt.get("id", f"dt-{i}")))
        entries.append({
            "trail_id": f"trail-dt-{i:04d}",
            "phase": _safe_str(dt.get("phase", "decision")),
            "timestamp": _safe_str(dt.get("timestamp", "")),
            "observation": _safe_str(dt.get("context", dt.get("observation", ""))),
            "hypothesis": _safe_str(dt.get("rationale", dt.get("hypothesis", ""))),
            "action": _safe_str(dt.get("action", dt.get("decision", ""))),
            "result": _safe_str(dt.get("outcome", dt.get("result", ""))),
            "next_candidate": _safe_str(dt.get("next_action", dt.get("next_candidate", ""))),
            "source_type": "decision_traces",
            "source_id": decision_id,
            "source_location": f"decision_traces[{i}]",
            "derived_from": [],
            "task_id": _safe_str(dt.get("task_id", "")),
            "decision_id": decision_id,
            "event_id": "",
            "source_refs": [_make_source_ref("decision_traces", decision_id)],
            "redaction_status": "clean",
        })

    # From task_execution_records
    for i, tr in enumerate(task_records[:MAX_TRAIL_ENTRIES]):
        if not isinstance(tr, dict):
            continue
        record_id = _safe_str(tr.get("record_id", tr.get("id", tr.get("task_id", f"tr-{i}"))))
        entries.append({
            "trail_id": f"trail-tr-{i:04d}",
            "phase": _safe_str(tr.get("phase", "execution")),
            "timestamp": _safe_str(tr.get("timestamp", tr.get("started_at", ""))),
            "observation": _safe_str(tr.get("summary", tr.get("observation", ""))),
            "hypothesis": "",
            "action": _safe_str(tr.get("action", tr.get("task_type", ""))),
            "result": _safe_str(tr.get("result", tr.get("outcome", ""))),
            "next_candidate": "",
            "source_type": "task_execution_records",
            "source_id": record_id,
            "source_location": f"task_execution_records[{i}]",
            "derived_from": [],
            "task_id": _safe_str(tr.get("task_id", "")),
            "decision_id": "",
            "event_id": _safe_str(tr.get("event_id", "")),
            "source_refs": [_make_source_ref("task_execution_records", record_id)],
            "redaction_status": "clean",
        })

    # From run_ledger
    for i, rl in enumerate(run_ledger[:MAX_TRAIL_ENTRIES]):
        if not isinstance(rl, dict):
            continue
        event_id = _safe_str(rl.get("event_id", f"rl-{i}"))
        entries.append({
            "trail_id": f"trail-rl-{i:04d}",
            "phase": _safe_str(rl.get("phase", "ledger")),
            "timestamp": _safe_str(rl.get("timestamp", "")),
            "observation": _safe_str(rl.get("summary", rl.get("input_summary", ""))),
            "hypothesis": "",
            "action": _safe_str(rl.get("event_type", rl.get("action", ""))),
            "result": _safe_str(rl.get("outcome", rl.get("result", ""))),
            "next_candidate": "",
            "source_type": "run_ledger",
            "source_id": event_id,
            "source_location": f"run_ledger[{i}]",
            "derived_from": [sr for sr in _safe_list(rl.get("source_refs", [])) if isinstance(sr, str)],
            "task_id": _safe_str(rl.get("task_id", "")),
            "decision_id": "",
            "event_id": event_id,
            "source_refs": [_make_source_ref("run_ledger", event_id)],
            "redaction_status": "clean",
        })

    # Determine status
    total_sources = len(decision_traces) + len(task_records) + len(run_ledger)
    status = "complete"
    if total_sources == 0:
        status = "empty"
    elif len(entries) >= MAX_TRAIL_ENTRIES:
        status = "degraded"
        reason_codes.append("max_entries_truncated")

    trail: dict = {
        "schema_version": TRAIL_SCHEMA_VERSION,
        "run_id": run_id,
        "session_id": session_id,
        "status": status,
        "reason_codes": reason_codes,
        "entries": entries,
    }

    if not entries and total_sources == 0:
        return None

    return _redact_value(trail)


def build_scenario_candidates(
    session_data: dict,
    session_id: str | None = None,
    run_id: str | None = None,
) -> list | None:
    """Build scenario_candidates from coverage gaps and skipped decisions."""
    coverage_gate = _safe_dict(session_data.get("coverage_gate", session_data.get("context", {}).get("coverage_gate", {})))
    scenario_coverage = _safe_dict(session_data.get("scenario_coverage", session_data.get("context", {}).get("scenario_coverage", {})))
    decision_traces = _safe_list(session_data.get("decision_traces", []))

    candidates: List[dict] = []

    # From missing families (coverage_gate)
    missing_families = _safe_list(coverage_gate.get("missing_families", []))
    for mf in missing_families[:MAX_CANDIDATES]:
        if isinstance(mf, dict):
            family = _safe_str(mf.get("family", mf.get("name", "")))
            reason = _safe_str(mf.get("reason", ""))
        else:
            family = _safe_str(mf)
            reason = "family coverage gap"
        if family:
            cid = f"cand-mf-{family.replace(' ', '_').lower()}"
            candidates.append({
                "candidate_id": cid,
                "run_id": run_id,
                "session_id": session_id,
                "title": f"Coverage gap: {family}",
                "rationale": reason or "Not covered in this run",
                "expected_outcome": f"Expand coverage for {family}",
                "required_conditions": ["run_completed"],
                "risk_level": "medium",
                "adoption_status": "candidate",
                "source_refs": [_make_source_ref("coverage_gate", "missing_families")],
            })

    # From missing scenarios (scenario_coverage)
    missing_sc = _safe_list(scenario_coverage.get("missing_scenarios", []))
    for ms in missing_sc[:MAX_CANDIDATES]:
        if isinstance(ms, dict):
            sid = _safe_str(ms.get("scenario_id", ms.get("id", "")))
            title = _safe_str(ms.get("title", sid))
        else:
            sid = _safe_str(ms)
            title = sid
        if sid:
            cid = f"cand-ms-{sid}"
            candidates.append({
                "candidate_id": cid,
                "run_id": run_id,
                "session_id": session_id,
                "title": title or sid,
                "rationale": "Scenario not covered in this run",
                "expected_outcome": f"Run scenario {sid}",
                "required_conditions": ["run_completed"],
                "risk_level": "medium",
                "adoption_status": "candidate",
                "source_refs": [_make_source_ref("scenario_coverage", "missing_scenarios")],
            })

    # From skipped/deferred decision traces
    for i, dt in enumerate(decision_traces[:MAX_CANDIDATES]):
        if not isinstance(dt, dict):
            continue
        action = _safe_str(dt.get("action", dt.get("decision", ""))).lower()
        if action in ("skip", "skipped", "defer", "deferred", "postpone"):
            target = _safe_str(dt.get("target", dt.get("url", dt.get("scenario", ""))))
            reason = _safe_str(dt.get("reason", dt.get("rationale", "")))
            decision_id = _safe_str(dt.get("decision_id", f"dt-skip-{i}"))
            cid = f"cand-dt-{i:04d}"
            candidates.append({
                "candidate_id": cid,
                "run_id": run_id,
                "session_id": session_id,
                "title": target or f"Skipped decision {decision_id}",
                "rationale": reason or "Skipped during execution",
                "expected_outcome": "Re-evaluate on next run",
                "required_conditions": ["run_completed"],
                "risk_level": "low",
                "adoption_status": "deferred",
                "source_refs": [_make_source_ref("decision_traces", decision_id)],
            })

    if not candidates:
        return None

    return candidates[:MAX_CANDIDATES]


def build_all_review_fields(
    session_data: dict,
    session_id: str | None = None,
    run_id: str | None = None,
) -> Dict[str, Any]:
    """Build all three additive review fields from finalized session data.

    Returns a dict with keys: target_system_profile, attack_review_trail, scenario_candidates.
    Each value may be None when no meaningful data exists.
    """
    session_id = session_id or _safe_str(session_data.get("session_id", "")) or None
    run_id = run_id or _safe_str(session_data.get("run_id", "")) or None

    return {
        "target_system_profile": build_target_system_profile(session_data, session_id, run_id),
        "attack_review_trail": build_attack_review_trail(session_data, session_id, run_id),
        "scenario_candidates": build_scenario_candidates(session_data, session_id, run_id),
    }
