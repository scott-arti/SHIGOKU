from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
from typing import Any

from src.core.utils.json_utils import safe_json_loads


_REPORT_FILENAME_RE = re.compile(r"haddix_report_(\d{8})_(\d{6})\.md$", re.IGNORECASE)
_SESSION_FILENAME_RE = re.compile(r"session_(\d{8})_(\d{6})\.json$", re.IGNORECASE)
_GENERATED_LINE_RE = re.compile(r"^\*\*Generated:\*\*\s*(.+?)\s*$", re.MULTILINE)
_SOURCE_SESSION_LINE_RE = re.compile(r"^\*\*Source Session:\*\*\s*(.+?)\s*$", re.MULTILINE)
_SCENARIO_COVERAGE_LINE_RE = re.compile(
    r"^Coverage:\s*(\d+)\s*/\s*(\d+)\s*\([^)]*\)\s*,\s*Missing:\s*(.+?)\s*$",
    re.MULTILINE,
)
_SCENARIO_TABLE_ROW_RE = re.compile(
    r"^\|\s*SCN(\d+)\s*\|.*\|\s*(YES|NO)\s*\|\s*\d+\s*\|$",
    re.IGNORECASE | re.MULTILINE,
)


def _parse_dt_from_compact(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y%m%d%H%M%S")
    except Exception:
        return None


def _parse_dt_from_session_name(name: str) -> datetime | None:
    match = _SESSION_FILENAME_RE.match(name)
    if not match:
        return None
    return _parse_dt_from_compact(f"{match.group(1)}{match.group(2)}")


def _parse_dt_from_report_name(name: str) -> datetime | None:
    match = _REPORT_FILENAME_RE.match(name)
    if not match:
        return None
    return _parse_dt_from_compact(f"{match.group(1)}{match.group(2)}")


def _normalize_tokens(raw: Any) -> list[str]:
    if isinstance(raw, str):
        value = raw.strip().lower()
        if not value or value == "-":
            return []
        return [value]
    if not isinstance(raw, list):
        return []
    normalized: list[str] = []
    for item in raw:
        token = str(item or "").strip().lower()
        if not token or token == "-":
            continue
        if token not in normalized:
            normalized.append(token)
    return sorted(normalized)


def _parse_generated_datetime(report_text: str) -> str | None:
    match = _GENERATED_LINE_RE.search(report_text)
    if not match:
        return None
    raw = str(match.group(1)).strip()
    if raw.endswith(" JST"):
        base = raw[: -len(" JST")].strip()
        try:
            parsed = datetime.strptime(base, "%Y-%m-%d %H:%M:%S")
            return parsed.replace(tzinfo=timezone(timedelta(hours=9))).isoformat()
        except Exception:
            pass
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S %z").isoformat()
    except Exception:
        pass
    try:
        return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").isoformat()
    except Exception:
        return raw


def _parse_source_session(report_text: str) -> str | None:
    match = _SOURCE_SESSION_LINE_RE.search(report_text)
    if not match:
        return None
    value = str(match.group(1)).strip()
    return value or None


def _parse_report_scenario_coverage(report_text: str) -> dict[str, Any]:
    coverage_match = _SCENARIO_COVERAGE_LINE_RE.search(report_text)
    if coverage_match:
        covered = int(coverage_match.group(1))
        required = int(coverage_match.group(2))
        missing_raw = str(coverage_match.group(3) or "").strip()
        missing_tokens = [] if missing_raw == "-" else _normalize_tokens([x.strip() for x in missing_raw.split(",")])
        return {
            "covered_count": covered,
            "required_count": required,
            "missing_scenarios": missing_tokens,
        }

    rows = _SCENARIO_TABLE_ROW_RE.findall(report_text or "")
    if not rows:
        return {
            "covered_count": None,
            "required_count": None,
            "missing_scenarios": [],
        }

    required_count = len(rows)
    covered_count = sum(1 for _, covered in rows if str(covered).strip().upper() == "YES")
    return {
        "covered_count": covered_count,
        "required_count": required_count,
        "missing_scenarios": [],
    }


def parse_report_metadata(report_path: Path) -> dict[str, Any]:
    text = report_path.read_text(encoding="utf-8")
    generated_at = _parse_generated_datetime(text)
    report_ts = _parse_dt_from_report_name(report_path.name)
    source_session = _parse_source_session(text)
    scenario_coverage = _parse_report_scenario_coverage(text)
    return {
        "path": str(report_path.resolve()),
        "generated_at": generated_at,
        "report_timestamp": report_ts.isoformat() if report_ts else None,
        "source_session": source_session,
        "scenario_coverage": scenario_coverage,
    }


def infer_sessions_dir(report_path: Path) -> Path | None:
    if report_path.parent.name == "reports":
        candidate = report_path.parent.parent / "sessions"
        if candidate.exists():
            return candidate
    candidate = report_path.parent / "sessions"
    if candidate.exists():
        return candidate
    return None


def _resolve_source_session_path(raw_source: str, report_path: Path, sessions_dir: Path | None) -> Path | None:
    source_candidate = Path(str(raw_source).strip())
    candidates: list[Path] = []
    if source_candidate.is_absolute():
        # Docker path compatibility:
        # report header may contain container path like /workspace/projects/.../session_*.json.
        # この場合、ホスト/一時ディレクトリ上にある report 側 workspace を優先する。
        parts = source_candidate.parts
        if len(parts) >= 2 and parts[1] == "workspace":
            rel_under_workspace = Path(*parts[2:])
            report_parts = report_path.resolve().parts
            if "workspace" in report_parts:
                idx = report_parts.index("workspace")
                if idx >= 1:
                    host_prefix = Path(report_parts[0])
                    for token in report_parts[1:idx]:
                        host_prefix = host_prefix / token
                    candidates.append((host_prefix / "workspace" / rel_under_workspace).resolve())
            repo_root = Path(__file__).resolve().parents[2]
            candidates.append((repo_root / "workspace" / rel_under_workspace).resolve())
            candidates.append((Path.cwd() / "workspace" / rel_under_workspace).resolve())
            # literal container path は最後にフォールバック
            candidates.append(source_candidate)
        else:
            candidates.append(source_candidate)
    else:
        candidates.append((Path.cwd() / source_candidate).resolve())
        candidates.append((report_path.parent / source_candidate).resolve())
        if sessions_dir is not None:
            candidates.append((sessions_dir / source_candidate.name).resolve())
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _list_session_files(sessions_dir: Path) -> list[Path]:
    files = sorted(sessions_dir.glob("session_*.json"))
    if files:
        return files
    latest = sessions_dir / "latest.json"
    if latest.exists():
        return [latest]
    return []


def _session_sort_key(path: Path) -> tuple[int, float]:
    seq = -1
    dt = _parse_dt_from_session_name(path.name)
    if dt is not None:
        seq = int(dt.strftime("%Y%m%d%H%M%S"))
    try:
        mtime = float(path.stat().st_mtime)
    except Exception:
        mtime = 0.0
    return (seq, mtime)


def _select_session_by_report_timestamp(report_meta: dict[str, Any], session_files: list[Path]) -> Path | None:
    report_ts_raw = report_meta.get("report_timestamp")
    report_dt: datetime | None = None
    if isinstance(report_ts_raw, str):
        try:
            report_dt = datetime.fromisoformat(report_ts_raw)
        except Exception:
            report_dt = None

    if report_dt is None:
        return max(session_files, key=_session_sort_key) if session_files else None

    best_path: Path | None = None
    best_delta: float | None = None
    for candidate in session_files:
        session_dt = _parse_dt_from_session_name(candidate.name)
        if session_dt is None:
            continue
        delta = abs((report_dt - session_dt).total_seconds())
        if best_delta is None or delta < best_delta:
            best_delta = delta
            best_path = candidate
    if best_path is not None:
        return best_path
    return max(session_files, key=_session_sort_key) if session_files else None


def _extract_session_scenario_coverage(session_data: dict[str, Any]) -> dict[str, Any]:
    coverage = session_data.get("scenario_coverage")
    if not isinstance(coverage, dict):
        context = session_data.get("context", {})
        if isinstance(context, dict):
            coverage = context.get("scenario_coverage")
    if not isinstance(coverage, dict):
        return {
            "covered_count": None,
            "required_count": None,
            "missing_scenarios": [],
        }

    covered_count = coverage.get("covered_count")
    required_count = coverage.get("required_count")
    try:
        covered_num = int(covered_count) if covered_count is not None else None
    except Exception:
        covered_num = None
    try:
        required_num = int(required_count) if required_count is not None else None
    except Exception:
        required_num = None

    missing_scenarios = _normalize_tokens(coverage.get("missing_scenarios", []))
    if not missing_scenarios:
        items = coverage.get("coverage_items", [])
        if isinstance(items, list):
            inferred_missing: list[str] = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                if bool(item.get("covered", False)):
                    continue
                sid = str(item.get("scenario_id", "") or "").strip().lower()
                if sid and sid not in inferred_missing:
                    inferred_missing.append(sid)
            missing_scenarios = sorted(inferred_missing)

    return {
        "covered_count": covered_num,
        "required_count": required_num,
        "missing_scenarios": missing_scenarios,
    }


def _extract_session_missing_families(session_data: dict[str, Any]) -> list[str]:
    context = session_data.get("context", {})
    if not isinstance(context, dict):
        return []
    gate = context.get("coverage_gate", {})
    if not isinstance(gate, dict):
        return []
    return _normalize_tokens(gate.get("missing_families", []))


def _build_comparison(report_cov: dict[str, Any], session_cov: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    reason_codes: list[str] = []

    report_covered = report_cov.get("covered_count")
    report_required = report_cov.get("required_count")
    session_covered = session_cov.get("covered_count")
    session_required = session_cov.get("required_count")

    covered_match = (
        report_covered is not None
        and report_required is not None
        and session_covered is not None
        and session_required is not None
        and int(report_covered) == int(session_covered)
        and int(report_required) == int(session_required)
    )
    if (
        report_covered is not None
        and report_required is not None
        and session_covered is not None
        and session_required is not None
        and not covered_match
    ):
        reason_codes.append("scenario_coverage_count_mismatch")

    report_missing = _normalize_tokens(report_cov.get("missing_scenarios", []))
    session_missing = _normalize_tokens(session_cov.get("missing_scenarios", []))
    missing_set_match = set(report_missing) == set(session_missing)
    if not missing_set_match:
        reason_codes.append("scenario_missing_set_mismatch")

    comparison = {
        "scenario_coverage_counts_match": covered_match,
        "scenario_missing_set_match": missing_set_match,
        "report_missing_scenarios": report_missing,
        "session_missing_scenarios": session_missing,
    }
    return comparison, reason_codes


def verify_report_session_consistency(
    report_path: Path | str,
    *,
    session_path: Path | str | None = None,
    sessions_dir: Path | str | None = None,
) -> dict[str, Any]:
    reason_codes: list[str] = []

    report_file = Path(report_path).expanduser().resolve()
    if not report_file.exists():
        return {
            "status": "blocked",
            "rerun_required": False,
            "reason_codes": ["report_not_found"],
            "report": {"path": str(report_file)},
            "session": {},
            "comparison": {},
            "suggested_next_step": "Provide a valid report path.",
        }

    try:
        report_meta = parse_report_metadata(report_file)
    except Exception as exc:
        return {
            "status": "blocked",
            "rerun_required": False,
            "reason_codes": ["report_parse_failed"],
            "report": {"path": str(report_file), "error": str(exc)},
            "session": {},
            "comparison": {},
            "suggested_next_step": "Fix report file format or provide another report.",
        }

    chosen_session: Path | None = None
    session_selection = "none"

    resolved_sessions_dir: Path | None = Path(sessions_dir).expanduser().resolve() if sessions_dir else None
    if resolved_sessions_dir and not resolved_sessions_dir.exists():
        reason_codes.append("sessions_dir_not_found")
        resolved_sessions_dir = None

    if session_path:
        candidate = Path(session_path).expanduser().resolve()
        if candidate.exists():
            chosen_session = candidate
            session_selection = "explicit_session_argument"
        else:
            reason_codes.append("explicit_session_not_found")
    else:
        source_session_raw = report_meta.get("source_session")
        if source_session_raw:
            source_path = _resolve_source_session_path(str(source_session_raw), report_file, resolved_sessions_dir)
            if source_path is not None:
                chosen_session = source_path.resolve()
                session_selection = "source_session_header"
            else:
                reason_codes.append("source_session_not_found")
                return {
                    "status": "blocked",
                    "rerun_required": False,
                    "reason_codes": sorted(set(reason_codes)),
                    "report": report_meta,
                    "session": {"selection": "source_session_header"},
                    "comparison": {},
                    "suggested_next_step": "Source session in report header was not found. Regenerate report or provide --session.",
                }

    if chosen_session is None:
        if resolved_sessions_dir is None:
            resolved_sessions_dir = infer_sessions_dir(report_file)
        if resolved_sessions_dir is None:
            reason_codes.append("sessions_dir_not_resolved")
            return {
                "status": "blocked",
                "rerun_required": False,
                "reason_codes": sorted(set(reason_codes)),
                "report": report_meta,
                "session": {},
                "comparison": {},
                "suggested_next_step": "Provide --sessions-dir or --session.",
            }

        session_files = _list_session_files(resolved_sessions_dir)
        if not session_files:
            reason_codes.append("session_not_found")
            return {
                "status": "blocked",
                "rerun_required": False,
                "reason_codes": sorted(set(reason_codes)),
                "report": report_meta,
                "session": {"sessions_dir": str(resolved_sessions_dir)},
                "comparison": {},
                "suggested_next_step": "No session files found. Run scan first or provide --session.",
            }

        chosen_session = _select_session_by_report_timestamp(report_meta, session_files)
        session_selection = "report_timestamp_nearest" if chosen_session else "none"
        if chosen_session is None:
            reason_codes.append("session_not_found")
            return {
                "status": "blocked",
                "rerun_required": False,
                "reason_codes": sorted(set(reason_codes)),
                "report": report_meta,
                "session": {"sessions_dir": str(resolved_sessions_dir)},
                "comparison": {},
                "suggested_next_step": "Session selection failed. Provide --session explicitly.",
            }

    try:
        session_raw = chosen_session.read_text(encoding="utf-8")
        session_data = safe_json_loads(session_raw, context=f"report_consistency:{chosen_session.name}")
        if not isinstance(session_data, dict):
            raise ValueError("session data is not an object")
    except Exception as exc:
        reason_codes.append("session_parse_failed")
        return {
            "status": "blocked",
            "rerun_required": False,
            "reason_codes": sorted(set(reason_codes)),
            "report": report_meta,
            "session": {"path": str(chosen_session), "selection": session_selection, "error": str(exc)},
            "comparison": {},
            "suggested_next_step": "Session file is invalid. Repair session JSON or provide another session.",
        }

    session_cov = _extract_session_scenario_coverage(session_data)
    session_missing_families = _extract_session_missing_families(session_data)

    comparison, compare_reasons = _build_comparison(
        report_meta.get("scenario_coverage", {}),
        session_cov,
    )
    reason_codes.extend(compare_reasons)

    status = "consistent"
    rerun_required = False
    if compare_reasons:
        status = "inconsistent"
        rerun_required = True

    return {
        "status": status,
        "rerun_required": rerun_required,
        "reason_codes": sorted(set(reason_codes)),
        "report": report_meta,
        "session": {
            "path": str(chosen_session.resolve()),
            "selection": session_selection,
            "scenario_coverage": session_cov,
            "coverage_gate_missing_families": session_missing_families,
        },
        "comparison": comparison,
        "suggested_next_step": (
            "Rerun report generation from the intended session and compare again."
            if rerun_required
            else "Use this report/session pair as the source of truth."
        ),
    }
