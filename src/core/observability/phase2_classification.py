from __future__ import annotations

from typing import Any


FAILURE_CATEGORIES: tuple[str, ...] = (
    "timeout",
    "error",
    "schema_mismatch",
    "network",
    "auth",
    "data_contract",
    "unknown",
)

_REASON_CODE_EXACT_MAP: dict[str, str] = {
    "timeout_phase2": "timeout",
    "timeout": "timeout",
    "circuit_open": "timeout",
    "schema_mismatch": "schema_mismatch",
    "type_mismatch": "schema_mismatch",
    "missing_field": "schema_mismatch",
    "contract_violation": "data_contract",
    "validation_error": "data_contract",
    "unauthorized": "auth",
    "forbidden": "auth",
    "session_expired": "auth",
    "dns_error": "network",
    "connection_error": "network",
    "tls_error": "network",
    "socket_error": "network",
}


def classify_failure_pattern(*, reason_code: str = "", error_message: str = "") -> str:
    reason = str(reason_code or "").strip().lower()
    if reason:
        mapped = _REASON_CODE_EXACT_MAP.get(reason)
        if mapped:
            return mapped
        if any(k in reason for k in ("timeout", "circuit_open")):
            return "timeout"
        if any(k in reason for k in ("schema", "contract", "missing_field", "type_mismatch")):
            return "schema_mismatch"
        if any(k in reason for k in ("auth", "unauthorized", "forbidden", "session_expired")):
            return "auth"
        if any(k in reason for k in ("dns", "connect", "network", "tls", "socket", "ttfb")):
            return "network"
        if "validation" in reason:
            return "data_contract"
        # reason_code がある場合は文言依存を避け、明示的に error とする。
        return "error"
    token = str(error_message or "").lower()
    if "schema" in token and ("mismatch" in token or "contract" in token):
        return "schema_mismatch"
    if "timeout" in token:
        return "timeout"
    if any(k in token for k in ("401", "403", "unauthorized", "forbidden", "auth", "session_expired")):
        return "auth"
    if any(k in token for k in ("connection", "dns", "network", "socket", "tls", "ttfb")):
        return "network"
    if "contract" in token or "validation" in token:
        return "data_contract"
    if token.strip():
        return "error"
    return "unknown"


def classify_schema_mismatch_severity(
    *,
    added: int = 0,
    removed: int = 0,
    type_changed: int = 0,
    nullability_changed: int = 0,
    missing_required_fields: int = 0,
) -> dict[str, Any]:
    # Breaking changes are prioritized.
    breaking_score = max(0, int(removed)) + max(0, int(type_changed)) + max(0, int(missing_required_fields))
    non_breaking_score = max(0, int(added)) + max(0, int(nullability_changed))
    total = breaking_score + non_breaking_score

    if breaking_score >= 3 or missing_required_fields >= 1:
        severity = "critical"
    elif breaking_score >= 1:
        severity = "high"
    elif non_breaking_score >= 3:
        severity = "medium"
    elif total > 0:
        severity = "low"
    else:
        severity = "none"

    return {
        "severity": severity,
        "breaking_score": breaking_score,
        "non_breaking_score": non_breaking_score,
        "total_changes": total,
    }
