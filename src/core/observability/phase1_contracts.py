from __future__ import annotations

import os
import time
import uuid
from typing import Any


REQUIRED_OBSERVABILITY_FIELDS: tuple[str, ...] = (
    "trace_id",
    "request_id",
    "test_case_id",
    "build_id",
    "endpoint",
    "error_type",
    "timeout_ms",
    "retry_count",
    "dns_ms",
    "connect_ms",
    "tls_ms",
    "ttfb_ms",
    "read_ms",
)


def generate_correlation_ids(*, build_id: str | None = None) -> dict[str, str]:
    resolved_build_id = (
        build_id
        or os.getenv("CI_BUILD_ID")
        or os.getenv("GITHUB_RUN_ID")
        or os.getenv("BUILD_ID")
        or f"local-{int(time.time())}"
    )
    trace_id = uuid.uuid4().hex
    request_id = uuid.uuid4().hex[:16]
    return {
        "trace_id": trace_id,
        "request_id": request_id,
        "test_case_id": "unassigned",
        "build_id": str(resolved_build_id),
    }


def validate_event_required_fields(event: dict[str, Any]) -> dict[str, Any]:
    missing = [field for field in REQUIRED_OBSERVABILITY_FIELDS if field not in event or event[field] in (None, "")]
    present = len(REQUIRED_OBSERVABILITY_FIELDS) - len(missing)
    completeness = present / len(REQUIRED_OBSERVABILITY_FIELDS)
    return {
        "status": "ok" if not missing else "missing_fields",
        "missing_fields": missing,
        "present_count": present,
        "required_count": len(REQUIRED_OBSERVABILITY_FIELDS),
        "required_fields_completeness": round(completeness, 6),
    }


def ensure_observability_fields(
    payload: dict[str, Any],
    *,
    correlation: dict[str, Any] | None = None,
    endpoint: str = "",
    error_type: str = "none",
    timeout_ms: int = 0,
    retry_count: int = 0,
    test_case_id: str = "unassigned",
) -> dict[str, Any]:
    merged = dict(payload or {})
    corr = dict(correlation or {})
    merged.setdefault("trace_id", str(corr.get("trace_id", "")))
    merged.setdefault("request_id", str(corr.get("request_id", "")))
    merged.setdefault("build_id", str(corr.get("build_id", "")))
    merged.setdefault("test_case_id", str(corr.get("test_case_id", test_case_id)))
    merged.setdefault("endpoint", endpoint)
    merged.setdefault("error_type", error_type)
    merged.setdefault("timeout_ms", int(timeout_ms))
    merged.setdefault("retry_count", int(retry_count))
    merged.setdefault("dns_ms", 0)
    merged.setdefault("connect_ms", 0)
    merged.setdefault("tls_ms", 0)
    merged.setdefault("ttfb_ms", 0)
    merged.setdefault("read_ms", 0)
    return merged


def evaluate_minimum_sample_size(sample_size: int, minimum_sample_size: int) -> dict[str, Any]:
    current = max(0, int(sample_size))
    threshold = max(1, int(minimum_sample_size))
    hold = current < threshold
    return {
        "status": "hold" if hold else "ok",
        "sample_size": current,
        "minimum_sample_size": threshold,
        "decision": "defer_alert" if hold else "evaluate_alert",
    }
