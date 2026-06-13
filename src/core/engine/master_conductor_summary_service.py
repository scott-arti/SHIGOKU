"""
Summary Service

_generate_summary() から切り出す pure aggregation ヘルパー群。
failure reason aggregation、duration percentile、coverage gate assembly
を pure function 化する。

依存方向: master_conductor.py -> master_conductor_summary_service.py -> なし
本 service から master_conductor.py への import は禁止。
warning log emit は facade 側の責務とする。
"""

from __future__ import annotations

from typing import Any

from src.core.observability.phase2_classification import classify_failure_pattern


def compute_failure_aggregation(
    completed_tasks: list[Any],
    *,
    normalize_failure_reason_code: Any = None,
) -> dict[str, Any]:
    """completed_tasks から failure reason aggregation を計算する（pure function）。

    Args:
        completed_tasks: Task オブジェクトのリスト（state==FAILED のみ処理）
        normalize_failure_reason_code: (failure_phase, failure_reason, error) -> str

    Returns:
        dict with:
          failed_reason_codes: dict[str, int]
          failed_failure_categories: dict[str, int]
          unknown_failure_count: int
          unknown_rate: float
    """
    failed_reason_codes: dict[str, int] = {}
    failed_failure_categories: dict[str, int] = {}
    unknown_failure_count = 0
    failed_count = 0

    for task in completed_tasks:
        from src.core.domain.model.task import TaskState
        if task.state != TaskState.FAILED:
            continue
        failed_count += 1
        reason_code = str(getattr(task, "failure_reason_code", "") or "").strip()
        if not reason_code and normalize_failure_reason_code is not None:
            reason_code = normalize_failure_reason_code(
                str(getattr(task, "failure_phase", "") or ""),
                getattr(task, "failure_reason", "") or getattr(task, "error", ""),
                getattr(task, "error", ""),
            )
            task.failure_reason_code = reason_code
        failed_reason_codes[reason_code] = failed_reason_codes.get(reason_code, 0) + 1
        failure_category = classify_failure_pattern(
            reason_code=reason_code,
            error_message=str(getattr(task, "error", "") or ""),
        )
        failed_failure_categories[failure_category] = failed_failure_categories.get(failure_category, 0) + 1
        if failure_category == "unknown":
            unknown_failure_count += 1

    unknown_rate = unknown_failure_count / failed_count if failed_count > 0 else 0.0

    return {
        "failed_reason_codes": dict(sorted(failed_reason_codes.items(), key=lambda kv: (-kv[1], kv[0]))),
        "failed_failure_categories": dict(sorted(failed_failure_categories.items(), key=lambda kv: (-kv[1], kv[0]))),
        "unknown_failure_count": unknown_failure_count,
        "unknown_rate": unknown_rate,
        "failed_count": failed_count,
    }


def compute_duration_percentile(
    execution_log: Any,
) -> dict[str, Any]:
    """execution_log から duration percentile を計算する（pure function）。

    Returns:
        dict with p95_seconds, p99_seconds, pr_execution_time_slo dict
    """
    records = execution_log.get_all() if execution_log is not None and hasattr(execution_log, "get_all") else []
    duration_samples = [
        float(d)
        for d in (record.duration_seconds() for record in records)
        if d is not None and d >= 0
    ]
    duration_samples.sort()

    def _percentile(samples: list[float], ratio: float) -> float:
        if not samples:
            return 0.0
        index = int(round((len(samples) - 1) * ratio))
        index = max(0, min(index, len(samples) - 1))
        return float(samples[index])

    p95_seconds = _percentile(duration_samples, 0.95)
    p99_seconds = _percentile(duration_samples, 0.99)

    return {
        "p95_seconds": p95_seconds,
        "p99_seconds": p99_seconds,
        "sample_count": len(duration_samples),
        "pr_execution_time_slo": {
            "target_p95_seconds": 900.0,
            "target_p99_seconds": 1200.0,
            "observed_p95_seconds": p95_seconds,
            "observed_p99_seconds": p99_seconds,
            "sample_count": len(duration_samples),
            "insufficient_samples": len(duration_samples) < 100,
            "status": "pass" if p95_seconds <= 900.0 and p99_seconds <= 1200.0 else "fail",
        },
    }
