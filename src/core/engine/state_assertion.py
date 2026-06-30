from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class StateAssertionResult:
    allowed: bool
    reason_code: str = ""
    audit: dict[str, Any] = field(default_factory=dict)


def evaluate_state_assertion(
    *,
    lane: str,
    assertion: dict[str, Any] | None,
    task_metadata: dict[str, Any] | None,
    current_versions: dict[str, int] | None,
) -> StateAssertionResult:
    if lane not in {"mutating", "aggressive_exclusive"}:
        return StateAssertionResult(True, audit={"assertion_result": "not_required"})

    assertion = assertion or {}
    task_metadata = task_metadata or {}
    current_versions = current_versions or {}
    precondition = str(assertion.get("precondition", "") or "")
    postcondition = str(assertion.get("postcondition", "") or "")

    if not precondition:
        return StateAssertionResult(
            False,
            "state_assertion_precondition_missing",
            {"assertion_result": "failed", "reason_code": "state_assertion_precondition_missing"},
        )
    if not postcondition:
        return StateAssertionResult(
            False,
            "state_assertion_postcondition_missing",
            {"assertion_result": "failed", "reason_code": "state_assertion_postcondition_missing"},
        )

    if precondition == "fresh_auth_context":
        task_auth = int(task_metadata.get("auth_context_version", 0) or 0)
        current_auth = int(current_versions.get("auth_context_version", 0) or 0)
        if current_auth > 0 and task_auth < current_auth:
            return StateAssertionResult(
                False,
                "state_assertion_stale_auth_context",
                {
                    "assertion_result": "failed",
                    "reason_code": "state_assertion_stale_auth_context",
                    "task_auth_context_version": task_auth,
                    "current_auth_context_version": current_auth,
                },
            )

    return StateAssertionResult(
        True,
        audit={
            "assertion_result": "passed",
            "precondition": precondition,
            "postcondition": postcondition,
        },
    )
