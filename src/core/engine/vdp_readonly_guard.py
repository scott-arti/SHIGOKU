"""
VDP read-only request guard — SGK-2026-0421 Step 5 (design constraint E).

M3a allows only read-equivalent follow-ups. HTTP method alone is NEVER
sufficient: a GET can still perform state changes, and a POST can carry a
GraphQL *query* (read) or *mutation* (state change).

Decision rules:
1. GraphQL ``mutation`` (explicit or detected in body) → rejected.
2. POST/PUT/PATCH/DELETE:
   - allowed ONLY when it is a GraphQL query (read semantics);
   - otherwise rejected (state-changing).
3. GET/HEAD/OPTIONS:
   - rejected when action semantics is a state-changing operation
     (form_submit / workflow_transition / upload / update / delete /
     state_change) or when the body carries a GraphQL mutation;
   - otherwise allowed (read).
4. Unknown method → rejected (fail-closed).
5. OOB follow-ups additionally require explicit ProgramCapabilityMatrix
   permission and an in-scope destination (checked by the executor).

Body content is only keyword-scanned for GraphQL operation detection; it is
never logged, stored, or included in any verdict field.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

# Semantics that indicate a state change even on a GET request.
STATE_CHANGING_SEMANTICS = frozenset({
    "form_submit",
    "workflow_transition",
    "upload",
    "update",
    "delete",
    "state_change",
    "approval",
    "invite",
    "refund",
})

# HTTP methods that are state-changing by default.
STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Methods that are read-equivalent by default (GET/HEAD/OPTIONS).
READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

_GRAPHQL_MUTATION_RE = re.compile(
    r"^\s*mutation\b", re.IGNORECASE | re.MULTILINE
)
_GRAPHQL_QUERY_RE = re.compile(
    r"^\s*query\b", re.IGNORECASE | re.MULTILINE
)


@dataclass(frozen=True)
class ReadonlyVerdict:
    """Result of the M3a read-only classification."""

    allowed: bool
    risk_class: str  # read_only | state_changing | out_of_band | unknown
    method: str
    operation: str  # graphql_query | graphql_mutation | normal | unknown
    reason: str = ""


def detect_graphql_operation(
    body: Any = None,
    content_type: str = "",
) -> str:
    """Detect a GraphQL operation keyword from a request body.

    Deterministic keyword scan only — body content is never returned or
    stored. Returns "query", "mutation", or "".

    Args:
        body: Request body (str or bytes) or None.
        content_type: Optional Content-Type header value (e.g. for json).
    """
    if body is None:
        return ""
    if isinstance(body, bytes):
        try:
            text = body.decode("utf-8", errors="ignore")
        except Exception:
            return ""
    elif isinstance(body, str):
        text = body
    else:
        # Non-string bodies (dict/json payloads) are scanned as JSON text.
        try:
            import json as _json

            text = _json.dumps(body)
        except Exception:
            return ""
    # JSON-encoded GraphQL commonly uses {"query": "..."} or {"operationName":...}
    if '"mutation' in text or "'mutation" in text or '"mutation"' in text:
        return "mutation"
    if '"query"' in text and "mutation" in text:
        return "mutation"
    if _GRAPHQL_MUTATION_RE.search(text):
        return "mutation"
    if '"query"' in text or _GRAPHQL_QUERY_RE.search(text):
        return "query"
    return ""


def evaluate_readonly_request(
    method: str,
    *,
    action_semantics: str = "",
    graphql_operation: str = "",
    body: Any = None,
    url: str = "",
    content_type: str = "",
) -> ReadonlyVerdict:
    """Classify a request as M3a read-only or state-changing.

    Args:
        method: HTTP method (case-insensitive).
        action_semantics: Optional semantic label of the action
            (form_submit, workflow_transition, upload, update, delete,
            state_change, read, ...).
        graphql_operation: Explicit GraphQL operation ("query"/"mutation").
        body: Request body for GraphQL operation sniffing when not explicit.
        url: Request URL (informational only; never echoed verbatim into
            the reason when it may carry secrets).
        content_type: Content-Type header value.

    Returns:
        ReadonlyVerdict with allowed flag and a deterministic reason.
    """
    m = str(method or "").strip().upper()
    if not m:
        return ReadonlyVerdict(
            allowed=False,
            risk_class="unknown",
            method=m,
            operation="unknown",
            reason="empty_method",
        )

    op = str(graphql_operation or "").strip().lower()
    if not op:
        op = detect_graphql_operation(body, content_type)

    # 1. GraphQL mutation is never M3a-safe.
    if op == "mutation":
        return ReadonlyVerdict(
            allowed=False,
            risk_class="state_changing",
            method=m,
            operation="graphql_mutation",
            reason="graphql_mutation_rejected_in_m3a",
        )

    # 2. State-changing methods require GraphQL query semantics to pass.
    if m in STATE_CHANGING_METHODS:
        if op == "query":
            return ReadonlyVerdict(
                allowed=True,
                risk_class="read_only",
                method=m,
                operation="graphql_query",
                reason="graphql_query_on_post_allowed",
            )
        return ReadonlyVerdict(
            allowed=False,
            risk_class="state_changing",
            method=m,
            operation="normal",
            reason=f"state_changing_method_{m.lower()}_rejected_in_m3a",
        )

    # 3. Read-equivalent methods: reject state-changing semantics.
    if m in READ_METHODS:
        sem = str(action_semantics or "").strip().lower()
        if sem in STATE_CHANGING_SEMANTICS:
            return ReadonlyVerdict(
                allowed=False,
                risk_class="state_changing",
                method=m,
                operation="normal",
                reason=f"state_changing_semantics_{sem}_rejected_in_m3a",
            )
        return ReadonlyVerdict(
            allowed=True,
            risk_class="read_only",
            method=m,
            operation="normal",
            reason="read_equivalent_allowed",
        )

    # 4. Unknown method → fail-closed.
    return ReadonlyVerdict(
        allowed=False,
        risk_class="unknown",
        method=m,
        operation="unknown",
        reason="unknown_method_rejected_in_m3a",
    )


def is_state_changing_method(method: str) -> bool:
    return str(method or "").strip().upper() in STATE_CHANGING_METHODS
