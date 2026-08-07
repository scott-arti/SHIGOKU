"""
VDP Scope Validator — SGK-2026-0421 Step 4 (pure, fail-closed).

Re-evaluate scope for a target URL before any communication.

Design constraints (subtask plan §6 / design constraint C):
- ``scope_definition`` 未指定、解析不能、scope不明は通信禁止。
- 「No scope defined」を許可として扱わない。
- 空の ``in_scope_domains``（scopeが定義されていても対象不明）は fail-closed。
- redirect 先、browser 遷移先、派生URL、OOB 送信先は通信ごとに独立再検証。
- process-global singleton scope（ScopeParser/EthicsGuard）を一時変更しない。
  判定は明示 scope snapshot を専用 EthicsGuard インスタンスへ渡す純粋関数とし、
  他 task の scope へ影響しない（並行通信でも結果が交差しない）。
"""
from __future__ import annotations

import copy
from typing import Optional

from src.core.models.vdp_contract import ScopeRevalidationResult
from src.core.security.ethics_guard import (
    ActionType,
    ActionResult,
    EthicsGuard,
    ScopeDefinition,
)


def _validate_url_pure(
    url: str,
    scope_definition: Optional[ScopeDefinition],
) -> tuple[bool, str]:
    """Validate a single URL against an explicit scope definition.

    Pure: never mutates the passed scope_definition nor any global guard
    state. Fail-closed: missing scope definition, empty in_scope_domains,
    and "No scope defined" semantics all return not-allowed.
    """
    if scope_definition is None:
        return False, "scope_definition_not_provided"

    if not getattr(scope_definition, "in_scope_domains", None):
        return False, "empty_in_scope_domains"

    guard = EthicsGuard(scope=copy.deepcopy(scope_definition))
    result, reason = guard.check_action(ActionType.HTTP_REQUEST, url)
    if reason == "No scope defined":
        return False, reason
    return result == ActionResult.ALLOWED, reason


def revalidate_scope_for_request(
    url: str,
    scope_definition: Optional[ScopeDefinition] = None,
    redirect_from: Optional[str] = None,
) -> ScopeRevalidationResult:
    """Re-evaluate whether a target URL is in scope before communication.

    Fail-closed: when ``scope_definition`` is not provided the verdict is
    ``scope_revalidation_blocked`` — the global singleton scope is NOT used
    (a global scope may be absent, in which case the legacy parser would
    answer "No scope defined" = allowed, which is forbidden here).

    When ``redirect_from`` is provided, both the redirect source and the
    destination are validated independently; either failing yields
    ``redirect_out_of_scope``.

    Pure function: same inputs always produce same outputs. The passed
    ``scope_definition`` is never modified and no global state is touched.

    Args:
        url: The target URL to validate.
        scope_definition: Explicit scope snapshot. None → fail-closed block.
        redirect_from: Optional redirect source URL for redirect detection.

    Returns:
        ``ScopeRevalidationResult`` with verdict and allowed flag.
    """
    if scope_definition is None:
        return ScopeRevalidationResult.indeterminate(
            "scope_definition_not_provided"
        )

    url_valid, url_reason = _validate_url_pure(url, scope_definition)

    if redirect_from:
        redirect_valid, _redirect_reason = _validate_url_pure(
            redirect_from, scope_definition
        )
        if not redirect_valid or not url_valid:
            return ScopeRevalidationResult.redirect_to_out_of_scope(
                original=redirect_from,
                redirected_to=url,
            )

    if not url_valid:
        if redirect_from:
            return ScopeRevalidationResult.redirect_to_out_of_scope(
                original=redirect_from,
                redirected_to=url,
            )
        # Scope不明（空 in_scope_domains 等）は out_of_scope ではなく
        # fail-closed の scope_revalidation_blocked へ写像する。
        if url_reason in ("empty_in_scope_domains", "No scope defined"):
            return ScopeRevalidationResult.indeterminate(url_reason)
        return ScopeRevalidationResult.out_of_scope(
            url_reason or f"Target {url} is out of scope"
        )

    return ScopeRevalidationResult.allow()
