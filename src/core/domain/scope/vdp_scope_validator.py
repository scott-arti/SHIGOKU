"""
VDP Scope Validator — SGK-2026-0419 Item 3.2 (pure, no shared-state mutation).

Re-evaluate scope for a target URL before any communication.
Uses the existing ScopeParser and EthicsGuard infrastructure.

Returns a ``ScopeRevalidationResult`` from ``vdp_contract.py``.

Key design constraints (SGK-2026-0419 Item G):
- Must NOT mutate the passed ``scope_definition`` (defensive copy if needed).
- Must validate BOTH the original URL and the redirect target independently.
- Must be pure: same inputs → same outputs, no global state mutation.
"""
from __future__ import annotations

import copy
from typing import Optional

from src.core.models.vdp_contract import ScopeRevalidationResult
from src.core.security.scope_parser import get_scope_parser
from src.core.security.ethics_guard import ScopeDefinition


def _validate_url_pure(url: str, scope_definition: Optional[ScopeDefinition]) -> tuple[bool, str]:
    """Validate a single URL against a scope definition without mutating global state.

    Creates a temporary guard with the provided scope, validates, then restores.
    This ensures the function is pure: no side effects on shared state.
    """
    parser = get_scope_parser()

    if scope_definition is None:
        is_valid, reason = parser.validate_target(url)
        return is_valid, reason

    # Make a defensive copy to avoid mutating the passed scope_definition
    scope_copy = copy.deepcopy(scope_definition)

    guard = parser._guard
    saved_scope = guard.scope
    try:
        guard.set_scope(scope_copy)
        is_valid, reason = parser.validate_target(url)
    finally:
        if saved_scope is not None:
            guard.set_scope(saved_scope)
        else:
            guard.scope = None

    return is_valid, reason


def revalidate_scope_for_request(
    url: str,
    scope_definition: Optional[ScopeDefinition] = None,
    redirect_from: Optional[str] = None,
) -> ScopeRevalidationResult:
    """Re-evaluate whether a target URL is in scope before communication.

    Uses the existing ``ScopeParser`` (ethics guard) to validate the target.
    When a redirect chain is provided, both the original and the redirect
    destination are validated independently. Either failing → out_of_scope.

    Pure function: same inputs always produce same outputs. No global state
    mutation. The passed ``scope_definition`` is never modified.

    Args:
        url: The target URL to validate.
        scope_definition: Optional explicit scope; if None, the global
            singleton parser's current scope is used. Never mutated.
        redirect_from: Optional redirect source URL for redirect detection.

    Returns:
        ``ScopeRevalidationResult`` with verdict and allowed flag.
    """
    # Validate the target URL
    url_valid, url_reason = _validate_url_pure(url, scope_definition)

    # If a redirect_from is provided, validate the redirect source independently
    if redirect_from:
        redirect_valid, redirect_reason = _validate_url_pure(redirect_from, scope_definition)
        # Both must be valid — if either fails, it's out of scope
        if not redirect_valid:
            return ScopeRevalidationResult.redirect_to_out_of_scope(
                original=redirect_from,
                redirected_to=url,
            )
        if not url_valid:
            return ScopeRevalidationResult.redirect_to_out_of_scope(
                original=redirect_from,
                redirected_to=url,
            )

    if not url_valid:
        # If a redirect happened and the target fails, use redirect_out_of_scope
        if redirect_from:
            return ScopeRevalidationResult.redirect_to_out_of_scope(
                original=redirect_from,
                redirected_to=url,
            )
        # Otherwise the URL itself is out of scope
        return ScopeRevalidationResult.out_of_scope(
            url_reason or f"Target {url} is out of scope"
        )

    return ScopeRevalidationResult.allow()
