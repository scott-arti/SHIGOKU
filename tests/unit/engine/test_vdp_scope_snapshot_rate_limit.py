"""
SGK-2026-0430 F2 — scope-snapshot rate-limit regression test.

The live rerun (session_20260807_152745) exposed a latent bug: the VDP scope
snapshot (``_build_vdp_scope_snapshot``) defaulted ``max_requests_per_minute``
to 0 when target_info lacks the field. EthicsGuard treats 0 as "rate limit
exceeded: 0/min", so the follow-up executor's scope revalidation falsely
blocked EVERY follow-up at S07 (``scope_block_incorrect`` / ``out_of_scope``)
— attempts stayed 0 despite the W2 drain working (S04/S05 reached, 4 tasks
queued and dispatched).

Fix: the snapshot falls back to the fast-path scope contract default (60)
when target_info carries no explicit value; explicit values are respected.
Product-independent: the target is opaque.
"""
from __future__ import annotations

import threading
from unittest.mock import MagicMock

from src.core.domain.scope.vdp_scope_validator import revalidate_scope_for_request
from src.core.engine.master_conductor import MasterConductor


def _minimal_mc_with_target_info(target_info: dict):
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = MagicMock()
    mc.context.target_info = dict(target_info)
    return mc


def test_snapshot_defaults_rate_limit_to_contract_value():
    """target_info without max_requests_per_minute -> 60 (fast-path contract),
    never 0 (which EthicsGuard reads as 'rate limit exceeded')."""
    mc = _minimal_mc_with_target_info(
        {"in_scope_domains": ["opaque-target.test"]}
    )
    scope = mc._build_vdp_scope_snapshot()
    assert scope is not None
    assert scope.max_requests_per_minute == 60


def test_snapshot_respects_explicit_rate_limit():
    mc = _minimal_mc_with_target_info(
        {
            "in_scope_domains": ["opaque-target.test"],
            "max_requests_per_minute": 120,
        }
    )
    scope = mc._build_vdp_scope_snapshot()
    assert scope.max_requests_per_minute == 120


def test_snapshot_scope_allows_follow_up_urls():
    """With the fixed snapshot scope, the live rerun's follow-up URLs pass
    the executor's revalidation (rate limit 60, not 0)."""
    mc = _minimal_mc_with_target_info(
        {"in_scope_domains": ["localhost"]}
    )
    scope = mc._build_vdp_scope_snapshot()
    for url in (
        "http://localhost:3000/rest/admin/:opaque",
        "http://localhost:3000/api/Challenges/?name",
        "http://localhost:3000/orders/history?query",
    ):
        result = revalidate_scope_for_request(url, scope_definition=scope)
        assert result.allowed, f"{url}: {result.verdict}"


def test_snapshot_missing_scope_is_fail_closed():
    """No verified in-scope domains -> None (M3a stays fail-closed)."""
    mc = _minimal_mc_with_target_info({})
    assert mc._build_vdp_scope_snapshot() is None
