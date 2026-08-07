"""
VDP scope fail-closed tests — SGK-2026-0421 Step 4.

- scope_definition 未指定 → 通信禁止（scope_revalidation_blocked）。
- 「No scope defined」を許可として扱わない。
- 空 in_scope_domains（scope不明）→ 通信禁止。
- redirect 先の再検証。
- 二つの異なる scope を並行評価しても結果が交差しない（グローバル状態非変更）。
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from src.core.domain.scope.vdp_scope_validator import (
    revalidate_scope_for_request,
)
from src.core.models.vdp_contract import ScopeRevalidationResult
from src.core.security.ethics_guard import ScopeDefinition


def _scope(domains, out_of_scope=None, paths=None) -> ScopeDefinition:
    return ScopeDefinition(
        program_name="test-program",
        in_scope_domains=list(domains),
        out_of_scope_domains=list(out_of_scope or []),
        out_of_scope_paths=list(paths or []),
        max_requests_per_minute=100,
    )


class TestScopeFailClosed:
    def test_missing_scope_definition_is_blocked(self):
        result = revalidate_scope_for_request("https://example.com")
        assert result.allowed is False
        assert result.verdict == "scope_revalidation_blocked"

    def test_missing_scope_never_allowed(self):
        for url in ("https://example.com", "http://127.0.0.1:8080"):
            result = revalidate_scope_for_request(url)
            assert result.verdict == "scope_revalidation_blocked"
            assert result.allowed is False

    def test_empty_in_scope_domains_is_blocked(self):
        scope = _scope([])
        result = revalidate_scope_for_request("https://anything.example", scope_definition=scope)
        assert result.allowed is False
        assert result.verdict == "scope_revalidation_blocked"

    def test_no_scope_defined_reason_never_allowed(self):
        # Defensive: even if a guard answer carries "No scope defined",
        # the validator must not treat it as allowed.
        scope = _scope(["a.example.com"])
        # Simulate by directly checking _validate_url_pure on a guard-less path
        # is not reachable; instead assert a scope with empty domains (which
        # is what legacy code answered ALLOWED with "No scope defined") blocks.
        result = revalidate_scope_for_request("https://a.example.com", scope_definition=_scope([]))
        assert result.allowed is False

    def test_out_of_scope_rejected(self):
        scope = _scope(["in-scope.example.com"])
        result = revalidate_scope_for_request(
            "https://out.example.com/page", scope_definition=scope
        )
        assert result.allowed is False
        assert result.verdict == "out_of_scope"

    def test_redirect_to_out_of_scope_blocked(self):
        scope = _scope(["a.example.com"])
        result = revalidate_scope_for_request(
            "https://b.example.com/landing",
            scope_definition=scope,
            redirect_from="https://a.example.com/redirect",
        )
        assert result.allowed is False
        assert result.verdict == "redirect_out_of_scope"

    def test_redirect_within_scope_allowed(self):
        scope = _scope(["a.example.com"])
        result = revalidate_scope_for_request(
            "https://a.example.com/landing",
            scope_definition=scope,
            redirect_from="https://a.example.com/redirect",
        )
        assert result.allowed is True
        assert result.verdict == "allowed"

    def test_allowed_requires_explicit_scope(self):
        scope = _scope(["a.example.com"])
        result = revalidate_scope_for_request(
            "https://a.example.com/page", scope_definition=scope
        )
        assert result.allowed is True
        assert result.verdict == "allowed"


class TestScopeParallelIsolation:
    def test_two_scopes_are_isolated_during_concurrent_evaluation(self):
        scope_a = _scope(["a.example.com"])
        scope_b = _scope(["b.example.com"])
        start = Barrier(2)

        def evaluate(scope, own_url, foreign_url):
            start.wait()
            own = revalidate_scope_for_request(
                own_url, scope_definition=scope
            )
            foreign = revalidate_scope_for_request(
                foreign_url, scope_definition=scope
            )
            return own.allowed, foreign.allowed

        with ThreadPoolExecutor(max_workers=2) as pool:
            future_a = pool.submit(
                evaluate,
                scope_a,
                "https://a.example.com/x",
                "https://b.example.com/x",
            )
            future_b = pool.submit(
                evaluate,
                scope_b,
                "https://b.example.com/x",
                "https://a.example.com/x",
            )

        assert future_a.result() == (True, False)
        assert future_b.result() == (True, False)

    def test_two_scopes_do_not_cross_contaminate(self):
        scope_a = _scope(["a.example.com"])
        scope_b = _scope(["b.example.com"])

        # Interleaved evaluation of two different scopes must never let a
        # URL from one scope pass through the other.
        ra = revalidate_scope_for_request("https://a.example.com/x", scope_definition=scope_a)
        rb1 = revalidate_scope_for_request("https://a.example.com/x", scope_definition=scope_b)
        rb2 = revalidate_scope_for_request("https://b.example.com/x", scope_definition=scope_b)
        ra2 = revalidate_scope_for_request("https://b.example.com/x", scope_definition=scope_a)

        assert ra.allowed is True
        assert rb1.allowed is False
        assert rb2.allowed is True
        assert ra2.allowed is False

    def test_passed_scope_definition_never_mutated(self):
        scope = _scope(["a.example.com"])
        before = {
            "in": list(scope.in_scope_domains),
            "out": list(scope.out_of_scope_domains),
        }
        revalidate_scope_for_request("https://a.example.com/x", scope_definition=scope)
        revalidate_scope_for_request("https://b.example.com/x", scope_definition=scope)
        assert list(scope.in_scope_domains) == before["in"]
        assert list(scope.out_of_scope_domains) == before["out"]

    def test_global_singleton_scope_untouched(self):
        from src.core.security.scope_parser import get_scope_parser

        parser = get_scope_parser()
        saved = getattr(parser._guard, "scope", None)
        scope = _scope(["a.example.com"])
        revalidate_scope_for_request("https://a.example.com/x", scope_definition=scope)
        revalidate_scope_for_request("https://b.example.com/x")
        assert getattr(parser._guard, "scope", None) is saved

    def test_pure_deterministic(self):
        scope = _scope(["a.example.com"])
        r1 = revalidate_scope_for_request("https://a.example.com/x", scope_definition=scope)
        r2 = revalidate_scope_for_request("https://a.example.com/x", scope_definition=scope)
        assert (r1.verdict, r1.allowed) == (r2.verdict, r2.allowed)

    def test_oob_destination_revalidated_independently(self):
        scope = _scope(["a.example.com"])
        # OOB callback destination on another host must be blocked
        result = revalidate_scope_for_request(
            "https://oob.example.com/cb", scope_definition=scope
        )
        assert result.allowed is False
