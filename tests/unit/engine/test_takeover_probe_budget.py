"""Tests for takeover probe budget, dedupe window, and shared probe cache."""

import time

import pytest

from src.core.engine.takeover_probe_budget import (
    DedupeWindow,
    ProbeBudget,
    ProbeCache,
    check_probe_allowed,
)


# ---------------------------------------------------------------------------
# ProbeCache
# ---------------------------------------------------------------------------

class TestProbeCache:
    def test_make_key_is_consistent(self):
        """ProbeCache generates consistent keys from (candidate_id, provider, probe_type)."""
        cache = ProbeCache(ttl_seconds=3600)
        key1 = cache.make_key("cand-1", "github_pages", "http_probe")
        key2 = cache.make_key("cand-1", "github_pages", "http_probe")
        assert key1 == key2

    def test_make_key_differs_on_any_input(self):
        """Different inputs produce different keys."""
        cache = ProbeCache()
        key_a = cache.make_key("cand-1", "github_pages", "http_probe")
        key_b = cache.make_key("cand-2", "github_pages", "http_probe")
        key_c = cache.make_key("cand-1", "azure", "http_probe")
        key_d = cache.make_key("cand-1", "github_pages", "dns_probe")
        assert len({key_a, key_b, key_c, key_d}) == 4

    def test_set_and_get(self):
        """ProbeCache stores and retrieves results by key."""
        cache = ProbeCache()
        cache.set("key-1", {"status": "ok"})
        assert cache.get("key-1") == {"status": "ok"}

    def test_get_missing_returns_none(self):
        """ProbeCache returns None for missing key."""
        cache = ProbeCache()
        assert cache.get("nonexistent") is None

    def test_ttl_expiry(self):
        """ProbeCache respects TTL (cache entry expires after N seconds)."""
        cache = ProbeCache(ttl_seconds=0.05)  # 50ms TTL
        cache.set("key-1", {"status": "ok"})
        # Immediately readable.
        assert cache.get("key-1") == {"status": "ok"}
        time.sleep(0.1)
        assert cache.get("key-1") is None

    def test_ttl_not_expired_yet(self):
        """Entries within TTL are still valid."""
        cache = ProbeCache(ttl_seconds=60)
        cache.set("key-1", {"status": "ok"})
        assert cache.get("key-1") == {"status": "ok"}


# ---------------------------------------------------------------------------
# ProbeBudget
# ---------------------------------------------------------------------------

class TestProbeBudget:
    def test_consume_allows_within_budget(self):
        """ProbeBudget allows probes within budget."""
        budget = ProbeBudget(max_probes=3, window_seconds=3600)
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is True

    def test_consume_blocks_when_exceeded(self):
        """ProbeBudget blocks probes when budget exceeded."""
        budget = ProbeBudget(max_probes=2, window_seconds=3600)
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is False

    def test_remaining_counts_correctly(self):
        """ProbeBudget.remaining returns correct count."""
        budget = ProbeBudget(max_probes=5, window_seconds=3600)
        assert budget.remaining("target-a") == 5
        budget.consume("target-a")
        assert budget.remaining("target-a") == 4
        budget.consume("target-a")
        budget.consume("target-a")
        assert budget.remaining("target-a") == 2

    def test_reset_clears_target(self):
        """ProbeBudget.reset clears the budget for a target."""
        budget = ProbeBudget(max_probes=2, window_seconds=3600)
        budget.consume("target-a")
        budget.consume("target-a")
        assert budget.consume("target-a") is False

        budget.reset("target-a")
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is True

    def test_window_expiry_allows_new_probes(self):
        """ProbeBudget resets after time window (old timestamps expire)."""
        budget = ProbeBudget(max_probes=2, window_seconds=0.1)  # 100ms window
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is True
        assert budget.consume("target-a") is False

        time.sleep(0.15)  # Wait past window
        assert budget.consume("target-a") is True  # Window expired, new slot

    def test_per_target_isolation(self):
        """Budget is tracked independently per target."""
        budget = ProbeBudget(max_probes=2, window_seconds=3600)
        budget.consume("target-a")
        budget.consume("target-a")
        assert budget.consume("target-a") is False
        # target-b is independent and has its full budget.
        assert budget.consume("target-b") is True
        assert budget.consume("target-b") is True
        assert budget.consume("target-b") is False


# ---------------------------------------------------------------------------
# DedupeWindow
# ---------------------------------------------------------------------------

class TestDedupeWindow:
    def test_is_duplicate_true_within_window(self):
        """DedupeWindow prevents duplicate probe within window."""
        dedupe = DedupeWindow(window_seconds=300)
        dedupe.record("key-1")
        assert dedupe.is_duplicate("key-1") is True

    def test_is_duplicate_false_for_new_key(self):
        """New keys are not duplicates."""
        dedupe = DedupeWindow(window_seconds=300)
        assert dedupe.is_duplicate("new-key") is False

    def test_window_expires(self):
        """DedupeWindow allows probe after window expires."""
        dedupe = DedupeWindow(window_seconds=0.1)  # 100ms
        dedupe.record("key-1")
        assert dedupe.is_duplicate("key-1") is True
        time.sleep(0.15)
        assert dedupe.is_duplicate("key-1") is False  # Expired

    def test_re_record_resets_window(self):
        """Recording the same key again resets the dedupe window."""
        dedupe = DedupeWindow(window_seconds=0.15)
        dedupe.record("key-1")
        time.sleep(0.08)
        dedupe.record("key-1")  # Re-record resets
        time.sleep(0.08)
        # Total elapsed is 0.16s, but only 0.08s since last record.
        assert dedupe.is_duplicate("key-1") is True


# ---------------------------------------------------------------------------
# check_probe_allowed (integration of all three)
# ---------------------------------------------------------------------------

class TestCheckProbeAllowed:
    """Integration tests for check_probe_allowed()."""

    def _make_fixtures(self, *, ttl=3600, max_probes=10, budget_window=3600, dedupe_window=300):
        cache = ProbeCache(ttl_seconds=ttl)
        budget = ProbeBudget(max_probes=max_probes, window_seconds=budget_window)
        dedupe = DedupeWindow(window_seconds=dedupe_window)
        return cache, budget, dedupe

    def test_allowed_on_first_probe(self):
        """check_probe_allowed() returns allowed when all checks pass."""
        cache, budget, dedupe = self._make_fixtures()
        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert result == {"allowed": True, "reason": "allowed", "cached_result": None}

    def test_cache_hit_blocks(self):
        """check_probe_allowed() returns cache_hit when cache entry exists and is valid."""
        cache, budget, dedupe = self._make_fixtures()
        probe_key = cache.make_key("cand-1", "github_pages", "http_probe")
        cache.set(probe_key, {"status": "dangling"})

        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert result == {
            "allowed": False,
            "reason": "cache_hit",
            "cached_result": {"status": "dangling"},
        }

    def test_cache_hit_not_consumes_budget(self):
        """A cache hit should not consume a budget slot."""
        cache, budget, dedupe = self._make_fixtures(max_probes=1)
        probe_key = cache.make_key("cand-1", "github_pages", "http_probe")
        cache.set(probe_key, {"status": "dangling"})

        # Cache hit — no budget consumed.
        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert result["reason"] == "cache_hit"

        # Budget should still be full.
        assert budget.remaining("target-a") == 1

    def test_stale_candidate_bypasses_cache(self):
        """Stale candidates bypass cache and re-verify."""
        cache, budget, dedupe = self._make_fixtures()
        probe_key = cache.make_key("cand-1", "github_pages", "http_probe")
        cache.set(probe_key, {"status": "dangling"})

        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
            is_stale=True,
        )
        # Stale → cache bypassed, fresh probe allowed.
        assert result["reason"] == "allowed"
        assert result["cached_result"] is None

    def test_budget_exceeded_blocks(self):
        """check_probe_allowed() returns budget_exceeded when budget is exhausted."""
        cache, budget, dedupe = self._make_fixtures(max_probes=1)

        # First probe consumes the only slot.
        r1 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r1["reason"] == "allowed"

        # Second probe (different candidate) hits budget_exceeded.
        r2 = check_probe_allowed(
            candidate_id="cand-2",
            target="target-a",
            provider="azure",
            probe_type="dns_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r2 == {"allowed": False, "reason": "budget_exceeded", "cached_result": None}

    def test_duplicate_blocked(self):
        """check_probe_allowed() returns duplicate_blocked when duplicate within window."""
        cache, budget, dedupe = self._make_fixtures()

        # First probe allowed.
        r1 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r1["reason"] == "allowed"

        # Second probe with same key → duplicate_blocked.
        r2 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r2 == {"allowed": False, "reason": "duplicate_blocked", "cached_result": None}

    def test_duplicate_does_not_consume_budget(self):
        """A duplicate block should not consume a budget slot."""
        cache, budget, dedupe = self._make_fixtures(max_probes=2)

        # First probe for candidate-1 consumes budget (remaining: 1).
        r1 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r1["reason"] == "allowed"

        # Duplicate candidate-1 is blocked by dedupe, no budget consumed
        # (remaining: still 1).
        r2 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r2["reason"] == "duplicate_blocked"

        # A different candidate should still be allowed because the duplicate
        # did not consume a budget slot (remaining: 1 → now 0).
        r3 = check_probe_allowed(
            candidate_id="cand-2",
            target="target-a",
            provider="azure",
            probe_type="dns_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r3["reason"] == "allowed"

        # Now budget is exhausted (remaining: 0).
        r4 = check_probe_allowed(
            candidate_id="cand-3",
            target="target-a",
            provider="aws_s3",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert r4["reason"] == "budget_exceeded"

    def test_budget_checked_before_dedupe_when_budget_exhausted(self):
        """Budget is checked before dedupe; exhausted budget returns budget_exceeded
        without recording dedupe."""
        cache, budget, dedupe = self._make_fixtures(max_probes=0)

        # Budget already at zero — budget_exceeded, no dedupe recorded.
        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert result["reason"] == "budget_exceeded"
        # Dedupe should NOT have this key because we never got past budget check.
        probe_key = cache.make_key("cand-1", "github_pages", "http_probe")
        assert dedupe.is_duplicate(probe_key) is False

    def test_combined_order_cache_before_budget(self):
        """Cache hit returns before budget is consumed."""
        cache, budget, dedupe = self._make_fixtures(max_probes=0)
        probe_key = cache.make_key("cand-1", "github_pages", "http_probe")
        cache.set(probe_key, {"status": "ok"})

        # Even though budget is 0, cache hit returns first.
        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert result["reason"] == "cache_hit"

    def test_allowed_records_dedupe(self):
        """When allowed, the probe key is recorded in dedupe so subsequent calls are
        blocked."""
        cache, budget, dedupe = self._make_fixtures()

        _ = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )

        # Now a second call with the same inputs should be duplicate_blocked.
        result = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
        )
        assert result["reason"] == "duplicate_blocked"

    def test_stale_candidate_still_respects_dedupe(self):
        """Even stale candidates respect the dedupe window (no rapid re-probe)."""
        cache, budget, dedupe = self._make_fixtures()

        # First stale call allowed.
        r1 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
            is_stale=True,
        )
        assert r1["reason"] == "allowed"

        # Second stale call within window → duplicate blocked.
        r2 = check_probe_allowed(
            candidate_id="cand-1",
            target="target-a",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=dedupe,
            is_stale=True,
        )
        assert r2["reason"] == "duplicate_blocked"
