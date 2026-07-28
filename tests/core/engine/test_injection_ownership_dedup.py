"""
Tests for injection task ownership normalization and deduplication.

Covers plan steps:
- Step 1: ownership key = (normalized_url, vuln_family)
- Step 2: ownership admission in _add_tasks() rejects duplicate (url, family) pairs
- Step 3: Different families on same URL are allowed; same family is rejected
- Step 4: Task-local _context (pipeline.py) and guard/backfill suppression policy
"""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.agents.swarm.base import Task
from src.core.engine.master_conductor import MasterConductor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_task(
    task_id: str,
    agent_type: str = "InjectionSwarm",
    category: str = "xss_candidate",
    target: str = "http://example.com/page",
    targets: list | None = None,
    tags: list | None = None,
    priority: int = 80,
    params: dict | None = None,
) -> Task:
    """Create a minimal Task for ownership tests."""
    base_params: dict = {
        "category": category,
        "tags": tags or [category],
        "_context": {},
    }
    if targets is not None:
        base_params["targets"] = targets
    if target:
        base_params["target"] = target
    if params:
        base_params.update(params)
    return Task(
        id=task_id,
        name=f"Test {task_id}",
        agent_type=agent_type,
        priority=priority,
        params=base_params,
        target=target,
        tags=tags or [category],
    )


# ---------------------------------------------------------------------------
# Tests: ownership key helper
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Reusable MasterConductor fixture helpers
# ---------------------------------------------------------------------------

def _make_mc_for_test():
    """Create a minimal MasterConductor with all async/side-effect deps mocked."""
    with (
        patch("src.core.engine.master_conductor.get_findings_repository"),
        patch("src.core.engine.master_conductor.AsyncDatabaseWriter"),
        patch("src.core.engine.master_conductor.AgentFactory"),
        patch("src.core.engine.master_conductor.SmartScheduler"),
        patch("src.core.engine.master_conductor.KnowledgeGraph"),
        patch("src.core.engine.master_conductor.get_event_bus") as mock_eb,
        patch("src.core.engine.master_conductor.get_phase_gate"),
        patch("src.core.engine.master_conductor.get_notifier"),
    ):
        mock_eb.return_value.start = AsyncMock()
        mc = MasterConductor()
        mc.risk_predictor = MagicMock()
        mc.task_queue = MagicMock()
        mc.task_queue.get_by_id.return_value = None
        mc._derived_task_count = 0
        return mc


class TestOwnershipKeyHelper:
    """Test the _make_ownership_key / _resolve_vuln_family_from_category helpers."""

    @pytest.mark.parametrize(
        "category, expected_families",
        [
            ("xss_candidate", {"xss", "injection"}),
            ("id_param", {"injection", "xss", "access_control"}),
            ("csrf_candidate", {"csrf", "auth"}),
            ("api_candidate", {"api", "injection"}),
            ("command_injection", {"injection"}),
            ("file_param", {"injection", "api"}),
        ],
    )
    def test_category_to_vuln_families(self, category, expected_families):
        """Categories should map to their vuln families via existing helper."""
        mc = _make_mc_for_test()
        families = mc._map_category_to_vuln_families(category)
        assert families == expected_families

    def test_ownership_key_normalizes_url(self):
        """Ownership key should normalize URL by stripping trailing slash and hash."""
        mc = _make_mc_for_test()

        key1 = mc._make_ownership_key("http://example.com/page/", "xss_candidate", "test")
        key2 = mc._make_ownership_key("http://example.com/page", "xss_candidate", "test")
        assert key1 == key2, "Trailing slash should be normalized"

        key3 = mc._make_ownership_key("http://example.com/page#section", "xss_candidate", "test")
        assert key3 == key2, "Hash fragment should be stripped"


# ---------------------------------------------------------------------------
# Tests: ownership admission in _add_tasks()
# ---------------------------------------------------------------------------

class TestOwnershipAdmission:
    """Test that _add_tasks() rejects duplicate ownership keys."""

    @pytest.fixture
    def mc(self):
        return _make_mc_for_test()

    def test_first_task_is_accepted(self, mc):
        """First task for a given (url, family) should be accepted."""
        task = _make_task("test-1", category="xss_candidate", target="http://example.com/xss")
        count = mc._add_tasks([task], source="recon.tagged_xss_candidate")
        assert count == 1
        assert mc.task_queue.add.called

    def test_same_url_family_rejected(self, mc):
        """Second task with same (url, family, execution_path) should be rejected."""
        url = "http://example.com/xss"
        task1 = _make_task("test-1", category="xss_candidate", target=url)
        task2 = _make_task("test-2", category="xss_candidate", target=url,
                           params={
                               "category": "xss_candidate",
                               "tags": ["xss_candidate"],
                               "_context": {},
                               "target": url,
                           })

        count1 = mc._add_tasks([task1], source="recon.tagged_xss_candidate")
        count2 = mc._add_tasks([task2], source="recon.tagged_xss_candidate")
        assert count1 == 1, "First task should be added"
        assert count2 == 0, "Second task with same (url, family, exec_path) should be suppressed"

    def test_different_family_same_url_allowed(self, mc):
        """Different vuln families on the same URL are allowed (no family overlap)."""
        url = "http://example.com/multi"
        # xss_candidate → {xss, injection}, csrf_candidate → {csrf, auth}
        # No overlap → both allowed
        task_xss = _make_task("xss-1", category="xss_candidate", target=url)
        task_csrf = _make_task("csrf-1", category="csrf_candidate", target=url,
                               params={
                                   "category": "csrf_candidate",
                                   "tags": ["csrf_candidate", "auth_endpoint"],
                                   "_context": {},
                                   "target": url,
                               })

        count1 = mc._add_tasks([task_xss], source="recon.tagged_xss_candidate")
        count2 = mc._add_tasks([task_csrf], source="recon.tagged_csrf_candidate")

        assert count1 == 1, "XSS task should be added"
        assert count2 == 1, "CSRF task on same URL but different family should be added"

    def test_non_injection_tasks_not_affected(self, mc):
        """Discovery and other non-injection tasks skip ownership tracking."""
        url = "http://example.com/page"
        task_xss = _make_task("inj-1", category="xss_candidate", target=url)
        task_disc = _make_task("disc-1", agent_type="DiscoverySwarm", category="discovery",
                               target=url, tags=["discovery"])

        count1 = mc._add_tasks([task_xss], source="recon")
        count2 = mc._add_tasks([task_disc], source="replan")

        assert count1 == 1
        assert count2 == 1, "Non-injection tasks should not be affected by ownership tracking"

    def test_guard_backfill_suppression_policy(self, mc):
        """coverage_backfill_guard tasks should NOT be suppressed by normal tasks
        because they have different execution_paths."""
        url = "http://example.com/csrf"

        # Normal CSRF task
        task_normal = _make_task("csrf-1", category="csrf_candidate", target=url,
                                 params={
                                     "category": "csrf_candidate",
                                     "source_category": "tagged_csrf_candidate",
                                     "tags": ["csrf_candidate", "auth_endpoint"],
                                     "_context": {},
                                     "target": url,
                                     "selection_origin": "recon.tagged_csrf_candidate",
                                 })

        # Backfill guard task (different execution_path)
        task_guard = _make_task("csrf-guard-1", category="csrf_candidate", target=url,
                                params={
                                    "category": "csrf_candidate",
                                    "source_category": "coverage_backfill",
                                    "tags": ["csrf_candidate", "auth_endpoint"],
                                    "_context": {},
                                    "target": url,
                                    "selection_origin": "coverage_backfill_guard",
                                })

        count1 = mc._add_tasks([task_normal], source="recon.tagged_csrf_candidate")
        count2 = mc._add_tasks([task_guard], source="coverage_backfill_guard")

        assert count1 == 1
        assert count2 == 1, (
            "Backfill guard task with different execution_path should be allowed"
        )

    def test_guard_backfill_allowed_when_no_normal_owner(self, mc):
        """Backfill guard task should be accepted when no normal task owns the pair."""
        url = "http://example.com/csrf-backfill-only"

        # No normal CSRF task first
        task_guard = _make_task("csrf-guard-2", category="csrf_candidate", target=url,
                                params={
                                    "category": "csrf_candidate",
                                    "source_category": "coverage_backfill",
                                    "tags": ["csrf_candidate", "auth_endpoint"],
                                    "_context": {},
                                    "target": url,
                                })

        count = mc._add_tasks([task_guard], source="coverage_backfill")
        assert count == 1, "Backfill guard task should be accepted when no normal owner exists"

    def test_different_execution_path_same_url_family_allowed(self, mc):
        """recon.tagged_* and master_conductor.recon.* both normalize to
        recon_tagged — same (url, family) should be suppressed (deduplicated)."""
        url = "http://example.com/xss"
        task_pipeline = _make_task("pipeline-1", category="xss_candidate", target=url,
                                   params={
                                       "category": "xss_candidate",
                                       "tags": ["xss_candidate"],
                                       "_context": {},
                                       "target": url,
                                       "selection_origin": "recon.tagged_xss_candidate",
                                   })

        c1 = mc._add_tasks([task_pipeline], source="recon.tagged_xss_candidate")
        c2 = mc._add_tasks([_make_task("mc-1", category="xss_candidate", target=url,
                                       params={
                                           "category": "xss_candidate",
                                           "tags": ["xss_candidate"],
                                           "_context": {},
                                           "target": url,
                                           "selection_origin": "master_conductor.recon.xss_candidate",
                                       })], source="master_conductor.recon")

        assert c1 == 1
        # Both normalize to "recon_tagged" → same execution_path → suppressed
        assert c2 == 0, "recon.tagged and master_conductor.recon should dedup to same ownership key"

    def test_release_ownership_allows_re_enqueue(self, mc):
        """After _release_ownership, same (url, family, execution_path) can be re-enqueued."""
        url = "http://example.com/xss"
        task1 = _make_task("xss-1", category="xss_candidate", target=url,
                           params={
                               "category": "xss_candidate",
                               "tags": ["xss_candidate"],
                               "_context": {},
                               "target": url,
                               "selection_origin": "recon.tagged_xss_candidate",
                           })

        # First enqueue
        c1 = mc._add_tasks([task1], source="recon.tagged_xss_candidate")
        assert c1 == 1

        # Release ownership (simulating task completion)
        mc._release_ownership(task1)

        # Re-enqueue with a fresh task (different ID, same URL+family+exec_path)
        task2 = _make_task("xss-2", category="xss_candidate", target=url,
                           params={
                               "category": "xss_candidate",
                               "tags": ["xss_candidate"],
                               "_context": {},
                               "target": url,
                               "selection_origin": "recon.tagged_xss_candidate",
                           })
        c2 = mc._add_tasks([task2], source="recon.tagged_xss_candidate")
        assert c2 == 1, "After release, re-enqueue with fresh task should be allowed"

    def test_file_param_category_dedup(self, mc):
        """file_param category participates in ownership dedup with injection+api families."""
        url = "http://example.com/download?file=report.pdf"
        task1 = _make_task("fp-1", category="file_param", target=url,
                           params={
                               "category": "file_param",
                               "tags": ["file_param"],
                               "_context": {},
                               "target": url,
                               "selection_origin": "recon.tagged_file_param",
                           })

        # Same URL, same family (file_param → {injection, api}) → rejected
        task2 = _make_task("fp-2", category="file_param", target=url,
                           params={
                               "category": "file_param",
                               "tags": ["file_param"],
                               "_context": {},
                               "target": url,
                               "selection_origin": "recon.tagged_file_param",
                           })

        c1 = mc._add_tasks([task1], source="recon.tagged_file_param")
        c2 = mc._add_tasks([task2], source="recon.tagged_file_param")
        assert c1 == 1
        assert c2 == 0, "file_param duplicate (same url, same family) should be suppressed"


# ---------------------------------------------------------------------------
# Tests: URL normalization for ownership key
# ---------------------------------------------------------------------------

class TestOwnershipUrlNormalization:
    """Edge cases for URL normalization in ownership key."""

    @pytest.fixture
    def mc(self):
        mc = _make_mc_for_test()
        mc._owned_injection_targets = set()
        return mc

    def test_trailing_slash_normalized(self, mc):
        """http://example.com/page/ and http://example.com/page should be treated as same."""
        url_a = "http://example.com/page/"
        url_b = "http://example.com/page"

        task_a = _make_task("a", category="xss_candidate", target=url_a)
        task_b = _make_task("b", category="xss_candidate", target=url_b)

        c1 = mc._add_tasks([task_a], source="test")
        c2 = mc._add_tasks([task_b], source="test")
        assert c1 == 1
        assert c2 == 0, "Trailing slash variant should be treated as duplicate"

    def test_hash_fragment_stripped(self, mc):
        """URLs with hash fragments should be normalized to base URL."""
        url_a = "http://example.com/page#/route"
        url_b = "http://example.com/page"

        task_a = _make_task("a", category="xss_candidate", target=url_a)
        task_b = _make_task("b", category="xss_candidate", target=url_b)

        c1 = mc._add_tasks([task_a], source="test")
        c2 = mc._add_tasks([task_b], source="test")
        assert c1 == 1
        assert c2 == 0, "Hash fragment variant should be treated as duplicate"

    def test_query_params_same_key_different_values_not_deduped(self, mc):
        """Same query key, different values should remain distinct ownership targets."""
        url_a = "http://example.com/page?id=1"
        url_b = "http://example.com/page?id=2"

        task_a = _make_task("a", category="xss_candidate", target=url_a,
                            params={"_context": {}, "target": url_a, "category": "xss_candidate",
                                    "tags": ["xss_candidate"], "selection_origin": "test"})
        task_b = _make_task("b", category="xss_candidate", target=url_b,
                            params={"_context": {}, "target": url_b, "category": "xss_candidate",
                                    "tags": ["xss_candidate"], "selection_origin": "test"})

        c1 = mc._add_tasks([task_a], source="test")
        c2 = mc._add_tasks([task_b], source="test")
        assert c1 == 1
        assert c2 == 1, "Same query key with different values should stay distinct"

    def test_query_params_same_pairs_different_order_deduped(self, mc):
        """Equivalent query pairs in different orders should normalize to the same key."""
        url_a = "http://example.com/page?b=2&a=1"
        url_b = "http://example.com/page?a=1&b=2"

        task_a = _make_task("a", category="xss_candidate", target=url_a,
                            params={"_context": {}, "target": url_a, "category": "xss_candidate",
                                    "tags": ["xss_candidate"], "selection_origin": "test"})
        task_b = _make_task("b", category="xss_candidate", target=url_b,
                            params={"_context": {}, "target": url_b, "category": "xss_candidate",
                                    "tags": ["xss_candidate"], "selection_origin": "test"})

        c1 = mc._add_tasks([task_a], source="test")
        c2 = mc._add_tasks([task_b], source="test")
        assert c1 == 1
        assert c2 == 0, "Same query pairs in different orders should deduplicate"

    def test_query_params_different_key_not_deduped(self, mc):
        """Different query keys → not deduplicated."""
        url_a = "http://example.com/page?id=1"
        url_b = "http://example.com/page?name=alice"

        task_a = _make_task("a", category="xss_candidate", target=url_a,
                            params={"_context": {}, "target": url_a, "category": "xss_candidate",
                                    "tags": ["xss_candidate"], "selection_origin": "test"})
        task_b = _make_task("b", category="xss_candidate", target=url_b,
                            params={"_context": {}, "target": url_b, "category": "xss_candidate",
                                    "tags": ["xss_candidate"], "selection_origin": "test"})

        c1 = mc._add_tasks([task_a], source="test")
        c2 = mc._add_tasks([task_b], source="test")
        assert c1 == 1
        assert c2 == 1, "Different query keys should be distinct dedup keys"

    def test_javascript_path_special_handling(self, mc):
        """javascript/ path URLs with same query keys should be deduplicated;
        different query keys should be distinct."""
        url_a = "http://example.com/vulnerabilities/javascript/?name=test"
        url_b = "http://example.com/vulnerabilities/javascript/"

        task_a = _make_task("a", category="xss_candidate", target=url_a)
        task_b = _make_task("b", category="xss_candidate", target=url_b)

        c1 = mc._add_tasks([task_a], source="test")
        c2 = mc._add_tasks([task_b], source="test")
        assert c1 == 1
        # ?name vs empty query → different keys → NOT deduplicated
        assert c2 == 1, "javascript/ with different query keys should be distinct targets"

    def test_fixed_execution_path_vocabulary(self, mc):
        """Verify the canonical execution_path vocabulary after normalization.
        recon.tagged_* and master_conductor.recon.* both normalize to recon_tagged."""
        url = "http://example.com/xss"

        # Canonical normalized values
        canonical_origins = [
            "recon_tagged",
            "coverage_backfill",
            "coverage_backfill_guard",
            "history_replay",
            "fallback",
        ]

        for i, origin in enumerate(canonical_origins):
            task = _make_task(f"vocab-{i}", category="xss_candidate", target=url,
                              params={
                                  "category": "xss_candidate",
                                  "tags": ["xss_candidate"],
                                  "_context": {},
                                  "target": url,
                                  "selection_origin": origin,
                              })
            c = mc._add_tasks([task], source=origin)
            assert c == 1, f"First enqueue for {origin} should succeed"

            # Same origin re-enqueue should be suppressed
            task2 = _make_task(f"vocab-{i}-dup", category="xss_candidate", target=url,
                               params={
                                   "category": "xss_candidate",
                                   "tags": ["xss_candidate"],
                                   "_context": {},
                                   "target": url,
                                   "selection_origin": origin,
                               })
            c2 = mc._add_tasks([task2], source=origin)
            assert c2 == 0, f"Same canonical origin {origin} re-enqueue should be suppressed"

            # Release and verify re-enqueue works
            mc._release_ownership(task)
            task3 = _make_task(f"vocab-{i}-re", category="xss_candidate", target=url,
                               params={
                                   "category": "xss_candidate",
                                   "tags": ["xss_candidate"],
                                   "_context": {},
                                   "target": url,
                                   "selection_origin": origin,
                               })
            c3 = mc._add_tasks([task3], source=origin)
            assert c3 == 1, f"After release, {origin} re-enqueue should succeed"
            mc._release_ownership(task3)
