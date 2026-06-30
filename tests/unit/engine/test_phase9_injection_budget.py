"""
Phase 9 (SGK-2026-0318) T-3.1 + T-3.2: Injection URL budget enforcement
and deterministic post-join merge.

Tests:
  1. test_per_url_budget_consume_allowed — worker returns success with budget_decision
  2. test_per_url_budget_rejected_returns_skipped — budget exceeded → status="rejected"
  3. test_per_url_sub_result_no_context_mutation — worker does not mutate shared current_context
  4. test_deterministic_merge_order — merge result order is deterministic based on fingerprints
  5. test_merge_preserves_finding_counts — skipped/rejected results don't lose findings from successful workers
  6. test_budget_decision_recorded_in_sub_result — budget_decision dict is populated
"""
import pytest

from src.core.engine.swarm_dispatcher import SwarmDispatcher
from src.core.engine.budget_policy import (
    ExecutionBudgetPolicy,
    BudgetReasonCode,
)
from src.core.models.swarm import PerUrlSubResult, SwarmResult
from src.core.models.finding import Finding, VulnType, Severity


# ============================================================================
# Helpers
# ============================================================================

def _make_finding(title: str) -> Finding:
    """Create a minimal Finding for test purposes."""
    return Finding(
        vuln_type=VulnType.SQL_INJECTION,
        severity=Severity.MEDIUM,
        title=title,
        description=f"test description for {title}",
        target_url="https://example.com/test",
    )


# ============================================================================
# T-3.1 Tests: Budget Enforcement via _build_per_url_sub_result
# ============================================================================


class TestBuildPerUrlSubResult:
    """T-3.1: Budget enforcement in _build_per_url_sub_result()."""

    def test_per_url_budget_consume_allowed(self):
        """When budget allows, _build_per_url_sub_result returns pending with allowed=True."""
        dispatcher = SwarmDispatcher()
        # Use high burst so budget is not exhausted
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=100)

        result = dispatcher._build_per_url_sub_result(
            source_url="https://example.com/page?id=1",
            origin_key="https://example.com",
            request_fingerprint="fp_req_001",
            payload_fingerprint="fp_pay_001",
        )

        assert result.status == "pending"
        assert result.source_url == "https://example.com/page?id=1"
        assert result.origin_key == "https://example.com"
        assert result.request_fingerprint == "fp_req_001"
        assert result.payload_fingerprint == "fp_pay_001"
        assert result.budget_decision["allowed"] is True
        assert result.budget_decision["reason_code"] == ""
        assert result.budget_decision["wait_seconds"] == 0.0
        assert result.is_skipped_or_rejected is False

    def test_per_url_budget_rejected_returns_rejected(self):
        """When budget is exceeded with reason_code, status="rejected"."""
        dispatcher = SwarmDispatcher()
        # Tiny burst to trigger budget exhaustion immediately
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=1)

        # First URL: allowed
        result1 = dispatcher._build_per_url_sub_result(
            source_url="https://example.com/page?id=1",
            origin_key="https://example.com",
        )
        assert result1.status == "pending"

        # Second URL: budget exhausted → rejected
        result2 = dispatcher._build_per_url_sub_result(
            source_url="https://example.com/page?id=2",
            origin_key="https://example.com",
        )
        assert result2.status == "rejected"
        assert result2.budget_decision["allowed"] is False
        assert result2.budget_decision["reason_code"] == BudgetReasonCode.BUDGET_EXCEEDED
        assert result2.is_skipped_or_rejected is True

    def test_budget_decision_recorded_in_sub_result(self):
        """budget_decision dict is populated with correct fields."""
        dispatcher = SwarmDispatcher()
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=10)

        result = dispatcher._build_per_url_sub_result(
            source_url="https://example.com/test",
            origin_key="https://example.com",
        )

        bd = result.budget_decision
        assert isinstance(bd, dict)
        assert "allowed" in bd
        assert "wait_seconds" in bd
        assert "reason_code" in bd
        assert bd["allowed"] is True

        # After exhausting budget
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=1)
        dispatcher._budget_policy.consume("https://other.example.com")  # burn the token
        result2 = dispatcher._build_per_url_sub_result(
            source_url="https://other.example.com/test",
            origin_key="https://other.example.com",
        )
        assert result2.budget_decision["allowed"] is False
        assert result2.budget_decision["reason_code"] == BudgetReasonCode.BUDGET_EXCEEDED

    def test_per_url_sub_result_no_context_mutation(self):
        """Worker does not mutate shared current_context — returns PerUrlSubResult objects.

        This test verifies that _build_per_url_sub_result returns independent
        PerUrlSubResult objects, and that modifying one result does not affect
        another result or a shared context dict.
        """
        dispatcher = SwarmDispatcher()
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=100)

        # Simulated "shared current_context" (what workers must NOT mutate)
        shared_context: dict = {
            "findings": [],
            "url_results": {},
            "tested_params": [],
        }

        # Worker 1: budget allowed, returns its own result
        result1 = dispatcher._build_per_url_sub_result(
            source_url="https://example.com/page1",
            origin_key="https://example.com",
            request_fingerprint="fp1",
            payload_fingerprint="pp1",
        )
        # Simulate worker filling in result (NOT shared_context)
        finding1 = _make_finding("SQLi on page1")
        result1.findings.append(finding1)
        result1.tested_params.append("id")
        result1.url_result["page1"] = "tested"
        result1.status = "success"

        # Worker 2: budget allowed, returns its own result
        result2 = dispatcher._build_per_url_sub_result(
            source_url="https://example.com/page2",
            origin_key="https://example.com",
            request_fingerprint="fp2",
            payload_fingerprint="pp2",
        )
        finding2 = _make_finding("XSS on page2")
        result2.findings.append(finding2)
        result2.tested_params.append("name")
        result2.url_result["page2"] = "tested"
        result2.status = "success"

        # shared_context must remain untouched
        assert shared_context["findings"] == []
        assert shared_context["url_results"] == {}
        assert shared_context["tested_params"] == []

        # Each sub-result is independent
        assert len(result1.findings) == 1
        assert result1.findings[0].title == "SQLi on page1"
        assert len(result2.findings) == 1
        assert result2.findings[0].title == "XSS on page2"
        assert result1.tested_params == ["id"]
        assert result2.tested_params == ["name"]


# ============================================================================
# T-3.2 Tests: Deterministic Post-Join Merge
# ============================================================================


class TestMergePerUrlSubResults:
    """T-3.2: Deterministic merge via _merge_per_url_sub_results()."""

    def _make_sub_result(
        self,
        source_url: str,
        rf: str = "",
        pf: str = "",
        findings=None,
        tested_params=None,
        url_result=None,
        status: str = "success",
    ) -> PerUrlSubResult:
        """Helper to create a PerUrlSubResult with optional findings/params."""
        return PerUrlSubResult(
            source_url=source_url,
            origin_key="https://example.com",
            request_fingerprint=rf,
            payload_fingerprint=pf,
            findings=findings or [],
            tested_params=tested_params or [],
            url_result=url_result or {},
            budget_decision={"allowed": True, "wait_seconds": 0.0, "reason_code": ""},
            status=status,
        )

    def test_deterministic_merge_order(self):
        """Merge result order is deterministic based on fingerprints.

        Even when results are passed in random order, the merge output
        maintains a consistent order determined by
        (source_url, request_fingerprint, payload_fingerprint).
        """
        dispatcher = SwarmDispatcher()

        r1 = self._make_sub_result("https://example.com/c", rf="fp_c", pf="pp_c",
                                   findings=[_make_finding("C finding")])
        r2 = self._make_sub_result("https://example.com/a", rf="fp_a", pf="pp_a",
                                   findings=[_make_finding("A finding")])
        r3 = self._make_sub_result("https://example.com/b", rf="fp_b", pf="pp_b",
                                   findings=[_make_finding("B finding")])

        # Pass in non-sorted order
        merged = SwarmDispatcher._merge_per_url_sub_results([r3, r1, r2])

        # Findings should be in sorted order: a, b, c
        assert len(merged["findings"]) == 3
        assert merged["findings"][0].title == "A finding"
        assert merged["findings"][1].title == "B finding"
        assert merged["findings"][2].title == "C finding"

        # Repeated call with different input order must produce same output order
        merged2 = SwarmDispatcher._merge_per_url_sub_results([r2, r3, r1])
        assert [f.title for f in merged2["findings"]] == ["A finding", "B finding", "C finding"]

        # Different fingerprints determine order within same source_url
        r4 = self._make_sub_result("https://example.com/a", rf="fp_a", pf="pp_x",
                                   findings=[_make_finding("AX finding")])
        r5 = self._make_sub_result("https://example.com/a", rf="fp_a", pf="pp_y",
                                   findings=[_make_finding("AY finding")])
        merged3 = SwarmDispatcher._merge_per_url_sub_results([r5, r4, r1, r2, r3])
        # Expected sorted order: a/pp_a, a/pp_x, a/pp_y, b, c  (5 total)
        expected = ["A finding", "AX finding", "AY finding", "B finding", "C finding"]
        assert [f.title for f in merged3["findings"]] == expected

    def test_merge_preserves_finding_counts(self):
        """Skipped/rejected results don't lose findings from successful workers."""
        dispatcher = SwarmDispatcher()

        r_ok1 = self._make_sub_result("https://example.com/a",
                                      findings=[_make_finding("OK finding 1")],
                                      status="success")
        r_skip = self._make_sub_result("https://example.com/b",
                                       status="skipped")
        r_ok2 = self._make_sub_result("https://example.com/c",
                                      findings=[_make_finding("OK finding 2")],
                                      status="success")
        r_reject = self._make_sub_result("https://example.com/d",
                                         status="rejected")
        r_fail = self._make_sub_result("https://example.com/e",
                                       findings=[_make_finding("Fail finding")],
                                       status="failed")

        merged = SwarmDispatcher._merge_per_url_sub_results(
            [r_ok1, r_skip, r_ok2, r_reject, r_fail]
        )

        # Findings from success + failed workers are included
        assert len(merged["findings"]) == 3
        finding_titles = {f.title for f in merged["findings"]}
        assert finding_titles == {"OK finding 1", "OK finding 2", "Fail finding"}

        # Counts reflect correct categorization
        assert merged["counts"]["success"] == 2
        assert merged["counts"]["skipped"] == 1
        assert merged["counts"]["rejected"] == 1
        assert merged["counts"]["failed"] == 1
        assert merged["counts"]["total"] == 5

    def test_merge_includes_all_result_fields(self):
        """Merge preserves url_results and tested_params."""
        dispatcher = SwarmDispatcher()

        r1 = self._make_sub_result(
            "https://example.com/a",
            findings=[_make_finding("a1")],
            tested_params=["id", "name"],
            url_result={"a_status": 200},
        )
        r2 = self._make_sub_result(
            "https://example.com/b",
            findings=[_make_finding("b1")],
            tested_params=["name", "email"],  # "name" is duplicate
            url_result={"b_status": 500},
        )

        merged = SwarmDispatcher._merge_per_url_sub_results([r1, r2])

        assert len(merged["findings"]) == 2
        # tested_params are deduplicated
        assert sorted(merged["tested_params"]) == ["email", "id", "name"]
        # url_results are merged (latter overwrites on key collision)
        assert merged["url_results"] == {"a_status": 200, "b_status": 500}

    def test_merge_empty_list(self):
        """Empty sub_results list produces empty merge."""
        merged = SwarmDispatcher._merge_per_url_sub_results([])
        assert merged["findings"] == []
        assert merged["url_results"] == {}
        assert merged["tested_params"] == []
        assert merged["counts"]["total"] == 0

    def test_merge_all_skipped(self):
        """All results skipped/rejected still returns valid empty merge."""
        r1 = self._make_sub_result("https://example.com/a", status="skipped")
        r2 = self._make_sub_result("https://example.com/b", status="rejected")

        merged = SwarmDispatcher._merge_per_url_sub_results([r1, r2])

        assert merged["findings"] == []
        assert merged["url_results"] == {}
        assert merged["tested_params"] == []
        assert merged["counts"]["skipped"] == 1
        assert merged["counts"]["rejected"] == 1
        assert merged["counts"]["total"] == 2


# ============================================================================
# Integration Tests: Actual dispatch path with budget enforcement
# ============================================================================


class TestInjectionUrlBudgetIntegration:
    """Integration tests exercising the actual dispatch path through
    dispatch_injection_urls_with_budget().
    """

    @pytest.mark.asyncio
    async def test_integration_budget_exceeded_urls_skipped(self):
        """Set burst=2, dispatch 5 URLs, assert 3 are skipped/rejected with budget_reason.

        Verifies:
        - _build_per_url_sub_result budget enforcement runs before each dispatch
        - URLs beyond burst are not dispatched (skipped/rejected)
        - _merge_per_url_sub_results produces correct counts
        """
        dispatcher = SwarmDispatcher()
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=2)

        # Mock _dispatch_to_single_swarm to avoid network / aggressive-limiter calls
        dispatched_urls: list = []

        async def _mock_dispatch(swarm_name, target, task_name, params):
            dispatched_urls.append(target)
            return SwarmResult(
                findings=[],
                status="success",
                swarm_name=swarm_name,
            )

        dispatcher._dispatch_to_single_swarm = _mock_dispatch  # type: ignore[method-assign]

        urls = [
            "https://example.com/page?id=1",
            "https://example.com/page?id=2",
            "https://example.com/page?id=3",
            "https://example.com/page?id=4",
            "https://example.com/page?id=5",
        ]

        merged = await dispatcher.dispatch_injection_urls_with_budget(
            urls=urls,
            origin_key="https://example.com",
        )

        # Burst=2 → only 2 URLs should have been dispatched
        assert merged["counts"]["success"] == 2
        assert merged["counts"]["rejected"] == 3
        assert merged["counts"]["total"] == 5
        assert merged["counts"]["skipped"] == 0
        assert merged["counts"]["failed"] == 0

        # Exactly 2 URLs reached the mock dispatch
        assert len(dispatched_urls) == 2
        assert dispatched_urls == urls[:2]

    @pytest.mark.asyncio
    async def test_integration_merge_result_has_skip_evidence(self):
        """Merged dict includes skip_count and reject_count.

        Verifies:
        - Merged result dict contains 'counts' with 'skipped' and 'rejected' keys
        - Budget-exceeded URLs produce rejected entries with budget_decision reason_code
        - All findings/url_results/tested_params present even when budget rejects some URLs
        """
        dispatcher = SwarmDispatcher()
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=2)

        async def _mock_dispatch(swarm_name, target, task_name, params):
            # First two URLs return findings, rest would be rejected by budget
            findings = []
            if "id=1" in target:
                findings = [_make_finding("SQLi on page1")]
            elif "id=2" in target:
                findings = [_make_finding("XSS on page2")]
            return SwarmResult(
                findings=findings,
                status="success",
                swarm_name=swarm_name,
            )

        dispatcher._dispatch_to_single_swarm = _mock_dispatch  # type: ignore[method-assign]

        urls = [
            "https://example.com/page?id=1",
            "https://example.com/page?id=2",
            "https://example.com/page?id=3",
        ]

        merged = await dispatcher.dispatch_injection_urls_with_budget(
            urls=urls,
            origin_key="https://example.com",
        )

        # Verify counts include skip/reject evidence
        assert "counts" in merged
        assert "skipped" in merged["counts"]
        assert "rejected" in merged["counts"]
        assert merged["counts"]["success"] == 2
        assert merged["counts"]["rejected"] == 1
        assert merged["counts"]["skipped"] == 0
        assert merged["counts"]["total"] == 3

        # Findings from successful workers are preserved
        assert len(merged["findings"]) == 2
        finding_titles = {f.title for f in merged["findings"]}
        assert finding_titles == {"SQLi on page1", "XSS on page2"}

    @pytest.mark.asyncio
    async def test_integration_all_urls_rejected_by_budget(self):
        """When burst=0, all URLs are rejected without dispatch."""
        dispatcher = SwarmDispatcher()
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=0)

        dispatch_count = 0

        async def _mock_dispatch(swarm_name, target, task_name, params):
            nonlocal dispatch_count
            dispatch_count += 1
            return SwarmResult(
                findings=[],
                status="success",
                swarm_name=swarm_name,
            )

        dispatcher._dispatch_to_single_swarm = _mock_dispatch  # type: ignore[method-assign]

        urls = [
            "https://example.com/page?id=1",
            "https://example.com/page?id=2",
        ]

        merged = await dispatcher.dispatch_injection_urls_with_budget(
            urls=urls,
            origin_key="https://example.com",
        )

        # All rejected, none dispatched
        assert merged["counts"]["rejected"] == 2
        assert merged["counts"]["total"] == 2
        assert merged["findings"] == []
        assert dispatch_count == 0

    @pytest.mark.asyncio
    async def test_integration_empty_url_list(self):
        """Empty URL list produces valid empty merge."""
        dispatcher = SwarmDispatcher()
        dispatcher._budget_policy = ExecutionBudgetPolicy(rpm=60000, burst=10)

        merged = await dispatcher.dispatch_injection_urls_with_budget(
            urls=[],
            origin_key="https://example.com",
        )

        assert merged["counts"]["total"] == 0
        assert merged["findings"] == []
        assert merged["url_results"] == {}
        assert merged["tested_params"] == []
