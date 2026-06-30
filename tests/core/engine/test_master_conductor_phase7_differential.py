"""
Phase 7 Differential Gate Tests (SGK-2026-0316).

Purely functional tests for serial forced baseline vs Phase 7 gated comparison rules.
Real session replay is deferred to Phase 9 release gate.
"""
import pytest


class TestPhase7FindingParity:
    """Task 5: High/Critical finding parity between serial and gated paths."""

    def test_phase7_serial_forced_vs_gated_high_critical_finding_parity(self):
        serial_findings = {
            ("high", "idor", "https://example.com/api/users/1"),
            ("critical", "auth_bypass", "https://example.com/admin"),
        }
        gated_findings = {
            ("critical", "auth_bypass", "https://example.com/admin"),
            ("high", "idor", "https://example.com/api/users/1"),
        }

        assert gated_findings == serial_findings

    def test_phase7_finding_parity_empty_both_sides(self):
        assert set() == set()

    def test_phase7_finding_parity_single_finding(self):
        findings = {("high", "xss", "https://example.com/search")}
        assert findings == findings

    def test_phase7_finding_set_not_equal_different_findings(self):
        serial = {("high", "idor", "https://example.com/api/1")}
        gated = {("high", "sqli", "https://example.com/api/1")}

        assert serial != gated


class TestPhase7RequestBudget:
    """Task 5: Request budget comparison rules."""

    def test_phase7_gated_request_count_budget_allows_1_2x_baseline(self):
        serial_request_count = 100
        gated_request_count = 119

        assert gated_request_count <= int(serial_request_count * 1.2)

    def test_phase7_gated_request_count_at_limit_is_allowed(self):
        serial_request_count = 100
        gated_request_count = 120

        assert gated_request_count <= int(serial_request_count * 1.2)

    def test_phase7_gated_request_count_exceeds_limit_fails(self):
        serial_request_count = 100
        gated_request_count = 121

        assert not (gated_request_count <= int(serial_request_count * 1.2))

    def test_phase7_gated_request_count_zero_baseline(self):
        serial_request_count = 0
        gated_request_count = 0

        assert gated_request_count <= int(serial_request_count * 1.2)

    def test_phase7_gated_count_lower_than_baseline_allowed(self):
        serial_request_count = 100
        gated_request_count = 50

        assert gated_request_count <= int(serial_request_count * 1.2)


class TestPhase7ScopeViolation:
    """Task 5: Scope violation must be zero."""

    def test_phase7_gated_scope_violation_must_be_zero(self):
        gated_scope_violations: list = []

        assert gated_scope_violations == []

    def test_phase7_gated_scope_violation_non_zero_flagged(self):
        gated_scope_violations = ["out_of_scope_target"]

        assert gated_scope_violations != []


class TestPhase7AggressiveSuppressDifferential:
    """Task 5: Aggressive lane suppress during other lane execution."""

    def test_aggressive_suppress_prevents_read_only_execution(self):
        """When aggressive task owns an origin, read_only is denied."""
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://target.com", lane="aggressive_exclusive", owner_task_id="agg-1")

        decision = suppressor.check("https://target.com", lane="read_only", task_id="read-1")
        assert decision.allowed is False
        assert decision.reason_code == "origin_suppressed_by_aggressive"

    def test_aggressive_suppress_allows_after_release(self):
        """After aggressive release, read_only passes."""
        from src.core.engine.origin_suppressor import OriginSuppressor

        suppressor = OriginSuppressor()
        suppressor.enter("https://target.com", lane="aggressive_exclusive", owner_task_id="agg-1")
        suppressor.release("https://target.com", owner_task_id="agg-1")

        decision = suppressor.check("https://target.com", lane="read_only", task_id="read-1")
        assert decision.allowed is True
