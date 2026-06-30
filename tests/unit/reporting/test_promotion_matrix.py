"""T-6.1: Promotion/demotion matrix tests for Phase 9."""

import pytest
from src.reporting.promotion_matrix import PromotionMatrix, PromotionDecision


class TestPromotionMatrix:
    """Unit tests for the promotion/demotion matrix."""

    def setup_method(self):
        self.matrix = PromotionMatrix()

    # --- T-6.1 test 1: safest combo promotes ---
    def test_ga_public_read_only_promotes(self):
        """ga + public + read_only should promote as the safest combination."""
        decision = self.matrix.evaluate("public", "ga", "read_only")
        assert decision.action == "promote"
        assert decision.candidate_default_flag is True
        assert decision.requires_manual_approval is False
        assert "safe for promotion" in decision.reason

    # --- T-6.1 test 2: experimental maturity always holds ---
    def test_experimental_holds(self):
        """Any experimental maturity should hold regardless of other factors."""
        for risk_tier in ("public", "authenticated", "admin"):
            for lane in ("read_only", "stateful_read"):
                decision = self.matrix.evaluate(risk_tier, "experimental", lane)
                assert decision.action == "hold", (
                    f"experimental + {risk_tier} + {lane} should hold"
                )
                assert decision.requires_manual_approval is True

    # --- T-6.1 test 3: mutating-heavy risk tier always holds ---
    def test_mutating_heavy_holds(self):
        """mutating-heavy risk tier always results in hold."""
        for maturity in ("ga", "beta", "experimental"):
            for lane in ("read_only", "stateful_read", "mutating", "aggressive_exclusive"):
                decision = self.matrix.evaluate("mutating-heavy", maturity, lane)
                assert decision.action == "hold", (
                    f"mutating-heavy + {maturity} + {lane} should hold"
                )
                assert decision.requires_manual_approval is True
                assert "mutex audit" in decision.reason.lower()

    # --- T-6.1 test 4: demote on parity failure ---
    def test_demote_on_parity_failure(self):
        """finding_parity < 100% should override to demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={"finding_parity": 99, "scope_violation": 0, "event_drop": 0},
        )
        assert decision.action == "demote"
        assert decision.candidate_default_flag is False
        assert decision.requires_manual_approval is True
        assert "finding_parity=99%" in decision.reason

    def test_demote_on_scope_violation(self):
        """scope_violation > 0 should override to demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={"finding_parity": 100, "scope_violation": 1, "event_drop": 0},
        )
        assert decision.action == "demote"
        assert "scope_violation=1" in decision.reason

    def test_demote_on_event_drop(self):
        """event_drop > 0 should override to demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={"finding_parity": 100, "scope_violation": 0, "event_drop": 2},
        )
        assert decision.action == "demote"
        assert "event_drop=2" in decision.reason

    def test_demote_multiple_failures(self):
        """Multiple gate failures should all appear in reason."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={"finding_parity": 95, "scope_violation": 3, "event_drop": 1},
        )
        assert decision.action == "demote"
        assert "finding_parity=95%" in decision.reason
        assert "scope_violation=3" in decision.reason
        assert "event_drop=1" in decision.reason

    def test_no_demote_when_gate_results_clean(self):
        """Clean gate results should not trigger demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={"finding_parity": 100, "scope_violation": 0, "event_drop": 0},
        )
        assert decision.action == "promote"

    # --- T-6.1 test 5: admin + beta holds ---
    def test_admin_beta_holds(self):
        """admin targets with beta maturity should hold for more canary evidence."""
        for lane in ("read_only", "stateful_read"):
            decision = self.matrix.evaluate("admin", "beta", lane)
            assert decision.action == "hold", (
                f"admin + beta + {lane} should hold"
            )
            assert "canary" in decision.reason.lower()
            assert decision.candidate_default_flag is False

    # --- T-6.1 test 6: aggressive_exclusive requires manual approval ---
    def test_manual_approval_required_for_aggressive(self):
        """aggressive_exclusive lane requires manual approval."""
        decision = self.matrix.evaluate("public", "ga", "aggressive_exclusive")
        assert decision.action == "hold"
        assert decision.requires_manual_approval is True
        assert "manual approval" in decision.reason.lower()

    def test_manual_approval_required_for_mutating(self):
        """mutating lane requires manual approval."""
        decision = self.matrix.evaluate("public", "ga", "mutating")
        assert decision.action == "hold"
        assert decision.requires_manual_approval is True

    # --- T-6.1 test 7: candidates separate from config ---
    def test_default_flag_candidates_separate_from_config(self):
        """get_default_flag_candidates returns dict without mutating any settings."""
        candidates = self.matrix.get_default_flag_candidates()

        # Should be a dict
        assert isinstance(candidates, dict)

        # Keys should follow the tier.maturity.lane pattern
        for key, value in candidates.items():
            assert value is True
            parts = key.split(".")
            assert len(parts) == 3, f"Key '{key}' should have 3 dot-separated parts"
            risk_tier, maturity, lane = parts
            assert risk_tier in ("public", "authenticated")
            assert maturity == "ga"
            assert lane in ("read_only", "stateful_read")

        # Expected combinations: 2 tiers × 1 maturity × 2 lanes = 4
        assert len(candidates) == 4, (
            f"Expected 4 candidates (2 tiers × 1 maturity × 2 lanes), got {len(candidates)}"
        )

        # Verify each expected key exists
        expected = {
            "public.ga.read_only": True,
            "public.ga.stateful_read": True,
            "authenticated.ga.read_only": True,
            "authenticated.ga.stateful_read": True,
        }
        for key in expected:
            assert key in candidates, f"Expected candidate key '{key}' not found"
            assert candidates[key] is True

    # --- T-6.1 test 8: matrix generates all combinations ---
    def test_matrix_generates_all_combinations(self):
        """generate_matrix_table should produce at least 32 combinations."""
        table = self.matrix.generate_matrix_table()

        # 4 tiers × 3 maturities × 4 lanes = 48 combinations
        assert len(table) >= 32, (
            f"Expected at least 32 combinations, got {len(table)}"
        )
        assert len(table) == 48, (
            f"Expected 48 combinations (4×3×4), got {len(table)}"
        )

        # Every row should have all required fields
        required_fields = {
            "action", "target_risk_tier", "specialist_maturity",
            "lane_policy", "candidate_default_flag", "reason",
            "requires_manual_approval", "gate_results",
        }
        for row in table:
            assert set(row.keys()) == required_fields, (
                f"Row missing fields: {required_fields - set(row.keys())}"
            )
            assert row["action"] in ("promote", "hold", "demote")

        # Verify we have all unique combinations
        combos = {
            (row["target_risk_tier"], row["specialist_maturity"], row["lane_policy"])
            for row in table
        }
        assert len(combos) == 48, f"Expected 48 unique combos, got {len(combos)}"

    # --- Additional edge case tests ---
    def test_ga_authenticated_stateful_read_promotes(self):
        """ga + authenticated + stateful_read should promote."""
        decision = self.matrix.evaluate("authenticated", "ga", "stateful_read")
        assert decision.action == "promote"
        assert decision.candidate_default_flag is True
        assert decision.requires_manual_approval is False

    def test_ga_admin_read_only_holds(self):
        """ga + admin + read_only should hold (admin not in promotable tiers)."""
        decision = self.matrix.evaluate("admin", "ga", "read_only")
        assert decision.action == "hold"
        assert decision.candidate_default_flag is False

    def test_beta_public_read_only_holds(self):
        """beta + public + read_only should hold (beta not promotable)."""
        decision = self.matrix.evaluate("public", "beta", "read_only")
        assert decision.action == "hold"
        assert decision.candidate_default_flag is False

    def test_gate_results_none_does_not_crash(self):
        """None gate_results should be treated as empty (no demote)."""
        decision = self.matrix.evaluate("public", "ga", "read_only", gate_results=None)
        assert decision.action == "promote"

    def test_gate_results_empty_does_not_crash(self):
        """Empty gate_results dict should not trigger demote."""
        decision = self.matrix.evaluate("public", "ga", "read_only", gate_results={})
        assert decision.action == "promote"

    def test_unknown_values_fallback_safely(self):
        """Unknown/empty risk_tier/maturity/lane should hold (conservative default)."""
        decision = self.matrix.evaluate("unknown", "unknown", "unknown")
        assert decision.action == "hold"
        assert decision.candidate_default_flag is False

    def test_demote_supersedes_mutating_heavy(self):
        """Demote from gate_results should override even mutating-heavy default."""
        decision = self.matrix.evaluate(
            "mutating-heavy", "ga", "read_only",
            gate_results={"finding_parity": 50, "scope_violation": 0, "event_drop": 0},
        )
        assert decision.action == "demote"
        assert "finding_parity=50%" in decision.reason

    def test_promotion_decision_is_dataclass(self):
        """PromotionDecision should be a proper dataclass with expected fields."""
        d = PromotionDecision(
            action="promote",
            target_risk_tier="public",
            specialist_maturity="ga",
            lane_policy="read_only",
            candidate_default_flag=True,
            reason="test reason",
            requires_manual_approval=False,
        )
        assert d.action == "promote"
        assert d.target_risk_tier == "public"
        assert d.specialist_maturity == "ga"
        assert d.lane_policy == "read_only"
        assert d.candidate_default_flag is True
        assert d.requires_manual_approval is False

    def test_demote_reason_aggregates_all_failures(self):
        """Demote reason should include all failing gate metrics."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={"finding_parity": 90, "scope_violation": 2, "event_drop": 0},
        )
        assert decision.action == "demote"
        assert "finding_parity=90%" in decision.reason
        assert "scope_violation=2" in decision.reason
        assert "event_drop" not in decision.reason  # not > 0

    # --- Blocker B-5: Phase 9 No-Go metric tests ---

    def test_request_budget_violation_demotes(self):
        """request_budget_violation_count > 0 should demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={
                "finding_parity": 100,
                "request_budget_violation_count": 1,
            },
        )
        assert decision.action == "demote"
        assert "request_budget_violation_count=1" in decision.reason

    def test_origin_budget_violation_demotes(self):
        """origin_budget_violation_count > 0 should demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={
                "finding_parity": 100,
                "origin_budget_violation_count": 1,
            },
        )
        assert decision.action == "demote"
        assert "origin_budget_violation_count=1" in decision.reason

    def test_secret_leak_demotes(self):
        """secret_leak_count > 0 should demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={
                "finding_parity": 100,
                "secret_leak_count": 5,
            },
        )
        assert decision.action == "demote"
        assert "secret_leak_count=5" in decision.reason

    def test_reader_fail_demotes(self):
        """reader_compatibility_status='fail' should demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={
                "finding_parity": 100,
                "reader_compatibility_status": "fail",
            },
        )
        assert decision.action == "demote"
        assert "reader_compatibility_status=fail" in decision.reason

    def test_rollback_fail_demotes(self):
        """rollback_drill_status='fail' should demote."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={
                "finding_parity": 100,
                "rollback_drill_status": "fail",
            },
        )
        assert decision.action == "demote"
        assert "rollback_drill_status=fail" in decision.reason

    def test_missing_gate_result_holds(self):
        """gate_result with None values should hold (conservative safety)."""
        decision = self.matrix.evaluate(
            "public", "ga", "read_only",
            gate_results={
                "finding_parity": 100,
                "scope_violation_count": None,
            },
        )
        assert decision.action == "hold"
        assert decision.requires_manual_approval is True
        assert "cannot determine safety" in decision.reason.lower()
