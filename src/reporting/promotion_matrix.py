"""Phase 9 promotion/demotion matrix (T-6.1).

Maps target risk tiers, specialist maturity levels, and lane policies to
promotion decisions. Returns default flag candidates without mutating
config/shigoku.yaml defaults.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

# All valid values for each axis
_RISK_TIERS: tuple[str, ...] = ("public", "authenticated", "admin", "mutating-heavy")
_MATURITIES: tuple[str, ...] = ("ga", "beta", "experimental")
_LANE_POLICIES: tuple[str, ...] = ("read_only", "stateful_read", "mutating", "aggressive_exclusive")

# Specialist maturities that require manual approval regardless of lane/risk
_MANUAL_APPROVAL_MATURITIES: frozenset[str] = frozenset({"experimental"})

# Lanes that require manual approval regardless of maturity/risk
_MANUAL_APPROVAL_LANES: frozenset[str] = frozenset({"mutating", "aggressive_exclusive"})

# Risk tier that always requires mutex audit (hold, no promotion)
_HEAVY_RISK_TIER: str = "mutating-heavy"

# Safe lanes for promotion consideration
_SAFE_PROMOTION_LANES: frozenset[str] = frozenset({"read_only", "stateful_read"})

# Risk tiers eligible for promotion (excluding mutating-heavy)
_PROMOTABLE_RISK_TIERS: frozenset[str] = frozenset({"public", "authenticated"})


@dataclass
class PromotionDecision:
    """A single promotion/demotion matrix decision.

    Attributes:
        action: One of "promote", "hold", "demote".
        target_risk_tier: Target risk tier (public, authenticated, admin, mutating-heavy).
        specialist_maturity: Specialist maturity level (ga, beta, experimental).
        lane_policy: Lane policy (read_only, stateful_read, mutating, aggressive_exclusive).
        candidate_default_flag: True if this combination is a candidate for default enable.
        reason: Human-readable explanation of the decision.
        requires_manual_approval: True if manual gate approval is required.
    """

    action: str
    target_risk_tier: str
    specialist_maturity: str
    lane_policy: str
    candidate_default_flag: bool = False
    reason: str = ""
    requires_manual_approval: bool = False


class PromotionMatrix:
    """Phase 9 promotion/demotion decision matrix.

    Evaluates each (risk_tier, maturity, lane_policy) combination and produces
    a PromotionDecision. The matrix is conservative: it starts from "hold" and
    only promotes explicitly safe combinations.

    Gate results (Phase 9 No-Go metrics) can override any decision to "demote".
    Explicitly-None metric values trigger a conservative "hold" for safety.
    """

    def evaluate(
        self,
        risk_tier: str,
        maturity: str,
        lane: str,
        gate_results: Dict[str, Any] | None = None,
    ) -> PromotionDecision:
        """Evaluate a single (risk_tier, maturity, lane) combination.

        Args:
            risk_tier: Target risk tier.
            maturity: Specialist maturity.
            lane: Lane policy.
            gate_results: Optional dict with Phase 9 No-Go metrics.
                          Metrics with explicitly-None values trigger hold.
                          Non-zero violations or fail-statuses trigger demote.

        Returns:
            PromotionDecision with action, reason, and flags.
        """
        risk_tier = (risk_tier or "").lower()
        maturity = (maturity or "").lower()
        lane = (lane or "").lower()
        gate_results = gate_results or {}

        # --- Phase 9 No-Go gate check (overrides everything) ---
        # Hold when any explicitly-present metric is None (conservative safety)
        for key in gate_results:
            if gate_results[key] is None:
                return PromotionDecision(
                    action="hold",
                    target_risk_tier=risk_tier,
                    specialist_maturity=maturity,
                    lane_policy=lane,
                    candidate_default_flag=False,
                    reason=f"Gate result '{key}' is None; cannot determine safety (hold)",
                    requires_manual_approval=True,
                )

        # Extract all Phase 9 metric values (support both old and new key names)
        finding_parity = gate_results.get("finding_parity", 100)
        scope_violation = gate_results.get("scope_violation", 0)
        event_drop = gate_results.get("event_drop", 0)
        scope_violation_count = gate_results.get("scope_violation_count", 0)
        origin_budget_violation_count = gate_results.get("origin_budget_violation_count", 0)
        request_budget_violation_count = gate_results.get("request_budget_violation_count", 0)
        critical_event_drop_count = gate_results.get("critical_event_drop_count", 0)
        secret_leak_count = gate_results.get("secret_leak_count", 0)
        reader_compatibility_status = str(
            gate_results.get("reader_compatibility_status", "pass")
        ).lower()
        rollback_drill_status = str(
            gate_results.get("rollback_drill_status", "pass")
        ).lower()

        # Handle finding_parity as dict (Phase 9 canonical) or number (backward compat)
        if isinstance(finding_parity, dict):
            fp_parity = finding_parity.get("high_critical_parity")
            finding_parity = fp_parity if isinstance(fp_parity, (int, float)) else 100.0

        # Collect all No-Go violations
        violations: List[str] = []
        if finding_parity < 100:
            violations.append(f"finding_parity={finding_parity}% (<100%)")
        if scope_violation > 0:
            violations.append(f"scope_violation={scope_violation}")
        if event_drop > 0:
            violations.append(f"event_drop={event_drop}")
        if scope_violation_count > 0:
            violations.append(f"scope_violation_count={scope_violation_count}")
        if origin_budget_violation_count > 0:
            violations.append(
                f"origin_budget_violation_count={origin_budget_violation_count}"
            )
        if request_budget_violation_count > 0:
            violations.append(
                f"request_budget_violation_count={request_budget_violation_count}"
            )
        if critical_event_drop_count > 0:
            violations.append(
                f"critical_event_drop_count={critical_event_drop_count}"
            )
        if secret_leak_count > 0:
            violations.append(f"secret_leak_count={secret_leak_count}")
        if reader_compatibility_status == "fail":
            violations.append("reader_compatibility_status=fail")
        if rollback_drill_status == "fail":
            violations.append("rollback_drill_status=fail")

        if violations:
            return PromotionDecision(
                action="demote",
                target_risk_tier=risk_tier,
                specialist_maturity=maturity,
                lane_policy=lane,
                candidate_default_flag=False,
                reason=f"Gate failure: {'; '.join(violations)}",
                requires_manual_approval=True,
            )

        # --- Manual approval determination ---
        requires_manual = (
            maturity in _MANUAL_APPROVAL_MATURITIES
            or lane in _MANUAL_APPROVAL_LANES
            or risk_tier == _HEAVY_RISK_TIER
        )

        # --- mutating-heavy risk tier always holds ---
        if risk_tier == _HEAVY_RISK_TIER:
            return PromotionDecision(
                action="hold",
                target_risk_tier=risk_tier,
                specialist_maturity=maturity,
                lane_policy=lane,
                candidate_default_flag=False,
                reason="mutating-heavy target requires mutex audit; promotion is not eligible",
                requires_manual_approval=True,
            )

        # --- experimental maturity always holds ---
        if maturity == "experimental":
            return PromotionDecision(
                action="hold",
                target_risk_tier=risk_tier,
                specialist_maturity=maturity,
                lane_policy=lane,
                candidate_default_flag=False,
                reason="experimental specialist maturity requires manual approval",
                requires_manual_approval=True,
            )

        # --- mutating / aggressive_exclusive lane holds ---
        if lane in _MANUAL_APPROVAL_LANES:
            return PromotionDecision(
                action="hold",
                target_risk_tier=risk_tier,
                specialist_maturity=maturity,
                lane_policy=lane,
                candidate_default_flag=False,
                reason=f"{lane} lane policy requires manual approval",
                requires_manual_approval=True,
            )

        # --- beta + admin holds ---
        if maturity == "beta" and risk_tier == "admin":
            return PromotionDecision(
                action="hold",
                target_risk_tier=risk_tier,
                specialist_maturity=maturity,
                lane_policy=lane,
                candidate_default_flag=False,
                reason="beta specialist on admin target needs more canary evidence",
                requires_manual_approval=requires_manual,
            )

        # --- Promote: ga + promotable risk tier + safe lane ---
        if (
            maturity == "ga"
            and risk_tier in _PROMOTABLE_RISK_TIERS
            and lane in _SAFE_PROMOTION_LANES
        ):
            return PromotionDecision(
                action="promote",
                target_risk_tier=risk_tier,
                specialist_maturity=maturity,
                lane_policy=lane,
                candidate_default_flag=True,
                reason=f"ga specialist on {risk_tier} target with {lane} lane is safe for promotion",
                requires_manual_approval=False,
            )

        # --- Default: hold (conservative) ---
        return PromotionDecision(
            action="hold",
            target_risk_tier=risk_tier,
            specialist_maturity=maturity,
            lane_policy=lane,
            candidate_default_flag=False,
            reason="no explicit promotion path; held for further evidence",
            requires_manual_approval=requires_manual,
        )

    def generate_matrix_table(self) -> List[Dict[str, Any]]:
        """Generate decisions for all (risk_tier, maturity, lane) combinations.

        Returns:
            List of dicts, each with the full PromotionDecision fields
            plus an explicit gate_results field (empty dict for pure matrix lookup).
        """
        results: List[Dict[str, Any]] = []
        for risk_tier in _RISK_TIERS:
            for maturity in _MATURITIES:
                for lane in _LANE_POLICIES:
                    decision = self.evaluate(risk_tier, maturity, lane)
                    results.append(
                        {
                            "action": decision.action,
                            "target_risk_tier": decision.target_risk_tier,
                            "specialist_maturity": decision.specialist_maturity,
                            "lane_policy": decision.lane_policy,
                            "candidate_default_flag": decision.candidate_default_flag,
                            "reason": decision.reason,
                            "requires_manual_approval": decision.requires_manual_approval,
                            "gate_results": {},
                        }
                    )
        return results

    def get_default_flag_candidates(self) -> Dict[str, bool]:
        """Return flag candidates for all combinations that are eligible for promotion.

        This method returns candidates but does NOT mutate any config settings.
        Callers decide whether to apply these candidates.

        Returns:
            Dict mapping combination keys to candidate flag values (True).
        """
        candidates: Dict[str, bool] = {}
        for risk_tier in _RISK_TIERS:
            for maturity in _MATURITIES:
                for lane in _LANE_POLICIES:
                    decision = self.evaluate(risk_tier, maturity, lane)
                    if decision.action == "promote" and decision.candidate_default_flag:
                        key = f"{risk_tier}.{maturity}.{lane}"
                        candidates[key] = True
        return candidates
