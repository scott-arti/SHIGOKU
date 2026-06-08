from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_ROUTE_ORDER = {
    "shigoku_only": 0,
    "shigoku_hitl": 1,
    "human_preferred": 2,
}


@dataclass
class InterventionDecision:
    route: str
    scenario_id: str
    confidence: float
    reasons: list[str]
    matched_signals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "scenario_id": self.scenario_id,
            "confidence": self.confidence,
            "reasons": self.reasons,
            "matched_signals": self.matched_signals,
        }


class InterventionPolicy:
    """Task-level intervention policy.

    The policy is intentionally target-agnostic and relies only on generic
    signals from task metadata (name/action/category/tags/target/params).
    """

    def __init__(self, matrix: dict[str, Any] | None = None):
        self.matrix = matrix or {}
        self.defaults = self.matrix.get("defaults", {}) if isinstance(self.matrix, dict) else {}
        self.category_routes = self.matrix.get("category_routes", {}) if isinstance(self.matrix, dict) else {}
        self.scenarios = self.matrix.get("scenarios", []) if isinstance(self.matrix, dict) else []

    @staticmethod
    def _normalize_route(route: str) -> str:
        candidate = str(route or "").strip().lower()
        if candidate in _ROUTE_ORDER:
            return candidate
        aliases = {
            "auto": "shigoku_only",
            "autonomous": "shigoku_only",
            "hitl": "shigoku_hitl",
            "human_in_the_loop": "shigoku_hitl",
            "human": "human_preferred",
        }
        return aliases.get(candidate, "shigoku_only")

    @staticmethod
    def _flatten_signal_text(task: Any) -> str:
        chunks: list[str] = []

        def _append(value: Any) -> None:
            if value is None:
                return
            if isinstance(value, str):
                token = value.strip()
                if token:
                    chunks.append(token)
                return
            if isinstance(value, (int, float, bool)):
                chunks.append(str(value))
                return
            if isinstance(value, list):
                for item in value:
                    _append(item)
                return
            if isinstance(value, dict):
                for k, v in value.items():
                    key = str(k).strip().lower()
                    # keep a compact subset of keys to avoid excessive noise
                    if key in {
                        "category",
                        "tags",
                        "scenario",
                        "reason",
                        "target",
                        "targets",
                        "endpoint",
                        "flow",
                        "attack_type",
                        "authz_probe",
                        "description",
                        "title",
                        "smell_type",
                    }:
                        _append(v)
                return

        _append(getattr(task, "name", ""))
        _append(getattr(task, "action", ""))
        _append(getattr(task, "agent_type", ""))
        _append(getattr(task, "target", ""))
        _append(getattr(task, "tags", []))
        _append(getattr(task, "params", {}))
        return " ".join(chunks).lower()

    @staticmethod
    def _route_from_friction_score(score: int) -> str:
        if score <= 3:
            return "shigoku_only"
        if score <= 6:
            return "shigoku_hitl"
        return "human_preferred"

    def _score_high_friction_dimensions(
        self,
        *,
        signal_text: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        text = str(signal_text or "").lower()
        p = params if isinstance(params, dict) else {}

        def _count_hits(tokens: tuple[str, ...]) -> int:
            return sum(1 for token in tokens if token in text)

        # 1) Out-of-band dependency (email/SMS/external channel)
        oob_tokens = (
            "password reset",
            "reset token",
            "email verification",
            "verification code",
            "magic link",
            "invite acceptance",
            "sms otp",
            "account activation",
            "confirmation code",
            "out-of-band",
            "oob",
            "mailbox",
        )
        oob_hits = _count_hits(oob_tokens)
        oob_score = 2 if oob_hits >= 1 else 0

        # 2) Semantic/business interpretation dependency
        semantic_tokens = (
            "business logic",
            "semantic abuse",
            "approval flow",
            "policy bypass",
            "intent abuse",
            "pricing rule",
            "coupon rule",
            "refund policy",
        )
        semantic_hits = _count_hits(semantic_tokens)
        semantic_score = 2 if semantic_hits >= 1 else 0

        # 3) State-machine depth (multi-step transitions)
        state_tokens = (
            "state machine",
            "multi-step flow",
            "workflow abuse",
            "state transition",
            "precondition",
            "chain",
            "chaining",
            "checkout",
            "order flow",
        )
        state_hits = _count_hits(state_tokens)
        targets = p.get("targets", [])
        target_count = len(targets) if isinstance(targets, list) else 0
        if state_hits >= 2 or target_count >= 3:
            state_score = 2
        elif state_hits == 1 or target_count >= 2:
            state_score = 1
        else:
            state_score = 0

        # 4) Side-effect risk (potentially destructive/irreversible actions)
        high_side_effect_tokens = (
            "password reset",
            "magic link",
            "delete",
            "refund",
            "transfer",
            "purchase",
            "role=admin",
            "is_admin",
            "internal network map",
            "metadata endpoint",
            "169.254.169.254",
            "cloud metadata",
        )
        medium_side_effect_tokens = (
            "change password",
            "password update",
            "profile update",
            "settings update",
            "admin action",
        )
        high_side_hits = _count_hits(high_side_effect_tokens)
        medium_side_hits = _count_hits(medium_side_effect_tokens)
        if high_side_hits >= 1:
            side_effect_score = 2
        elif medium_side_hits >= 1:
            side_effect_score = 1
        else:
            side_effect_score = 0

        # 5) Low reproducibility under automation (async/OOB/race/non-deterministic)
        low_repro_tokens = (
            "captcha",
            "otp",
            "email",
            "mailbox",
            "out-of-band",
            "oob",
            "race condition",
            "real-time",
            "websocket",
            "manual verify",
            "human checkpoint",
        )
        reproducible_tokens = (
            "api",
            "id tampering",
            "payload fuzz",
            "deterministic",
            "schema diff",
            "response diff",
            "endpoint discovery",
        )
        low_repro_hits = _count_hits(low_repro_tokens)
        reproducible_hits = _count_hits(reproducible_tokens)
        if low_repro_hits >= 2:
            reproducibility_score = 2
        elif low_repro_hits >= 1:
            reproducibility_score = 1
        elif reproducible_hits >= 2:
            reproducibility_score = 0
        else:
            reproducibility_score = 1

        axes = {
            "oob_dependency": int(oob_score),
            "semantic_dependency": int(semantic_score),
            "state_transition_depth": int(state_score),
            "side_effect_risk": int(side_effect_score),
            "low_reproducibility": int(reproducibility_score),
        }
        score = sum(int(v) for v in axes.values())
        return {
            "score": int(score),
            "axes": axes,
            "signals": {
                "oob_hits": int(oob_hits),
                "semantic_hits": int(semantic_hits),
                "state_hits": int(state_hits),
                "target_count": int(target_count),
                "high_side_hits": int(high_side_hits),
                "medium_side_hits": int(medium_side_hits),
                "low_repro_hits": int(low_repro_hits),
                "reproducible_hits": int(reproducible_hits),
            },
        }

    def decide(self, task: Any) -> dict[str, Any]:
        params = getattr(task, "params", {}) if task is not None else {}
        params = params if isinstance(params, dict) else {}
        category = str(params.get("category", "") or "").strip().lower()
        signal_text = self._flatten_signal_text(task)

        # Explicit override is the strongest signal.
        if bool(params.get("requires_human_input", False)):
            decision = InterventionDecision(
                route="human_preferred",
                scenario_id="explicit_requires_human_input",
                confidence=1.0,
                reasons=["Task explicitly marked as requires_human_input=true"],
                matched_signals=["requires_human_input"],
            )
            return decision.to_dict()

        best_route = self._normalize_route(self.defaults.get("route", "shigoku_only"))
        best_scenario = "default_route"
        best_score = 0
        best_reasons = ["No high-friction signal matched"]
        best_matches: list[str] = []

        if category and category in self.category_routes:
            best_route = self._normalize_route(self.category_routes.get(category))
            best_scenario = f"category_route:{category}"
            best_score = 20
            best_reasons = [f"Category '{category}' mapped to {best_route}"]
            best_matches = [category]

        for scenario in self.scenarios:
            if not isinstance(scenario, dict):
                continue
            scenario_id = str(scenario.get("id", "") or "").strip() or "unnamed"
            route = self._normalize_route(scenario.get("route", best_route))
            priority = int(scenario.get("priority", 0) or 0)
            signals_any = scenario.get("signals_any", [])
            if not isinstance(signals_any, list):
                signals_any = []

            matched = []
            for token in signals_any:
                token_str = str(token or "").strip().lower()
                if token_str and token_str in signal_text:
                    matched.append(token_str)

            if not matched:
                continue

            score = priority + len(matched) * 4
            current_rank = (_ROUTE_ORDER.get(route, 0), score)
            best_rank = (_ROUTE_ORDER.get(best_route, 0), best_score)
            if current_rank > best_rank:
                best_route = route
                best_scenario = scenario_id
                best_score = score
                best_reasons = [f"Matched scenario '{scenario_id}'"]
                best_matches = matched[:8]

        friction_meta: dict[str, Any] = {}
        high_friction_targets = {
            "scn_08_oob_external_channel_flow",
            "scn_10_semantic_business_logic",
            "scn_11_multi_vector_chain",
            "scn_12_advanced_ssrf_internal_topology",
        }
        if best_scenario in high_friction_targets:
            friction_meta = self._score_high_friction_dimensions(
                signal_text=signal_text,
                params=params,
            )
            friction_score = int(friction_meta.get("score", 0) or 0)
            routed = self._route_from_friction_score(friction_score)
            axes = friction_meta.get("axes", {}) if isinstance(friction_meta.get("axes"), dict) else {}

            # Scenario-specific safety overrides
            # SCN08: OOB channel dependency should stay human-preferred.
            if best_scenario == "scn_08_oob_external_channel_flow" and int(axes.get("oob_dependency", 0) or 0) >= 2:
                routed = "human_preferred"
            # SCN10: semantic/business intent dependency tends to be human-efficient.
            if best_scenario == "scn_10_semantic_business_logic" and int(axes.get("semantic_dependency", 0) or 0) >= 2:
                routed = "human_preferred"
            # SCN12: internal topology + low reproducibility is high-risk.
            if (
                best_scenario == "scn_12_advanced_ssrf_internal_topology"
                and int(axes.get("side_effect_risk", 0) or 0) >= 2
                and int(axes.get("low_reproducibility", 0) or 0) >= 1
            ):
                routed = "human_preferred"

            # SCN08/10/11/12 は最低でも HITL へ寄せる
            if _ROUTE_ORDER.get(routed, 0) < _ROUTE_ORDER["shigoku_hitl"]:
                routed = "shigoku_hitl"
            best_route = routed
            best_reasons = [
                (
                    f"High-friction routing score={friction_score}/10 "
                    "(oob, semantic, state, side_effect, reproducibility)"
                ),
                f"Matched scenario '{best_scenario}'",
            ]

        confidence = min(1.0, 0.35 + (best_score / 140.0))
        decision = InterventionDecision(
            route=best_route,
            scenario_id=best_scenario,
            confidence=round(confidence, 3),
            reasons=best_reasons,
            matched_signals=best_matches,
        )
        payload = decision.to_dict()
        if friction_meta:
            payload["friction_score"] = int(friction_meta.get("score", 0) or 0)
            payload["friction_axes"] = friction_meta.get("axes", {})
            payload["friction_signals"] = friction_meta.get("signals", {})
            payload["route_decision_basis"] = "high_friction_router"
        return payload
