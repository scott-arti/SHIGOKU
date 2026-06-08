from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


_DEFAULT_STRATEGY_SELECTOR: Optional["StrategySelector"] = None


@dataclass
class StrategyDecision:
    strategy_id: str
    confidence: float
    rationale: str
    priority_delta: int = 0
    param_overrides: dict[str, Any] = field(default_factory=dict)
    tag_hints: list[str] = field(default_factory=list)

    @property
    def is_default(self) -> bool:
        return self.strategy_id == "balanced_default"


class StrategySelector:
    """
    Target characteristics -> strategy mapping.

    Design goals:
    - Robust default strategy on unknown/missing signals.
    - Non-invasive by default (mostly param/tag hints).
    - Optional priority delta only in high-confidence contexts.
    """

    def select(
        self,
        task: Any,
        target_info: Optional[dict[str, Any]] = None,
        mode: str = "bugbounty",
    ) -> StrategyDecision:
        text, signals = self._extract_signals(task, target_info or {})
        mode_norm = str(mode or "bugbounty").strip().lower()

        if mode_norm == "ctf":
            return StrategyDecision(
                strategy_id="ctf_speedrun",
                confidence=0.9,
                rationale="CTF mode prioritizes speed and broad exploit attempts.",
                priority_delta=10,
                param_overrides={
                    "parallel_attacks": True,
                    "skip_slow_methods": True,
                },
                tag_hints=["strategy:ctf_speedrun", "fast_path"],
            )

        if "waf" in signals:
            return StrategyDecision(
                strategy_id="stealth_evasion",
                confidence=0.85,
                rationale="WAF indicators detected; use stealth and evasive probing.",
                priority_delta=5,
                param_overrides={
                    "stealth_mode": True,
                    "use_proxy_rotation": True,
                    "low_noise": True,
                },
                tag_hints=["strategy:stealth_evasion", "waf_aware"],
            )

        if any(s in signals for s in ("auth", "jwt", "oauth", "mfa", "login")):
            return StrategyDecision(
                strategy_id="auth_deep_dive",
                confidence=0.8,
                rationale="Authentication/authorization surface detected.",
                param_overrides={
                    "auth_focus": True,
                    "session_aware": True,
                },
                tag_hints=["strategy:auth_deep_dive", "auth"],
            )

        if any(s in signals for s in ("file_upload", "upload")):
            return StrategyDecision(
                strategy_id="upload_chain",
                confidence=0.78,
                rationale="Upload surface detected; prepare chaining-oriented validation.",
                param_overrides={
                    "upload_hardening_checks": True,
                    "post_upload_validation": True,
                },
                tag_hints=["strategy:upload_chain", "upload"],
            )

        if any(s in signals for s in ("api", "graphql", "json")):
            return StrategyDecision(
                strategy_id="api_precision",
                confidence=0.72,
                rationale="API-oriented target detected; prioritize parameter/context precision.",
                param_overrides={
                    "api_precision_mode": True,
                },
                tag_hints=["strategy:api_precision", "api"],
            )

        return StrategyDecision(
            strategy_id="balanced_default",
            confidence=0.6,
            rationale="Default robust strategy applied due to weak/ambiguous target signals.",
            param_overrides={"balanced_mode": True},
            tag_hints=["strategy:balanced_default"],
        )

    def _extract_signals(self, task: Any, target_info: dict[str, Any]) -> tuple[str, set[str]]:
        parts: list[str] = []
        for attr in ("name", "agent_type", "action", "target"):
            val = getattr(task, attr, "")
            if val:
                parts.append(str(val))

        params = getattr(task, "params", {}) or {}
        for key in ("target", "url", "path", "endpoint", "route", "method", "type", "vuln_type"):
            val = params.get(key)
            if val:
                parts.append(str(val))

        tags = getattr(task, "tags", []) or []
        if isinstance(tags, list):
            parts.extend(str(t) for t in tags)

        # Context-aware hints
        waf_hint = (
            target_info.get("waf")
            or target_info.get("waf_detected")
            or params.get("waf")
        )
        if waf_hint:
            parts.append(str(waf_hint))

        text = " ".join(parts).lower()
        signals: set[str] = set()

        keyword_map = {
            "waf": ["waf", "cloudflare", "akamai", "imperva", "modsecurity"],
            "auth": ["auth", "authorization", "permission", "acl"],
            "jwt": ["jwt", "token"],
            "oauth": ["oauth", "redirect_uri", "pkce"],
            "mfa": ["mfa", "2fa"],
            "login": ["login", "signin", "session"],
            "file_upload": ["file_upload", "file-upload", "upload"],
            "upload": ["upload"],
            "api": ["api", "/v1/", "/v2/", "rest"],
            "graphql": ["graphql"],
            "json": ["json"],
        }
        for signal, keywords in keyword_map.items():
            if any(k in text for k in keywords):
                signals.add(signal)

        return text, signals


def get_strategy_selector() -> StrategySelector:
    global _DEFAULT_STRATEGY_SELECTOR
    if _DEFAULT_STRATEGY_SELECTOR is None:
        _DEFAULT_STRATEGY_SELECTOR = StrategySelector()
    return _DEFAULT_STRATEGY_SELECTOR

