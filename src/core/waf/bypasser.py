from __future__ import annotations

from typing import Optional

from src.core.attack.waf_mutator import MutationType


class WAFBypasser:
    """
    WAF-specific bypass planner.

    The bypasser selects low-risk header variants and mutation focus based on
    a detected WAF family.
    """

    def build_bypass_headers(self, waf_name: Optional[str], attempt: int = 0) -> dict[str, str]:
        waf = (waf_name or "generic").lower()
        idx = max(0, int(attempt))

        generic_profiles = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
        ]

        waf_profiles: dict[str, list[dict[str, str]]] = {
            "cloudflare": [
                {"CF-Connecting-IP": "127.0.0.1"},
                {"X-Forwarded-For": "127.0.0.1, 10.0.0.1"},
            ],
            "aws_waf": [
                {"X-Forwarded-For": "127.0.0.1"},
                {"X-Real-IP": "127.0.0.1"},
            ],
            "akamai": [
                {"True-Client-IP": "127.0.0.1"},
                {"X-Forwarded-For": "127.0.0.1"},
            ],
            "imperva": [
                {"X-Client-IP": "127.0.0.1"},
                {"X-Forwarded-For": "127.0.0.1"},
            ],
            "modsecurity": [
                {"X-Original-URL": "/"},
                {"X-Rewrite-URL": "/"},
            ],
        }

        profiles = waf_profiles.get(waf, generic_profiles)
        return profiles[idx % len(profiles)]

    def choose_mutation_types(self, waf_name: Optional[str]) -> list[MutationType]:
        waf = (waf_name or "generic").lower()
        if waf == "cloudflare":
            return [MutationType.ENCODE, MutationType.CASE, MutationType.WHITESPACE]
        if waf == "aws_waf":
            return [MutationType.ENCODE, MutationType.SYNTAX, MutationType.CONCAT]
        if waf == "akamai":
            return [MutationType.CASE, MutationType.COMMENT, MutationType.ENCODE]
        if waf == "imperva":
            return [MutationType.ENCODE, MutationType.PADDING, MutationType.WHITESPACE]
        if waf == "modsecurity":
            return [MutationType.COMMENT, MutationType.WHITESPACE, MutationType.SYNTAX]
        return [MutationType.ENCODE, MutationType.CASE, MutationType.WHITESPACE]
