"""
Preflight observability: CLI formatting, remediation display, and metrics.

Provides:
- format_failures_for_cli(): human-readable failure report
- PreflightMetrics: simple counter-based metrics
- build_snapshot_summary(): compact debug trace
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from src.core.preflight.models import PreflightFailure, PreflightSnapshot, PreflightResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CLI formatting
# ---------------------------------------------------------------------------

def format_failures_for_cli(result: PreflightResult) -> str:
    """Format preflight failures for terminal display.

    Produces a compact, actionable report suitable for CLI output.
    Secrets are never included.
    """
    if result.passed:
        return ""

    lines = [
        "",
        "=" * 60,
        "  PREFLIGHT GATE FAILED",
        "=" * 60,
        "",
        f"  {len(result.failures)} check(s) did not pass:",
        "",
    ]

    for i, failure in enumerate(result.failures, 1):
        lines.append(f"  [{i}] {failure.reason_code}")
        if failure.category:
            lines.append(f"      Category: {failure.category}")
        if failure.remediation:
            lines.append(f"      Fix: {failure.remediation}")
        if failure.evidence:
            safe_evidence = {k: v for k, v in failure.evidence.items()
                           if k not in ("token", "cookie", "bearer", "authorization")}
            lines.append(f"      Details: {safe_evidence}")
        lines.append("")

    if result.snapshot and result.snapshot.elapsed_ms:
        lines.append(f"  Gate completed in {result.snapshot.elapsed_ms:.0f}ms")
    lines.append("=" * 60)
    lines.append("")

    return "\n".join(lines)


def format_remediation_summary(failures: List[PreflightFailure]) -> str:
    """Produce a one-line-per-failure remediation summary."""
    lines = []
    for f in failures:
        lines.append(f"  - {f.reason_code}: {f.remediation or 'No remediation available'}")
    return "\n".join(lines)


def format_tool_status_table(tool_results: Dict[str, str]) -> str:
    """Format tool check results as a table."""
    if not tool_results:
        return "  No tool checks performed."

    lines = ["  Tool Status:"]
    for name, status in sorted(tool_results.items()):
        status_icon = "OK" if status == "ok" else "FAIL"
        lines.append(f"    {name:20s} {status_icon}  ({status})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Metrics (simple in-process counters)
# ---------------------------------------------------------------------------

class PreflightMetrics:
    """Simple in-process metrics for preflight gate observability.

    Counters are not persisted across processes.  Use logging or an
    external metrics system for production monitoring.
    """

    def __init__(self) -> None:
        self.pass_total: int = 0
        self.fail_total: int = 0
        self.fail_by_reason: Dict[str, int] = {}
        self.caido_unreachable_total: int = 0
        self.auth_probe_login_redirect_total: int = 0
        self.auth_probe_session_expired_total: int = 0
        self.auth_probe_waf_challenge_total: int = 0
        self.ai_fallback_total: int = 0
        self.ai_unknown_total: int = 0

    def record(self, result: PreflightResult) -> None:
        """Record metrics from a preflight result."""
        if result.passed:
            self.pass_total += 1
            return

        self.fail_total += 1
        for failure in result.failures:
            code = failure.reason_code
            self.fail_by_reason[code] = self.fail_by_reason.get(code, 0) + 1

            if code.startswith("CAIDO_"):
                self.caido_unreachable_total += 1
            if code == "AUTH_LOGIN_PAGE":
                self.auth_probe_login_redirect_total += 1
            if code == "AUTH_SESSION_EXPIRED":
                self.auth_probe_session_expired_total += 1
            if code == "AUTH_WAF_CHALLENGE":
                self.auth_probe_waf_challenge_total += 1

        if result.snapshot and result.snapshot.auth_result:
            if result.snapshot.auth_result.ai_used:
                self.ai_fallback_total += 1
                if result.snapshot.auth_result.ai_label == "unknown":
                    self.ai_unknown_total += 1

    def summary(self) -> Dict[str, Any]:
        """Return a dict suitable for logging or JSON dump."""
        return {
            "preflight_pass_total": self.pass_total,
            "preflight_fail_total": self.fail_total,
            "caido_unreachable_total": self.caido_unreachable_total,
            "auth_probe_login_redirect_total": self.auth_probe_login_redirect_total,
            "auth_probe_session_expired_total": self.auth_probe_session_expired_total,
            "auth_probe_waf_challenge_total": self.auth_probe_waf_challenge_total,
            "ai_fallback_total": self.ai_fallback_total,
            "ai_unknown_total": self.ai_unknown_total,
            "fail_by_reason": dict(self.fail_by_reason),
        }


# Global metrics instance
_metrics = PreflightMetrics()


def get_metrics() -> PreflightMetrics:
    """Return the global preflight metrics instance."""
    return _metrics
