"""
Guard Enforcement Metrics (Step 9: SGK-2026-0335).

Lightweight in-process metrics collection for the compiled guard pipeline.
Provides counters, gauges, and histograms for runtime observability,
SLO tracking, and rollout stage validation.

Counters defined per spec section 13.11:
- ``guard_decision_total{layer,decision,reason_code}``
- ``policy_fail_closed_total``
- ``active_bundle_read_failure_total``
- ``compile_failed_total``
- ``manual_review_required_total``
- ``bundle_import_to_ready_seconds`` (histogram)

Thread-safe via a reentrant lock.  No external dependencies (V1 is
text-based export, not Prometheus).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Metric value containers
# ---------------------------------------------------------------------------


@dataclass
class LabeledCounter:
    """Counter with string labels (e.g. ``layer=mc,decision=block``)."""

    _data: dict[str, int] = field(default_factory=dict)

    def inc(self, labels: str, value: int = 1) -> None:
        self._data[labels] = self._data.get(labels, 0) + value

    def get(self, labels: str) -> int:
        return self._data.get(labels, 0)

    def snapshot(self) -> dict[str, int]:
        return dict(self._data)


@dataclass
class SimpleCounter:
    """Counter without labels."""

    _value: int = 0

    def inc(self, delta: int = 1) -> None:
        self._value += delta

    def get(self) -> int:
        return self._value


@dataclass
class SimpleHistogram:
    """Append-only histogram storing raw values for later aggregation."""

    _values: list[float] = field(default_factory=list)

    def observe(self, value: float) -> None:
        self._values.append(value)

    def snapshot(self) -> dict[str, Any]:
        vs = list(self._values)
        if not vs:
            return {"count": 0, "sum": 0.0, "avg": 0.0, "min": 0.0, "max": 0.0}
        return {
            "count": len(vs),
            "sum": sum(vs),
            "avg": sum(vs) / len(vs),
            "min": min(vs),
            "max": max(vs),
        }


# ---------------------------------------------------------------------------
# GuardMetricsCollector
# ---------------------------------------------------------------------------


class GuardMetricsCollector:
    """Collects guard enforcement metrics.

    Thread-safe via ``threading.Lock``.  Singleton via ``get_guard_metrics()``.

    Usage::

        from src.core.security.guard_metrics import get_guard_metrics
        get_guard_metrics().record_guard_decision("mc", "block", "out_of_scope_host")
        get_guard_metrics().record_policy_fail_closed()
        metrics = get_guard_metrics().snapshot()
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # --- counters ---
        self.guard_decision_total = LabeledCounter()
        self.policy_fail_closed_total = SimpleCounter()
        self.active_bundle_read_failure_total = SimpleCounter()
        self.compile_failed_total = SimpleCounter()
        self.manual_review_required_total = SimpleCounter()

        # --- histogram ---
        self.bundle_import_to_ready_seconds = SimpleHistogram()

        # --- derived labels helper ---
        self._import_start: Optional[float] = None  # for timing

    # ------------------------------------------------------------------
    # Record methods (called by guard pipeline hooks)
    # ------------------------------------------------------------------

    def record_guard_decision(
        self,
        layer: str,
        decision: str,
        reason_code: str,
    ) -> None:
        """Record a guard decision from ``evaluate_at_layer()``."""
        labels = f"layer={layer},decision={decision},reason_code={reason_code}"
        with self._lock:
            self.guard_decision_total.inc(labels)

    def record_policy_fail_closed(self) -> None:
        """Record a fail-closed event (policy unavailable / integrity error)."""
        with self._lock:
            self.policy_fail_closed_total.inc()

    def record_active_bundle_read_failure(self) -> None:
        """Record a failure to read/load active bundle or compiled policy."""
        with self._lock:
            self.active_bundle_read_failure_total.inc()

    def record_compile_failed(self) -> None:
        """Record a compile failure (status ``compile_failed``)."""
        with self._lock:
            self.compile_failed_total.inc()

    def record_manual_review_required(self) -> None:
        """Record a ``manual_review_required`` compile status."""
        with self._lock:
            self.manual_review_required_total.inc()

    # ------------------------------------------------------------------
    # Timing helpers
    # ------------------------------------------------------------------

    def start_import_timer(self) -> None:
        """Mark the start of a bundle import-to-ready cycle."""
        with self._lock:
            self._import_start = time.monotonic()

    def record_import_to_ready(self) -> None:
        """Record the elapsed seconds from ``start_import_timer()``."""
        with self._lock:
            if self._import_start is not None:
                elapsed = time.monotonic() - self._import_start
                self.bundle_import_to_ready_seconds.observe(elapsed)
                self._import_start = None

    # ------------------------------------------------------------------
    # Snapshot (for export / dashboard)
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a dict of all current metric values for export/monitoring."""
        with self._lock:
            return {
                "guard_decision_total": self.guard_decision_total.snapshot(),
                "policy_fail_closed_total": self.policy_fail_closed_total.get(),
                "active_bundle_read_failure_total": self.active_bundle_read_failure_total.get(),
                "compile_failed_total": self.compile_failed_total.get(),
                "manual_review_required_total": self.manual_review_required_total.get(),
                "bundle_import_to_ready_seconds": self.bundle_import_to_ready_seconds.snapshot(),
            }

    def reset(self) -> None:
        """Reset all counters (useful between test runs)."""
        with self._lock:
            self.guard_decision_total = LabeledCounter()
            self.policy_fail_closed_total = SimpleCounter()
            self.active_bundle_read_failure_total = SimpleCounter()
            self.compile_failed_total = SimpleCounter()
            self.manual_review_required_total = SimpleCounter()
            self.bundle_import_to_ready_seconds = SimpleHistogram()
            self._import_start = None


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

_guard_metrics_instance: Optional[GuardMetricsCollector] = None
_metrics_lock = threading.Lock()


def get_guard_metrics() -> GuardMetricsCollector:
    """Return the singleton ``GuardMetricsCollector`` instance."""
    global _guard_metrics_instance
    if _guard_metrics_instance is None:
        with _metrics_lock:
            if _guard_metrics_instance is None:
                _guard_metrics_instance = GuardMetricsCollector()
    return _guard_metrics_instance


def reset_guard_metrics() -> None:
    """Reset the singleton metrics collector (for testing)."""
    global _guard_metrics_instance
    with _metrics_lock:
        _guard_metrics_instance = None
