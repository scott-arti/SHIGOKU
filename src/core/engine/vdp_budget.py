"""
VDP Execution Budget — SGK-2026-0419 Step 2.

Multi-level budget enforcement at asset/actor/hypothesis granularity.
Integrates with ExecutionBudgetV1 canonical model.
Implements circuit breaker for 429/5xx/timeout/latency.

Fail-closed: budget exhaustion and circuit open reject all consumption.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.models.vdp_contract import (
    BudgetReasonCodeV1,
    ExecutionBudgetV1,
)


# ---------------------------------------------------------------------------
# Budget decision
# ---------------------------------------------------------------------------

@dataclass
class BudgetDecision:
    """Result of a budget consumption check."""
    allowed: bool
    wait_seconds: float = 0.0
    reason_code: str = ""

    @classmethod
    def allow(cls) -> "BudgetDecision":
        return cls(allowed=True)

    @classmethod
    def reject(cls, wait_seconds: float, reason_code: str) -> "BudgetDecision":
        return cls(allowed=False, wait_seconds=wait_seconds, reason_code=reason_code)


# ---------------------------------------------------------------------------
# Internal per-key budget tracking
# ---------------------------------------------------------------------------

@dataclass
class _KeyBudget:
    """Internal tracking for a single asset/actor/hypothesis budget window."""
    count: int = 0
    window_start: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# Internal circuit breaker tracking
# ---------------------------------------------------------------------------

@dataclass
class _CircuitState:
    """Tracks error counts and circuit state for a single key."""
    error_429_count: int = 0
    error_5xx_count: int = 0
    timeout_count: int = 0
    high_latency_count: int = 0
    circuit_opened_at: float = 0.0
    circuit_open_reason: str = ""
    last_reset: float = field(default_factory=time.monotonic)


# ---------------------------------------------------------------------------
# VdpExecutionBudget
# ---------------------------------------------------------------------------

class VdpExecutionBudget:
    """Multi-level budget enforcement for VDP execution.

    Tracks budgets at:
    - Global: max_requests, max_follow_ups, max_retries, max_concurrency,
      max_runtime_seconds, max_artifact_bytes
    - Per-asset: burst + cooldown
    - Per-actor: burst + cooldown
    - Per-hypothesis: burst + cooldown (for follow-ups)

    Circuit breaker at per-asset level: 429, 5xx, timeout, latency.
    All checks are fail-closed — unknown state or exhaustion blocks further consumption.
    """

    def __init__(
        self,
        max_requests: int = 1000,
        max_follow_ups: int = 50,
        max_retries: int = 3,
        max_concurrency: int = 10,
        max_runtime_seconds: int = 3600,
        max_artifact_bytes: int = 100 * 1024 * 1024,
        per_asset_burst: int = 50,
        per_asset_cooldown_seconds: float = 60.0,
        per_actor_burst: int = 30,
        per_actor_cooldown_seconds: float = 60.0,
        per_hypothesis_burst: int = 20,
        per_hypothesis_cooldown_seconds: float = 60.0,
        circuit_breaker_429_threshold: int = 5,
        circuit_breaker_5xx_threshold: int = 10,
        circuit_breaker_timeout_threshold: int = 5,
        circuit_breaker_latency_ms_threshold: int = 5000,
        circuit_breaker_cooldown_seconds: float = 60.0,
        circuit_breaker_latency_sample_window: int = 5,
    ):
        # Global limits
        self.max_requests = max_requests
        self.max_follow_ups = max_follow_ups
        self.max_retries = max_retries
        self.max_concurrency = max_concurrency
        self.max_runtime_seconds = max_runtime_seconds
        self.max_artifact_bytes = max_artifact_bytes

        # Per-key limits
        self.per_asset_burst = per_asset_burst
        self.per_asset_cooldown_seconds = per_asset_cooldown_seconds
        self.per_actor_burst = per_actor_burst
        self.per_actor_cooldown_seconds = per_actor_cooldown_seconds
        self.per_hypothesis_burst = per_hypothesis_burst
        self.per_hypothesis_cooldown_seconds = per_hypothesis_cooldown_seconds

        # Circuit breaker config
        self.circuit_breaker_429_threshold = circuit_breaker_429_threshold
        self.circuit_breaker_5xx_threshold = circuit_breaker_5xx_threshold
        self.circuit_breaker_timeout_threshold = circuit_breaker_timeout_threshold
        self.circuit_breaker_latency_ms_threshold = circuit_breaker_latency_ms_threshold
        self.circuit_breaker_cooldown_seconds = circuit_breaker_cooldown_seconds
        self.circuit_breaker_latency_sample_window = circuit_breaker_latency_sample_window

        # Internal state
        self._assets: Dict[str, _KeyBudget] = {}
        self._actors: Dict[str, _KeyBudget] = {}
        self._hypotheses: Dict[str, _KeyBudget] = {}
        self._retries: Dict[str, int] = defaultdict(int)
        self._circuits: Dict[str, _CircuitState] = {}
        self._lock = threading.Lock()

        # Global counters
        self._requests_used: int = 0
        self._follow_ups_used: int = 0
        self._artifact_bytes_used: int = 0
        self._inflight: int = 0
        self._start_time: Optional[float] = None

    # ------------------------------------------------------------------
    # Factory from canonical model
    # ------------------------------------------------------------------

    @classmethod
    def from_model(cls, model: ExecutionBudgetV1) -> "VdpExecutionBudget":
        """Create a VdpExecutionBudget from an ExecutionBudgetV1 model."""
        return cls(
            max_requests=model.max_requests,
            max_follow_ups=model.max_follow_ups,
            max_retries=model.max_retries,
            max_concurrency=model.max_concurrency,
            max_runtime_seconds=model.max_runtime_seconds,
            max_artifact_bytes=model.max_artifact_bytes,
            per_asset_burst=model.per_asset_burst,
            per_asset_cooldown_seconds=model.per_asset_cooldown_seconds,
            per_actor_burst=model.per_actor_burst,
            per_actor_cooldown_seconds=model.per_actor_cooldown_seconds,
            per_hypothesis_burst=model.per_hypothesis_burst,
            per_hypothesis_cooldown_seconds=model.per_hypothesis_cooldown_seconds,
            circuit_breaker_429_threshold=model.circuit_breaker_429_threshold,
            circuit_breaker_5xx_threshold=model.circuit_breaker_5xx_threshold,
            circuit_breaker_timeout_threshold=model.circuit_breaker_timeout_threshold,
            circuit_breaker_latency_ms_threshold=model.circuit_breaker_latency_ms_threshold,
        )

    # ------------------------------------------------------------------
    # Main consumption interface
    # ------------------------------------------------------------------

    def _check_limits(
        self,
        asset_key: str,
        actor_key: str,
        hypothesis_key: str,
        *,
        check_concurrency: bool = True,
    ) -> BudgetDecision:
        """Check ALL budget limits WITHOUT consuming anything.

        Atomicity contract (SGK-2026-0421 design constraint G): consumption
        must never end partially — either every dimension commits or none
        does. ``peek()`` / ``consume()`` share this single check.
        """
        # 0. Runtime budget check
        runtime_result = self._check_runtime()
        if not runtime_result.allowed:
            return runtime_result

        # 1. Global request count
        if self._requests_used >= self.max_requests:
            return BudgetDecision.reject(0.0, BudgetReasonCodeV1.REQUESTS_EXHAUSTED)

        # 2. Concurrency check
        if check_concurrency and self._inflight >= self.max_concurrency:
            return BudgetDecision.reject(0.0, BudgetReasonCodeV1.CONCURRENCY_EXCEEDED)

        # 3. Circuit breaker check (per asset)
        if asset_key:
            circuit_result = self._check_circuit(asset_key)
            if not circuit_result.allowed:
                return circuit_result

        # 4. Per-key budget checks (asset, actor, hypothesis)
        if asset_key:
            asset_result = self._check_key_budget(
                self._assets, asset_key,
                self.per_asset_burst, self.per_asset_cooldown_seconds,
                BudgetReasonCodeV1.ASSET_BUDGET_EXHAUSTED,
            )
            if not asset_result.allowed:
                return asset_result

        if actor_key:
            actor_result = self._check_key_budget(
                self._actors, actor_key,
                self.per_actor_burst, self.per_actor_cooldown_seconds,
                BudgetReasonCodeV1.ACTOR_BUDGET_EXHAUSTED,
            )
            if not actor_result.allowed:
                return actor_result

        if hypothesis_key:
            hyp_result = self._check_key_budget(
                self._hypotheses, hypothesis_key,
                self.per_hypothesis_burst, self.per_hypothesis_cooldown_seconds,
                BudgetReasonCodeV1.HYPOTHESIS_BUDGET_EXHAUSTED,
            )
            if not hyp_result.allowed:
                return hyp_result

        return BudgetDecision.allow()

    def peek(
        self,
        asset_key: str = "",
        actor_key: str = "",
        hypothesis_key: str = "",
    ) -> BudgetDecision:
        """Check whether a request token is available WITHOUT consuming.

        Used by the admission gate before capability/HITL checks so a
        rejected admission never consumes budget (design constraint G).
        """
        with self._lock:
            return self._check_limits(asset_key, actor_key, hypothesis_key)

    def consume(
        self,
        asset_key: str = "",
        actor_key: str = "",
        hypothesis_key: str = "",
    ) -> BudgetDecision:
        """Attempt to consume a request token across all budget dimensions.

        Atomic: all limits are checked first; increments are committed only
        when every dimension passes. A rejected consumption never leaves
        partial consumption behind.
        """
        with self._lock:
            decision = self._check_limits(asset_key, actor_key, hypothesis_key)
            if not decision.allowed:
                return decision

            # ---- atomic commit (all dimensions) ----
            self._requests_used += 1
            if asset_key:
                self._commit_key_budget(self._assets, asset_key, self.per_asset_cooldown_seconds)
            if actor_key:
                self._commit_key_budget(self._actors, actor_key, self.per_actor_cooldown_seconds)
            if hypothesis_key:
                self._commit_key_budget(self._hypotheses, hypothesis_key, self.per_hypothesis_cooldown_seconds)
            return BudgetDecision.allow()

    def consume_follow_up(self, hypothesis_key: str) -> BudgetDecision:
        """Consume a follow-up token for a hypothesis (atomic)."""
        with self._lock:
            if self._follow_ups_used >= self.max_follow_ups:
                return BudgetDecision.reject(0.0, BudgetReasonCodeV1.FOLLOW_UPS_EXHAUSTED)

            hyp_result = self._check_key_budget(
                self._hypotheses, hypothesis_key,
                self.per_hypothesis_burst, self.per_hypothesis_cooldown_seconds,
                BudgetReasonCodeV1.FOLLOW_UPS_EXHAUSTED,
            )
            if not hyp_result.allowed:
                return hyp_result

            self._follow_ups_used += 1
            self._commit_key_budget(self._hypotheses, hypothesis_key, self.per_hypothesis_cooldown_seconds)
            return BudgetDecision.allow()

    def consume_follow_up_request(
        self,
        *,
        asset_key: str,
        actor_key: str,
        hypothesis_key: str,
    ) -> BudgetDecision:
        """Atomically reserve one follow-up and its first network request.

        No counter or per-key window is changed unless both the follow-up and
        request limits allow the operation.  This is the M3a admission path;
        it prevents a rejected request from leaving a partially consumed
        follow-up budget.
        """
        with self._lock:
            if self._follow_ups_used >= self.max_follow_ups:
                return BudgetDecision.reject(
                    0.0, BudgetReasonCodeV1.FOLLOW_UPS_EXHAUSTED
                )
            request_result = self._check_limits(
                asset_key,
                actor_key,
                hypothesis_key,
                check_concurrency=False,
            )
            if not request_result.allowed:
                return request_result

            self._follow_ups_used += 1
            self._requests_used += 1
            if asset_key:
                self._commit_key_budget(
                    self._assets, asset_key, self.per_asset_cooldown_seconds
                )
            if actor_key:
                self._commit_key_budget(
                    self._actors, actor_key, self.per_actor_cooldown_seconds
                )
            if hypothesis_key:
                self._commit_key_budget(
                    self._hypotheses,
                    hypothesis_key,
                    self.per_hypothesis_cooldown_seconds,
                )
            return BudgetDecision.allow()

    def consume_retry(self, attempt_key: str) -> BudgetDecision:
        """Consume a retry token for a specific attempt."""
        with self._lock:
            current = self._retries.get(attempt_key, 0)
            if current >= self.max_retries:
                return BudgetDecision.reject(0.0, BudgetReasonCodeV1.RETRIES_EXHAUSTED)
            self._retries[attempt_key] = current + 1
            return BudgetDecision.allow()

    def consume_artifact_bytes(self, byte_count: int) -> bool:
        """Consume artifact bytes. Returns True if within budget."""
        with self._lock:
            if self._artifact_bytes_used + byte_count > self.max_artifact_bytes:
                return False
            self._artifact_bytes_used += byte_count
            return True

    # ------------------------------------------------------------------
    # Concurrency tracking
    # ------------------------------------------------------------------

    def acquire_concurrency(self) -> bool:
        """Atomically check and acquire a concurrency slot.

        Returns:
            True if concurrency slot was acquired, False if max_concurrency
            would be exceeded.
        """
        with self._lock:
            if self._inflight >= self.max_concurrency:
                return False
            self._inflight += 1
            return True

    def release_concurrency(self) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)

    # ------------------------------------------------------------------
    # Runtime tracking
    # ------------------------------------------------------------------

    def mark_start(self) -> None:
        with self._lock:
            if self._start_time is None:
                self._start_time = time.monotonic()

    def _check_runtime(self) -> BudgetDecision:
        if self._start_time is None:
            return BudgetDecision.allow()
        elapsed = time.monotonic() - self._start_time
        if elapsed >= self.max_runtime_seconds:
            return BudgetDecision.reject(0.0, BudgetReasonCodeV1.RUNTIME_EXCEEDED)
        return BudgetDecision.allow()

    # ------------------------------------------------------------------
    # Response recording (circuit breaker)
    # ------------------------------------------------------------------

    def record_response(
        self,
        asset_key: str,
        status_code: int,
        latency_ms: float = 0.0,
    ) -> None:
        """Record a response for circuit breaker tracking."""
        with self._lock:
            circuit = self._ensure_circuit(asset_key)

            if status_code == 429:
                circuit.error_429_count += 1
            elif 500 <= status_code < 600:
                circuit.error_5xx_count += 1

            if latency_ms >= self.circuit_breaker_latency_ms_threshold:
                circuit.high_latency_count += 1

    def record_timeout(self, asset_key: str) -> None:
        """Record a timeout for circuit breaker tracking."""
        with self._lock:
            circuit = self._ensure_circuit(asset_key)
            circuit.timeout_count += 1

    # ------------------------------------------------------------------
    # Circuit breaker internal
    # ------------------------------------------------------------------

    def _ensure_circuit(self, asset_key: str) -> _CircuitState:
        if asset_key not in self._circuits:
            self._circuits[asset_key] = _CircuitState()
        return self._circuits[asset_key]

    def _check_circuit(self, asset_key: str) -> BudgetDecision:
        circuit = self._circuits.get(asset_key)
        if circuit is None:
            return BudgetDecision.allow()

        now = time.monotonic()

        # If circuit is open, check cooldown
        if circuit.circuit_open_reason:
            if (now - circuit.circuit_opened_at) >= self.circuit_breaker_cooldown_seconds:
                # Reset circuit
                circuit.error_429_count = 0
                circuit.error_5xx_count = 0
                circuit.timeout_count = 0
                circuit.high_latency_count = 0
                circuit.circuit_open_reason = ""
                circuit.circuit_opened_at = 0.0
                circuit.last_reset = now
                return BudgetDecision.allow()
            # Still open
            return BudgetDecision.reject(
                wait_seconds=self.circuit_breaker_cooldown_seconds - (now - circuit.circuit_opened_at),
                reason_code=circuit.circuit_open_reason,
            )

        # Check thresholds
        if circuit.error_429_count >= self.circuit_breaker_429_threshold:
            circuit.circuit_open_reason = BudgetReasonCodeV1.CIRCUIT_OPEN_429
            circuit.circuit_opened_at = now
            return BudgetDecision.reject(self.circuit_breaker_cooldown_seconds, circuit.circuit_open_reason)

        if circuit.error_5xx_count >= self.circuit_breaker_5xx_threshold:
            circuit.circuit_open_reason = BudgetReasonCodeV1.CIRCUIT_OPEN_5XX
            circuit.circuit_opened_at = now
            return BudgetDecision.reject(self.circuit_breaker_cooldown_seconds, circuit.circuit_open_reason)

        if circuit.timeout_count >= self.circuit_breaker_timeout_threshold:
            circuit.circuit_open_reason = BudgetReasonCodeV1.CIRCUIT_OPEN_TIMEOUT
            circuit.circuit_opened_at = now
            return BudgetDecision.reject(self.circuit_breaker_cooldown_seconds, circuit.circuit_open_reason)

        if circuit.high_latency_count >= self.circuit_breaker_latency_sample_window:
            circuit.circuit_open_reason = BudgetReasonCodeV1.CIRCUIT_OPEN_LATENCY
            circuit.circuit_opened_at = now
            return BudgetDecision.reject(self.circuit_breaker_cooldown_seconds, circuit.circuit_open_reason)

        return BudgetDecision.allow()

    # ------------------------------------------------------------------
    # Per-key budget helpers (check / commit separated for atomicity)
    # ------------------------------------------------------------------

    def _check_key_budget(
        self,
        store: Dict[str, _KeyBudget],
        key: str,
        burst: int,
        cooldown_seconds: float,
        reason_code: str,
    ) -> BudgetDecision:
        """Check a per-key burst window WITHOUT consuming (non-mutating)."""
        now = time.monotonic()
        budget = store.get(key)
        if budget is None:
            return BudgetDecision.allow()
        if (now - budget.window_start) >= cooldown_seconds:
            # Window would be reset on commit — treat as available.
            return BudgetDecision.allow()
        if budget.count < burst:
            return BudgetDecision.allow()
        remaining = cooldown_seconds - (now - budget.window_start)
        return BudgetDecision.reject(max(0.0, remaining), reason_code)

    def _commit_key_budget(
        self,
        store: Dict[str, _KeyBudget],
        key: str,
        cooldown_seconds: float,
    ) -> None:
        """Commit one consumption to a per-key budget (mutating)."""
        now = time.monotonic()
        budget = store.get(key)
        if budget is None:
            store[key] = _KeyBudget(count=1, window_start=now)
            return
        if (now - budget.window_start) >= cooldown_seconds:
            budget.count = 0
            budget.window_start = now
        budget.count += 1

    # ------------------------------------------------------------------
    # Snapshot
    # ------------------------------------------------------------------

    def snapshot(self) -> Dict[str, Any]:
        """Return a serializable budget snapshot for checkpointing."""
        with self._lock:
            return {
                "requests_used": self._requests_used,
                "follow_ups_used": self._follow_ups_used,
                "artifact_bytes_used": self._artifact_bytes_used,
                "inflight": self._inflight,
                "start_time": self._start_time,
                "max_requests": self.max_requests,
                "max_follow_ups": self.max_follow_ups,
                "max_retries": self.max_retries,
                "max_concurrency": self.max_concurrency,
                "max_runtime_seconds": self.max_runtime_seconds,
                "max_artifact_bytes": self.max_artifact_bytes,
            }

    # ------------------------------------------------------------------
    # Checkpoint save/restore (full state including circuit breaker)
    # ------------------------------------------------------------------

    def to_checkpoint_dict(self) -> Dict[str, Any]:
        """Serialize all budget state for checkpoint persistence.

        Includes: global counters, per-key budgets, circuit breaker state,
        retry counters, and runtime start time.
        """
        with self._lock:
            assets: Dict[str, Dict[str, Any]] = {}
            for key, kb in self._assets.items():
                assets[key] = {"count": kb.count, "window_start": kb.window_start}

            actors: Dict[str, Dict[str, Any]] = {}
            for key, kb in self._actors.items():
                actors[key] = {"count": kb.count, "window_start": kb.window_start}

            hypotheses: Dict[str, Dict[str, Any]] = {}
            for key, kb in self._hypotheses.items():
                hypotheses[key] = {"count": kb.count, "window_start": kb.window_start}

            circuits: Dict[str, Dict[str, Any]] = {}
            for key, cs in self._circuits.items():
                circuits[key] = {
                    "error_429_count": cs.error_429_count,
                    "error_5xx_count": cs.error_5xx_count,
                    "timeout_count": cs.timeout_count,
                    "high_latency_count": cs.high_latency_count,
                    "circuit_opened_at": cs.circuit_opened_at,
                    "circuit_open_reason": cs.circuit_open_reason,
                    "last_reset": cs.last_reset,
                }

            retries: Dict[str, int] = dict(self._retries)

            return {
                "config": {
                    "max_requests": self.max_requests,
                    "max_follow_ups": self.max_follow_ups,
                    "max_retries": self.max_retries,
                    "max_concurrency": self.max_concurrency,
                    "max_runtime_seconds": self.max_runtime_seconds,
                    "max_artifact_bytes": self.max_artifact_bytes,
                    "per_asset_burst": self.per_asset_burst,
                    "per_asset_cooldown_seconds": self.per_asset_cooldown_seconds,
                    "per_actor_burst": self.per_actor_burst,
                    "per_actor_cooldown_seconds": self.per_actor_cooldown_seconds,
                    "per_hypothesis_burst": self.per_hypothesis_burst,
                    "per_hypothesis_cooldown_seconds": self.per_hypothesis_cooldown_seconds,
                    "circuit_breaker_429_threshold": self.circuit_breaker_429_threshold,
                    "circuit_breaker_5xx_threshold": self.circuit_breaker_5xx_threshold,
                    "circuit_breaker_timeout_threshold": self.circuit_breaker_timeout_threshold,
                    "circuit_breaker_latency_ms_threshold": self.circuit_breaker_latency_ms_threshold,
                    "circuit_breaker_cooldown_seconds": self.circuit_breaker_cooldown_seconds,
                    "circuit_breaker_latency_sample_window": self.circuit_breaker_latency_sample_window,
                },
                "counters": {
                    "requests_used": self._requests_used,
                    "follow_ups_used": self._follow_ups_used,
                    "artifact_bytes_used": self._artifact_bytes_used,
                    "inflight": self._inflight,
                },
                "runtime": {
                    "start_time": self._start_time,
                },
                "per_key": {
                    "assets": assets,
                    "actors": actors,
                    "hypotheses": hypotheses,
                },
                "retries": retries,
                "circuits": circuits,
            }

    @classmethod
    def from_checkpoint_dict(cls, d: Dict[str, Any]) -> "VdpExecutionBudget":
        """Restore a VdpExecutionBudget from a checkpoint dict.

        Args:
            d: Dict previously produced by ``to_checkpoint_dict()``.

        Returns:
            Restored VdpExecutionBudget with all state intact.
        """
        config = d.get("config", {})
        budget = cls(
            max_requests=config.get("max_requests", 1000),
            max_follow_ups=config.get("max_follow_ups", 50),
            max_retries=config.get("max_retries", 3),
            max_concurrency=config.get("max_concurrency", 10),
            max_runtime_seconds=config.get("max_runtime_seconds", 3600),
            max_artifact_bytes=config.get("max_artifact_bytes", 100 * 1024 * 1024),
            per_asset_burst=config.get("per_asset_burst", 50),
            per_asset_cooldown_seconds=config.get("per_asset_cooldown_seconds", 60.0),
            per_actor_burst=config.get("per_actor_burst", 30),
            per_actor_cooldown_seconds=config.get("per_actor_cooldown_seconds", 60.0),
            per_hypothesis_burst=config.get("per_hypothesis_burst", 20),
            per_hypothesis_cooldown_seconds=config.get("per_hypothesis_cooldown_seconds", 60.0),
            circuit_breaker_429_threshold=config.get("circuit_breaker_429_threshold", 5),
            circuit_breaker_5xx_threshold=config.get("circuit_breaker_5xx_threshold", 10),
            circuit_breaker_timeout_threshold=config.get("circuit_breaker_timeout_threshold", 5),
            circuit_breaker_latency_ms_threshold=config.get("circuit_breaker_latency_ms_threshold", 5000),
            circuit_breaker_cooldown_seconds=config.get("circuit_breaker_cooldown_seconds", 60.0),
            circuit_breaker_latency_sample_window=config.get("circuit_breaker_latency_sample_window", 5),
        )

        # Restore counters (but always reset inflight to 0 — on resume,
        # no requests are in flight; and reset start_time so runtime restarts)
        counters = d.get("counters", {})
        budget._requests_used = counters.get("requests_used", 0)
        budget._follow_ups_used = counters.get("follow_ups_used", 0)
        budget._artifact_bytes_used = counters.get("artifact_bytes_used", 0)
        budget._inflight = 0  # never restore inflight from checkpoint

        # Restore runtime (but reset start_time so the runtime budget restarts)
        budget._start_time = None  # never restore start_time from checkpoint

        # Restore per-key budgets
        per_key = d.get("per_key", {})
        for key, state in per_key.get("assets", {}).items():
            budget._assets[key] = _KeyBudget(
                count=state.get("count", 0),
                window_start=state.get("window_start", time.monotonic()),
            )
        for key, state in per_key.get("actors", {}).items():
            budget._actors[key] = _KeyBudget(
                count=state.get("count", 0),
                window_start=state.get("window_start", time.monotonic()),
            )
        for key, state in per_key.get("hypotheses", {}).items():
            budget._hypotheses[key] = _KeyBudget(
                count=state.get("count", 0),
                window_start=state.get("window_start", time.monotonic()),
            )

        # Restore retries
        retries = d.get("retries", {})
        for key, count in retries.items():
            budget._retries[key] = count

        # Restore circuit breaker state
        circuits = d.get("circuits", {})
        for key, state in circuits.items():
            cs = _CircuitState(
                error_429_count=state.get("error_429_count", 0),
                error_5xx_count=state.get("error_5xx_count", 0),
                timeout_count=state.get("timeout_count", 0),
                high_latency_count=state.get("high_latency_count", 0),
                circuit_opened_at=state.get("circuit_opened_at", 0.0),
                circuit_open_reason=state.get("circuit_open_reason", ""),
                last_reset=state.get("last_reset", time.monotonic()),
            )
            budget._circuits[key] = cs

        return budget
