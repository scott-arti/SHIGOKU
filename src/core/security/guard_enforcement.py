"""
Runtime Guard Enforcement Helper (Phase 2: SGK-2026-0335).

Provides the rollout-stage / kill-switch mechanism and a thin shared-
evaluator adapter that every enforcement layer calls.

Rollout stages (strictly additive in scope):
- ``shadow_read_only``: evaluate but never block (observability only).
- ``mc_only``: MasterConductor preflight + dispatch gate block (Phase 1).
- ``worker_external_hard``: MC + worker/network/external-tool hard block.

Default: ``mc_only`` (preserves Phase 1 behaviour).

SGK-2026-0370: Adds ``BridgeVerdict`` and ``bridge_guard_and_phase_gate()``
so that compiled guard decisions and PhaseGate capability verdicts are
safely combined at all three call-sites (task creation, dispatch,
post-exploit), with ``reason_origin``, ``reason_codes``, and
``source_refs`` preserved in session/report artifacts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, Optional

from src.core.security.compiled_guard_models import (
    GuardDecision,
    GuardInput,
    LoadedGuardPolicy,
)
from src.core.security.compiled_guard_evaluator import (
    evaluate_guard,
    evaluate_with_loader_error,
)

logger = logging.getLogger(__name__)

# Shared guard context for non-network-client consumers (managers, adapters,
# context-runner).  Set by MC after bundle resolution.  Read by enforcement
# points at runtime.
_shared_guard_context: Optional[dict[str, Any]] = None


def set_shared_guard_context(ctx: Optional[dict[str, Any]]) -> None:
    """Set the shared guard context (Phase 2: SGK-2026-0335).

    Called by MC after bundle resolution.  Managers, adapters, and
    context-runners that don't own a network_client pull from this.
    """
    global _shared_guard_context
    _shared_guard_context = dict(ctx) if ctx else None

    # Also update network_client's shared context so all paths converge
    try:
        from src.core.infra.network_client import AsyncNetworkClient
        AsyncNetworkClient.update_shared_guard_context(ctx)
    except ImportError:
        pass


def get_shared_guard_context() -> Optional[dict[str, Any]]:
    """Return the current shared guard context, or None."""
    return _shared_guard_context


def clear_shared_guard_context() -> None:
    """Clear the shared guard context (Phase 2: SGK-2026-0335).

    Called on MC shutdown, rollback/rebind, or mode change out of bugbounty.
    """
    global _shared_guard_context
    _shared_guard_context = None
    try:
        from src.core.infra.network_client import AsyncNetworkClient
        AsyncNetworkClient.update_shared_guard_context(None)
    except ImportError:
        pass


class EnforcementStage(str, Enum):
    SHADOW_READ_ONLY = "shadow_read_only"
    MC_ONLY = "mc_only"
    WORKER_EXTERNAL_HARD = "worker_external_hard"


# ---------------------------------------------------------------------------
# Stage resolution
# ---------------------------------------------------------------------------

_DEFAULT_STAGE = EnforcementStage.MC_ONLY


def resolve_enforcement_stage(
    explicit: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
) -> EnforcementStage:
    """Resolve the current enforcement stage.

    Resolution order:
    1. Explicit argument (CLI / per-run override).
    2. ``context.target_info["guard_enforcement_stage"]`` (from settings).
    3. Environment variable ``SHIGOKU_GUARD_ENFORCEMENT_STAGE``.
    4. Default: ``mc_only``.

    Returns:
        The resolved ``EnforcementStage``.
    """
    import os

    value: Optional[str] = explicit
    if not value and isinstance(context, dict):
        value = str(context.get("guard_enforcement_stage", "") or "").strip()
    if not value:
        value = os.environ.get("SHIGOKU_GUARD_ENFORCEMENT_STAGE", "").strip()
    if not value:
        return _DEFAULT_STAGE

    try:
        return EnforcementStage(value.lower())
    except ValueError:
        logger.warning(
            "Unknown guard enforcement stage '%s', falling back to %s",
            value, _DEFAULT_STAGE.value,
        )
        return _DEFAULT_STAGE


def stage_allows_block(stage: EnforcementStage, layer: str) -> bool:
    """Return True if *stage* permits actual blocking at *layer*.

    Layers:
      - ``mc``: MasterConductor preflight / dispatch.
      - ``worker``: Worker / manager tool execution.
      - ``network``: HTTP send.
      - ``external``: External tool / subprocess execution.
    """
    if stage == EnforcementStage.WORKER_EXTERNAL_HARD:
        return True  # all layers hard-block
    if stage == EnforcementStage.MC_ONLY:
        return layer == "mc"
    # shadow_read_only: never block
    return False


# ---------------------------------------------------------------------------
# Thin shared-evaluator adapter
# ---------------------------------------------------------------------------


def evaluate_at_layer(
    policy: Optional[LoadedGuardPolicy],
    guard_input: GuardInput,
    layer: str,
    stage: Optional[EnforcementStage] = None,
    context: Optional[dict[str, Any]] = None,
) -> GuardDecision:
    """Evaluate the compiled guard at the given enforcement layer.

    This is the single runtime adapter that every enforcement point should
    call.  It handles:
    - No policy → fail-closed (loader error reason preserved).
    - ``shadow_read_only`` → evaluate but always return ``allow``.
    - ``mc_only`` → block only when ``layer == "mc"``.
    - ``worker_external_hard`` → block for all layers.

    Args:
        policy: Resolved ``LoadedGuardPolicy`` (may be None if bundle missing).
        guard_input: Normalised guard input.
        layer: Enforcement layer label (``mc``, ``worker``, ``network``, ``external``).
        stage: Pre-resolved enforcement stage (resolved from context if None).
        context: Run context dict (for stage resolution fallback).

    Returns:
        ``GuardDecision``.  In shadow mode, always ``allow`` regardless of
        evaluation result.
    """
    if stage is None:
        stage = resolve_enforcement_stage(context=context)

    # Policy unavailable → always fail-closed (never shadow).
    # The stage/rollout mechanism controls whether a VALID policy can block;
    # when there is no policy at all, the only safe choice is to block.
    if policy is None or not policy.is_ready():
        decision = evaluate_with_loader_error(
            error_reason_code="policy_unavailable",
            enforcement_layer=layer,
        )
        logger.warning(
            "Guard BLOCKED at layer=%s stage=%s reason=%s (policy unavailable)",
            layer, stage.value if stage else "unknown", decision.reason_code,
        )
        _record_metrics(decision, layer)
        return decision

    decision = evaluate_guard(policy, guard_input, enforcement_layer=layer)

    if decision.decision == "block" and not stage_allows_block(stage, layer):
        logger.info(
            "Guard would block at layer=%s reason=%s (stage=%s, shadow)",
            layer, decision.reason_code, stage.value,
        )
        shadow_decision = GuardDecision.allow(
            reason_code=f"shadow_{decision.reason_code}",
            enforcement_layer=layer,
            policy_id=policy.policy_id,
            bundle_id=policy.bundle_id,
        )
        _record_metrics(shadow_decision, layer)
        return shadow_decision

    if decision.decision == "block":
        logger.warning(
            "Guard BLOCKED at layer=%s stage=%s reason=%s",
            layer, stage.value, decision.reason_code,
        )

    _record_metrics(decision, layer)
    return decision


# ---------------------------------------------------------------------------
# Host extraction helper
# ---------------------------------------------------------------------------


def extract_host_from_target(target: Optional[str]) -> str:
    """Extract a canonical lowercase host from a URL or host string.

    Returns "" if target is None or unparseable.
    """
    if not target:
        return ""
    from urllib.parse import urlparse

    stripped = target.strip()
    # If it already looks like a bare host (no scheme, no path), use as-is
    if "/" not in stripped and "://" not in stripped:
        return stripped.lower()

    # Otherwise parse as URL
    normalized = stripped if "://" in stripped else f"http://{stripped}"
    try:
        parsed = urlparse(normalized)
        return (parsed.hostname or parsed.netloc or "").strip().lower()
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Helper: build guard context from MC context
# ---------------------------------------------------------------------------


def resolve_policy_from_context(
    context: Optional[dict[str, Any]],
    workspace_root: str = ".",
) -> Optional[LoadedGuardPolicy]:
    """Try to resolve a loaded guard policy from MC context dict.

    Returns None if no bundle context is available (non-bugbounty or
    missing bundle — caller handles fail-closed).
    """
    if not isinstance(context, dict):
        return None
    bundle_dir = context.get("bundle_dir", "")
    compiled_path = context.get("compiled_guard_policy_path", "")
    if not compiled_path and not bundle_dir:
        return None

    from src.core.security.compiled_guard_loader import (
        GuardLoadError,
        load_active_policy_from_bundle_dir,
    )

    if bundle_dir:
        result = load_active_policy_from_bundle_dir(
            bundle_dir=bundle_dir,
            expected_program=None,
        )
    else:
        # compiled_path: assume the parent dir has active_bundle.json
        from pathlib import Path
        parent = Path(compiled_path).parent
        result = load_active_policy_from_bundle_dir(
            bundle_dir=str(parent),
            expected_program=None,
        )

    if isinstance(result, GuardLoadError):
        logger.warning(
            "Could not load policy from context: %s — %s",
            result.reason_code, result.message,
        )
        return None
    return result


# ---------------------------------------------------------------------------
# Bridge: guard decision + PhaseGate verdict → unified verdict (SGK-2026-0370)
# ---------------------------------------------------------------------------

# Allowed unified verdicts.
BridgeVerdictValue = Literal[
    "allow", "defer", "requires_hitl", "route_to_report", "lock_phase"
]

# Allowed reason origin values.
BridgeReasonOrigin = Literal["compiled_guard", "phase_gate", "combined"]

# Recognised compiled-guard decision values that carry special semantics.
_GUARD_BLOCK = "block"
_GUARD_REQUIRES_HITL = "requires_hitl"
_GUARD_DEGRADE_TO_REPORT = "degrade_to_report"
_GUARD_ALLOW = "allow"


@dataclass
class BridgeVerdict:
    """Unified verdict combining compiled-guard and PhaseGate results.

    This is a lightweight DTO that ensures the compiled guard's ``block``
    is never overridden by PhaseGate, while ``requires_hitl`` and
    ``degrade_to_report`` are preserved with their original reason so
    they are not silently dropped from the queue.

    Attributes:
        verdict: ``allow``, ``defer``, ``requires_hitl``, ``route_to_report``,
                 or ``lock_phase``.
        reason_origin: Which system produced the decisive reason.
        reason_codes: Machine-readable reason codes (merged from both sources).
        source_refs: Human-readable source references for audit trace.
        gate_summary: Dict suitable for session / report artifact fields
                      (``reason_origin``, ``reason_codes``, ``source_refs``,
                      ``compiled_guard_decision``).
    """

    verdict: BridgeVerdictValue = "allow"
    reason_origin: BridgeReasonOrigin = "combined"
    reason_codes: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    gate_summary: dict[str, Any] = field(default_factory=dict)


def bridge_guard_and_phase_gate(
    guard_decision: "GuardDecision",
    phase_gate_allowed: bool,
    phase_gate_reason: str = "",
) -> BridgeVerdict:
    """Bridge compiled-guard decision with a PhaseGate capability verdict.

    **Invariants (never violated):**

    - If the compiled guard returns ``block``, the unified verdict is
      ``lock_phase`` regardless of what PhaseGate says.
    - ``requires_hitl`` and ``degrade_to_report`` are preserved with
      their origin so they are not silently dropped from the queue.

    Args:
        guard_decision: The compiled guard's decision.
        phase_gate_allowed: PhaseGate ``can_create_attack_task()`` result.
        phase_gate_reason: PhaseGate rejection reason (empty string if allowed).

    Returns:
        ``BridgeVerdict`` with all audit fields populated.
    """
    gd = guard_decision.decision
    reason_codes: list[str] = []
    source_refs: list[str] = []

    # Always collect guard reason codes and source refs for audit.
    if guard_decision.reason_code:
        reason_codes.append(f"guard:{guard_decision.reason_code}")
    if guard_decision.source_refs:
        source_refs.extend(guard_decision.source_refs)

    # ---- 1. compiled guard is authoritative for hard-block ----------------
    if gd == _GUARD_BLOCK:
        if phase_gate_reason and phase_gate_reason != "OK":
            reason_codes.append(f"phase_gate:{phase_gate_reason}")
        return BridgeVerdict(
            verdict="lock_phase",
            reason_origin="compiled_guard",
            reason_codes=reason_codes,
            source_refs=source_refs,
            gate_summary={
                "reason_origin": "compiled_guard",
                "reason_codes": list(reason_codes),
                "source_refs": list(source_refs),
                "compiled_guard_decision": "block",
                "phase_gate_allowed": phase_gate_allowed,
                "phase_gate_reason": phase_gate_reason,
            },
        )

    # ---- 2. requires_hitl is preserved (not deny) -------------------------
    if gd == _GUARD_REQUIRES_HITL:
        return BridgeVerdict(
            verdict="requires_hitl",
            reason_origin="compiled_guard",
            reason_codes=reason_codes,
            source_refs=source_refs,
            gate_summary={
                "reason_origin": "compiled_guard",
                "reason_codes": list(reason_codes),
                "source_refs": list(source_refs),
                "compiled_guard_decision": "requires_hitl",
                "phase_gate_allowed": phase_gate_allowed,
                "phase_gate_reason": phase_gate_reason,
            },
        )

    # ---- 3. degrade_to_report is preserved (not deny) ---------------------
    if gd == _GUARD_DEGRADE_TO_REPORT:
        return BridgeVerdict(
            verdict="route_to_report",
            reason_origin="compiled_guard",
            reason_codes=reason_codes,
            source_refs=source_refs,
            gate_summary={
                "reason_origin": "compiled_guard",
                "reason_codes": list(reason_codes),
                "source_refs": list(source_refs),
                "compiled_guard_decision": "degrade_to_report",
                "phase_gate_allowed": phase_gate_allowed,
                "phase_gate_reason": phase_gate_reason,
            },
        )

    # ---- 4. guard allows → PhaseGate decides -----------------------------
    # guard says allow, but PhaseGate may defer
    if not phase_gate_allowed:
        if phase_gate_reason and phase_gate_reason != "OK":
            reason_codes.append(f"phase_gate:{phase_gate_reason}")
        return BridgeVerdict(
            verdict="defer",
            reason_origin="phase_gate",
            reason_codes=reason_codes,
            source_refs=source_refs,
            gate_summary={
                "reason_origin": "phase_gate",
                "reason_codes": list(reason_codes),
                "source_refs": list(source_refs),
                "compiled_guard_decision": "allow",
                "phase_gate_allowed": False,
                "phase_gate_reason": phase_gate_reason,
            },
        )

    # Both allow → go ahead
    reason_codes.append("phase_gate:OK")
    return BridgeVerdict(
        verdict="allow",
        reason_origin="combined",
        reason_codes=reason_codes,
        source_refs=source_refs,
        gate_summary={
            "reason_origin": "combined",
            "reason_codes": list(reason_codes),
            "source_refs": list(source_refs),
            "compiled_guard_decision": "allow",
            "phase_gate_allowed": True,
            "phase_gate_reason": "OK",
        },
    )


# ---------------------------------------------------------------------------
# Metrics hook (Step 9: SGK-2026-0335)
# ---------------------------------------------------------------------------


def _record_metrics(decision: "GuardDecision", layer: str) -> None:
    """Record a guard decision to the metrics collector.

    Called after every ``evaluate_at_layer()`` decision so that the
    metrics collector captures every evaluation regardless of rollout stage
    (including shadow-mode allow'd decisions and fail-closed blocks).
    """
    try:
        from src.core.security.guard_metrics import get_guard_metrics  # type: ignore[import]

        metrics = get_guard_metrics()
        metrics.record_guard_decision(
            layer=layer or "unknown",
            decision=decision.decision,
            reason_code=decision.reason_code,
        )
        if getattr(decision, "fail_closed", False):
            metrics.record_policy_fail_closed()
    except Exception:
        pass  # metrics are best-effort; never fail enforcement
