"""
Compiled Guard Models: DTOs for bundle guard policy contract.

Provides the shared contract types used by loader, evaluator, and
runtime consumers: LoadedGuardPolicy, GuardInput, GuardDecision,
and fail-closed error DTOs.

These types follow the spec contract defined in:
  docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# LoadedGuardPolicy
# ---------------------------------------------------------------------------


@dataclass
class LoadedGuardPolicy:
    """Resolved guard policy from active bundle + compiled_guard_policy.yaml.

    Attributes:
        bundle_id: Immutable snapshot identity from active_bundle.json.
        policy_id: Canonical policy ID (e.g. ``bbp:hackerone:tiktok:...``).
        provider: ``hackerone`` or ``bugcrowd``.
        program_name: Human-readable program name.
        program_alias: Mutable alias used for active mapping resolution.
        compiled_policy_path: Absolute or resolved path to compiled_guard_policy.yaml.
        compiled_policy_hash: Expected hash from active mapping, verified against file.
        schema_version: Reader schema version from compiled policy.
        compile_status: Must be ``ready`` for runtime use.
        raw_policy: Deserialized compiled_guard_policy.yaml payload as dict.
    """

    bundle_id: str
    policy_id: str
    provider: str
    program_name: str
    program_alias: str
    compiled_policy_path: str
    compiled_policy_hash: str
    schema_version: int = 1
    compile_status: str = "ready"
    raw_policy: dict[str, Any] = field(default_factory=dict)

    def is_ready(self) -> bool:
        return self.compile_status == "ready"


# ---------------------------------------------------------------------------
# GuardInput
# ---------------------------------------------------------------------------


@dataclass
class GuardInput:
    """Normalised input passed to the shared guard evaluator.

    All fields except ``bundle_id`` and ``policy_id`` are optional for
    Phase 1 host / path / post-exploit / attack-class evaluation.  Future
    enforcement layers will fill additional fields.
    """

    bundle_id: str = ""
    policy_id: str = ""
    target: str = ""
    host: str = ""
    phase: str = ""
    attack_class: str = ""
    requested_action: str = ""
    proposed_tool: str = ""
    budget_snapshot: dict[str, Any] = field(default_factory=dict)
    enforcement_layer: str = ""


# ---------------------------------------------------------------------------
# GuardDecision
# ---------------------------------------------------------------------------


@dataclass
class GuardDecision:
    """Single-deterministic output from guard evaluator.

    Attributes:
        decision: ``allow``, ``block``, ``requires_hitl``, or ``degrade_to_report``.
        reason_code: Machine-readable reason code.
        matched_rule_ids: Runtime rule IDs that matched.
        matched_rule_origin_ids: Origin IDs for audit trace.
        source_refs: Human-readable source references.
        policy_id: Policy ID used for the decision.
        bundle_id: Bundle ID used for the decision.
        decision_trace_id: Stable deterministic trace ID.
        enforcement_layer: The enforcement layer that produced the decision.
        fail_closed: Whether this decision was produced by a fail-closed path.
    """

    decision: str = "block"
    reason_code: str = "unknown"
    matched_rule_ids: list[str] = field(default_factory=list)
    matched_rule_origin_ids: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    policy_id: str = ""
    bundle_id: str = ""
    decision_trace_id: str = ""
    enforcement_layer: str = ""
    fail_closed: bool = False

    @classmethod
    def allow(
        cls,
        reason_code: str = "in_scope",
        matched_rule_ids: Optional[list[str]] = None,
        matched_rule_origin_ids: Optional[list[str]] = None,
        source_refs: Optional[list[str]] = None,
        policy_id: str = "",
        bundle_id: str = "",
        enforcement_layer: str = "",
        host: str = "",
        target: str = "",
        phase: str = "",
        attack_class: str = "",
    ) -> "GuardDecision":
        return cls(
            decision="allow",
            reason_code=reason_code,
            matched_rule_ids=list(matched_rule_ids or []),
            matched_rule_origin_ids=list(matched_rule_origin_ids or []),
            source_refs=list(source_refs or []),
            policy_id=policy_id,
            bundle_id=bundle_id,
            enforcement_layer=enforcement_layer,
            decision_trace_id=_generate_trace_id(
                "allow", reason_code, policy_id, bundle_id,
                host=host, target=target, phase=phase,
                attack_class=attack_class, enforcement_layer=enforcement_layer,
            ),
            fail_closed=False,
        )

    @classmethod
    def block(
        cls,
        reason_code: str,
        matched_rule_ids: Optional[list[str]] = None,
        matched_rule_origin_ids: Optional[list[str]] = None,
        source_refs: Optional[list[str]] = None,
        policy_id: str = "",
        bundle_id: str = "",
        enforcement_layer: str = "",
        fail_closed: bool = False,
        host: str = "",
        target: str = "",
        phase: str = "",
        attack_class: str = "",
    ) -> "GuardDecision":
        return cls(
            decision="block",
            reason_code=reason_code,
            matched_rule_ids=list(matched_rule_ids or []),
            matched_rule_origin_ids=list(matched_rule_origin_ids or []),
            source_refs=list(source_refs or []),
            policy_id=policy_id,
            bundle_id=bundle_id,
            enforcement_layer=enforcement_layer,
            decision_trace_id=_generate_trace_id(
                "block", reason_code, policy_id, bundle_id,
                host=host, target=target, phase=phase,
                attack_class=attack_class, enforcement_layer=enforcement_layer,
            ),
            fail_closed=fail_closed,
        )


# ---------------------------------------------------------------------------
# GuardLoadError
# ---------------------------------------------------------------------------


@dataclass
class GuardLoadError:
    """Fail-closed error returned when loader cannot resolve a valid policy.

    Attributes:
        reason_code: Machine-readable code (e.g. ``active_bundle_missing``).
        message: Human-readable description.
        details: Optional additional context.
    """

    reason_code: str
    message: str
    details: Optional[dict[str, Any]] = None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _generate_trace_id(
    decision: str,
    reason_code: str,
    policy_id: str = "",
    bundle_id: str = "",
    host: str = "",
    target: str = "",
    phase: str = "",
    attack_class: str = "",
    enforcement_layer: str = "",
) -> str:
    """Deterministic trace ID from stable inputs.

    Same ``(decision, reason_code, policy_id, bundle_id, host, target,
    phase, attack_class, enforcement_layer)`` always produces the same
    trace ID.  Adding host/target/phase/attack_class prevents collisions
    between different evaluations within the same policy.
    """
    seed = ":".join((
        decision, reason_code, policy_id, bundle_id,
        host, target, phase, attack_class, enforcement_layer,
    ))
    digest = hashlib.sha256(seed.encode()).hexdigest()[:12]
    return f"gd-{digest}"
