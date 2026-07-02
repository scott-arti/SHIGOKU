"""
Compiled Guard Evaluator: pure-function guard decision engine.

Evaluates ``GuardInput`` against a ``LoadedGuardPolicy`` and returns
a deterministic ``GuardDecision``.  No I/O is performed.

Phase 1 supported checks:
- exact host allow / wildcard allow
- wildcard / exact deny
- URL prefix deny
- post-exploit phase deny
- attack_class deny
- default deny for unknown hosts
- loader failure based fail-closed deny
"""

from __future__ import annotations

import logging
from typing import Optional

from src.core.security.compiled_guard_models import (
    LoadedGuardPolicy,
    GuardDecision,
    GuardInput,
)

logger = logging.getLogger(__name__)

# Reason codes
REASON_ALLOW_EXACT_HOST = "in_scope_exact_host"
REASON_ALLOW_WILDCARD_HOST = "in_scope_wildcard_host"
REASON_ALLOW_DEFAULT = "in_scope_default_allow"

REASON_DENY_EXACT_HOST = "out_of_scope_host"
REASON_DENY_WILDCARD_HOST = "out_of_scope_wildcard_host"
REASON_DENY_URL_PREFIX = "out_of_scope_url_prefix"
REASON_DENY_POST_EXPLOIT = "phase_post_exploit_denied"
REASON_DENY_ATTACK_CLASS = "attack_class_denied"
REASON_DENY_DEFAULT = "out_of_scope_default_deny"
REASON_DENY_FAIL_CLOSED = "policy_fail_closed"

# Post-exploit phase name
PHASE_POST_EXPLOIT = "post_exploit"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_guard(
    policy: LoadedGuardPolicy,
    guard_input: GuardInput,
    enforcement_layer: str = "evaluator",
) -> GuardDecision:
    """Evaluate a ``GuardInput`` against a loaded guard policy.

    Returns a deterministic ``GuardDecision``.

    Args:
        policy: Loaded, validated guard policy (must have compile_status=ready).
        guard_input: Normalised guard input.
        enforcement_layer: Label for the calling enforcement layer (e.g. ``mc``).

    Returns:
        ``GuardDecision`` with decision/reason_code/matched_rules.
    """
    # Extract context early (used in trace IDs even for fail-closed paths)
    host = (guard_input.host or "").strip().lower()
    target = (guard_input.target or "").strip()
    phase = (guard_input.phase or "").strip().lower()
    attack_class = (guard_input.attack_class or "").strip().lower()

    if not policy or not policy.is_ready():
        return GuardDecision.block(
            reason_code=REASON_DENY_FAIL_CLOSED,
            source_refs=["compiled_guard_evaluator#fail_closed"],
            policy_id=getattr(policy, "policy_id", ""),
            bundle_id=getattr(policy, "bundle_id", ""),
            enforcement_layer=enforcement_layer,
            host=host, target=target, phase=phase, attack_class=attack_class,
            fail_closed=True,
        )

    raw = policy.raw_policy

    # ---- 1. post-exploit phase deny (highest priority in Phase 1) ----------
    if phase == PHASE_POST_EXPLOIT:
        phases_rules = raw.get("rules", {}).get("phases", {})
        pe_rule = phases_rules.get(PHASE_POST_EXPLOIT, {})
        if pe_rule.get("decision") == "deny":
            return GuardDecision.block(
                reason_code=REASON_DENY_POST_EXPLOIT,
                matched_rule_origin_ids=_collect_origin_ids(raw, "post_exploit"),
                source_refs=list(pe_rule.get("source_refs", [])),
                policy_id=policy.policy_id,
                bundle_id=policy.bundle_id,
                enforcement_layer=enforcement_layer,
                host=host, target=target, phase=phase, attack_class=attack_class,
            )

    # ---- 2. attack_class deny ----------------------------------------------
    if attack_class:
        ac_rules = raw.get("rules", {}).get("attack_classes", {})
        ac_rule = ac_rules.get(attack_class, {})
        if ac_rule.get("decision") == "deny":
            return GuardDecision.block(
                reason_code=REASON_DENY_ATTACK_CLASS,
                matched_rule_origin_ids=_collect_origin_ids(raw, attack_class),
                source_refs=list(ac_rule.get("source_refs", [])),
                policy_id=policy.policy_id,
                bundle_id=policy.bundle_id,
                enforcement_layer=enforcement_layer,
                host=host, target=target, phase=phase, attack_class=attack_class,
            )

    if not host and not target:
        # No host to evaluate — default deny
        return GuardDecision.block(
            reason_code=REASON_DENY_DEFAULT,
            source_refs=["compiled_guard_evaluator#no_host"],
            policy_id=policy.policy_id,
            bundle_id=policy.bundle_id,
            enforcement_layer=enforcement_layer,
            host=host, target=target, phase=phase, attack_class=attack_class,
        )

    scope = raw.get("scope", {})

    # ---- 3. explicit deny hosts --------------------------------------------
    deny_hosts = scope.get("deny_hosts", [])
    for dh in deny_hosts:
        if _host_matches(host, dh):
            origin_ids = _find_origins_for_subject(raw, dh)
            return GuardDecision.block(
                reason_code=REASON_DENY_EXACT_HOST if not dh.startswith("*.") else REASON_DENY_WILDCARD_HOST,
                matched_rule_ids=[f"scope.host.deny.{dh}"],
                matched_rule_origin_ids=origin_ids,
                source_refs=_collect_source_refs_for_subject(raw, dh),
                policy_id=policy.policy_id,
                bundle_id=policy.bundle_id,
                enforcement_layer=enforcement_layer,
                host=host, target=target, phase=phase, attack_class=attack_class,
            )

    # ---- 4. URL prefix deny ------------------------------------------------
    deny_url_prefixes = scope.get("deny_url_prefixes", [])
    for dup in deny_url_prefixes:
        if target.startswith(dup):
            origin_ids = _find_origins_for_subject(raw, dup)
            return GuardDecision.block(
                reason_code=REASON_DENY_URL_PREFIX,
                matched_rule_ids=[f"scope.url_prefix.deny.{dup}"],
                matched_rule_origin_ids=origin_ids,
                source_refs=_collect_source_refs_for_subject(raw, dup),
                policy_id=policy.policy_id,
                bundle_id=policy.bundle_id,
                enforcement_layer=enforcement_layer,
                host=host, target=target, phase=phase, attack_class=attack_class,
            )

    # ---- 5. allow hosts ----------------------------------------------------
    allow_hosts = scope.get("allow_hosts", [])
    for ah in allow_hosts:
        if _host_matches(host, ah):
            origin_ids = _find_origins_for_subject(raw, ah)
            return GuardDecision.allow(
                reason_code=REASON_ALLOW_EXACT_HOST if not ah.startswith("*.") else REASON_ALLOW_WILDCARD_HOST,
                matched_rule_ids=[f"scope.host.allow.{ah}"],
                matched_rule_origin_ids=origin_ids,
                source_refs=_collect_source_refs_for_subject(raw, ah),
                policy_id=policy.policy_id,
                bundle_id=policy.bundle_id,
                enforcement_layer=enforcement_layer,
                host=host, target=target, phase=phase, attack_class=attack_class,
            )

    # ---- 6. default deny ---------------------------------------------------
    return GuardDecision.block(
        reason_code=REASON_DENY_DEFAULT,
        source_refs=["compiled_guard_evaluator#default_deny"],
        policy_id=policy.policy_id,
        bundle_id=policy.bundle_id,
        enforcement_layer=enforcement_layer,
        host=host, target=target, phase=phase, attack_class=attack_class,
    )


def evaluate_with_loader_error(
    error_reason_code: str,
    enforcement_layer: str = "evaluator",
) -> GuardDecision:
    """Produce a fail-closed decision when the loader returned an error.

    The original loader error code is preserved as ``reason_code`` so that
    metrics, alerts, and block-reason dashboards can distinguish between
    different failure modes (e.g. ``active_bundle_missing`` vs
    ``policy_integrity_error``).

    Args:
        error_reason_code: The loader's reason code (e.g. ``active_bundle_missing``).
        enforcement_layer: Label for the calling layer.

    Returns:
        A ``block`` decision with ``fail_closed=True`` and the original
        ``error_reason_code`` as ``reason_code``.
    """
    return GuardDecision.block(
        reason_code=error_reason_code,
        source_refs=[f"compiled_guard_loader#{error_reason_code}"],
        enforcement_layer=enforcement_layer,
        fail_closed=True,
    )


# ---------------------------------------------------------------------------
# Host matching helpers (pure, deterministic)
# ---------------------------------------------------------------------------


def _host_matches(target_host: str, pattern: str) -> bool:
    """Match a host against a scope pattern.

    Supports:
    - Exact match: ``example.com`` == ``example.com``
    - Wildcard match: ``sub.example.com`` matches ``*.example.com``
    - Generic wildcard: ``anything.tiktokv.us`` matches ``*tiktokv.us``
    """
    target = target_host.lower()
    pat = pattern.lower()

    if pat.startswith("*."):
        base = pat[2:]  # Remove "*."
        return target.endswith("." + base) or target == base
    elif pat.startswith("*"):
        base = pat[1:]  # Remove "*" (e.g. "*tiktokv.us" -> "tiktokv.us")
        return target.endswith(base)
    return target == pat


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------


def _collect_origin_ids(raw: dict, context: str) -> list[str]:
    """Collect rule_origin_ids from audit section for a given context."""
    origins = raw.get("audit", {}).get("rule_origins", [])
    result: list[str] = []
    for o in origins:
        if isinstance(o, dict) and context in str(o.get("subject", "")):
            result.append(o.get("rule_origin_id", ""))
    return [r for r in result if r]


def _find_origins_for_subject(raw: dict, subject: str) -> list[str]:
    """Find rule_origin_ids whose subject matches."""
    origins = raw.get("audit", {}).get("rule_origins", [])
    result: list[str] = []
    for o in origins:
        if isinstance(o, dict) and o.get("subject", "") == subject:
            oid = o.get("rule_origin_id", "")
            if oid:
                result.append(oid)
    return result


def _collect_source_refs_for_subject(raw: dict, subject: str) -> list[str]:
    """Collect source_refs for a matching subject."""
    origins = raw.get("audit", {}).get("rule_origins", [])
    result: list[str] = []
    for o in origins:
        if isinstance(o, dict) and o.get("subject", "") == subject:
            if o.get("source_ref"):
                result.append(o["source_ref"])
    return result
