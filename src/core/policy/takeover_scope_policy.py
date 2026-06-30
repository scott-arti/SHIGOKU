"""TakeoverScopePolicy — scope-level blocking signals for takeover candidates.

Plan sections 3.3, 3.4.3, 4.5:
- ``scope_policy.takeover_allowed``: Boolean flag per scope/target.
  If False, all takeover candidates for that target are blocked.
- ``claim_action_allowed=False by default``: Provider-side resource creation
  is never automated.
- These are evaluated as blocking signals during recipe candidate selection.
- A candidate with ``scope_policy.takeover_allowed=False`` or
  ``claim_action_allowed=False`` must NEVER reach ``confirmed`` verdict.
- The scope policy is a standalone check callable from both the selector and the gate.
"""

from typing import Dict, Optional, Set


class TakeoverScopePolicy:
    """Per-target scope policy for takeover testing.

    Encodes two orthogonal concerns:

    1. ``takeover_allowed`` — does the engagement scope permit takeover
       testing for this target? Derived from the allowed_targets set.
    2. ``claim_action_allowed`` — can automation claim (create) provider-side
       resources? This is ALWAYS False by default (plan section 4.5).

    Usage:
        policy = TakeoverScopePolicy(allowed_targets={"example.com", "*.test.com"})
        if policy.is_takeover_allowed(target):
            ...  # proceed with takeover evaluation
    """

    def __init__(
        self,
        allowed_targets: Optional[Set[str]] = None,
        claim_allowed: bool = False,
    ):
        """Initialise the scope policy.

        Args:
            allowed_targets: Set of target domain names for which takeover
                testing is explicitly permitted. An empty set or None means
                *all targets are allowed* (permissive default).
            claim_allowed: Whether automated claim actions are permitted.
                Defaults to False (plan section 4.5: claim_action_allowed=false).
                This override exists for testing; production callers should
                leave it at False.
        """
        self._allowed = allowed_targets or None
        self._claim_allowed = bool(claim_allowed)

    def is_takeover_allowed(self, target: str) -> bool:
        """Check if takeover testing is allowed for *target*.

        When ``_allowed`` is None (no explicit allowlist), the policy is
        permissive and returns True for every target.

        When ``_allowed`` is a set, the target must be an exact member
        to be allowed (default-deny for takeover testing).

        Args:
            target: The target domain name (e.g. ``"example.com"``).

        Returns:
            True if takeover testing is permitted for this target.
        """
        if self._allowed is None:
            # Permissive — no explicit allowlist means all targets allowed
            return True
        return target in self._allowed

    def claim_action_allowed(self, target: str) -> bool:
        """Return whether automated claim actions are allowed for *target*.

        Per plan section 4.5, this is ALWAYS False by default. Provider-side
        resource creation is never automated.

        The *target* parameter is accepted for call-site compatibility with
        ``is_takeover_allowed`` but is ignored — claim actions are globally
        disabled regardless of target.

        Args:
            target: The target domain name (accepted for compatibility).

        Returns:
            False — automated claims are never permitted by default.
        """
        return self._claim_allowed


def evaluate_scope_signals(
    target: str,
    policy: TakeoverScopePolicy,
) -> Dict[str, bool]:
    """Evaluate scope-level blocking signals for a takeover candidate.

    This is the canonical entry point for the recipe selector and the
    success gate. It returns a flat dict of scope-derived signals that
    can be checked before evaluating recipe triggers or computing verdicts.

    Args:
        target: The target domain name (e.g. the subdomain from a
            ``TakeoverCandidate``).
        policy: An initialised ``TakeoverScopePolicy``.

    Returns:
        A dict with two keys:
        - ``scope_policy_blocks_takeover`` (bool): True when the target is
          NOT in the allowed set for takeover testing.
        - ``claim_action_allowed`` (bool): Always False by default (plan 4.5).
    """
    allowed = policy.is_takeover_allowed(target)
    return {
        "scope_policy_blocks_takeover": not allowed,
        "claim_action_allowed": policy.claim_action_allowed(target),
    }
