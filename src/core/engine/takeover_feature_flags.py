"""Shadow mode comparison, feature flag, and kill switch for Takeover v2.

Plan sections 3.4.5, 4.3: Staged rollout capability with:
  - Shadow mode: run old and new paths in parallel and compare results.
  - Feature flag: enable/disable takeover v2 via TAKEOVER_V2_ENABLED.
  - Kill switch: emergency rollback to legacy behavior regardless of feature flag.

Classes
-------
TakeoverFeatureFlags — Reads feature flags from environment variables.

Functions
---------
should_use_v2()          — Return True if takeover v2 pipeline should be used.
shadow_compare_results() — Compare v2 and legacy result dicts, log differences.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ── Environment variable names ──────────────────────────────────────────────
_ENV_ENABLED = "TAKEOVER_V2_ENABLED"
_ENV_SHADOW = "TAKEOVER_V2_SHADOW"
_ENV_KILLSWITCH = "TAKEOVER_V2_KILLSWITCH"

# ── Truthy / falsy value sets ───────────────────────────────────────────────
_TRUTHY_VALUES = frozenset({"true", "1", "yes"})
_FALSY_VALUES = frozenset({"false", "0", "no"})


def _is_truthy(value: str) -> bool:
    """Return True if *value* is a recognised truthy string ('true', '1', 'yes').

    Unrecognised strings are treated as falsy (safe default).
    """
    return value.strip().lower() in _TRUTHY_VALUES


# ════════════════════════════════════════════════════════════════════════════
# TakeoverFeatureFlags
# ════════════════════════════════════════════════════════════════════════════


class TakeoverFeatureFlags:
    """Environment-variable-based feature flags for the takeover v2 rollout.

    All properties re-read ``os.environ`` on each access so that callers
    always see the current value.  This makes the class suitable for use in
    long-running processes where flags may be toggled at runtime.
    """

    @property
    def enabled(self) -> bool:
        """Return True when the takeover v2 pipeline is enabled.

        Reads ``TAKEOVER_V2_ENABLED``.  Defaults to ``True``.
        Truthy values: ``"true"``, ``"1"``, ``"yes"``.
        Falsy / empty / unrecognised values are treated as disabled.
        """
        raw = os.environ.get(_ENV_ENABLED, "true")
        return _is_truthy(raw)

    @property
    def shadow_mode(self) -> bool:
        """Return True when shadow mode is active.

        Reads ``TAKEOVER_V2_SHADOW``.  Defaults to ``False``.
        When active, the v2 pipeline and legacy path run in parallel and
        results are compared.
        """
        raw = os.environ.get(_ENV_SHADOW, "false")
        return _is_truthy(raw)

    @property
    def kill_switch_active(self) -> bool:
        """Return True when the emergency kill switch is engaged.

        Reads ``TAKEOVER_V2_KILLSWITCH``.  Defaults to ``False``.
        When active, **all** takeover operations fall back to the legacy
        path immediately, regardless of the ``enabled`` flag.
        """
        raw = os.environ.get(_ENV_KILLSWITCH, "false")
        return _is_truthy(raw)


# ════════════════════════════════════════════════════════════════════════════
# Public helpers
# ════════════════════════════════════════════════════════════════════════════


def should_use_v2() -> bool:
    """Return True when the takeover v2 pipeline should be used.

    Decision order (short-circuit):
      1. If the kill switch is active → **always return False**.
      2. If the feature flag is disabled → return False.
      3. Otherwise → return True.
    """
    flags = TakeoverFeatureFlags()
    if flags.kill_switch_active:
        return False
    return flags.enabled


def shadow_compare_results(
    v2_result: dict[str, Any],
    legacy_result: dict[str, Any],
    candidate_id: str,
) -> dict[str, Any]:
    """Compare v2 and legacy takeover results, logging differences.

    Parameters
    ----------
    v2_result:
        The result dictionary produced by the new takeover v2 pipeline.
    legacy_result:
        The result dictionary produced by the legacy (pre-v2) path.
    candidate_id:
        Identifier of the takeover candidate being compared (used in log output).

    Returns
    -------
    dict
        A comparison summary with these keys:
        - ``"differences"`` — list of ``{key, v2_value, legacy_value}`` dicts
          for shared keys whose values differ.
        - ``"v2_only"`` — list of keys present only in *v2_result*.
        - ``"legacy_only"`` — list of keys present only in *legacy_result*.
        - ``"match"`` — ``True`` when no differences were found and both
          result sets are effectively equivalent.
    """
    v2_keys = set(v2_result or {})
    legacy_keys = set(legacy_result or {})

    # Collect keys, skipping internal metadata (underscore-prefixed).
    v2_visible = {k for k in v2_keys if not k.startswith("_")}
    legacy_visible = {k for k in legacy_keys if not k.startswith("_")}

    # Shared keys — compare values.
    shared = v2_visible & legacy_visible
    differences: list[dict[str, Any]] = []
    for key in sorted(shared):
        v2_val = v2_result[key]
        legacy_val = legacy_result[key]
        if v2_val != legacy_val:
            differences.append({
                "key": key,
                "v2_value": v2_val,
                "legacy_value": legacy_val,
            })

    # Keys that exist in only one result set.
    v2_only = sorted(v2_visible - legacy_visible)
    legacy_only = sorted(legacy_visible - v2_visible)

    has_divergence = bool(differences or v2_only or legacy_only)

    if has_divergence:
        logger.warning(
            "Shadow comparison divergence for candidate %s: "
            "%d differences, %d v2-only keys, %d legacy-only keys",
            candidate_id, len(differences), len(v2_only), len(legacy_only),
        )

    return {
        "differences": differences,
        "v2_only": v2_only,
        "legacy_only": legacy_only,
        "match": not has_divergence,
    }
