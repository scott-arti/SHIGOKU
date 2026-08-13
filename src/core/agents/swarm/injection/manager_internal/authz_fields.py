"""SGK-2026-0448 lever 2: mechanical impact/reproduction_steps for authz findings.

Pure helpers that fill Finding.impact / Finding.reproduction_steps from the
observed authorization differential ONLY (LLM-free, no fabrication). The
signal predicate mirrors payout_grade._match_firing_marker's authz branch —
deliberately NOT imported from payout_grade.py (the gate file stays
untouched). Fail-closed: when the signals do not satisfy the requirement the
helpers return (None, None) and callers leave the finding as-is.

Status roles are explicit (``authenticated_status`` / ``unauthenticated_status``)
so callers never mislabel which request was authenticated — the
``unauth_success`` token produced by build_authz_differential is a "test
request succeeded" token and its semantic role depends on the caller.
"""


def authz_signals_satisfied(signals) -> bool:
    """True when the authz_differential signals satisfy the payout-grade
    marker requirement: (auth_success AND unauth_success) or
    status_improved_with_auth."""
    if not isinstance(signals, list):
        return False
    return (
        ("auth_success" in signals and "unauth_success" in signals)
        or "status_improved_with_auth" in signals
    )


def build_authz_impact_and_reproduction_steps(
    *,
    scenario: str,
    url: str,
    method: str,
    authenticated_status: int,
    unauthenticated_status: int,
    signals,
) -> tuple:
    """Mechanical impact + reproduction_steps from the detected facts.

    Returns ``(impact, reproduction_steps)`` when
    ``authz_signals_satisfied(signals)``, else ``(None, None)``. The text
    states only what was observed: method/url and the two response statuses,
    labeled with their actual authorization roles. Two branches:

    - both requests succeeded (auth_success AND unauth_success): the claim
      is that unauthenticated access is allowed.
    - only status_improved_with_auth: the claim is that authentication is
      required (the unauthenticated request is denied).

    No product tokens, no extra claims.
    """
    if not authz_signals_satisfied(signals):
        return None, None
    both_ok = "auth_success" in signals and "unauth_success" in signals
    m = str(method or "GET").strip().upper() or "GET"
    if both_ok:
        impact = (
            f"Unauthenticated access to {url} is allowed: an authenticated {m} "
            f"request returns status {authenticated_status} while the same {m} "
            f"without authentication headers returns status {unauthenticated_status} "
            "(both requests succeeded) — an authorization differential for "
            "unauthenticated access is confirmed."
        )
        steps = [
            f"Send {m} {url} with the original authentication headers — observed status {authenticated_status}.",
            f"Send the same {m} {url} without authentication headers — observed status {unauthenticated_status}.",
            "Compare the responses: both requests succeeded under different authorization contexts, confirming unauthenticated access.",
        ]
    else:
        impact = (
            f"The endpoint {url} requires authentication: an authenticated {m} "
            f"request returns status {authenticated_status} while the same {m} "
            f"without authentication headers returns status {unauthenticated_status} "
            "— access is granted only with authentication."
        )
        steps = [
            f"Send {m} {url} with the original authentication headers — observed status {authenticated_status}.",
            f"Send the same {m} {url} without authentication headers — observed status {unauthenticated_status}.",
            "Compare the responses: the authenticated request is granted access while the unauthenticated request is denied.",
        ]
    return impact, steps
