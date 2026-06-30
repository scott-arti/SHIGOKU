"""Takeover report normalizer — separate takeover_verdict from global finding state.

Per plan sections 3.4.4, 4.7, 4.12: The ``takeover_verdict`` must be separated
from the global finding ``confirmed`` state. The report layer must clearly
distinguish automation results from HITL-required results.

Usage::

    from src.reporting.takeover_report_normalizer import normalize_takeover_for_report

    block = normalize_takeover_for_report(runner_result, provider_entry=pe)

``runner_result`` is the dict returned by
``OptimizedRecipeRunner._finalize_results()``.

``provider_entry`` is an optional ``ProviderEntry`` from the provider matrix.
When supplied, it populates ``manual_checklist`` and ``verification_urls``.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.core.adapters.external.takeover_provider_matrix_adapter import ProviderEntry

# ── Verdict reason code → human-readable description ──────────────────────

_VERDICT_REASON_DESCRIPTIONS: Dict[str, str] = {
    "missing_cname": "No CNAME chain detected for candidate",
    "stale_candidate": "Candidate data is older than 30 days",
    "tool_disagreement": "Multiple takeover tools returned conflicting results",
    "provider_no_auto_confirm": "Provider does not support automated confirmation",
    "scope_policy_blocks_claim": "Scope policy blocks automated claim action",
    "insufficient_evidence": "Not enough evidence types collected (minimum 2 required)",
    "infrastructure_unhealthy": "Infrastructure issue prevented complete verification",
}

_AUTOMATION_BOUNDARY = (
    "provider resource creation never automated; HITL required for claim"
)

_PRODUCER_STEP = "recon.step3_live_check"


# ── Public API ────────────────────────────────────────────────────────────

def normalize_takeover_for_report(
    runner_result: dict,
    provider_entry: Optional[ProviderEntry] = None,
) -> dict:
    """Normalize a takeover runner result into a structured report block.

    Parameters
    ----------
    runner_result : dict
        Output from ``OptimizedRecipeRunner._finalize_results()``.
    provider_entry : ProviderEntry, optional
        Provider matrix entry; used to populate ``manual_checklist`` and
        ``verification_urls``.

    Returns
    -------
    dict
        Structured report block with these keys:
        - takeover_status
        - global_confirmed (always ``False``)
        - automation_boundary
        - provider_name
        - evidence_summary
        - verdict_reason_codes
        - verdict_reason_descriptions
        - manual_review_required
        - manual_checklist
        - verification_urls
        - infrastructure_state
        - trace

        The entire dict is JSON-serializable.
    """
    summary: dict = runner_result.get("summary", {})
    raw_verdict: str = str(runner_result.get("takeover_verdict") or "no_finding")
    infrastructure_state: str = str(
        runner_result.get("infrastructure_state") or "ok"
    )

    # ── Determine takeover_status ────────────────────────────────────
    takeover_status = _resolve_takeover_status(raw_verdict, summary)

    # ── Verdict reason codes and descriptions ────────────────────────
    reason_codes: list[str] = list(runner_result.get("verdict_reason_codes") or [])
    reason_descriptions: list[str] = _map_reason_codes_to_descriptions(reason_codes)

    # ── Evidence extraction ──────────────────────────────────────────
    evidence = _extract_evidence(runner_result)

    # ── Provider-derived fields ──────────────────────────────────────
    provider_name: Optional[str] = (
        provider_entry.provider_id if provider_entry is not None else None
    )
    manual_checklist: list[str]
    verification_urls: list[str]
    if provider_entry is not None:
        manual_checklist = list(provider_entry.hitl_checkpoint_types)
        verification_urls = list(provider_entry.verification_urls)
    else:
        manual_checklist = []
        verification_urls = []

    is_manual_review = (
        takeover_status in ("manual_review_required", "high_priority_manual_check")
        or bool(runner_result.get("manual_review_required", False))
    )

    is_high_priority = (takeover_status == "high_priority_manual_check")

    # ── Trace block ──────────────────────────────────────────────────
    trace = {
        "producer_step": runner_result.get("producer_step", _PRODUCER_STEP),
        "source_line": runner_result.get("source_line"),
        "recipe_name": str(runner_result.get("recipe_name", "")),
    }
    # Include session_id and artifact_hash if present on the runner result
    # (these may be injected by the caller or the runner in future versions)
    for extra_key in ("session_id", "artifact_hash"):
        if extra_key in runner_result:
            trace[extra_key] = runner_result[extra_key]

    # ── Assemble report block ────────────────────────────────────────
    report_block: dict = {
        "takeover_status": takeover_status,
        "global_confirmed": False,
        "high_priority": is_high_priority,
        "automation_boundary": _AUTOMATION_BOUNDARY,
        "provider_name": provider_name,
        "evidence_summary": evidence,
        "verdict_reason_codes": reason_codes,
        "verdict_reason_descriptions": reason_descriptions,
        "manual_review_required": is_manual_review,
        "manual_checklist": manual_checklist,
        "verification_urls": verification_urls,
        "infrastructure_state": infrastructure_state,
        "trace": trace,
    }

    return report_block


# ── Internal helpers ──────────────────────────────────────────────────────

def _resolve_takeover_status(raw_verdict: str, summary: dict) -> str:
    """Determine the final takeover_status from the raw verdict and summary.

    Priority:
      1. ``summary.all_blocked``  → ``"blocked"``
      2. ``summary.major_failure`` → ``"failed"``
      3. Otherwise use *raw_verdict* (which should be one of:
         ``confirmed``, ``high_priority_manual_check``,
         ``manual_review_required``, ``no_finding``).
    """
    if summary.get("all_blocked"):
        return "blocked"
    if summary.get("major_failure"):
        return "failed"
    return raw_verdict


def _map_reason_codes_to_descriptions(reason_codes: list[str]) -> list[str]:
    """Map a list of verdict reason codes to human-readable descriptions.

    Known codes are drawn from ``_VERDICT_REASON_DESCRIPTIONS``.
    Unknown codes are included with a generic fallback label.
    """
    descriptions: list[str] = []
    for code in reason_codes:
        desc = _VERDICT_REASON_DESCRIPTIONS.get(code)
        if desc is not None:
            descriptions.append(desc)
        else:
            # Unknown / future code — include verbatim with a prefix
            descriptions.append(f"Unknown reason: {code}")
    return descriptions


def _extract_evidence(runner_result: dict) -> dict:
    """Scan runner result steps for takeover-related evidence.

    Returns a dict with:
      - evidence_count
      - tool_results (successful steps)
      - cname_chain
      - http_status
      - error_token
    """
    steps: dict = runner_result.get("steps", {})
    summary: dict = runner_result.get("summary", {})

    evidence_count = int(summary.get("success_count", 0))
    tool_results: list[dict] = []
    cname_chain: list[str] = []
    http_status: Optional[int] = None
    error_token: Optional[str] = None

    for _step_id, step in sorted(steps.items()):
        if step.get("status") != "success":
            continue
        data: dict = step.get("data") or {}
        tool_results.append(dict(step))

        # Extract cname_chain from step data
        if "cname_chain" in data and isinstance(data["cname_chain"], list):
            cname_chain = data["cname_chain"]

        # Extract http_status from step data
        if "http_status" in data and http_status is None:
            hs = data["http_status"]
            if isinstance(hs, int):
                http_status = hs

        # Extract error_token from step data
        if "error_token" in data and error_token is None:
            et = data["error_token"]
            if isinstance(et, str) and et.strip():
                error_token = et

    return {
        "evidence_count": evidence_count,
        "tool_results": tool_results,
        "cname_chain": cname_chain,
        "http_status": http_status,
        "error_token": error_token,
    }
