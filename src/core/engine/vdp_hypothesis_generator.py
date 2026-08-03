"""
VDP Hypothesis Generator — SGK-2026-0420.

Deterministic, capability-driven hypothesis generation. NO runtime LLM, NO
network, NO product-specific strings (no known URLs, no product names, no
known-vulnerability labels, no flags hard-coded in this module).

Design rules (SGK-2026-0420 plan):
- Capability classification is semantic (object r/w/d, auth/session/token,
  role/permission/ownership, state transition, file upload, external URL
  fetch, render/store/search/template, async job/webhook, time/order/
  concurrency/idempotency) — never keyed to a specific product.
- All IDs (hypothesis_id, dedup_key, verdict_id, next_action_id) come from
  SHA-256 over canonical JSON (see ``deterministic_id`` in vdp_contract).
  No UUID / current time / random enters deterministic outputs.
- ``dedup_key`` merges truly identical hypotheses (capability, asset,
  actors, trust boundary, resource owner, variant).
- ``diversity_bucket`` is an internal key limiting how many similar
  hypotheses survive per bucket (diversity budget).
- LLM-style proposals are validated by ``validate_proposal_dict()`` — a pure
  deterministic validator. Malformed/unknown-action proposals are rejected.
- Label leakage: generic challenge markers (flag/ctf) and a config-supplied
  denylist (settings.vdp.label_leakage_denylist) cause rejection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from src.core.engine.vdp_observation_adapter import Observation, ObservationSourceKind
from src.core.engine.recipe_contracts import (
    VDP_ACTION_CLASSES,
    VDP_REASON_CODES,
    VDP_RISK_CLASSES,
    VDP_SCOPE_VERDICTS,
    VDP_STOP_CONDITIONS,
    validate_vdp_action_class,
)
from src.core.models.vdp_contract import (
    EvidenceVerdictV1,
    ExecutionBudgetV1,
    HypothesisRecord,
    NextActionRecord,
    ScopeRevalidationResult,
    deterministic_id,
    validate_hypothesis_record_v0420,
)

GENERATOR_VERSION = "sgk-2026-0420-v1"

# ---------------------------------------------------------------------------
# Capability classification (semantic, deterministic)
# ---------------------------------------------------------------------------

CAPABILITY_OBJECT_RW = "object_read_write_delete"
CAPABILITY_AUTH = "authentication_session_token"
CAPABILITY_ROLE = "role_permission_ownership"
CAPABILITY_STATE = "state_transition_approval_invite_refund"
CAPABILITY_UPLOAD = "file_upload_transform_publish"
CAPABILITY_EXTERNAL_URL = "external_url_fetch_callback_redirect"
CAPABILITY_RENDER = "render_store_search_template"
CAPABILITY_ASYNC = "asynchronous_job_webhook"
CAPABILITY_TIME = "time_order_concurrency_idempotency"

_CAPABILITY_ORDER: Dict[str, int] = {
    CAPABILITY_OBJECT_RW: 1,
    CAPABILITY_AUTH: 2,
    CAPABILITY_ROLE: 3,
    CAPABILITY_STATE: 4,
    CAPABILITY_UPLOAD: 5,
    CAPABILITY_EXTERNAL_URL: 6,
    CAPABILITY_RENDER: 7,
    CAPABILITY_ASYNC: 8,
    CAPABILITY_TIME: 9,
}

# Generic capability keywords — NOT product names. Matched against URL path,
# primary label, entity type, and candidate labels (lower-cased).
_CAPABILITY_KEYWORDS: List[Tuple[str, str]] = [
    (CAPABILITY_UPLOAD, "upload"),
    (CAPABILITY_AUTH, "login"),
    (CAPABILITY_AUTH, "signin"),
    (CAPABILITY_AUTH, "signup"),
    (CAPABILITY_AUTH, "logout"),
    (CAPABILITY_AUTH, "session"),
    (CAPABILITY_AUTH, "token"),
    (CAPABILITY_AUTH, "jwt"),
    (CAPABILITY_AUTH, "oauth"),
    (CAPABILITY_AUTH, "auth"),
    (CAPABILITY_AUTH, "password"),
    (CAPABILITY_ROLE, "role"),
    (CAPABILITY_ROLE, "permission"),
    (CAPABILITY_ROLE, "owner"),
    (CAPABILITY_ROLE, "admin"),
    (CAPABILITY_ROLE, "account"),
    (CAPABILITY_ROLE, "profile"),
    (CAPABILITY_STATE, "approve"),
    (CAPABILITY_STATE, "approval"),
    (CAPABILITY_STATE, "refund"),
    (CAPABILITY_STATE, "invite"),
    (CAPABILITY_STATE, "transition"),
    (CAPABILITY_STATE, "state"),
    (CAPABILITY_STATE, "status"),
    (CAPABILITY_STATE, "review"),
    (CAPABILITY_EXTERNAL_URL, "redirect"),
    (CAPABILITY_EXTERNAL_URL, "callback"),
    (CAPABILITY_EXTERNAL_URL, "fetch"),
    (CAPABILITY_EXTERNAL_URL, "proxy"),
    (CAPABILITY_EXTERNAL_URL, "link"),
    (CAPABILITY_RENDER, "search"),
    (CAPABILITY_RENDER, "render"),
    (CAPABILITY_RENDER, "template"),
    (CAPABILITY_RENDER, "view"),
    (CAPABILITY_RENDER, "download"),
    (CAPABILITY_RENDER, "store"),
    (CAPABILITY_ASYNC, "webhook"),
    (CAPABILITY_ASYNC, "job"),
    (CAPABILITY_ASYNC, "task"),
    (CAPABILITY_ASYNC, "async"),
    (CAPABILITY_ASYNC, "queue"),
    (CAPABILITY_ASYNC, "cron"),
    (CAPABILITY_TIME, "race"),
    (CAPABILITY_TIME, "concurrency"),
    (CAPABILITY_TIME, "idempot"),
    (CAPABILITY_TIME, "nonce"),
    (CAPABILITY_TIME, "timestamp"),
    (CAPABILITY_TIME, "version"),
    (CAPABILITY_TIME, "order"),
]

_MUTATION_BY_CAPABILITY: Dict[str, str] = {
    CAPABILITY_OBJECT_RW: "object_id_tamper",
    CAPABILITY_AUTH: "session_token_reuse",
    CAPABILITY_ROLE: "role_owner_field_tamper",
    CAPABILITY_STATE: "state_flip",
    CAPABILITY_UPLOAD: "malicious_upload_type",
    CAPABILITY_EXTERNAL_URL: "redirect_target_callback",
    CAPABILITY_RENDER: "template_search_injection",
    CAPABILITY_ASYNC: "webhook_job_payload",
    CAPABILITY_TIME: "replay_order_race",
}

_REQUIRED_EVIDENCE_BY_CAPABILITY: Dict[str, List[str]] = {
    CAPABILITY_OBJECT_RW: ["authz_impact_not_proven", "semantic_diff_owner_permission_sensitive_field"],
    CAPABILITY_AUTH: ["untested_no_second_account", "payload_request_mismatch"],
    CAPABILITY_ROLE: ["authz_impact_not_proven", "semantic_diff_owner_permission_sensitive_field"],
    CAPABILITY_STATE: ["state_change_not_verified", "state_change_readback"],
    CAPABILITY_UPLOAD: ["state_change_not_verified", "semantic_diff_owner_permission_sensitive_field"],
    CAPABILITY_EXTERNAL_URL: ["ssrf_proof_missing", "unique_oob_callback"],
    CAPABILITY_RENDER: ["payload_request_mismatch", "semantic_diff_owner_permission_sensitive_field"],
    CAPABILITY_ASYNC: ["state_change_not_verified", "payload_request_mismatch"],
    CAPABILITY_TIME: ["insufficient_timing_validation", "state_change_readback"],
}

_RISK_BY_CAPABILITY: Dict[str, str] = {
    CAPABILITY_OBJECT_RW: "read_only",
    CAPABILITY_AUTH: "read_only",
    CAPABILITY_ROLE: "read_only",
    CAPABILITY_STATE: "state_changing",
    CAPABILITY_UPLOAD: "state_changing",
    CAPABILITY_EXTERNAL_URL: "out_of_band",
    CAPABILITY_RENDER: "read_only",
    CAPABILITY_ASYNC: "state_changing",
    CAPABILITY_TIME: "read_only",
}

# Deterministic per-class budget estimate, aligned with ExecutionBudgetV1 keys.
_BUDGET_ESTIMATE_BY_CAPABILITY: Dict[str, Dict[str, int]] = {
    CAPABILITY_OBJECT_RW: {"max_requests": 10, "max_follow_ups": 2, "max_retries": 1},
    CAPABILITY_AUTH: {"max_requests": 8, "max_follow_ups": 2, "max_retries": 1},
    CAPABILITY_ROLE: {"max_requests": 12, "max_follow_ups": 3, "max_retries": 1},
    CAPABILITY_STATE: {"max_requests": 6, "max_follow_ups": 2, "max_retries": 0},
    CAPABILITY_UPLOAD: {"max_requests": 6, "max_follow_ups": 2, "max_retries": 0},
    CAPABILITY_EXTERNAL_URL: {"max_requests": 8, "max_follow_ups": 2, "max_retries": 1},
    CAPABILITY_RENDER: {"max_requests": 10, "max_follow_ups": 2, "max_retries": 1},
    CAPABILITY_ASYNC: {"max_requests": 6, "max_follow_ups": 2, "max_retries": 0},
    CAPABILITY_TIME: {"max_requests": 15, "max_follow_ups": 3, "max_retries": 2},
}

# Information gain rank (higher = more valuable). Deterministic.
_INFORMATION_GAIN_BY_CAPABILITY: Dict[str, int] = {
    CAPABILITY_AUTH: 5,
    CAPABILITY_ROLE: 5,
    CAPABILITY_STATE: 4,
    CAPABILITY_UPLOAD: 4,
    CAPABILITY_EXTERNAL_URL: 4,
    CAPABILITY_TIME: 3,
    CAPABILITY_ASYNC: 3,
    CAPABILITY_OBJECT_RW: 2,
    CAPABILITY_RENDER: 2,
}


def classify_capability(observation: Observation) -> str:
    """Deterministically classify a typed Observation into a capability.

    Keyword matching is semantic/generic only. No product names or known
    vulnerability labels are used.
    """
    haystack = " ".join(
        [
            observation.url.lower(),
            observation.primary_label.lower(),
            observation.entity_type.lower(),
            " ".join(observation.candidate_labels).lower(),
        ]
    )
    for capability, keyword in _CAPABILITY_KEYWORDS:
        if keyword in haystack:
            return capability

    # Default: object read/write/delete by HTTP method.
    method = observation.method.upper()
    if method in ("POST", "PUT", "PATCH"):
        return CAPABILITY_OBJECT_RW  # write
    if method == "DELETE":
        return CAPABILITY_OBJECT_RW  # delete
    return CAPABILITY_OBJECT_RW  # read


# ---------------------------------------------------------------------------
# Label leakage detection (generic; denylist comes from config)
# ---------------------------------------------------------------------------

# Generic challenge markers — not product-specific.
_FLAG_MARKER_RE = re.compile(r"(?:flag|ctf)\s*[=:{]", re.IGNORECASE)
_ANSWER_MARKER_RE = re.compile(r"(known[_ -]?answer|expected[_ -]?result|answer[_ -]?key)", re.IGNORECASE)
_CVE_MARKER_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def detect_label_leakage(text: str) -> List[str]:
    """Return leakage reasons found in a text string (generic markers only).

    Product names are checked separately via the config-supplied denylist
    (``leakage_denylist`` param of ``generate_hypotheses``), so no product
    names are embedded in this module.
    """
    reasons: List[str] = []
    if _FLAG_MARKER_RE.search(text):
        reasons.append("flag_marker_detected")
    if _ANSWER_MARKER_RE.search(text):
        reasons.append("known_answer_marker_detected")
    if _CVE_MARKER_RE.search(text):
        reasons.append("cve_marker_detected")
    return reasons


# ---------------------------------------------------------------------------
# Deterministic inference helpers
# ---------------------------------------------------------------------------


def infer_actors(observation: Observation) -> List[str]:
    """Infer actors from safe auth/actor booleans (deterministic).

    - has_auth_header / has_cookie → ``authA``
    - has_second_actor_evidence → ``authB``
    - has_admin_evidence → ``admin``
    - nothing → ``unauth``
    """
    actors: List[str] = []
    if observation.has_auth_header or observation.has_cookie:
        actors.append("authA")
    if observation.has_second_actor_evidence:
        actors.append("authB")
    if observation.has_admin_evidence:
        actors.append("admin")
    if not actors:
        actors.append("unauth")
    return actors


def infer_resource_owner(observation: Observation) -> str:
    """Infer a resource owner entity from the URL PATH only (deterministic).

    Uses ``urlparse(url).path`` so scheme/hostname are never treated as the
    owner. Returns "unknown" when no entity can be inferred — the builder
    then records a missing-owner precondition (authz hypotheses are not
    admitted).
    """
    path = urlparse(observation.url).path.rstrip("/")
    segments = [s for s in path.split("/") if s]
    if not segments:
        return "unknown"
    # Segment preceding an ID-like segment is the resource entity.
    for i in range(len(segments) - 1, 0, -1):
        if re.fullmatch(r"[0-9a-fA-F]{8,}|[0-9]+", segments[i]):
            return segments[i - 1]
    return segments[-1]


def infer_trust_boundary(observation: Observation) -> str:
    """Trust boundary from auth booleans (deterministic)."""
    if observation.has_auth_header or observation.has_cookie:
        return "authenticated"
    return "unauthenticated"


def build_controls(capability: str, observation: Observation) -> List[str]:
    """Deterministic baseline/attack/inverse control descriptions."""
    mutation = _MUTATION_BY_CAPABILITY.get(capability, "object_id_tamper")
    params = ", ".join(observation.param_names) or "<param>"
    return [
        f"baseline: unmodified request to {observation.url}",
        f"attack: {mutation} on {params}",
        f"inverse: revert {params} to baseline value",
    ]


def build_success_falsification(capability: str) -> Tuple[str, str]:
    """Deterministic success/falsification conditions for a capability."""
    success = {
        CAPABILITY_OBJECT_RW: "semantic diff in owner/permission/sensitive field with same requester",
        CAPABILITY_AUTH: "cross-actor behavior difference with an independent second account",
        CAPABILITY_ROLE: "owner/permission/sensitive-field difference across actors",
        CAPABILITY_STATE: "independent read-back confirms state change",
        CAPABILITY_UPLOAD: "uploaded artifact transforms/publishes with altered type semantics",
        CAPABILITY_EXTERNAL_URL: "unique attempt-scoped callback observed at OOB destination",
        CAPABILITY_RENDER: "injected input renders with altered template/search semantics",
        CAPABILITY_ASYNC: "asynchronous job/webhook executes with attacker-controlled payload semantics",
        CAPABILITY_TIME: "repeated baseline/attack/inverse controls show statistical difference",
    }.get(capability, "semantic behavior difference under attack control")
    falsification = "baseline and inverse controls show no semantic difference"
    return success, falsification


# ---------------------------------------------------------------------------
# Deterministic dedup / diversity keys
# ---------------------------------------------------------------------------


def compute_dedup_key(
    capability: str,
    asset: str,
    actors: List[str],
    trust_boundary: str,
    resource_owner: str,
    variant: str,
) -> str:
    """dedup_key: only truly identical hypotheses merge (owner+variant included)."""
    payload = {
        "capability": capability,
        "asset": asset,
        "actors": sorted(actors),
        "trust_boundary": trust_boundary,
        "resource_owner": resource_owner,
        "variant": variant,
    }
    return deterministic_id("dedup", payload, length=16)


def compute_diversity_bucket(capability: str, asset: str) -> str:
    """diversity_bucket: similar hypotheses are counted per bucket.

    Uses capability + host (not full URL) so different endpoints on the
    same target share a bucket and are subject to the diversity budget.
    """
    host = urlparse(asset).netloc.lower() if asset else ""
    payload = {"capability": capability, "host": host}
    return deterministic_id("diversity", payload, length=16)


# ---------------------------------------------------------------------------
# Proposal validation (deterministic; no LLM is invoked by this module)
# ---------------------------------------------------------------------------


@dataclass
class ProposalValidationResult:
    valid: bool
    errors: List[str] = field(default_factory=list)


_VALID_PROPOSAL_KEYS = {
    "capability",
    "action_class",
    "risk_class",
    "scope_verdict",
    "hypothesis_text",
    "trust_boundary",
    "resource_owner",
    "required_evidence",
}


def validate_proposal_dict(proposal: Any) -> ProposalValidationResult:
    """Deterministically validate an untrusted (LLM-style) proposal dict.

    The proposal is treated as untrusted input. Only proposals that map onto
    the typed action/risk/scope vocabulary are accepted. This function is
    tested with fake dicts; no LLM communication is performed by this module.
    """
    errors: List[str] = []
    if not isinstance(proposal, dict):
        return ProposalValidationResult(valid=False, errors=["proposal_not_a_dict"])

    unknown_keys = set(proposal.keys()) - _VALID_PROPOSAL_KEYS
    if unknown_keys:
        errors.append(f"unknown_keys={','.join(sorted(unknown_keys))}")

    capability = str(proposal.get("capability", "") or "").strip()
    if not capability:
        errors.append("capability_missing")
    elif capability not in _CAPABILITY_ORDER:
        errors.append(f"capability_unknown={capability}")

    action_class = str(proposal.get("action_class", "") or "").strip()
    if not action_class:
        errors.append("action_class_missing")
    elif not validate_vdp_action_class(action_class)["ok"]:
        errors.append(f"action_class_unknown={action_class}")

    risk_class = str(proposal.get("risk_class", "") or "").strip()
    if not risk_class:
        errors.append("risk_class_missing")
    elif risk_class not in VDP_RISK_CLASSES:
        errors.append(f"risk_class_unknown={risk_class}")

    trust_boundary = str(proposal.get("trust_boundary", "") or "").strip()
    if not trust_boundary:
        errors.append("trust_boundary_missing")

    resource_owner = str(proposal.get("resource_owner", "") or "").strip()
    if not resource_owner:
        errors.append("resource_owner_missing")

    scope_verdict = str(proposal.get("scope_verdict", "") or "").strip()
    if not scope_verdict:
        errors.append("scope_verdict_missing")
    elif scope_verdict not in VDP_SCOPE_VERDICTS:
        errors.append(f"scope_verdict_unknown={scope_verdict}")

    text = str(proposal.get("hypothesis_text", "") or "").strip()
    if not text:
        errors.append("hypothesis_text_missing")

    return ProposalValidationResult(valid=not errors, errors=errors)


# ---------------------------------------------------------------------------
# Generation result
# ---------------------------------------------------------------------------


@dataclass
class GenerationResult:
    """Result of hypothesis generation."""

    hypotheses: List[HypothesisRecord] = field(default_factory=list)
    rejected: List[Dict[str, Any]] = field(default_factory=list)
    suppressed: List[Dict[str, Any]] = field(default_factory=list)
    degraded: Optional[Dict[str, Any]] = None
    sources_unavailable: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def has_hypotheses(self) -> bool:
        return bool(self.hypotheses)


# ---------------------------------------------------------------------------
# Hypothesis builder
# ---------------------------------------------------------------------------


def build_hypothesis(
    observation: Observation,
    *,
    scope_verdict: str,
    scope_detail: str = "",
    generator_version: str = GENERATOR_VERSION,
    budget_estimate: Optional[Dict[str, Any]] = None,
) -> HypothesisRecord:
    """Deterministically build a fully-populated HypothesisRecord (v0420).

    All fields are derived from the typed Observation and the given scope
    verdict. No randomness, no timestamps, no secrets.
    """
    capability = classify_capability(observation)
    actors = infer_actors(observation)
    resource_owner = infer_resource_owner(observation)
    trust_boundary = infer_trust_boundary(observation)
    controls = build_controls(capability, observation)
    success_condition, falsification_condition = build_success_falsification(capability)

    preconditions: Dict[str, Any] = {}
    if capability == CAPABILITY_ROLE and resource_owner == "unknown":
        preconditions["resource_owner"] = "unknown"
    if capability == CAPABILITY_ROLE and "authA" not in actors:
        preconditions["actor"] = "authA_missing"
    if capability == CAPABILITY_ROLE:
        if not observation.has_second_actor_evidence:
            preconditions["actor_authB"] = "authB_missing"
        if not observation.has_admin_evidence:
            preconditions["actor_admin"] = "admin_missing"
    if scope_verdict != "allowed":
        preconditions["scope"] = scope_verdict

    variant = _MUTATION_BY_CAPABILITY.get(capability, "object_id_tamper")
    asset = observation.url
    dedup_key = compute_dedup_key(
        capability=capability,
        asset=asset,
        actors=actors,
        trust_boundary=trust_boundary,
        resource_owner=resource_owner,
        variant=variant,
    )
    diversity_bucket = compute_diversity_bucket(capability, asset)

    hypothesis_id = deterministic_id(
        "hyp",
        {
            "dedup_key": dedup_key,
            "observation_id": observation.observation_id,
            "diversity_bucket": diversity_bucket,
        },
    )

    required_evidence = _REQUIRED_EVIDENCE_BY_CAPABILITY.get(capability, ["payload_request_mismatch"])
    risk_class = _RISK_BY_CAPABILITY.get(capability, "read_only")
    if budget_estimate is None:
        budget_estimate = dict(_BUDGET_ESTIMATE_BY_CAPABILITY.get(capability, {}))

    priority_metrics = {
        "information_gain": _INFORMATION_GAIN_BY_CAPABILITY.get(capability, 1),
        "evidence_obtainability": 3 if scope_verdict == "allowed" else 1,
        "preconditions_satisfied": int(not preconditions),
        "required_requests": budget_estimate.get("max_requests", 10),
        "diversity_bucket": diversity_bucket,
    }
    priority_trace = [
        f"capability={capability}",
        f"information_gain={priority_metrics['information_gain']}",
        f"evidence_obtainability={priority_metrics['evidence_obtainability']}",
        f"preconditions_satisfied={priority_metrics['preconditions_satisfied']}",
        f"required_requests={priority_metrics['required_requests']}",
        f"diversity_bucket={diversity_bucket}",
    ]

    record = HypothesisRecord(
        hypothesis_id=hypothesis_id,
        observation_id=observation.observation_id,
        observation_ids=[observation.observation_id],
        asset=asset,
        capability=capability,
        hypothesis_text=(
            f"{capability} hypothesis on {asset} across trust boundary "
            f"{trust_boundary} (actors: {','.join(actors)})"
        ),
        trust_boundary=trust_boundary,
        actors=actors,
        preconditions=preconditions,
        controls=controls,
        success_condition=success_condition,
        falsification_condition=falsification_condition,
        required_evidence=required_evidence,
        priority_trace=priority_trace,
        resource_owner=resource_owner,
        dedup_key=dedup_key,
        generator_version=generator_version,
        risk_class=risk_class,
        scope_verdict=scope_verdict,
        budget_estimate=budget_estimate,
    )
    return record


# ---------------------------------------------------------------------------
# Main generation entry point
# ---------------------------------------------------------------------------


def build_unavailable_source_inventory() -> List[Dict[str, Any]]:
    """Deterministic inventory of not-yet-wired observation sources.

    SGK-2026-0420 wires ``recon_signal_bundle`` only; every other declared
    observation source (crawler, form, JavaScript, API schema, GraphQL,
    browser traffic, proxy history) is recorded as unavailable with a reason
    and the tracking task that will connect it (SGK-2026-0421).
    """
    not_wired = [
        ObservationSourceKind.CRAWLER, ObservationSourceKind.FORM,
        ObservationSourceKind.JAVASCRIPT, ObservationSourceKind.API_SCHEMA,
        ObservationSourceKind.GRAPHQL, ObservationSourceKind.BROWSER_TRAFFIC,
        ObservationSourceKind.PROXY_HISTORY,
    ]
    return [
        {"source": k.value, "status": "unavailable", "reason": "not_wired_in_0420", "tracking_task": "SGK-2026-0421"}
        for k in sorted(not_wired, key=lambda k: k.value)
    ]


def generate_hypotheses(
    observations: List[Observation],
    *,
    scope_verdict_provider: Callable[[str], ScopeRevalidationResult],
    budget_model: ExecutionBudgetV1,
    leakage_denylist: Optional[List[str]] = None,
    diversity_bucket_limit: int = 3,
    generator_version: str = GENERATOR_VERSION,
) -> GenerationResult:
    """Generate hypotheses from typed Observations (deterministic).

    Args:
        observations: Typed Observations from the ObservationAdapter.
        scope_verdict_provider: REQUIRED callable(url)->ScopeRevalidationResult.
            When missing/unavailable, scope is ``scope_revalidation_blocked``
            (fail-closed).
        budget_model: REQUIRED. Per-capability estimates are clamped to the
            canonical budget limits.  Source/version are recorded in each
            estimate.
        leakage_denylist: Config-supplied product/known-answer terms.
        diversity_bucket_limit: Max hypotheses per diversity bucket.
        generator_version: Version string stored on each record.

    Returns:
        GenerationResult with hypotheses, rejections, suppressions, degraded
        reason (total failure), and per-source availability inventory.
    """
    result = GenerationResult()
    denylist = [str(d).strip().lower() for d in (leakage_denylist or []) if str(d).strip()]

    # --- source inventory ---
    result.sources_unavailable = build_unavailable_source_inventory()

    if not observations:
        result.degraded = {
            "status": "degraded",
            "reason": "no_observations",
            "generator_version": generator_version,
        }
        return result

    # Phase A: build all valid candidate hypotheses
    candidates: List[Tuple[HypothesisRecord, Observation]] = []

    for observation in observations:
        obs_text = " ".join([
            observation.url, observation.primary_label,
            observation.entity_type, " ".join(observation.candidate_labels),
            " ".join(observation.param_names),
        ]).lower()

        leakage = detect_label_leakage(obs_text)
        if denylist:
            for term in denylist:
                if term and term in obs_text:
                    leakage.append("label_leakage_detected")
                    break
        if leakage:
            result.rejected.append({
                "observation_id": observation.observation_id,
                "reasons": leakage, "phase": "leakage",
            })
            continue

        # scope verdict — fail-closed on provider error / unknown verdict
        scope_verdict: str = ScopeRevalidationResult.indeterminate(
            "scope_verdict_provider_not_configured"
        ).verdict
        scope_detail: str = ""
        try:
            if scope_verdict_provider is not None:
                scope_result = scope_verdict_provider(observation.url)
                scope_verdict = scope_result.verdict
                scope_detail = scope_result.reason
        except Exception:
            scope_verdict = ScopeRevalidationResult.indeterminate(
                "scope_verdict_provider_raised"
            ).verdict
        if scope_verdict not in VDP_SCOPE_VERDICTS:
            scope_verdict = ScopeRevalidationResult.indeterminate(
                f"unknown_scope_verdict={scope_verdict}"
            ).verdict

        cap_budget = _BUDGET_ESTIMATE_BY_CAPABILITY.get(
            classify_capability(observation),
            {"max_requests": 10, "max_follow_ups": 2, "max_retries": 1},
        )
        budget_estimate = {
            "source": "ExecutionBudgetV1",
            "schema_version": budget_model.schema_version,
            "max_requests": min(cap_budget["max_requests"], budget_model.max_requests),
            "max_follow_ups": min(cap_budget["max_follow_ups"], budget_model.max_follow_ups),
            "max_retries": min(cap_budget["max_retries"], budget_model.max_retries),
            "source_version": f"ExecutionBudgetV1:v{budget_model.schema_version}",
        }

        try:
            hypothesis = build_hypothesis(
                observation,
                scope_verdict=scope_verdict,
                scope_detail=scope_detail,
                generator_version=generator_version,
                budget_estimate=budget_estimate,
            )
        except (ValueError, TypeError) as exc:
            result.rejected.append({
                "observation_id": observation.observation_id,
                "reasons": ["builder_error"], "detail": str(exc), "phase": "build",
            })
            continue

        validation_errors = validate_hypothesis_record_v0420(hypothesis)
        if validation_errors:
            result.rejected.append({
                "observation_id": observation.observation_id,
                "reasons": validation_errors, "phase": "schema",
            })
            continue

        candidates.append((hypothesis, observation))

    # Phase B: sort by canonical key (deterministic regardless of input order)
    candidates.sort(key=lambda h_obs: (h_obs[0].dedup_key, h_obs[0].hypothesis_id))

    # Phase C: dedup + diversity on sorted list
    bucket_counts: Dict[str, int] = {}
    seen_dedup_keys: set[str] = set()

    for hypothesis, observation in candidates:
        if hypothesis.dedup_key in seen_dedup_keys:
            result.suppressed.append({
                "hypothesis_id": hypothesis.hypothesis_id,
                "dedup_key": hypothesis.dedup_key,
                "reason": "duplicate_dedup_key", "phase": "dedup",
            })
            continue

        bucket = compute_diversity_bucket(hypothesis.capability, hypothesis.asset)
        bucket_count = bucket_counts.get(bucket, 0)
        if bucket_count >= diversity_bucket_limit:
            result.suppressed.append({
                "hypothesis_id": hypothesis.hypothesis_id,
                "dedup_key": hypothesis.dedup_key,
                "diversity_bucket": bucket,
                "reason": "diversity_budget_exceeded", "phase": "diversity",
            })
            continue

        seen_dedup_keys.add(hypothesis.dedup_key)
        bucket_counts[bucket] = bucket_count + 1
        result.hypotheses.append(hypothesis)

    # Phase D: final priority sort + rank
    def _sort_key(h: HypothesisRecord) -> Tuple[int, int, int, str]:
        preconditions_ok = 0 if h.preconditions else 1
        gain = _INFORMATION_GAIN_BY_CAPABILITY.get(h.capability, 1)
        requests = h.budget_estimate.get("max_requests", 10) if h.budget_estimate else 10
        return (-preconditions_ok, -gain, requests, h.hypothesis_id)

    result.hypotheses.sort(key=_sort_key)
    for rank, hypothesis in enumerate(result.hypotheses, start=1):
        hypothesis.priority_trace.append(f"rank={rank}")

    if not result.hypotheses and not result.degraded:
        result.degraded = {
            "status": "degraded",
            "reason": "all_observations_rejected_or_suppressed",
            "generator_version": generator_version,
        }
    return result


# ---------------------------------------------------------------------------
# M2 shadow: candidate verdicts + NextAction proposals (no queue injection)
# ---------------------------------------------------------------------------


@dataclass
class ShadowProposal:
    """Candidate verdict + NextAction for M2 shadow mode (queue NOT touched)."""

    verdict: EvidenceVerdictV1
    next_action: NextActionRecord


def build_shadow_proposals(
    hypotheses: List[HypothesisRecord],
    *,
    generator_version: str = GENERATOR_VERSION,
) -> List[ShadowProposal]:
    """Build candidate EvidenceVerdictV1 + NextActionRecord per hypothesis.

    - Verdicts are ``candidate`` (DETECTOR authority) — never ``confirmed``.
    - Hypothesis state advances to ``candidate`` via the canonical transition.
    - All IDs are deterministic.
    - The task queue is NOT touched here (caller decides persistence only).
    """
    proposals: List[ShadowProposal] = []
    for hypothesis in hypotheses:
        verdict_id = deterministic_id(
            "vrd",
            {
                "hypothesis_id": hypothesis.hypothesis_id,
                "status": "candidate",
                "generator_version": generator_version,
            },
        )
        reason_code = "generated_candidate"
        if reason_code not in VDP_REASON_CODES:
            raise ValueError(
                f"reason code {reason_code!r} not in public VDP_REASON_CODES vocabulary"
            )
        verdict = EvidenceVerdictV1(
            verdict_id=verdict_id,
            hypothesis_id=hypothesis.hypothesis_id,
            _status="candidate",
            reason_codes=[reason_code],
            validator_version=generator_version,
        )
        hypothesis.transition_to("candidate")

        first_gap = (
            hypothesis.required_evidence[0]
            if hypothesis.required_evidence
            else "evidence_gap_unspecified"
        )
        action_class = (
            "manual_review"
            if hypothesis.preconditions
            else ("follow_up_probe" if first_gap else "manual_review")
        )
        if action_class not in VDP_ACTION_CLASSES:
            raise ValueError(
                f"action_class {action_class!r} not in public VDP_ACTION_CLASSES vocabulary"
            )
        next_action_id = deterministic_id(
            "nxt",
            {
                "verdict_id": verdict_id,
                "action_class": action_class,
                "evidence_gap": first_gap,
            },
        )
        stop_condition = (
            "scope_revalidation_blocked" if hypothesis.scope_verdict != "allowed"
            else "evidence_gap_resolved_or_budget_exhausted"
        )
        if stop_condition not in VDP_STOP_CONDITIONS:
            raise ValueError(
                f"stop_condition {stop_condition!r} not in public VDP_STOP_CONDITIONS vocabulary"
            )
        next_action = NextActionRecord(
            next_action_id=next_action_id,
            verdict_id=verdict_id,
            evidence_gap=first_gap,
            required_preconditions=dict(hypothesis.preconditions),
            action_class=action_class,
            risk_class=hypothesis.risk_class,
            expected_information_gain=f"resolve evidence gap: {first_gap}",
            stop_condition=stop_condition,
        )
        proposals.append(ShadowProposal(verdict=verdict, next_action=next_action))
    return proposals
