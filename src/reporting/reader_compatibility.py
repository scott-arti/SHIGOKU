"""
Reader compatibility check (T-5.1): validate downstream readers can parse
Phase 6/8/9 artifacts alongside pre-Phase 6 artifacts.

Phase 9 (SGK-2026-0318) safety requirement: ensure no schema regression
blocks downstream consumers of session/report artifacts.
"""

from typing import Dict, Any, List


# Known valid fields / schema markers for each artifact family.
_OLD_SESSION_KEYS = frozenset({"completed_tasks", "targets", "session_id", "status", "metadata"})
_PHASE6_DECISION_TRACE_TYPES = frozenset({
    "task_retired", "task_superseded", "task_invalidated",
    "recon_dispatch", "vuln_hunter_dispatch", "recipe_injection",
    "replan", "priority_boost", "target_escalate", "skip_task", "fallback",
})
_PHASE8_SHADOW_DECISION_KEYS = frozenset({"shadow_decisions", "sub_results"})
_PHASE9_EVIDENCE_KEYS = frozenset({
    "rollback_drill_status", "reader_compatibility_status",
    "config_diff", "operator_command", "verification_result",
    "reason_code", "timestamp",
})


def check_reader_compatibility(artifacts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Validate that downstream readers can parse a collection of artifacts.

    Each artifact dict must include an '_artifact_type' key that signals which
    family it belongs to. Supported types:

        - 'session'        : pre-Phase 6 session artifacts
        - 'decision_trace' : Phase 6 decision_traces entries
        - 'swarm_result'   : Phase 8 SwarmResult with shadow_decisions
        - 'evidence_bundle': Phase 9 rollback/reader evidence bundles

    Unknown artifact types are noted but do NOT block the overall pass.

    Args:
        artifacts: List of artifact dicts, each with '_artifact_type'.

    Returns:
        Dict with 'reader_compatibility_status' ('pass'/'fail') and 'errors' list.
    """
    errors: List[str] = []

    for idx, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"artifact[{idx}]: not a dict, got {type(artifact).__name__}")
            continue

        artifact_type = artifact.get("_artifact_type", "")
        if not artifact_type:
            errors.append(f"artifact[{idx}]: missing _artifact_type key")
            continue

        checker = _CHECKER_MAP.get(artifact_type)
        if checker is None:
            # Unknown schema version is not blocking.
            continue
        try:
            errs = checker(artifact)
            errors.extend(errs)
        except Exception as exc:
            errors.append(f"artifact[{idx}]({artifact_type}): checker raised {exc}")

    status = "pass" if len(errors) == 0 else "fail"
    return {
        "reader_compatibility_status": status,
        "errors": errors,
    }


# -- per-family checkers -------------------------------------------------------

def _check_session_artifact(artifact: Dict[str, Any]) -> List[str]:
    """Validate a pre-Phase 6 session artifact is parseable."""
    errors: List[str] = []
    if not isinstance(artifact, dict):
        errors.append("session artifact: not a dict")
        return errors
    # Must have at least one standard field or at minimum be a dict
    has_standard = _OLD_SESSION_KEYS & set(artifact.keys())
    if not has_standard:
        errors.append("session artifact: no standard session keys found")
    return errors


def _check_decision_trace_artifact(artifact: Dict[str, Any]) -> List[str]:
    """Validate a Phase 6 decision_traces entry.

    Expected fields: decision_type (one of the known types), decision_id, timestamp.
    """
    errors: List[str] = []
    decision_type = artifact.get("decision_type", "")
    if not decision_type:
        errors.append("decision_trace artifact: missing decision_type")
    elif decision_type not in _PHASE6_DECISION_TRACE_TYPES:
        # Unknown decision_type is allowed (not blocking) per T-5.1 spec.
        pass
    # decision_id is not strictly required; lack of it is not blocking.
    return errors


def _check_swarm_result_artifact(artifact: Dict[str, Any]) -> List[str]:
    """Validate a Phase 8 SwarmResult with shadow_decisions field."""
    errors: List[str] = []
    shadow_decisions = artifact.get("shadow_decisions")
    if shadow_decisions is None:
        errors.append("swarm_result artifact: missing shadow_decisions field")
    elif not isinstance(shadow_decisions, list):
        errors.append("swarm_result artifact: shadow_decisions is not a list")
    return errors


def _check_evidence_bundle_artifact(artifact: Dict[str, Any]) -> List[str]:
    """Validate a Phase 9 evidence bundle (rollback drill or reader compat)."""
    errors: List[str] = []
    has_keys = _PHASE9_EVIDENCE_KEYS & set(artifact.keys())
    if not has_keys:
        errors.append("evidence_bundle artifact: no recognized Phase 9 evidence keys")
    # Extended metrics are optional; presence is not required.
    return errors


_CHECKER_MAP: Dict[str, Any] = {
    "session": _check_session_artifact,
    "decision_trace": _check_decision_trace_artifact,
    "swarm_result": _check_swarm_result_artifact,
    "evidence_bundle": _check_evidence_bundle_artifact,
}
