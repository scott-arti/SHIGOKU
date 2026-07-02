"""
Review Overrides: schema validation and helpers for review_findings.yaml and overrides.yaml.

Implements the human-review file contract defined in:
  docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md

Functions:
- validate_review_findings / validate_overrides: schema validation
- has_blocking_pending_findings / collect_blocking_finding_ids: compile gate checks
- resolve_review_status: combined review gate result
- apply_overrides_to_rules: merge overrides into rule candidates
- merge_review_candidates_with_findings: merge adapter output with existing review state
- generate_override_skeleton: suggest overrides from pending blocking findings
- load_review_findings / load_overrides: load and validate YAML files
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Union

import yaml

from .program_adapter_base import ReviewCandidate

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_STATUSES = {"pending", "accepted", "dismissed", "overridden"}
ALLOWED_RISK_LEVELS = {"low", "medium", "high", "critical"}
ALLOWED_ATTACK_CLASS_MODES = {"deny", "allow", "allow_with_constraints", "requires_hitl"}

REQUIRED_FINDING_FIELDS = [
    "finding_id",
    "category",
    "subject",
    "risk_level",
    "source_refs",
    "machine_guess",
    "status",
    "blocking",
]

# ---------------------------------------------------------------------------
# 1. validate_review_findings
# ---------------------------------------------------------------------------


def validate_review_findings(data: dict[str, Any]) -> list[str]:
    """Validate review_findings.yaml structure.

    Args:
        data: Parsed YAML data (dict with optional ``review_findings`` key).

    Returns:
        List of error messages; empty list means valid.
    """
    errors: list[str] = []

    findings_data = data.get("review_findings")
    if findings_data is None:
        errors.append("Missing required top-level key: 'review_findings'")
        return errors
    if not isinstance(findings_data, list):
        errors.append("'review_findings' must be a list")
        return errors

    for i, finding in enumerate(findings_data):
        prefix = f"review_findings[{i}]"
        if not isinstance(finding, dict):
            errors.append(f"{prefix}: must be a mapping")
            continue

        # Required fields
        for field in REQUIRED_FINDING_FIELDS:
            if field not in finding:
                errors.append(f"{prefix}: missing required field '{field}'")

        # Validate status
        status = finding.get("status")
        if status is not None and status not in ALLOWED_STATUSES:
            errors.append(
                f"{prefix}: status '{status}' is invalid; "
                f"allowed: {', '.join(sorted(ALLOWED_STATUSES))}"
            )

        # Validate risk_level
        risk_level = finding.get("risk_level")
        if risk_level is not None and risk_level not in ALLOWED_RISK_LEVELS:
            errors.append(
                f"{prefix}: risk_level '{risk_level}' is invalid; "
                f"allowed: {', '.join(sorted(ALLOWED_RISK_LEVELS))}"
            )

        # Validate blocking is boolean
        blocking = finding.get("blocking")
        if blocking is not None and not isinstance(blocking, bool):
            errors.append(
                f"{prefix}: 'blocking' must be boolean, got {type(blocking).__name__}"
            )

        # Validate source_refs is a list (if present)
        source_refs = finding.get("source_refs")
        if source_refs is not None and not isinstance(source_refs, list):
            errors.append(
                f"{prefix}: 'source_refs' must be a list, got {type(source_refs).__name__}"
            )

    return errors


# ---------------------------------------------------------------------------
# 2. validate_overrides
# ---------------------------------------------------------------------------


def validate_overrides(data: dict[str, Any]) -> list[str]:
    """Validate overrides.yaml structure.

    Args:
        data: Parsed YAML data (dict with optional ``overrides`` key).

    Returns:
        List of error messages; empty list means valid.
    """
    errors: list[str] = []

    overrides_data = data.get("overrides")
    if overrides_data is None:
        errors.append("Missing required top-level key: 'overrides'")
        return errors
    if not isinstance(overrides_data, dict):
        errors.append("'overrides' must be a mapping")
        return errors

    # Validate attack_classes modes
    attack_classes = overrides_data.get("attack_classes")
    if attack_classes is not None:
        if not isinstance(attack_classes, dict):
            errors.append("'overrides.attack_classes' must be a mapping")
        else:
            for class_name, class_def in attack_classes.items():
                prefix = f"overrides.attack_classes.{class_name}"
                if isinstance(class_def, dict):
                    mode = class_def.get("mode")
                    if mode is not None and mode not in ALLOWED_ATTACK_CLASS_MODES:
                        errors.append(
                            f"{prefix}: mode '{mode}' is invalid; "
                            f"allowed: {', '.join(sorted(ALLOWED_ATTACK_CLASS_MODES))}"
                        )
                elif class_def is not None:
                    errors.append(
                        f"{prefix}: must be a mapping, got {type(class_def).__name__}"
                    )

    # Validate budgets.requests_per_minute
    budgets = overrides_data.get("budgets")
    if budgets is not None and isinstance(budgets, dict):
        rpm = budgets.get("requests_per_minute")
        if rpm is not None:
            if not isinstance(rpm, (int, float)) or rpm <= 0:
                errors.append(
                    "overrides.budgets.requests_per_minute must be a positive number"
                )

    return errors


# ---------------------------------------------------------------------------
# 3. has_blocking_pending_findings
# ---------------------------------------------------------------------------


def has_blocking_pending_findings(findings: list[dict[str, Any]]) -> bool:
    """Check if any finding has ``blocking=true`` and ``status=pending``.

    Args:
        findings: List of finding dicts.

    Returns:
        True if at least one blocking+pending finding exists.
    """
    return any(
        f.get("blocking", False) is True and f.get("status") == "pending"
        for f in findings
    )


# ---------------------------------------------------------------------------
# 4. collect_blocking_finding_ids
# ---------------------------------------------------------------------------


def collect_blocking_finding_ids(findings: list[dict[str, Any]]) -> list[str]:
    """Return finding_ids that are both ``blocking=true`` and ``status=pending``.

    Args:
        findings: List of finding dicts.

    Returns:
        List of finding_id strings.
    """
    return [
        f["finding_id"]
        for f in findings
        if f.get("blocking", False) is True and f.get("status") == "pending"
    ]


# ---------------------------------------------------------------------------
# 5. resolve_review_status
# ---------------------------------------------------------------------------


def resolve_review_status(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute the review gate result from a list of findings.

    Args:
        findings: List of finding dicts.

    Returns:
        Dict with keys:
          - ``status``: ``ready`` or ``manual_review_required``
          - ``blocking_ids``: list of blocking+pending finding_id strings
          - ``total_pending``: total count of findings with status=pending
    """
    blocking_ids = collect_blocking_finding_ids(findings)
    total_pending = sum(1 for f in findings if f.get("status") == "pending")
    return {
        "status": "manual_review_required" if blocking_ids else "ready",
        "blocking_ids": blocking_ids,
        "total_pending": total_pending,
    }


# ---------------------------------------------------------------------------
# 6. apply_overrides_to_rules
# ---------------------------------------------------------------------------


def _candidate_to_dict(candidate: Any) -> dict[str, Any]:
    """Convert a RuleCandidate or dict to a plain dict."""
    if isinstance(candidate, dict):
        return dict(candidate)
    # It's a dataclass (RuleCandidate)
    result: dict[str, Any] = {
        "rule_id": getattr(candidate, "rule_id", ""),
        "category": getattr(candidate, "category", ""),
        "decision": getattr(candidate, "decision", "deny"),
        "subject": getattr(candidate, "subject", ""),
        "constraints": getattr(candidate, "constraints", {}),
        "origin_type": getattr(candidate, "origin_type", "policy_text"),
        "specificity": getattr(candidate, "specificity", "medium"),
        "source_ref": getattr(candidate, "source_ref", ""),
    }
    return result


def apply_overrides_to_rules(
    overrides: dict[str, Any],
    rule_candidates: list[Any],
) -> list[dict[str, Any]]:
    """Apply override settings to rule candidates.

    Override values take precedence over adapter-generated defaults.

    Args:
        overrides: Parsed overrides data (with ``overrides`` key).
        rule_candidates: List of rule candidate dicts or RuleCandidate DTOs.

    Returns:
        A new list of rule dicts with overrides applied.
    """
    # Convert all candidates to dicts
    rules: list[dict[str, Any]] = [_candidate_to_dict(rc) for rc in rule_candidates]

    override_data = overrides.get("overrides", {})
    if not isinstance(override_data, dict):
        return rules

    # --- Scope overrides -------------------------------------------------------
    scope = override_data.get("scope")
    if isinstance(scope, dict):
        # Remove existing scope rules that match overridden hosts/prefixes
        allow_hosts = scope.get("allow_hosts", []) or []
        deny_hosts = scope.get("deny_hosts", []) or []
        allow_url_prefixes = scope.get("allow_url_prefixes", []) or []
        deny_url_prefixes = scope.get("deny_url_prefixes", []) or []

        # Filter out scope rules whose subject is in one of the override lists
        override_subjects = set(allow_hosts) | set(deny_hosts) | set(allow_url_prefixes) | set(deny_url_prefixes)
        if override_subjects:
            rules = [
                r for r in rules
                if not (r.get("category") == "scope" and r.get("subject") in override_subjects)
            ]

        counter = 1
        for host in allow_hosts:
            rules.append({
                "rule_id": f"override.scope.host.allow.{counter}",
                "category": "scope",
                "decision": "allow",
                "subject": host,
                "constraints": {},
                "origin_type": "human_override",
                "specificity": "exact",
                "source_ref": "overrides.yaml#scope.allow_hosts",
            })
            counter += 1

        for host in deny_hosts:
            rules.append({
                "rule_id": f"override.scope.host.deny.{counter}",
                "category": "scope",
                "decision": "deny",
                "subject": host,
                "constraints": {},
                "origin_type": "human_override",
                "specificity": "exact",
                "source_ref": "overrides.yaml#scope.deny_hosts",
            })
            counter += 1

        for url_prefix in allow_url_prefixes:
            rules.append({
                "rule_id": f"override.scope.url_prefix.allow.{counter}",
                "category": "scope",
                "decision": "allow",
                "subject": url_prefix,
                "constraints": {},
                "origin_type": "human_override",
                "specificity": "exact",
                "source_ref": "overrides.yaml#scope.allow_url_prefixes",
            })
            counter += 1

        for url_prefix in deny_url_prefixes:
            rules.append({
                "rule_id": f"override.scope.url_prefix.deny.{counter}",
                "category": "scope",
                "decision": "deny",
                "subject": url_prefix,
                "constraints": {},
                "origin_type": "human_override",
                "specificity": "exact",
                "source_ref": "overrides.yaml#scope.deny_url_prefixes",
            })
            counter += 1

    # --- Attack class overrides ------------------------------------------------
    attack_classes = override_data.get("attack_classes")
    if isinstance(attack_classes, dict):
        for class_name, class_def in attack_classes.items():
            if not isinstance(class_def, dict):
                continue
            mode = class_def.get("mode")
            if mode is None:
                continue

            # Find existing rule for this attack class
            existing_idx = next(
                (i for i, r in enumerate(rules)
                 if r.get("category") == "attack_class" and r.get("subject") == class_name),
                None,
            )

            constraints = {}
            if "allowed_destinations" in class_def:
                constraints["allowed_destinations"] = class_def["allowed_destinations"]

            if existing_idx is not None:
                # Override the existing rule
                rules[existing_idx]["decision"] = mode
                rules[existing_idx]["origin_type"] = "human_override"
                rules[existing_idx]["source_ref"] = f"overrides.yaml#attack_classes.{class_name}"
                if constraints:
                    rules[existing_idx]["constraints"] = constraints
            else:
                rules.append({
                    "rule_id": f"override.attack_class.{class_name}",
                    "category": "attack_class",
                    "decision": mode,
                    "subject": class_name,
                    "constraints": constraints,
                    "origin_type": "human_override",
                    "specificity": "broad",
                    "source_ref": f"overrides.yaml#attack_classes.{class_name}",
                })

    # --- Auth overrides --------------------------------------------------------
    auth = override_data.get("auth")
    if isinstance(auth, dict):
        email_domains = auth.get("allowed_email_domains", []) or []
        if email_domains:
            # Remove existing auth rules for email domains
            rules = [r for r in rules if r.get("subject") != "allowed_email_domains"]
            rules.append({
                "rule_id": "override.auth.allowed_email_domains",
                "category": "auth",
                "decision": "allow",
                "subject": "allowed_email_domains",
                "constraints": {"domains": email_domains},
                "origin_type": "human_override",
                "specificity": "broad",
                "source_ref": "overrides.yaml#auth.allowed_email_domains",
            })

    # --- Budget overrides ------------------------------------------------------
    budgets = override_data.get("budgets")
    if isinstance(budgets, dict):
        rpm = budgets.get("requests_per_minute")
        if rpm is not None:
            rules = [r for r in rules if r.get("subject") != "requests_per_minute"]
            rules.append({
                "rule_id": "override.budgets.requests_per_minute",
                "category": "budget",
                "decision": "allow",
                "subject": "requests_per_minute",
                "constraints": {"requests_per_minute": rpm},
                "origin_type": "human_override",
                "specificity": "broad",
                "source_ref": "overrides.yaml#budgets.requests_per_minute",
            })

    return rules


# ---------------------------------------------------------------------------
# 7. merge_review_candidates_with_findings
# ---------------------------------------------------------------------------


def _generate_finding_id(index: int, provider_hint: str = "") -> str:
    """Generate a finding_id for a new review candidate."""
    prefix = "BC" if not provider_hint else provider_hint[:2].upper()
    return f"{prefix}-AMB-{index + 1:03d}"


def _review_candidate_to_finding(
    candidate: ReviewCandidate,
    finding_id: str,
) -> dict[str, Any]:
    """Convert a ReviewCandidate DTO into a review_findings entry dict."""
    return {
        "finding_id": finding_id,
        "category": candidate.category,
        "subject": candidate.subject,
        "risk_level": candidate.risk_level,
        "source_refs": list(candidate.source_refs),
        "machine_guess": dict(candidate.machine_guess) if candidate.machine_guess else {},
        "status": "pending",
        "blocking": candidate.blocking,
        "recommended_override_path": candidate.recommended_override_path,
    }


def merge_review_candidates_with_findings(
    adapter_candidates: list[ReviewCandidate],
    existing_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge adapter-generated review candidates with existing findings.

    New candidates get an auto-generated ``finding_id`` and ``status=pending``.
    Existing findings keep their resolved status.  Candidates with an
    already-populated ``finding_id`` that match an existing entry are updated
    in-place (fields from the adapter refresh the data, but status is preserved).

    Args:
        adapter_candidates: List of ReviewCandidate DTOs from adapter.
        existing_findings: Current review_findings entries as list of dicts.

    Returns:
        Merged list of finding dicts.
    """
    # Build lookup by finding_id for existing findings
    existing_by_id: dict[str, dict[str, Any]] = {}
    for f in existing_findings:
        fid = f.get("finding_id", "")
        if fid:
            existing_by_id[fid] = dict(f)

    result: list[dict[str, Any]] = []
    matched_ids: set[str] = set()

    # Determine starting index for new IDs (count existing AMB-pattern IDs)
    next_index = len(existing_by_id)

    for candidate in adapter_candidates:
        fid = candidate.finding_id.strip() if candidate.finding_id else ""

        if fid and fid in existing_by_id:
            # Update existing entry fields from adapter, preserve status
            existing = existing_by_id[fid]
            existing.update({
                "finding_id": fid,
                "category": candidate.category,
                "subject": candidate.subject,
                "risk_level": candidate.risk_level,
                "source_refs": list(candidate.source_refs),
                "machine_guess": dict(candidate.machine_guess) if candidate.machine_guess else existing.get("machine_guess", {}),
                "blocking": candidate.blocking,
                "recommended_override_path": candidate.recommended_override_path or existing.get("recommended_override_path", ""),
            })
            result.append(existing)
            matched_ids.add(fid)
        else:
            # New candidate: generate ID
            gen_id = _generate_finding_id(next_index)
            next_index += 1
            finding = _review_candidate_to_finding(candidate, gen_id)
            result.append(finding)

    # Preserve existing findings that were not matched by any adapter candidate
    for fid, existing in existing_by_id.items():
        if fid not in matched_ids:
            result.append(existing)

    return result


# ---------------------------------------------------------------------------
# 8. generate_override_skeleton
# ---------------------------------------------------------------------------


def generate_override_skeleton(
    review_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Generate a suggested overrides.yaml skeleton from pending blocking findings.

    Inspects the categories of pending+blocking findings and builds a skeleton
    that the operator can fill in.

    Args:
        review_candidates: List of finding dicts (typically the output of
            ``merge_review_candidates_with_findings``).

    Returns:
        Dict with top-level ``overrides`` key and a ``suggested_entries`` list
        describing which findings motivated each suggested entry.
    """
    blocking_pending = [
        f for f in review_candidates
        if f.get("blocking", False) is True and f.get("status") == "pending"
    ]

    skeleton: dict[str, Any] = {
        "overrides": {
            "scope": {
                "allow_hosts": [],
                "deny_hosts": [],
                "allow_url_prefixes": [],
                "deny_url_prefixes": [],
            },
            "attack_classes": {},
            "auth": {"allowed_email_domains": []},
            "budgets": {"requests_per_minute": 60},
        },
        "suggested_entries": [],
    }

    for finding in blocking_pending:
        fid = finding.get("finding_id", "")
        category = finding.get("category", "")
        subject = finding.get("subject", "")
        suggestion = {"finding_id": fid, "category": category, "subject": subject}

        if category == "temporal_scope":
            skeleton["overrides"]["scope"]["deny_url_prefixes"].append(subject)
            suggestion["action"] = "Added to scope.deny_url_prefixes"
        elif category in ("ssrf", "attack_class", "social_engineering", "dos", "post_exploit"):
            ac = skeleton["overrides"]["attack_classes"]
            # Derive the attack class name from subject or category
            ac_name = subject if subject else category
            if ac_name not in ac:
                ac[ac_name] = {"mode": "deny"}
                suggestion["action"] = f"Added attack_class.{ac_name} with mode=deny"
            else:
                suggestion["action"] = f"Review attack_class.{ac_name}"
        elif category == "auth":
            skeleton["overrides"]["auth"]["allowed_email_domains"] = []
            suggestion["action"] = "Review auth.allowed_email_domains"
        else:
            suggestion["action"] = "Manual review required"

        skeleton["suggested_entries"].append(suggestion)

    return skeleton


# ---------------------------------------------------------------------------
# 9. load_review_findings
# ---------------------------------------------------------------------------


def load_review_findings(path: Union[str, Path]) -> dict[str, Any]:
    """Load and validate a ``review_findings.yaml`` file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed dict with ``review_findings`` key.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file has invalid YAML syntax.
        ValueError: If validation fails.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"review_findings.yaml not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if data is None:
        data = {"review_findings": []}

    errors = validate_review_findings(data)
    if errors:
        raise ValueError(
            f"Validation errors in {file_path}:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    return data


# ---------------------------------------------------------------------------
# 10. load_overrides
# ---------------------------------------------------------------------------


def load_overrides(path: Union[str, Path]) -> dict[str, Any]:
    """Load and validate an ``overrides.yaml`` file.

    Args:
        path: Path to the YAML file.

    Returns:
        Parsed dict with ``overrides`` key.

    Raises:
        FileNotFoundError: If the file does not exist.
        yaml.YAMLError: If the file has invalid YAML syntax.
        ValueError: If validation fails.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"overrides.yaml not found: {file_path}")

    with open(file_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if data is None:
        data = {"overrides": {}}

    errors = validate_overrides(data)
    if errors:
        raise ValueError(
            f"Validation errors in {file_path}:\n" + "\n".join(f"  - {e}" for e in errors)
        )

    return data
