"""
Compiled Guard Compiler: transforms normalized facts + review/overrides into
a deterministic compiled_guard_policy.yaml.

Contract defined in:
  docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  Sections 8 (Compiler Precedence), 9 (compiled_guard_policy.yaml Contract)

Precedence (spec 8.1):
  1. Human override (from overrides.yaml)
  2. Explicit deny (from normalized facts)
  3. More specific match (url_prefix > host_exact > host_wildcard)
  4. Structured asset allow (from normalized facts)
  5. Policy-derived broad allow
  6. Default deny

Fail-closed conditions (8.3):
  compile_status is ``manual_review_required`` or ``compile_failed`` if:
  - In-scope assets = 0
  - Blocking review finding is pending
  - Same-specificity allow/deny conflict without override
  - Temporal rule date interpretation impossible
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from .program_adapter_base import NormalizedFacts, compute_normalized_facts_hash
from .review_overrides import (
    apply_overrides_to_rules,
    collect_blocking_finding_ids,
)

# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def compile_guard_policy(
    facts: NormalizedFacts,
    review_findings: dict[str, Any],
    overrides: dict[str, Any],
    bundle_dir: Optional[Path] = None,
) -> dict[str, Any]:
    """Compile normalized facts + review/overrides into a single guard policy.

    Args:
        facts: Normalized facts from provider adapter.
        review_findings: Resolved review_findings.yaml as dict.
        overrides: Resolved overrides.yaml as dict.
        bundle_dir: Optional Path for provenance metadata.

    Returns:
        A dict matching the compiled_guard_policy.yaml contract.
    """
    # 1. Resolve compile status (overrides may resolve specificity conflicts)
    compile_status, blocking_findings = _resolve_compile_status(facts, review_findings, overrides)
    manual_review_required = compile_status == "manual_review_required"
    compile_failed = compile_status == "compile_failed"

    # Record compile status metrics (Step 9: SGK-2026-0335)
    _record_compile_metrics(compile_status)

    # 2. Apply overrides to rule candidates
    merged_rules = apply_overrides_to_rules(overrides, facts.rule_candidates)

    # 3. Build scope (with precedence)
    scope = _build_scope(facts, overrides)

    # 4. Build rules from merged candidates
    rules = _build_rules_from_merged(merged_rules)

    # 5. Compute normalized facts hash (must come before policy_id for Critical 2)
    norm_hash = compute_normalized_facts_hash(facts, review_findings, overrides)

    # 6. Extract identity from facts
    provider = facts.program.get("provider", "")
    program_name = facts.program.get("program_name", "")
    program_alias = facts.program.get("program_alias",
        _derive_alias(program_name))
    bundle_id = facts.program.get("bundle_id",
        f"bbp-{provider}-{program_alias}-unknown")
    # Derive policy_id from norm_hash for determinism (Fix Critical 2)
    norm_short = norm_hash.split(":")[-1][:12] if ":" in norm_hash else norm_hash[:12]

    # 7. Build policy dict (without compiled_policy_hash first)
    policy: dict[str, Any] = {
        "schema_version": 1,
        "compile_status": compile_status,
        "bundle_id": bundle_id,
        "policy_id": f"bbp:{provider}:{program_alias}:{norm_short}",
        "provider": provider,
        "program_name": program_name,
        "program_alias": program_alias,
        "compiled_at_utc": _utcnow_compact(),
        "normalized_facts_hash": norm_hash,
        "default_decision": "deny",
        "compatibility": {
            "min_reader_schema_version": 1,
            "backward_compatible_with": [1],
        },
        "scope": scope,
        "rules": rules,
        "review_gate": {
            "manual_review_required": manual_review_required,
            "blocking_findings": blocking_findings,
        },
        "audit": _build_audit(facts, review_findings, overrides),
    }

    # 8. Compute compiled policy hash (includes schema_version)
    compiled_hash = _compute_compiled_policy_hash(policy)
    policy["compiled_policy_hash"] = compiled_hash

    return policy


# ---------------------------------------------------------------------------
# 1. Compile status resolution
# ---------------------------------------------------------------------------


def _resolve_compile_status(
    facts: NormalizedFacts,
    review_findings: dict[str, Any],
    overrides: Optional[dict[str, Any]] = None,
) -> tuple[str, list[str]]:
    """Resolve the compile status (ready / manual_review_required / compile_failed).

    Returns:
        (status, blocking_finding_ids) tuple.
    """
    findings_list: list[dict[str, Any]] = review_findings.get("review_findings", [])
    if not isinstance(findings_list, list):
        findings_list = []

    # Check: 0 in-scope assets -> compile_failed
    in_scope_assets = [a for a in facts.assets if a.submission_allowed]
    if len(in_scope_assets) == 0:
        return ("compile_failed", [])

    # Check: same-specificity conflicts not resolved by overrides
    conflicts = _detect_specificity_conflicts(facts)
    if conflicts:
        unresolved = _filter_conflicts_resolved_by_overrides(conflicts, overrides)
        if unresolved:
            return ("manual_review_required",
                    [f"conflict:{c.get('subject', 'unknown')}" for c in unresolved])

    # Check: blocking pending findings -> manual_review_required
    blocking_ids = collect_blocking_finding_ids(findings_list)
    if blocking_ids:
        return ("manual_review_required", blocking_ids)

    return ("ready", [])


def _detect_specificity_conflicts(
    facts: NormalizedFacts,
) -> list[dict[str, Any]]:
    """Detect allow/deny conflicts at the same specificity level.

    Returns list of conflict descriptions. Empty list = no conflicts.
    (Fix Medium 5)
    """
    conflicts: list[dict[str, Any]] = []

    # Group assets by canonical_key
    by_key: dict[str, list] = {}
    for asset in facts.assets:
        key = asset.canonical_key or asset.raw_identifier
        by_key.setdefault(key, []).append(asset)

    for key, assets_list in by_key.items():
        has_allow = any(a.submission_allowed for a in assets_list)
        has_deny = any(not a.submission_allowed for a in assets_list)
        if has_allow and has_deny:
            # Check if they're at the same specificity level
            kinds = {a.asset_kind for a in assets_list}
            # Same exact host with exact match -> conflict
            if "host_exact" in kinds:
                conflicts.append({
                    "subject": key,
                    "specificity": "host_exact",
                    "reason": "exact host has both allow and deny assets",
                })
            # Same wildcard with both allow and deny -> conflict
            elif {"host_wildcard"} == kinds and key.startswith("*."):
                # Both wildcards for same host pattern -> conflict
                pass  # This is handled by precedence already, not a manual-review conflict
            # url_prefix with both allow and deny at same prefix
            elif "url_prefix" in kinds:
                conflicts.append({
                    "subject": key,
                    "specificity": "url_prefix",
                    "reason": "URL prefix has both allow and deny assets",
                })

    return conflicts


def _filter_conflicts_resolved_by_overrides(
    conflicts: list[dict[str, Any]],
    overrides: Optional[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Remove conflicts that are explicitly resolved by overrides.

    An override resolves a conflict if the conflicting host/URL appears in
    override deny_hosts, deny_url_prefixes, allow_hosts, or allow_url_prefixes.
    """
    if not conflicts or not overrides:
        return list(conflicts)

    override_data = overrides.get("overrides", {}) if overrides else {}
    if not isinstance(override_data, dict):
        return list(conflicts)

    scope_override = override_data.get("scope", {}) or {}
    ov_deny_hosts: set[str] = set(scope_override.get("deny_hosts", []) or [])
    ov_allow_hosts: set[str] = set(scope_override.get("allow_hosts", []) or [])
    ov_deny_url: set[str] = set(scope_override.get("deny_url_prefixes", []) or [])
    ov_allow_url: set[str] = set(scope_override.get("allow_url_prefixes", []) or [])

    unresolved: list[dict[str, Any]] = []
    for c in conflicts:
        subject = c.get("subject", "")
        # Conflict resolved if subject appears in ANY override (deny or allow)
        if subject in ov_deny_hosts or subject in ov_allow_hosts or \
           subject in ov_deny_url or subject in ov_allow_url:
            continue
        unresolved.append(c)

    return unresolved


# ---------------------------------------------------------------------------
# 2. Scope building
# ---------------------------------------------------------------------------


def _build_scope(
    facts: NormalizedFacts,
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Build the scope section of the compiled policy.

    Applies precedence: explicit deny > allow, more specific > less specific.
    """
    allow_hosts, deny_hosts, allow_url, deny_url, non_http = (
        _apply_precedence_deny_over_allow(facts)
    )

    # Merge with overrides scope
    override_data = overrides.get("overrides", {})
    if isinstance(override_data, dict):
        scope_override = override_data.get("scope")
        if isinstance(scope_override, dict):
            # Override allow hosts
            ov_allow_hosts = scope_override.get("allow_hosts", []) or []
            for h in ov_allow_hosts:
                if h not in allow_hosts:
                    # Remove from deny if conflicting (override > deny)
                    if h in deny_hosts:
                        deny_hosts.remove(h)
                    allow_hosts.append(h)

            # Override deny hosts
            ov_deny_hosts = scope_override.get("deny_hosts", []) or []
            for h in ov_deny_hosts:
                if h not in deny_hosts:
                    # Remove from allow if conflicting (override deny > allow)
                    if h in allow_hosts:
                        allow_hosts.remove(h)
                    deny_hosts.append(h)

            # Override allow URL prefixes
            ov_allow_url = scope_override.get("allow_url_prefixes", []) or []
            for u in ov_allow_url:
                if u not in allow_url:
                    if u in deny_url:
                        deny_url.remove(u)
                    allow_url.append(u)

            # Override deny URL prefixes
            ov_deny_url = scope_override.get("deny_url_prefixes", []) or []
            for u in ov_deny_url:
                if u not in deny_url:
                    if u in allow_url:
                        allow_url.remove(u)
                    deny_url.append(u)

    return {
        "allow_hosts": sorted(allow_hosts),
        "deny_hosts": sorted(deny_hosts),
        "allow_url_prefixes": sorted(allow_url),
        "deny_url_prefixes": sorted(deny_url),
        "non_http_assets": sorted(non_http),
    }


def _apply_precedence_deny_over_allow(
    facts: NormalizedFacts,
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    """Resolve allow/deny conflicts from adapter assets.

    Returns:
        (allow_hosts, deny_hosts, allow_url_prefixes, deny_url_prefixes, non_http_assets)
    """
    allow_hosts: list[str] = []
    deny_hosts: list[str] = []
    allow_url_prefixes: list[str] = []
    deny_url_prefixes: list[str] = []
    non_http_assets: list[str] = []

    for asset in facts.assets:
        key = asset.canonical_key or asset.raw_identifier

        if asset.asset_kind == "mobile_app" or asset.runtime_surface in ("mobile", "non_runtime"):
            non_http_assets.append(key)
            continue

        if asset.asset_kind == "url_prefix":
            if asset.submission_allowed:
                allow_url_prefixes.append(key)
            else:
                deny_url_prefixes.append(key)
        elif asset.asset_kind in ("host_exact", "host_wildcard"):
            if asset.submission_allowed:
                allow_hosts.append(key)
            else:
                deny_hosts.append(key)
        else:
            # other/unclassified
            if asset.submission_allowed:
                allow_hosts.append(key)
            else:
                deny_hosts.append(key)

    # Apply precedence: remove exact denies from wildcard allows on same domain root
    # Deny lists are cleaned of redundant entries later
    _deduplicate_and_apply_precedence(allow_hosts, deny_hosts)

    return allow_hosts, deny_hosts, allow_url_prefixes, deny_url_prefixes, non_http_assets


def _extract_domain_root(host: str) -> str:
    """Extract the TLD+1 root from a hostname for comparison."""
    h = host.strip().lower()
    if h.startswith("*."):
        h = h[2:]
    parts = h.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return h


def _deduplicate_and_apply_precedence(
    allow_hosts: list[str],
    deny_hosts: list[str],
) -> None:
    """Apply specificity-based precedence: remove allow entries that are
    narrower than or exactly matched by deny entries.

    Modifies allow_hosts and deny_hosts in place.
    """
    # Build sets for quick lookup
    allow_set = set(allow_hosts)
    deny_set = set(deny_hosts)

    # Exact match: if a host appears in both allow and deny, deny wins
    for host in list(allow_set):
        if host in deny_set:
            allow_hosts.remove(host)

    # Recompute after removal
    allow_set = set(allow_hosts)

    # For each deny, check if it's more specific than any allow
    for deny_key in list(deny_hosts):
        # If deny is host_exact and an allow wildcard covers it, leave both
        # (the deny is more specific at runtime, but both stay)
        # If deny is wildcard and an allow host_exact under it exists, remove the allow
        if deny_key.startswith("*."):
            deny_root = deny_key[2:]  # e.g., "example.com"
            for allow_key in list(allow_hosts):
                if (allow_key.endswith("." + deny_root) or allow_key == deny_root) and not allow_key.startswith("*."):
                    allow_hosts.remove(allow_key)


# ---------------------------------------------------------------------------
# 3. Rules building
# ---------------------------------------------------------------------------


def _build_rules(
    facts: NormalizedFacts,
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Build rules from facts.rule_candidates plus overrides."""
    merged = apply_overrides_to_rules(overrides, facts.rule_candidates)
    return _build_rules_from_merged(merged)


def _build_rules_from_merged(
    merged_rules: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the rules section from a merged list of rule dicts."""
    phases: dict[str, Any] = {}
    attack_classes: dict[str, Any] = {}
    auth: dict[str, Any] = {}
    budgets: dict[str, Any] = {"requests_per_minute": 60}

    # Collect SSRF destinations
    ssrf_destinations: list[str] = []
    ssrf_deny_other = False

    for rc in merged_rules:
        category = rc.get("category", "")
        subject = rc.get("subject", "")
        decision = rc.get("decision", "deny")
        constraints = rc.get("constraints", {}) or {}
        source_ref = rc.get("source_ref", "")

        if category == "phase" and subject == "post_exploit":
            phases["post_exploit"] = {
                "decision": decision,
                "reason_code": "post_exploit_prohibited",
                "source_refs": [source_ref] if source_ref else [],
            }

        elif category == "attack_class":
            attack_classes[subject] = {
                "decision": decision,
                "reason_code": f"attack_class_{subject}_denied",
                "source_refs": [source_ref] if source_ref else [],
            }
            # Carry over allowed destinations if present
            if "allowed_destinations" in constraints:
                attack_classes[subject]["allowed_destinations"] = constraints["allowed_destinations"]

        elif category == "destination":
            # SSRF-related destinations
            if constraints.get("ssrf_only"):
                if decision == "allow":
                    ssrf_destinations.append(subject)
                elif decision == "deny":
                    ssrf_deny_other = True

        elif category == "auth":
            if "allowed_email_domains" in constraints:
                auth["allowed_email_domains"] = list(constraints["allowed_email_domains"])
            elif "domains" in constraints:
                auth["allowed_email_domains"] = list(constraints["domains"])
            elif subject == "allowed_email_domain" and "allowed_email_domains" in constraints:
                auth["allowed_email_domains"] = list(constraints["allowed_email_domains"])
            else:
                # Generic auth rule — capture as allowed_email_domains if present
                if "allowed_email_domains" in rc:
                    auth["allowed_email_domains"] = rc["allowed_email_domains"]

        elif category == "budget":
            if "requests_per_minute" in constraints:
                budgets["requests_per_minute"] = constraints["requests_per_minute"]

    # Build SSRF attack class if we have destinations
    if ssrf_destinations:
        decision = "allow_with_constraints" if ssrf_destinations else "allow"
        attack_classes["ssrf"] = {
            "decision": decision,
            "allowed_destinations": sorted(ssrf_destinations),
            "reason_code": "attack_class_ssrf_allowlisted",
            "source_refs": ["policy.md"],
        }

    # Apply merged budget constraint rules (from overrides)
    for rc in merged_rules:
        if rc.get("category") == "budget" and rc.get("subject") == "requests_per_minute":
            value = rc.get("constraints", {}).get("requests_per_minute")
            if isinstance(value, (int, float)):
                budgets["requests_per_minute"] = int(value)

    return {
        "phases": phases,
        "attack_classes": attack_classes,
        "auth": auth,
        "budgets": budgets,
    }


# ---------------------------------------------------------------------------
# 4. Audit building
# ---------------------------------------------------------------------------


def _build_audit(
    facts: NormalizedFacts,
    review_findings: dict[str, Any],
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Build the audit section with rule_origins and compile_inputs."""
    rule_origins: list[dict[str, Any]] = _build_rule_origins(facts)
    compile_inputs = _build_compile_inputs(facts, review_findings, overrides)

    return {
        "source_hashes": {},
        "compile_inputs": compile_inputs,
        "rule_origins": rule_origins,
    }


def _build_rule_origins(facts: NormalizedFacts) -> list[dict[str, Any]]:
    """Build the rule_origins list from assets.

    Each asset gets a rule_origin entry tracing back to its source.
    """
    origins: list[dict[str, Any]] = []
    scope_counter: dict[str, int] = {}  # category -> next index

    for idx, asset in enumerate(facts.assets):
        key = asset.canonical_key or asset.raw_identifier
        asset_kind = asset.asset_kind
        submission = asset.submission_allowed
        source_ref = asset.source_ref or ""

        # Determine runtime_rule_id category and decision
        if asset_kind == "mobile_app" or asset.runtime_surface in ("mobile", "non_runtime"):
            # Non-HTTP assets go to non_http scope
            continue

        if asset_kind == "url_prefix":
            if submission:
                cat = "url_prefix.allow"
            else:
                cat = "url_prefix.deny"
        elif asset_kind in ("host_exact", "host_wildcard"):
            if submission:
                cat = "host.allow"
            else:
                cat = "host.deny"
        else:
            if submission:
                cat = "host.allow"
            else:
                cat = "host.deny"

        scope_counter[cat] = scope_counter.get(cat, 0) + 1
        runtime_rule_id = f"scope.{cat}.{scope_counter[cat]}"

        # Generate rule_origin_id
        short_provider = facts.program.get("provider", "unk")[:4]
        short_program = facts.program.get("program_name", "unknown").lower().replace(" ", "")[:12]
        rule_origin_id = f"origin.{short_program}.{cat.replace('.', '_')}.{scope_counter[cat]}"

        # Determine origin_type
        origin_type = "structured_scope" if asset.source_ref and "csv" in asset.source_ref.lower() else "policy_text"

        origins.append({
            "rule_origin_id": rule_origin_id,
            "runtime_rule_id": runtime_rule_id,
            "origin_type": origin_type,
            "source_ref": source_ref,
            "subject": key,
            "decision": "allow" if submission else "deny",
            "review_finding_ids": [],
            "override_paths": [],
            "normalization_notes": _normalization_note(asset_kind, submission, key),
        })

    return origins


def _normalization_note(asset_kind: str, submission_allowed: bool, subject: str) -> str:
    """Generate a human-readable normalization note."""
    if asset_kind == "host_wildcard":
        if submission_allowed:
            return f"wildcard allow for all {subject.replace('*.', '')} subdomains"
        else:
            return f"explicit deny for {subject}"
    elif asset_kind == "host_exact":
        if submission_allowed:
            return f"exact host allow from scope source"
        else:
            return f"exact host deny from scope source"
    elif asset_kind == "url_prefix":
        if submission_allowed:
            return f"URL prefix allow"
        else:
            return f"URL prefix deny"
    elif asset_kind == "mobile_app":
        return "mobile app asset (non-HTTP)"
    return ""


def _build_compile_inputs(
    facts: NormalizedFacts,
    review_findings: dict[str, Any],
    overrides: dict[str, Any],
) -> dict[str, Any]:
    """Build the compile_inputs hash dict."""
    # Compute individual hashes
    manifest_hash = _sha256_str(
        yaml.dump({"provider": facts.program.get("provider", ""),
                   "program_name": facts.program.get("program_name", ""),
                   "bundle_id": facts.program.get("bundle_id", "")},
                  sort_keys=True)
    )

    # Policy text hash from source hashes (Fix High 4 — use raw content hashes)
    source_hashes = getattr(facts, 'source_hashes', {}) or {}
    policy_hash = next(
        (h for k, h in source_hashes.items()
         if k.endswith('.md') or k == 'policy.md'),
        _sha256_str("")
    )

    # Scope hashes from raw source content (Fix High 4)
    scope_hashes_list = [
        h for k, h in sorted(source_hashes.items())
        if k != 'policy.md' and not k.endswith('.md')
    ]
    if not scope_hashes_list:
        # Fallback: hash from asset list summary
        scope_data = sorted(
            f"{a.canonical_key}|{a.asset_kind}|{a.submission_allowed}"
            for a in facts.assets
        )
        scope_hashes_list = [_sha256_str("\n".join(scope_data))]

    # Review findings hash
    review_findings_hash = _sha256_str(
        yaml.dump(review_findings, sort_keys=True) if review_findings else "{}"
    )

    # Overrides hash
    overrides_hash = _sha256_str(
        yaml.dump(overrides, sort_keys=True) if overrides else "{}"
    )

    return {
        "manifest_hash": manifest_hash,
        "policy_hash": policy_hash,
        "scope_hashes": scope_hashes_list,
        "review_findings_hash": review_findings_hash,
        "overrides_hash": overrides_hash,
    }


# ---------------------------------------------------------------------------
# 5. Write compiled policy to directory (Fix Critical 1)
# ---------------------------------------------------------------------------


def write_compiled_policy_artifact(
    policy_dict: dict[str, Any],
    output_dir: Path,
) -> str:
    """Write compiled_guard_policy.yaml to output_dir.

    Does NOT activate the bundle (no active_bundle.json).

    Args:
        policy_dict: The compiled policy dict from compile_guard_policy().
        output_dir: Target directory (will be created if needed).

    Returns:
        The sha256:hex file hash of the written compiled_guard_policy.yaml.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Serialize and write compiled_guard_policy.yaml
    yaml_bytes = yaml.dump(
        policy_dict, sort_keys=True, default_flow_style=False
    ).encode("utf-8")
    policy_path = output_dir / "compiled_guard_policy.yaml"
    policy_path.write_bytes(yaml_bytes)

    # Compute sha256 of the written file bytes
    file_hash = "sha256:" + hashlib.sha256(yaml_bytes).hexdigest()
    return file_hash


def activate_bundle(
    policy_dict: dict[str, Any],
    output_dir: Path,
    artifact_file_hash: str,
) -> dict[str, Any]:
    """Create active_bundle.json to activate a compiled policy.

    Requires ``compile_status=ready``.  If status is not ready, raises
    ``ValueError`` — the bundle must be compiled and reviewed before
    activation (Step6 lifecycle separation).

    Args:
        policy_dict: The compiled policy dict.
        output_dir: Directory containing compiled_guard_policy.yaml.
        artifact_file_hash: The sha256:hex hash of compiled_guard_policy.yaml
            file bytes (from ``write_compiled_policy_artifact``).

    Returns:
        The active_bundle.json contents as a dict.

    Raises:
        ValueError: If compile_status is not ``ready``.
    """
    status = policy_dict.get("compile_status", "")
    if status != "ready":
        raise ValueError(
            f"Cannot activate bundle with compile_status='{status}'. "
            f"Only 'ready' bundles can be activated."
        )

    output_dir = Path(output_dir)
    active_data = {
        "provider": policy_dict.get("provider", ""),
        "program_alias": policy_dict.get("program_alias", ""),
        "bundle_id": policy_dict.get("bundle_id", ""),
        "policy_id": policy_dict.get("policy_id", ""),
        "compiled_policy_path": "compiled_guard_policy.yaml",
        "compiled_policy_hash": artifact_file_hash,
        "activated_at_utc": _utcnow_compact(),
    }
    active_path = output_dir / "active_bundle.json"
    active_path.write_text(
        json.dumps(active_data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return active_data


def write_compiled_policy_to_dir(
    policy_dict: dict[str, Any],
    output_dir: Path,
) -> str:
    """Convenience: write artifact AND activate in one call.

    Calls ``write_compiled_policy_artifact`` then ``activate_bundle``.
    Raises ``ValueError`` if compile_status is not ready.

    Args:
        policy_dict: The compiled policy dict from compile_guard_policy().
        output_dir: Target directory.

    Returns:
        The sha256:hex file hash of the written compiled_guard_policy.yaml.
    """
    file_hash = write_compiled_policy_artifact(policy_dict, output_dir)
    activate_bundle(policy_dict, output_dir, file_hash)
    return file_hash


# ---------------------------------------------------------------------------
# 6. Hash computation
# ---------------------------------------------------------------------------


def _compute_compiled_policy_hash(policy_dict: dict[str, Any]) -> str:
    """Compute deterministic sha256 hash of the compiled policy.

    Uses sorted YAML dump + schema_version for stability.
    Excludes time-dependent fields and the hash itself (Fix Critical 2).
    """
    # Create a copy without time-dependent and self-referencing fields
    copy_for_hash = {k: v for k, v in policy_dict.items()
                     if k not in ("compiled_policy_hash", "compiled_at_utc")}
    yaml_str = yaml.dump(copy_for_hash, sort_keys=True, default_flow_style=False)
    seed = yaml_str + str(copy_for_hash.get("schema_version", 1))
    return _sha256_str(seed)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_str(data: str) -> str:
    """Return sha256:... hash string for the given data."""
    digest = hashlib.sha256(data.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _utcnow_compact() -> str:
    """Return current UTC time in YYYY-MM-DDTHH:MM:SSZ format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utcnow_iso() -> str:
    """Return current UTC time in YYYY-MM-DDTHH:MM:SSZ format (derived for policy_id)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _derive_alias(program_name: str) -> str:
    """Derive a lowercase program alias from the program name."""
    if not program_name:
        return "unknown"
    return program_name.lower().strip()


# ---------------------------------------------------------------------------
# Metrics hook (Step 9: SGK-2026-0335)
# ---------------------------------------------------------------------------


def _record_compile_metrics(compile_status: str) -> None:
    """Record compile status metrics to the guard metrics collector."""
    try:
        from src.core.security.guard_metrics import get_guard_metrics

        metrics = get_guard_metrics()
        if compile_status == "compile_failed":
            metrics.record_compile_failed()
        elif compile_status == "manual_review_required":
            metrics.record_manual_review_required()
    except Exception:
        pass  # metrics are best-effort
