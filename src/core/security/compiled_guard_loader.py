"""
Compiled Guard Loader: resolve active bundle and load compiled_guard_policy.yaml.

Responsible for:
- Resolving an active bundle from ``--program`` alias or ``--bundle-id``.
- Reading ``active_bundle.json``.
- Loading and validating ``compiled_guard_policy.yaml``.
- Checking compile_status, hash integrity, and schema compatibility.
- Returning ``LoadedGuardPolicy`` on success or ``GuardLoadError`` on failure.

Phase 1 only: directory-based resolution using explicit bundle_dir or
sidecar active_bundle.json / compiled_guard_policy.yaml paths.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from src.core.security.compiled_guard_models import (
    GuardLoadError,
    LoadedGuardPolicy,
)

logger = logging.getLogger(__name__)

# Allowed compile_status values for runtime use.
_READY_STATUS = "ready"

# Reader-version: the maximum schema_version this reader can consume.
_SUPPORTED_READER_SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Reason codes for loader failures
# ---------------------------------------------------------------------------

REASON_ACTIVE_BUNDLE_MISSING = "active_bundle_missing"
REASON_ACTIVE_BUNDLE_REFERENCE_MISSING = "active_bundle_reference_missing"
REASON_POLICY_UNAVAILABLE = "policy_unavailable"
REASON_POLICY_NOT_READY = "policy_not_ready"
REASON_POLICY_INTEGRITY_ERROR = "policy_integrity_error"
REASON_POLICY_SCHEMA_UNSUPPORTED = "policy_schema_unsupported"
REASON_BUNDLE_PROGRAM_MISMATCH = "bundle_program_mismatch"


# ---------------------------------------------------------------------------
# Metrics helper (Step 9: SGK-2026-0335)
# ---------------------------------------------------------------------------


def _record_load_failure() -> None:
    """Record an ``active_bundle_read_failure`` metric."""
    try:
        from src.core.security.guard_metrics import get_guard_metrics

        get_guard_metrics().record_active_bundle_read_failure()
    except Exception:
        pass  # metrics are best-effort


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_active_policy_from_bundle_dir(
    bundle_dir: Union[str, Path],
    expected_program: Optional[str] = None,
) -> Union[LoadedGuardPolicy, GuardLoadError]:
    """Resolve active bundle from a directory containing active_bundle.json.

    Args:
        bundle_dir: Path to the bundle directory (e.g.
                    ``workspace/bugbounty/programs/hackerone/tiktok/``).
        expected_program: If set, validate ``program_alias`` matches.

    Returns:
        ``LoadedGuardPolicy`` on success, ``GuardLoadError`` on any failure.
    """
    result = _load_active_policy_from_bundle_dir_impl(bundle_dir, expected_program)
    if isinstance(result, GuardLoadError):
        _record_load_failure()
    return result


def _load_active_policy_from_bundle_dir_impl(
    bundle_dir: Union[str, Path],
    expected_program: Optional[str] = None,
) -> Union[LoadedGuardPolicy, GuardLoadError]:
    """Implementation (metrics are recorded by the outer wrapper)."""
    bundle_path = Path(bundle_dir)
    if not bundle_path.is_dir():
        return GuardLoadError(
            reason_code=REASON_ACTIVE_BUNDLE_MISSING,
            message=f"Bundle directory does not exist: {bundle_dir}",
            details={"bundle_dir": str(bundle_dir)},
        )

    # 1. Load active_bundle.json
    active_json = bundle_path / "active_bundle.json"
    if not active_json.exists():
        return GuardLoadError(
            reason_code=REASON_ACTIVE_BUNDLE_MISSING,
            message=f"active_bundle.json not found in {bundle_dir}",
            details={"expected_path": str(active_json)},
        )

    try:
        with open(active_json, "r", encoding="utf-8") as fh:
            active = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        return GuardLoadError(
            reason_code=REASON_ACTIVE_BUNDLE_MISSING,
            message=f"Failed to parse active_bundle.json: {exc}",
            details={"active_bundle_path": str(active_json)},
        )

    # Validate required fields
    for key in ("bundle_id", "policy_id", "compiled_policy_path", "compiled_policy_hash", "program_alias", "provider"):
        if not active.get(key):
            return GuardLoadError(
                reason_code=REASON_ACTIVE_BUNDLE_REFERENCE_MISSING,
                message=f"active_bundle.json missing required field: {key}",
                details={"active_bundle_path": str(active_json), "missing_field": key},
            )

    # Check program alias match
    if expected_program and active.get("program_alias", "") != expected_program:
        return GuardLoadError(
            reason_code=REASON_BUNDLE_PROGRAM_MISMATCH,
            message=f"Program alias mismatch: expected={expected_program}, got={active.get('program_alias')}",
            details={
                "expected_program": expected_program,
                "actual_program": active.get("program_alias"),
            },
        )

    # 2. Locate compiled_guard_policy.yaml
    policy_rel = active["compiled_policy_path"]
    policy_path = _resolve_policy_path(bundle_path, policy_rel)
    if policy_path is None or not policy_path.exists():
        return GuardLoadError(
            reason_code=REASON_POLICY_UNAVAILABLE,
            message=f"compiled_guard_policy.yaml not found: {policy_rel}",
            details={"bundle_dir": str(bundle_path), "compiled_policy_path": policy_rel},
        )

    # 3. Load compiled_guard_policy.yaml
    try:
        raw_policy = _load_yaml(policy_path)
    except (yaml.YAMLError, OSError) as exc:
        return GuardLoadError(
            reason_code=REASON_POLICY_UNAVAILABLE,
            message=f"Failed to load compiled_guard_policy.yaml: {exc}",
            details={"policy_path": str(policy_path)},
        )

    # 4. Check compile_status
    compile_status = raw_policy.get("compile_status", "")
    if compile_status != _READY_STATUS:
        return GuardLoadError(
            reason_code=REASON_POLICY_NOT_READY,
            message=f"Policy compile_status is '{compile_status}', expected '{_READY_STATUS}'",
            details={"policy_path": str(policy_path), "compile_status": compile_status},
        )

    # 5. Check schema_version compatibility (both lower and upper bounds)
    schema_version = raw_policy.get("schema_version", 0)
    compat = raw_policy.get("compatibility", {})
    min_reader = compat.get("min_reader_schema_version", 1)
    backward_compat = compat.get("backward_compatible_with", [])
    if not isinstance(backward_compat, list):
        backward_compat = [backward_compat]

    sv_int = int(schema_version)
    mr_int = int(min_reader)

    if sv_int < mr_int:
        return GuardLoadError(
            reason_code=REASON_POLICY_SCHEMA_UNSUPPORTED,
            message=f"Schema version {sv_int} < min_reader {mr_int}",
            details={
                "policy_path": str(policy_path),
                "schema_version": sv_int,
                "min_reader": mr_int,
            },
        )

    if sv_int > _SUPPORTED_READER_SCHEMA_VERSION:
        return GuardLoadError(
            reason_code=REASON_POLICY_SCHEMA_UNSUPPORTED,
            message=(
                f"Schema version {sv_int} exceeds reader supported version "
                f"{_SUPPORTED_READER_SCHEMA_VERSION}"
            ),
            details={
                "policy_path": str(policy_path),
                "schema_version": sv_int,
                "supported_reader_version": _SUPPORTED_READER_SCHEMA_VERSION,
            },
        )

    if mr_int > _SUPPORTED_READER_SCHEMA_VERSION:
        return GuardLoadError(
            reason_code=REASON_POLICY_SCHEMA_UNSUPPORTED,
            message=(
                f"min_reader_schema_version {mr_int} exceeds reader supported "
                f"version {_SUPPORTED_READER_SCHEMA_VERSION}"
            ),
            details={
                "policy_path": str(policy_path),
                "min_reader": mr_int,
                "supported_reader_version": _SUPPORTED_READER_SCHEMA_VERSION,
            },
        )

    if _SUPPORTED_READER_SCHEMA_VERSION not in backward_compat:
        return GuardLoadError(
            reason_code=REASON_POLICY_SCHEMA_UNSUPPORTED,
            message=(
                f"Reader version {_SUPPORTED_READER_SCHEMA_VERSION} is not in "
                f"backward_compatible_with: {backward_compat}"
            ),
            details={
                "policy_path": str(policy_path),
                "backward_compatible_with": backward_compat,
                "supported_reader_version": _SUPPORTED_READER_SCHEMA_VERSION,
            },
        )

    # 6. Verify compiled_policy_hash against active mapping
    expected_hash = active["compiled_policy_hash"]
    try:
        with open(policy_path, "rb") as fh:
            file_bytes = fh.read()
        actual_hash = f"sha256:{hashlib.sha256(file_bytes).hexdigest()}"
    except OSError as exc:
        return GuardLoadError(
            reason_code=REASON_POLICY_UNAVAILABLE,
            message=f"Failed to read policy for hash verification: {exc}",
            details={"policy_path": str(policy_path)},
        )

    if actual_hash != expected_hash:
        return GuardLoadError(
            reason_code=REASON_POLICY_INTEGRITY_ERROR,
            message=f"Policy hash mismatch: expected={expected_hash}, actual={actual_hash}",
            details={
                "policy_path": str(policy_path),
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
            },
        )

    # 7. Verify self-consistency: policy's own fields match active mapping
    if raw_policy.get("bundle_id", "") != active["bundle_id"]:
        return GuardLoadError(
            reason_code=REASON_POLICY_INTEGRITY_ERROR,
            message="bundle_id mismatch between active mapping and compiled policy",
            details={
                "active_bundle_id": active["bundle_id"],
                "policy_bundle_id": raw_policy.get("bundle_id"),
            },
        )
    if raw_policy.get("policy_id", "") != active["policy_id"]:
        return GuardLoadError(
            reason_code=REASON_POLICY_INTEGRITY_ERROR,
            message="policy_id mismatch between active mapping and compiled policy",
            details={
                "active_policy_id": active["policy_id"],
                "policy_policy_id": raw_policy.get("policy_id"),
            },
        )

    # 8. Build loaded policy
    return LoadedGuardPolicy(
        bundle_id=active["bundle_id"],
        policy_id=active["policy_id"],
        provider=active.get("provider", raw_policy.get("provider", "")),
        program_name=raw_policy.get("program_name", active.get("program_alias", "")),
        program_alias=active.get("program_alias", ""),
        compiled_policy_path=str(policy_path),
        compiled_policy_hash=active["compiled_policy_hash"],
        schema_version=int(raw_policy.get("schema_version", 1)),
        compile_status=compile_status,
        raw_policy=raw_policy,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_policy_path(bundle_dir: Path, policy_rel: str) -> Optional[Path]:
    """Resolve compiled_policy_path relative to bundle_dir or absolute."""
    candidate = Path(policy_rel)
    if candidate.is_absolute():
        return candidate
    # Check relative to bundle_dir
    resolved = bundle_dir / policy_rel
    if resolved.exists():
        return resolved
    # Fallback: check if it's relative to workspace bugbounty root
    # (for test fixtures where policy is in same dir as active_bundle.json)
    return bundle_dir / policy_rel


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and parse a YAML file, returning a dict."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise yaml.YAMLError(f"Expected a YAML mapping, got {type(data).__name__}")
    return data
