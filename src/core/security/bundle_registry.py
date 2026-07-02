"""
Bundle Registry: bundle storage, integrity, and data governance.

Implements:
- resolve_storage_path: canonical path resolution
- verify_active_mapping_integrity: 7-point integrity check (§13.8)
- scan_for_credentials: secret scanning (§13.4)
- validate_bundle_import: import validation (§13.4)
- prune_ephemeral_bundles: TTL cleanup (§13.8)
- list_orphaned_bundles: orphan detection
- get_bundle_retention_info: retention statistics
- atomic_activate: atomic activation write
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REQUIRED_ACTIVE_FIELDS = [
    "provider",
    "program_alias",
    "bundle_id",
    "policy_id",
    "compiled_policy_path",
    "compiled_policy_hash",
    "activated_at_utc",
]

REQUIRED_IMPORT_FILES = [
    "source_manifest.yaml",
    "policy.md",
    "review_findings.yaml",
    "overrides.yaml",
]

# Scope file patterns (at least one must exist)
SCOPE_FILE_PATTERNS = [
    "*.csv",
    "*.txt",
    "*.json",
    "scope_assets.*",
]

# Credential key patterns to scan for
CREDENTIAL_KEY_PATTERNS = re.compile(
    r"(api[_-]?key|token|password|secret|credential)", re.IGNORECASE
)

# Minimum length for a value to be considered a potential secret.
_MIN_SECRET_LENGTH = 12

# Embedded credential patterns inside string values (e.g. "token=ghp_abc...")
EMBEDDED_SECRET_PATTERN = re.compile(
    r"(api[\s_-]?key|token|password|secret)\s*[:=]\s*[" + "'" + r"\x27]?([a-zA-Z0-9+/=_.!@#$%^&*\-]{15,})",
    re.IGNORECASE,
)

# Env-var reference patterns (NOT secrets)
ENV_VAR_PATTERNS = [re.compile(r"^\$[A-Z_][A-Z0-9_]*$"), re.compile(r"^[A-Z_][A-Z0-9_]*$")]

# Ephemeral TTL in seconds (7 days)
EPHEMERAL_TTL_SECONDS = 7 * 86400

# ---------------------------------------------------------------------------
# BundleRegistry class
# ---------------------------------------------------------------------------


class BundleRegistry:
    """Registry for bug bounty program bundle storage and integrity."""

    def __init__(self, workspace_root: str = "workspace/bugbounty"):
        self._workspace_root = Path(workspace_root)

    # -----------------------------------------------------------------------
    # 1. resolve_storage_path
    # -----------------------------------------------------------------------

    def resolve_storage_path(
        self,
        provider: str,
        program_alias: str,
        bundle_id: str | None = None,
    ) -> Path:
        """Resolve the canonical storage path for a program/bundle.

        - Named bundle: ``{workspace_root}/programs/{provider}/{program_alias}/``
        - With bundle_id: ``.../bundles/{bundle_id}/``
        - Ephemeral: ``{workspace_root}/_ephemeral/{bundle_id}/``

        Args:
            provider: Provider name (e.g. ``hackerone``, ``bugcrowd``).
            program_alias: Program alias (e.g. ``tiktok``, ``fireblocks``).
            bundle_id: Optional bundle ID. If given and provider is empty,
                resolves as ephemeral.

        Returns:
            Resolved Path.
        """
        if not provider and bundle_id:
            # Ephemeral path
            return self._workspace_root / "_ephemeral" / bundle_id

        base = self._workspace_root / "programs" / provider / program_alias
        if bundle_id:
            return base / "bundles" / bundle_id
        return base

    # -----------------------------------------------------------------------
    # 2. verify_active_mapping_integrity
    # -----------------------------------------------------------------------

    def verify_active_mapping_integrity(
        self, provider: str, program_alias: str
    ) -> dict[str, Any]:
        """Run the 7-point active mapping integrity check (§13.8).

        Checks:
          1. active_bundle.json exists
          2. Has all required fields
          3. Referenced compiled_guard_policy.yaml exists
          4. compiled_policy_hash matches file hash
          5. Policy compile_status = ``ready``
          6. Policy bundle_id matches active_bundle.json
          7. Policy policy_id matches active_bundle.json

        Returns:
            Dict with ``valid`` (bool), ``checks`` (list of dicts),
            and ``error_summary`` (str).
        """
        checks: list[dict[str, Any]] = []
        bundle_dir = self.resolve_storage_path(provider, program_alias)
        active_json = bundle_dir / "active_bundle.json"

        # Check 1: active_bundle.json exists
        if not active_json.is_file():
            checks.append(
                {"check": "active_bundle_exists", "passed": False, "detail": "active_bundle.json not found"}
            )
            return {
                "valid": False,
                "checks": checks,
                "error_summary": "active_bundle.json not found",
            }
        checks.append(
            {"check": "active_bundle_exists", "passed": True, "detail": str(active_json)}
        )

        # Load active mapping
        try:
            active_data = json.loads(active_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            checks.append(
                {"check": "active_bundle_parse", "passed": False, "detail": str(e)}
            )
            return {
                "valid": False,
                "checks": checks,
                "error_summary": f"Failed to parse active_bundle.json: {e}",
            }

        # Check 2: Required fields present
        missing_fields = [f for f in REQUIRED_ACTIVE_FIELDS if not active_data.get(f)]
        if missing_fields:
            checks.append(
                {
                    "check": "required_fields",
                    "passed": False,
                    "detail": f"Missing fields: {', '.join(missing_fields)}",
                }
            )
            return {
                "valid": False,
                "checks": checks,
                "error_summary": f"Missing required fields: {', '.join(missing_fields)}",
            }
        checks.append(
            {"check": "required_fields", "passed": True, "detail": "all fields present"}
        )

        # Check 3: Referenced compiled_guard_policy.yaml exists
        policy_rel = active_data["compiled_policy_path"]
        policy_path = bundle_dir / policy_rel
        if not policy_path.is_file():
            checks.append(
                {
                    "check": "policy_file_exists",
                    "passed": False,
                    "detail": f"{policy_rel} not found",
                }
            )
            return {
                "valid": False,
                "checks": checks,
                "error_summary": f"compiled policy file not found: {policy_rel}",
            }
        checks.append(
            {"check": "policy_file_exists", "passed": True, "detail": str(policy_path)}
        )

        # Check 4: compiled_policy_hash matches file bytes
        expected_hash = active_data["compiled_policy_hash"]
        actual_hash = _sha256_file(policy_path)
        hash_ok = actual_hash == expected_hash
        checks.append(
            {
                "check": "hash_match",
                "passed": hash_ok,
                "detail": f"expected={expected_hash}, actual={actual_hash}",
            }
        )
        if not hash_ok:
            return {
                "valid": False,
                "checks": checks,
                "error_summary": f"Hash mismatch: expected={expected_hash}, actual={actual_hash}",
            }

        # Load policy YAML for remaining checks
        try:
            raw_policy = _load_yaml(policy_path)
        except Exception as e:
            checks.append(
                {"check": "policy_parse", "passed": False, "detail": str(e)}
            )
            return {
                "valid": False,
                "checks": checks,
                "error_summary": f"Failed to parse compiled policy: {e}",
            }

        # Check 5: compile_status = ready
        compile_status = raw_policy.get("compile_status", "")
        status_ok = compile_status == "ready"
        checks.append(
            {
                "check": "compile_status_ready",
                "passed": status_ok,
                "detail": f"status={compile_status}",
            }
        )
        if not status_ok:
            return {
                "valid": False,
                "checks": checks,
                "error_summary": f"compile_status is '{compile_status}', expected 'ready'",
            }

        # Check 6: bundle_id matches
        policy_bundle_id = raw_policy.get("bundle_id", "")
        active_bundle_id = active_data["bundle_id"]
        bundle_match = policy_bundle_id == active_bundle_id
        checks.append(
            {
                "check": "bundle_id_match",
                "passed": bundle_match,
                "detail": f"active={active_bundle_id}, policy={policy_bundle_id}",
            }
        )

        # Check 7: policy_id matches
        policy_policy_id = raw_policy.get("policy_id", "")
        active_policy_id = active_data["policy_id"]
        policy_match = policy_policy_id == active_policy_id
        checks.append(
            {
                "check": "policy_id_match",
                "passed": policy_match,
                "detail": f"active={active_policy_id}, policy={policy_policy_id}",
            }
        )

        all_passed = hash_ok and status_ok and bundle_match and policy_match
        error_summary = ""
        if not bundle_match:
            error_summary += f"bundle_id mismatch: active={active_bundle_id}, policy={policy_bundle_id}; "
        if not policy_match:
            error_summary += f"policy_id mismatch: active={active_policy_id}, policy={policy_policy_id}; "

        return {
            "valid": all_passed,
            "checks": checks,
            "error_summary": error_summary.strip("; "),
        }

    # -----------------------------------------------------------------------
    # 3. scan_for_credentials
    # -----------------------------------------------------------------------

    def scan_for_credentials(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan a dict for secret-like patterns.

        Flags values that match credential key names AND have values that look
        like real secrets (longer than 10 chars, not env var references).

        Args:
            data: Dict to scan (recursively).

        Returns:
            List of findings: ``[{"path": "overrides.auth.password", "risk": "high"}, ...]``
        """
        findings: list[dict[str, Any]] = []

        def _scan(obj: Any, path: str) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    if isinstance(value, str):
                        # Check if the key is a credential key
                        if CREDENTIAL_KEY_PATTERNS.search(key):
                            if _is_secret_value(value):
                                findings.append({"path": current_path, "risk": "high"})
                        # Check if the string VALUE contains an embedded secret pattern
                        _check_embedded_secret(value, current_path)
                    elif isinstance(value, (dict, list)):
                        _scan(value, current_path)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    current_path = f"{path}[{idx}]"
                    if isinstance(item, (dict, list)):
                        _scan(item, current_path)
                    elif isinstance(item, str):
                        if _is_secret_value(item):
                            findings.append({"path": current_path, "risk": "high"})
                        _check_embedded_secret(item, current_path)

        def _check_embedded_secret(value: str, current_path: str) -> None:
            """Check if a string value contains embedded credentials like token=xxx."""
            if EMBEDDED_SECRET_PATTERN.search(value):
                findings.append({"path": current_path, "risk": "high"})

        _scan(data, "")
        return findings

    # -----------------------------------------------------------------------
    # 4. validate_bundle_import
    # -----------------------------------------------------------------------

    def validate_bundle_import(self, bundle_dir: Path) -> dict[str, Any]:
        """Validate a bundle directory for import.

        Checks:
          - No secrets found in any bundle file (overrides, review_findings,
            policy, scope sources)
          - Credential references use env var format
          - Required files present

        Args:
            bundle_dir: Path to the bundle directory.

        Returns:
            Dict with ``valid``, ``errors``, ``warnings``.
        """
        bundle_dir = Path(bundle_dir)
        errors: list[str] = []
        warnings: list[str] = []

        # Check required files
        for req_file in REQUIRED_IMPORT_FILES:
            if not (bundle_dir / req_file).is_file():
                errors.append(f"Required file missing: {req_file}")

        # Check at least one scope file exists
        scope_files: list[Path] = []
        for pattern in SCOPE_FILE_PATTERNS:
            for match in sorted(bundle_dir.glob(pattern)):
                if match.is_file() and match not in scope_files:
                    scope_files.append(match)
        if not scope_files:
            errors.append("No scope file found (expected at least one *.csv, *.txt, or scope_assets.*)")

        # --- Secret scanning for structured files (YAML) ---
        def _scan_structured_file(file_path: Path, label: str) -> None:
            """Load a YAML file and scan the parsed dict for secrets."""
            if not file_path.is_file():
                return
            try:
                data = _load_yaml(file_path)
                findings = self.scan_for_credentials(data)
                for finding in findings:
                    errors.append(
                        f"Secret detected in {label} at path '{finding['path']}': {finding['risk']} risk"
                    )
            except Exception as e:
                warnings.append(f"Could not parse {label} for secret scan: {e}")

        # Scan overrides.yaml
        _scan_structured_file(bundle_dir / "overrides.yaml", "overrides.yaml")

        # Scan review_findings.yaml
        _scan_structured_file(bundle_dir / "review_findings.yaml", "review_findings.yaml")

        # --- Secret scanning for raw text files (policy.md, scope_assets.*) ---
        def _scan_raw_file(file_path: Path, label: str) -> None:
            """Read a file as raw text and scan for embedded secrets."""
            if not file_path.is_file():
                return
            try:
                raw_text = file_path.read_text(encoding="utf-8")
                # Wrap raw text in a dict so the embedded-secret pattern matcher runs
                findings = self.scan_for_credentials({"content": raw_text})
                for finding in findings:
                    errors.append(
                        f"Secret-like value found in {label}: {finding['risk']} risk"
                    )
            except Exception as e:
                warnings.append(f"Could not read {label} for secret scan: {e}")

        # Scan policy.md
        _scan_raw_file(bundle_dir / "policy.md", "policy.md")

        # Scan all discovered scope files
        for sf in scope_files:
            _scan_raw_file(sf, sf.name)

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    # -----------------------------------------------------------------------
    # 5. prune_ephemeral_bundles
    # -----------------------------------------------------------------------

    def prune_ephemeral_bundles(self, dry_run: bool = True) -> dict[str, Any]:
        """Remove ephemeral bundles older than 7 days.

        Args:
            dry_run: If True, only report what would be removed.

        Returns:
            Dict with ``pruned``, ``remaining``, ``dry_run``.
        """
        ephemeral_root = self._workspace_root / "_ephemeral"
        pruned = 0
        remaining = 0

        if not ephemeral_root.is_dir():
            return {"pruned": 0, "remaining": 0, "dry_run": dry_run}

        now = time.time()
        for entry in sorted(ephemeral_root.iterdir()):
            if not entry.is_dir():
                continue
            try:
                entry_mtime = entry.stat().st_mtime
            except OSError:
                remaining += 1
                continue

            age_seconds = now - entry_mtime
            if age_seconds > EPHEMERAL_TTL_SECONDS:
                if not dry_run:
                    shutil.rmtree(entry)
                pruned += 1
            else:
                remaining += 1

        return {"pruned": pruned, "remaining": remaining, "dry_run": dry_run}

    # -----------------------------------------------------------------------
    # 6. list_orphaned_bundles
    # -----------------------------------------------------------------------

    def list_orphaned_bundles(self) -> list[dict[str, Any]]:
        """Find bundles without valid active_bundle.json or with missing referenced files.

        Returns:
            List of orphan descriptions.
        """
        orphans: list[dict[str, Any]] = []

        programs_root = self._workspace_root / "programs"
        if not programs_root.is_dir():
            return orphans

        for provider_dir in sorted(programs_root.iterdir()):
            if not provider_dir.is_dir():
                continue
            provider_name = provider_dir.name
            for prog_dir in sorted(provider_dir.iterdir()):
                if not prog_dir.is_dir():
                    continue
                prog_name = prog_dir.name
                active_json = prog_dir / "active_bundle.json"

                if not active_json.is_file():
                    # Directory exists but no active mapping -> orphan
                    orphans.append(
                        {
                            "provider": provider_name,
                            "program_alias": prog_name,
                            "bundle_dir": str(prog_dir),
                            "reason": "no active_bundle.json",
                        }
                    )
                    continue

                # active_bundle.json exists, check it
                try:
                    active_data = json.loads(active_json.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    orphans.append(
                        {
                            "provider": provider_name,
                            "program_alias": prog_name,
                            "bundle_dir": str(prog_dir),
                            "reason": "corrupt active_bundle.json",
                        }
                    )
                    continue

                # Check referenced policy exists
                policy_rel = active_data.get("compiled_policy_path", "")
                if not policy_rel:
                    orphans.append(
                        {
                            "provider": provider_name,
                            "program_alias": prog_name,
                            "bundle_dir": str(prog_dir),
                            "reason": "compiled_policy_path missing from active_bundle.json",
                        }
                    )
                    continue

                policy_path = prog_dir / policy_rel
                if not policy_path.is_file():
                    orphans.append(
                        {
                            "provider": provider_name,
                            "program_alias": prog_name,
                            "bundle_dir": str(prog_dir),
                            "reason": f"referenced policy file missing: {policy_rel}",
                        }
                    )
                    continue

        return orphans

    # -----------------------------------------------------------------------
    # 7. get_bundle_retention_info
    # -----------------------------------------------------------------------

    def get_bundle_retention_info(
        self, provider: str, program_alias: str
    ) -> dict[str, Any]:
        """Get retention statistics for a program's bundles.

        Returns:
            Dict with ``total_bundles``, ``active_bundle_id``, ``superseded_count``,
            ``ephemeral_count``.
        """
        program_dir = self.resolve_storage_path(provider, program_alias)
        bundles_dir = program_dir / "bundles"

        total_bundles = 0
        if bundles_dir.is_dir():
            total_bundles = sum(1 for d in bundles_dir.iterdir() if d.is_dir())

        active_bundle_id = None
        active_json = program_dir / "active_bundle.json"
        if active_json.is_file():
            try:
                data = json.loads(active_json.read_text(encoding="utf-8"))
                active_bundle_id = data.get("bundle_id")
            except (json.JSONDecodeError, OSError):
                pass

        superseded_count = max(0, total_bundles - 1) if active_bundle_id else total_bundles

        ephemeral_dir = self._workspace_root / "_ephemeral"
        ephemeral_count = 0
        if ephemeral_dir.is_dir():
            ephemeral_count = sum(1 for d in ephemeral_dir.iterdir() if d.is_dir())

        return {
            "total_bundles": total_bundles,
            "active_bundle_id": active_bundle_id,
            "superseded_count": superseded_count,
            "ephemeral_count": ephemeral_count,
        }

    # -----------------------------------------------------------------------
    # 8. atomic_activate
    # -----------------------------------------------------------------------

    def atomic_activate(
        self,
        provider: str,
        program_alias: str,
        bundle_id: str,
        policy_id: str,
        compiled_policy_hash: str,
        compiled_policy_path: str,
    ) -> None:
        """Write active_bundle.json atomically.

        Validates all required fields, writes to temp file, then renames.

        Args:
            provider: Provider name.
            program_alias: Program alias.
            bundle_id: Bundle identifier.
            policy_id: Policy identifier.
            compiled_policy_hash: SHA256 hash of compiled policy file.
            compiled_policy_path: Path to compiled policy (relative to bundle dir).

        Raises:
            ValueError: If any required field is empty.
        """
        # Validate required fields
        fields = {
            "provider": provider,
            "program_alias": program_alias,
            "bundle_id": bundle_id,
            "policy_id": policy_id,
            "compiled_policy_hash": compiled_policy_hash,
            "compiled_policy_path": compiled_policy_path,
        }
        for key, value in fields.items():
            if not value:
                raise ValueError(f"Required field '{key}' cannot be empty")

        bundle_dir = self.resolve_storage_path(provider, program_alias)
        bundle_dir.mkdir(parents=True, exist_ok=True)

        activated_at_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        active_data = {
            "provider": provider,
            "program_alias": program_alias,
            "bundle_id": bundle_id,
            "policy_id": policy_id,
            "compiled_policy_path": compiled_policy_path,
            "compiled_policy_hash": compiled_policy_hash,
            "activated_at_utc": activated_at_utc,
        }

        active_path = bundle_dir / "active_bundle.json"
        tmp_path = bundle_dir / "active_bundle.json.tmp"

        # Write to temp file, then rename for atomicity
        tmp_path.write_text(
            json.dumps(active_data, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp_path, active_path)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Compute sha256 hash of a file as ``sha256:hexdigest``."""
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return f"sha256:{digest}"


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and parse a YAML file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise yaml.YAMLError(f"Expected a YAML mapping, got {type(data).__name__}")
    return data


def _is_secret_value(value: str) -> bool:
    """Check if a string value looks like a real credential.

    Returns True if the value:
      - Is longer than _MIN_SECRET_LENGTH characters
      - Is NOT an env var reference ($VAR or ALL_CAPS)
    """
    if value is None or not isinstance(value, str):
        return False
    if len(value) < _MIN_SECRET_LENGTH:
        return False

    # If value is clearly an env var reference, it's not a secret
    for pattern in ENV_VAR_PATTERNS:
        if pattern.match(value):
            return False

    return True
