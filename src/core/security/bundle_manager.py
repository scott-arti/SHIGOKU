"""
Bundle Manager: lifecycle operations for bug bounty program bundles.

Responsible for:
- import_bundle: create program_bundle/ snapshot from raw inputs
- compile_bundle: run adapter + compiler to produce compiled_guard_policy.yaml
- activate_bundle_manager: activate a compiled bundle for runtime use
- list_bundles / show_bundle: inspection operations
- run_preflight: pre-execution validation (program resolution, scope check)
- rollback_bundle: re-activate a previous bundle version

Contract defined in:
  docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
  Sections 11-12.

Storage layout (spec 13.8):
  {workspace_root}/programs/{provider}/{program_alias}/
    active_bundle.json
    compiled_guard_policy.yaml
    bundles/{bundle_id}/
      source_manifest.yaml
      policy.md
      scope_assets.csv / scope_assets.txt
      review_findings.yaml
      overrides.yaml
"""
from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import yaml

from .compiled_guard_compiler import (
    activate_bundle as _compiler_activate,
    compile_guard_policy,
    write_compiled_policy_artifact,
    write_compiled_policy_to_dir,
)
from .compiled_guard_loader import (
    GuardLoadError,
    LoadedGuardPolicy,
    load_active_policy_from_bundle_dir,
)
from .hackerone_adapter import HackerOneAdapter
from .bugcrowd_adapter import BugcrowdAdapter
from .review_overrides import load_review_findings, load_overrides
from .bundle_registry import BundleRegistry


# ---------------------------------------------------------------------------
# BundleManager
# ---------------------------------------------------------------------------


class BundleManager:
    """Manage the lifecycle of bug bounty program bundles.

    Handles import, compile, activate, list, show, preflight, and rollback
    operations for program bundles stored in the workspace.
    """

    def __init__(self, workspace_root: Union[str, Path] = "workspace/bugbounty"):
        self._workspace_root = Path(workspace_root)
        self._programs_dir = self._workspace_root / "programs"
        self._registry = BundleRegistry(str(workspace_root))

    # -----------------------------------------------------------------------
    # 1. import_bundle
    # -----------------------------------------------------------------------

    def import_bundle(
        self,
        provider: str,
        program_name: str,
        policy_path: str,
        scope_path: str,
        program_alias: Optional[str] = None,
        captured_at_utc: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create a program_bundle/ snapshot from raw source files.

        Args:
            provider: ``hackerone`` or ``bugcrowd``.
            program_name: Human-readable program name.
            policy_path: Path to policy.md file to copy.
            scope_path: Path to scope_assets.csv or .txt file to copy.
            program_alias: Short alias (default: lowercased program_name).
            captured_at_utc: Optional capture timestamp (RFC3339 UTC).

        Returns:
            Dict with ``bundle_id``, ``bundle_dir``, ``status``.
        """
        alias = program_alias or program_name.lower().replace(" ", "")
        timestamp = captured_at_utc or _utcnow_compact()
        short_hash = _short_hash(provider + alias + timestamp)

        bundle_id = f"bbp-{provider}-{alias}-{timestamp.replace(':', '')}-{short_hash}"

        # Scan raw policy and scope for credential-like values BEFORE writing (Fix 1)
        policy_src = Path(policy_path)
        scope_src = Path(scope_path)
        policy_text = policy_src.read_text(encoding="utf-8")
        scope_text = scope_src.read_text(encoding="utf-8")
        secret_findings = self._registry.scan_for_credentials({
            "policy_text": policy_text,
            "scope_text": scope_text,
        })
        if secret_findings:
            raise ValueError(
                f"Secret-like values found in policy/scope input. "
                f"Rejecting import. Findings: {secret_findings}"
            )

        # Create bundle directory
        bundle_dir = self._resolve_program_dir(provider, alias) / "bundles" / bundle_id
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # Determine scope file extension
        scope_ext = scope_src.suffix  # .csv or .txt
        scope_kind = "hackerone_csv" if scope_ext == ".csv" else "extracted_scope_block"
        scope_dest = f"scope_assets{scope_ext}"

        # Write source_manifest.yaml
        manifest = {
            "schema_version": 1,
            "provider": provider,
            "program_name": program_name,
            "program_alias": alias,
            "captured_at_utc": timestamp,
            "default_timezone": "UTC",
            "bundle_id": bundle_id,
            "policy_path": "policy.md",
            "scope_sources": [
                {"kind": scope_kind, "path": scope_dest},
            ],
        }
        (bundle_dir / "source_manifest.yaml").write_text(
            yaml.dump(manifest, sort_keys=False), encoding="utf-8"
        )

        # Copy policy and scope files
        shutil.copy2(str(policy_path), str(bundle_dir / "policy.md"))
        shutil.copy2(str(scope_path), str(bundle_dir / scope_dest))

        # Create empty review_findings.yaml and overrides.yaml stubs
        (bundle_dir / "review_findings.yaml").write_text("review_findings: []\n", encoding="utf-8")
        (bundle_dir / "overrides.yaml").write_text("overrides: {}\n", encoding="utf-8")

        return {
            "bundle_id": bundle_id,
            "bundle_dir": str(bundle_dir),
            "status": "imported",
        }

    # -----------------------------------------------------------------------
    # 2. compile_bundle
    # -----------------------------------------------------------------------

    def compile_bundle(
        self,
        bundle_dir: Union[str, Path],
    ) -> dict[str, Any]:
        """Compile a bundle: run adapter + compiler, write compiled policy.

        Args:
            bundle_dir: Path to the bundle snapshot directory (containing
                        source_manifest.yaml, policy.md, etc.).

        Returns:
            Dict with ``bundle_id``, ``compile_status``, ``blocking_findings``,
            ``policy_path``.
        """
        bp = Path(bundle_dir)
        manifest = _load_yaml(bp / "source_manifest.yaml")
        provider = manifest.get("provider", "")
        bundle_id = manifest.get("bundle_id", "")

        # Select adapter based on provider
        adapter = _select_adapter(provider, bp)
        facts = adapter.process()

        # Load review and overrides from the bundle dir
        try:
            review_findings = load_review_findings(bp / "review_findings.yaml")
        except (FileNotFoundError, ValueError):
            review_findings = {"review_findings": []}

        try:
            overrides = load_overrides(bp / "overrides.yaml")
        except (FileNotFoundError, ValueError):
            overrides = {"overrides": {}}

        # Compile
        import time as _time
        _compile_start = _time.monotonic()
        policy = compile_guard_policy(facts, review_findings, overrides)
        compile_status = policy.get("compile_status", "compile_failed")
        # Record compile-to-ready duration (Step 9: SGK-2026-0335)
        if compile_status == "ready":
            try:
                from src.core.security.guard_metrics import get_guard_metrics
                _elapsed = _time.monotonic() - _compile_start
                get_guard_metrics().bundle_import_to_ready_seconds.observe(_elapsed)
            except Exception:
                pass
        blocking_findings = policy.get("review_gate", {}).get("blocking_findings", [])

        # Write compiled policy artifact to bundle dir
        policy_path = bp / "compiled_guard_policy.yaml"
        write_compiled_policy_artifact(policy, bp)

        return {
            "bundle_id": bundle_id,
            "compile_status": compile_status,
            "blocking_findings": blocking_findings,
            "policy_path": str(policy_path),
        }

    # -----------------------------------------------------------------------
    # 3. activate_bundle_manager
    # -----------------------------------------------------------------------

    def activate_bundle_manager(
        self,
        bundle_dir: Union[str, Path],
    ) -> dict[str, Any]:
        """Activate a compiled bundle for runtime use.

        Reads compiled_guard_policy.yaml from the bundle snapshot dir,
        then atomically writes the artifact and active_bundle.json to the
        program directory via BundleRegistry.atomic_activate.

        Args:
            bundle_dir: Path to the bundle snapshot directory.

        Returns:
            Dict with ``bundle_id``, ``activated_at_utc``, ``status``.

        Raises:
            ValueError: If compile_status is not ``ready``.
        """
        bp = Path(bundle_dir)
        policy = _load_yaml(bp / "compiled_guard_policy.yaml")

        compile_status = policy.get("compile_status", "")
        if compile_status != "ready":
            raise ValueError(
                f"Cannot activate bundle with compile_status='{compile_status}'. "
                f"Only 'ready' bundles can be activated."
            )

        provider = policy.get("provider", "")
        program_alias = policy.get("program_alias", "")
        bundle_id = policy.get("bundle_id", "")
        policy_id = policy.get("policy_id", "")

        # Determine program directory
        program_dir = self._resolve_program_dir(provider, program_alias)
        program_dir.mkdir(parents=True, exist_ok=True)

        # Write compiled policy artifact to program dir (Fix 3)
        artifact_hash = write_compiled_policy_artifact(policy, program_dir)

        # Activate atomically via registry
        self._registry.atomic_activate(
            provider=provider,
            program_alias=program_alias,
            bundle_id=bundle_id,
            policy_id=policy_id,
            compiled_policy_hash=artifact_hash,
            compiled_policy_path="compiled_guard_policy.yaml",
        )

        return {
            "bundle_id": bundle_id,
            "activated_at_utc": _utcnow_compact(),
            "status": "activated",
        }

    # -----------------------------------------------------------------------
    # 4. list_bundles
    # -----------------------------------------------------------------------

    def list_bundles(
        self,
        provider: Optional[str] = None,
        program_alias: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """List all bundles in the storage tree.

        Args:
            provider: Filter by provider (optional).
            program_alias: Filter by program alias (optional).

        Returns:
            List of bundle info dicts.
        """
        results: list[dict[str, Any]] = []

        if not self._programs_dir.exists():
            return results

        for prov_dir in sorted(self._programs_dir.iterdir()):
            if not prov_dir.is_dir():
                continue
            prov_name = prov_dir.name
            if provider and prov_name != provider:
                continue

            for prog_dir in sorted(prov_dir.iterdir()):
                if not prog_dir.is_dir():
                    continue
                prog_name = prog_dir.name
                if program_alias and prog_name != program_alias:
                    continue

                # Look at active_bundle.json for activation info
                active_json = prog_dir / "active_bundle.json"
                activated = active_json.exists()

                # Look at bundles/ subdirectories
                bundles_dir = prog_dir / "bundles"
                if not bundles_dir.exists():
                    continue

                for bundle_dir in sorted(bundles_dir.iterdir()):
                    if not bundle_dir.is_dir():
                        continue
                    bid = bundle_dir.name
                    manifest = {}
                    compile_status = "unknown"
                    created_at = ""

                    manifest_path = bundle_dir / "source_manifest.yaml"
                    if manifest_path.exists():
                        manifest = _load_yaml(manifest_path)
                        created_at = manifest.get("captured_at_utc", "")

                    compiled_path = bundle_dir / "compiled_guard_policy.yaml"
                    if compiled_path.exists():
                        cp = _load_yaml(compiled_path)
                        compile_status = cp.get("compile_status", "unknown")

                    results.append({
                        "bundle_id": bid,
                        "bundle_dir": str(bundle_dir),
                        "provider": prov_name,
                        "program_alias": prog_name,
                        "compile_status": compile_status,
                        "activated": activated,
                        "created_at": created_at,
                    })

        return results

    # -----------------------------------------------------------------------
    # 5. show_bundle
    # -----------------------------------------------------------------------

    def show_bundle(
        self,
        bundle_id_or_dir: Union[str, Path],
    ) -> dict[str, Any]:
        """Show detailed info about a specific bundle.

        Args:
            bundle_id_or_dir: Bundle ID string or path to bundle directory.

        Returns:
            Dict with manifest, compile status, scope summary, activation info.
        """
        bp = Path(bundle_id_or_dir)
        # If it's not a directory, try to find it by bundle_id
        if not bp.is_dir():
            bp = self._find_bundle_by_id(str(bundle_id_or_dir))
            if bp is None:
                raise ValueError(f"Bundle not found: {bundle_id_or_dir}")

        manifest = {}
        manifest_path = bp / "source_manifest.yaml"
        if manifest_path.exists():
            manifest = _load_yaml(manifest_path)

        compile_status = "not_compiled"
        scope = None
        compiled_path = bp / "compiled_guard_policy.yaml"
        if compiled_path.exists():
            cp = _load_yaml(compiled_path)
            compile_status = cp.get("compile_status", "unknown")
            scope = cp.get("scope", {})

        bundle_id = manifest.get("bundle_id", bp.name)
        provider = manifest.get("provider", "")
        program_alias = manifest.get("program_alias", "")
        created_at = manifest.get("captured_at_utc", "")

        # Check activation
        activated = False
        if provider and program_alias:
            program_dir = self._resolve_program_dir(provider, program_alias)
            active_json = program_dir / "active_bundle.json"
            if active_json.exists():
                active_data = json.loads(active_json.read_text())
                activated = active_data.get("bundle_id") == bundle_id

        result: dict[str, Any] = {
            "bundle_id": bundle_id,
            "bundle_dir": str(bp),
            "manifest": manifest,
            "compile_status": compile_status,
            "activated": activated,
            "created_at": created_at,
        }

        if scope:
            result["scope"] = scope
            result["allow_hosts"] = scope.get("allow_hosts", [])
            result["deny_hosts"] = scope.get("deny_hosts", [])

        return result

    # -----------------------------------------------------------------------
    # 6. run_preflight
    # -----------------------------------------------------------------------

    def run_preflight(
        self,
        mode: str = "bugbounty",
        program: Optional[str] = None,
        bundle_id: Optional[str] = None,
        bundle_dir: Optional[str] = None,
        scope_opt: Optional[str] = None,
        target: Optional[str] = None,
        provider: str = "",
    ) -> dict[str, Any]:
        """Pre-execution validation before starting a bug bounty run.

        Args:
            mode: Operation mode (``bugbounty``).
            program: Program alias to resolve.
            bundle_id: Explicit bundle ID to pin.
            bundle_dir: Direct path to a bundle directory.
            scope_opt: [DEPRECATED] Do not use ``--scope`` with bug bounty mode.
            target: Optional target URL to validate against the policy.
            provider: Optional provider filter.

        Returns:
            Dict with ``policy``, ``bundle_id``, ``policy_id``, ``status``.

        Raises:
            ValueError: If mode is bugbounty and scope_opt is provided.
        """
        # Legacy scope rejection
        if mode == "bugbounty" and scope_opt is not None:
            raise ValueError(
                "--mode bugbounty requires --program or --bundle-id, not --scope. "
                "Use shigoku bugbounty bundle import/compile/activate to set up "
                "a program bundle first."
            )

        # Resolve bundle
        if bundle_dir:
            # Direct directory
            load_result = load_active_policy_from_bundle_dir(bundle_dir)
        elif bundle_id:
            # Search by bundle_id
            load_result = self._resolve_bundle_by_id(bundle_id, provider)
        elif program:
            # Search by program alias
            load_result = self._resolve_bundle_by_program(program, provider)
        else:
            return {
                "status": "error",
                "reason": "No program, bundle_id, or bundle_dir provided",
            }

        # Handle loader errors
        if isinstance(load_result, GuardLoadError):
            return {
                "status": "error",
                "reason_code": load_result.reason_code,
                "message": load_result.message,
                "details": load_result.details if hasattr(load_result, "details") else {},
            }

        # At this point, load_result is LoadedGuardPolicy
        policy: LoadedGuardPolicy = load_result

        # Fix 2: If both bundle_id and program given, verify they match
        if bundle_id and program:
            resolved_alias = policy.program_alias
            if resolved_alias != program:
                return {
                    "error": True,
                    "status": "error",
                    "reason_code": "bundle_program_mismatch",
                    "message": (
                        f"Program alias '{program}' does not match resolved "
                        f"bundle program '{resolved_alias}' (bundle_id={bundle_id})"
                    ),
                }

        # Optional target check
        if target:
            _quick_target_check(policy, target)

        return {
            "policy": policy,
            "bundle_id": policy.bundle_id,
            "policy_id": policy.policy_id,
            "status": "ready",
        }

    # -----------------------------------------------------------------------
    # 7. rollback_bundle
    # -----------------------------------------------------------------------

    def rollback_bundle(
        self,
        program_alias: str,
        target_bundle_id: str,
        provider: str = "",
    ) -> dict[str, Any]:
        """Rollback to a previous bundle version.

        Finds the target bundle in storage and re-activates it.

        Args:
            program_alias: Program alias.
            target_bundle_id: Bundle ID to rollback to.
            provider: Provider filter (optional).

        Returns:
            Dict with ``bundle_id``, ``activated_at_utc``, ``status``.

        Raises:
            ValueError: If bundle not found or compile_status is not ready.
        """
        # Find the bundle directory
        bundle_dir = self._find_bundle_in_workspace(program_alias, target_bundle_id, provider)
        if bundle_dir is None:
            raise ValueError(
                f"Bundle {target_bundle_id} not found for program '{program_alias}'"
            )

        # Load compiled policy
        compiled_path = bundle_dir / "compiled_guard_policy.yaml"
        if not compiled_path.exists():
            raise ValueError(
                f"Bundle {target_bundle_id} has no compiled_guard_policy.yaml"
            )

        policy = _load_yaml(compiled_path)
        compile_status = policy.get("compile_status", "")
        if compile_status != "ready":
            raise ValueError(
                f"Cannot rollback to bundle with compile_status='{compile_status}'. "
                f"Only 'ready' bundles can be activated."
            )

        prov = policy.get("provider", provider)
        alias = policy.get("program_alias", program_alias)
        bundle_id = policy.get("bundle_id", target_bundle_id)
        policy_id = policy.get("policy_id", "")

        # Activate atomically via registry (Fix 3)
        program_dir = self._resolve_program_dir(prov, alias)
        program_dir.mkdir(parents=True, exist_ok=True)
        artifact_hash = write_compiled_policy_artifact(policy, program_dir)
        self._registry.atomic_activate(
            provider=prov,
            program_alias=alias,
            bundle_id=bundle_id,
            policy_id=policy_id,
            compiled_policy_hash=artifact_hash,
            compiled_policy_path="compiled_guard_policy.yaml",
        )

        return {
            "bundle_id": target_bundle_id,
            "activated_at_utc": _utcnow_compact(),
            "status": "activated",
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _resolve_program_dir(self, provider: str, program_alias: str) -> Path:
        """Return the storage path for a specific program."""
        return self._programs_dir / provider / program_alias

    def _resolve_bundle_by_program(
        self, program: str, provider: str = ""
    ) -> Union[LoadedGuardPolicy, GuardLoadError]:
        """Resolve active bundle by program alias.

        Mirrors master_conductor._resolve_bundle_by_program pattern.
        """
        base = self._programs_dir
        if not base.exists():
            return GuardLoadError(
                reason_code="active_bundle_missing",
                message=f"Bug bounty programs base directory not found: {base}",
                details={"base_dir": str(base), "program": program},
            )

        candidates: list[Path] = []
        if provider:
            candidate = base / provider / program
            if candidate.is_dir():
                candidates.append(candidate)
        else:
            try:
                for prov_dir in sorted(base.iterdir()):
                    if not prov_dir.is_dir():
                        continue
                    candidate = prov_dir / program
                    if candidate.is_dir():
                        candidates.append(candidate)
            except OSError:
                pass

        if not candidates:
            return GuardLoadError(
                reason_code="active_bundle_missing",
                message=f"No bundle directory found for program '{program}'",
                details={"base_dir": str(base), "program": program},
            )

        return load_active_policy_from_bundle_dir(str(candidates[0]), expected_program=program)

    def _resolve_bundle_by_id(
        self, bundle_id: str, provider: str = ""
    ) -> Union[LoadedGuardPolicy, GuardLoadError]:
        """Resolve active bundle by bundle_id.

        Mirrors master_conductor._resolve_bundle_by_id pattern.
        """
        base = self._programs_dir
        if not base.exists():
            return GuardLoadError(
                reason_code="active_bundle_missing",
                message=f"Bug bounty programs base directory not found: {base}",
                details={"base_dir": str(base), "bundle_id": bundle_id},
            )

        # Search all program directories for an active_bundle.json matching bundle_id
        search_providers: list[str] = [provider] if provider else []
        if not search_providers:
            try:
                search_providers = [d.name for d in sorted(base.iterdir()) if d.is_dir()]
            except OSError:
                search_providers = []

        for prov in search_providers:
            prov_dir = base / prov
            if not prov_dir.is_dir():
                continue
            try:
                for prog_dir in sorted(prov_dir.iterdir()):
                    if not prog_dir.is_dir():
                        continue
                    active_json = prog_dir / "active_bundle.json"
                    if not active_json.exists():
                        continue
                    active_data = json.loads(active_json.read_text())
                    if active_data.get("bundle_id") == bundle_id:
                        return load_active_policy_from_bundle_dir(str(prog_dir))
            except (OSError, json.JSONDecodeError):
                continue

        return GuardLoadError(
            reason_code="active_bundle_missing",
            message=f"No active bundle found with bundle_id='{bundle_id}'",
            details={"base_dir": str(base), "bundle_id": bundle_id},
        )

    def _find_bundle_in_workspace(
        self, program_alias: str, bundle_id: str, provider: str = ""
    ) -> Optional[Path]:
        """Find a bundle directory by program_alias and bundle_id."""
        search_providers = [provider] if provider else []
        if not search_providers:
            try:
                search_providers = [
                    d.name for d in sorted(self._programs_dir.iterdir()) if d.is_dir()
                ]
            except OSError:
                pass

        for prov in search_providers:
            bundles_dir = self._programs_dir / prov / program_alias / "bundles"
            if not bundles_dir.exists():
                continue
            candidate = bundles_dir / bundle_id
            if candidate.is_dir():
                return candidate
        return None

    def _find_bundle_by_id(self, bundle_id: str) -> Optional[Path]:
        """Find a bundle directory by just bundle_id (search all programs)."""
        if not self._programs_dir.exists():
            return None
        for prov_dir in sorted(self._programs_dir.iterdir()):
            if not prov_dir.is_dir():
                continue
            for prog_dir in sorted(prov_dir.iterdir()):
                if not prog_dir.is_dir():
                    continue
                bundles_dir = prog_dir / "bundles"
                if not bundles_dir.exists():
                    continue
                candidate = bundles_dir / bundle_id
                if candidate.is_dir():
                    return candidate
        return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _select_adapter(provider: str, bundle_dir: Path):
    """Select and instantiate the correct adapter for the provider."""
    if provider == "hackerone":
        return HackerOneAdapter(bundle_dir)
    elif provider == "bugcrowd":
        return BugcrowdAdapter(bundle_dir)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def _quick_target_check(policy: LoadedGuardPolicy, target: str) -> None:
    """Perform a quick target validation against the compiled policy.

    Checks if the target host is in-scope (allow_hosts) or out-of-scope
    (deny_hosts).  This is a lightweight preflight check, not a full
    evaluator run.
    """
    raw = policy.raw_policy
    scope = raw.get("scope", {})
    allow_hosts = scope.get("allow_hosts", [])
    deny_hosts = scope.get("deny_hosts", [])

    # Extract host from target
    host = _extract_host(target)

    # Quick check
    for deny in deny_hosts:
        if _host_matches(host, deny):
            return  # Deny match — let evaluator handle it

    for allow in allow_hosts:
        if _host_matches(host, allow):
            return  # In scope

    # Not in scope — this is informational at preflight level
    return


def _extract_host(target: str) -> str:
    """Extract hostname from a URL or host string."""
    t = target.strip()
    # Remove scheme
    for scheme in ("https://", "http://"):
        if t.startswith(scheme):
            t = t[len(scheme):]
    # Remove path
    host = t.split("/")[0].split(":")[0]
    return host.lower()


def _host_matches(host: str, pattern: str) -> bool:
    """Check if a host matches a host pattern (exact or wildcard)."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # .example.com
        return host.endswith(suffix)
    return host == pattern.lower()


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and parse a YAML file, returning a dict."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise TypeError(f"Expected YAML mapping at {path}, got {type(data).__name__}")
    return data


def _utcnow_compact() -> str:
    """Return current UTC time in YYYY-MM-DDTHH:MM:SSZ format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _short_hash(seed: str) -> str:
    """Return a short (8-char) hex hash of the seed string."""
    return hashlib.sha256(seed.encode()).hexdigest()[:8]
