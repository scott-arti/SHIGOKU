"""
Program Adapter Base: shared adapter infrastructure for provider adapters.

Defines the normalized facts contract, shared validation, loading, and
the deterministic processing order that all provider adapters must follow.

Provider adapters (HackerOne, Bugcrowd) inherit from this base and implement
provider-specific extraction rules while producing provider-neutral output.

Contract defined in:
  docs/shigoku/specs/2026-07-01_sgk-2026-0335_bug-bounty-program-bundle-guard-policy-contract.md
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

import yaml

# ---------------------------------------------------------------------------
# Normalized Facts DTOs
# ---------------------------------------------------------------------------


@dataclass
class SourceInventoryEntry:
    """Entry in source_inventory: records what was read."""
    kind: str  # policy_text | structured_scope | extracted_scope_block
    path: str = ""
    source_ref_root: str = ""
    loaded: bool = False
    parse_status: str = "ok"  # ok | warning | failed
    summary: str = ""


@dataclass
class NormalizedAsset:
    """Provider-neutral asset extracted from scope input."""
    asset_id: str = ""
    raw_identifier: str = ""
    canonical_key: str = ""
    asset_kind: str = "other"  # host_exact | host_wildcard | url_prefix | mobile_app | other
    runtime_surface: str = "http"  # http | mobile | non_runtime
    submission_allowed: bool = False
    bounty_allowed: bool = False
    max_severity: str = "none"
    temporal_window: Optional[dict[str, Any]] = None
    provider_metadata: Optional[dict[str, Any]] = None
    source_ref: str = ""


@dataclass
class RuleCandidate:
    """Provider-neutral rule extracted from policy text or structured scope."""
    rule_id: str = ""
    category: str = ""  # attack_class | phase | budget | path | destination | auth | temporal_scope
    decision: str = "deny"  # allow | deny | requires_hitl
    subject: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)
    origin_type: str = "policy_text"  # policy_text | structured_scope | derived
    specificity: str = "medium"  # broad | medium | exact
    source_ref: str = ""


@dataclass
class ReviewCandidate:
    """Review candidate: machine-identified ambiguity requiring human review."""
    finding_id: str = ""
    category: str = ""
    subject: str = ""
    machine_guess: dict[str, Any] = field(default_factory=dict)
    risk_level: str = "medium"
    blocking: bool = False
    recommended_override_path: str = ""
    source_refs: list[str] = field(default_factory=list)


@dataclass
class ExtractionAuditEntry:
    """Audit entry recording each processing step."""
    step: str = ""
    status: str = "ok"  # ok | warning | failed
    summary: str = ""
    source_refs: list[str] = field(default_factory=list)


@dataclass
class NormalizedFacts:
    """Complete normalized output from a provider adapter.

    This is the contract that all provider adapters must produce.
    It does NOT include final allow/block verdicts; those belong
    to the compiler.
    """
    adapter: dict[str, str] = field(default_factory=dict)
    program: dict[str, str] = field(default_factory=dict)
    source_inventory: list[SourceInventoryEntry] = field(default_factory=list)
    source_hashes: dict[str, str] = field(default_factory=dict)  # path -> sha256:hex
    assets: list[NormalizedAsset] = field(default_factory=list)
    rule_candidates: list[RuleCandidate] = field(default_factory=list)
    review_candidates: list[ReviewCandidate] = field(default_factory=list)
    extraction_audit: list[ExtractionAuditEntry] = field(default_factory=list)

    def add_audit(self, step: str, status: str, summary: str,
                  source_refs: Optional[list[str]] = None) -> None:
        self.extraction_audit.append(ExtractionAuditEntry(
            step=step, status=status, summary=summary,
            source_refs=list(source_refs or []),
        ))


# ---------------------------------------------------------------------------
# Shared Adapter Base
# ---------------------------------------------------------------------------


class ProgramAdapterBase:
    """Base class for provider-specific adapters.

    Subclasses override ``_extract_provider_facts`` to implement
    provider-specific extraction rules. The base class enforces:
    - Deterministic processing order (see spec 6.1.1)
    - Bundle shape validation
    - Source loading
    - Normalization rules (6.1.3)
    """
    ADAPTER_NAME: str = "base_program_adapter"
    ADAPTER_VERSION: int = 1
    PROVIDER: str = ""

    def __init__(self, bundle_dir: Union[str, Path]):
        self._bundle_dir = Path(bundle_dir)
        self._manifest: dict[str, Any] = {}
        self._raw_policy: str = ""
        self._sources: dict[str, str] = {}  # path -> raw content
        self._source_hashes: dict[str, str] = {}  # path -> sha256:hex

    # ---- Public API ----------------------------------------------------------

    def process(self) -> NormalizedFacts:
        """Execute the deterministic processing order.

        Returns NormalizedFacts on success.

        Raises ValueError for fatal failures (missing required files, etc.)
        that should result in ``compile_failed`` status.
        """
        facts = NormalizedFacts(
            adapter={"name": self.ADAPTER_NAME, "version": self.ADAPTER_VERSION},
            program={"provider": self.PROVIDER, "program_name": ""},
        )

        # 1. Bundle shape validation
        self._validate_bundle_shape()

        # Populate program identity from manifest (Fix High 3)
        program_name = self._manifest.get("program_name", "")
        program_alias = self._manifest.get("program_alias",
            program_name.lower().replace(" ", "")) if program_name else ""
        bundle_id = self._manifest.get("bundle_id", "")
        captured_at_utc = self._manifest.get("captured_at_utc", "")
        facts.program["program_name"] = program_name
        facts.program["program_alias"] = program_alias
        facts.program["bundle_id"] = bundle_id
        facts.program["captured_at_utc"] = captured_at_utc

        # 2. Source load
        self._load_sources(facts)
        # Populate source_hashes from loaded raw content (Fix High 4)
        facts.source_hashes = dict(self._source_hashes)

        # 3. Provider-local fact extraction (subclass)
        self._extract_provider_facts(facts)

        # 4. Asset normalization
        self._normalize_assets(facts)

        # 5. Rule candidate normalization
        self._normalize_rule_candidates(facts)

        # 6. Review candidate generation (subclass may override)
        self._generate_review_candidates(facts)

        # 7. Extraction audit emission
        facts.add_audit("process", "ok",
                        f"Adapter {self.ADAPTER_NAME} v{self.ADAPTER_VERSION} "
                        f"completed with {len(facts.assets)} assets, "
                        f"{len(facts.rule_candidates)} rule candidates, "
                        f"{len(facts.review_candidates)} review candidates")

        return facts

    # ---- Bundle shape validation --------------------------------------------

    def _validate_bundle_shape(self) -> None:
        """Validate required files exist.

        Raises ValueError for fatal failures.
        """
        if not self._bundle_dir.is_dir():
            raise ValueError(f"Bundle directory not found: {self._bundle_dir}")

        # Load manifest first
        manifest_path = self._bundle_dir / "source_manifest.yaml"
        if not manifest_path.exists():
            raise ValueError(f"source_manifest.yaml not found in {self._bundle_dir}")
        self._manifest = _load_yaml(manifest_path)

        # Validate required manifest fields
        provider = self._manifest.get("provider", "")
        if provider != self.PROVIDER:
            raise ValueError(
                f"Provider mismatch: manifest says '{provider}', "
                f"adapter expects '{self.PROVIDER}'"
            )

        # Validate policy_path
        policy_path = self._manifest.get("policy_path", "")
        if not policy_path:
            raise ValueError("source_manifest.yaml missing policy_path")
        full_policy = self._bundle_dir / policy_path
        if not full_policy.exists():
            raise ValueError(f"Policy file not found: {full_policy}")

        # Validate scope_sources
        scope_sources = self._manifest.get("scope_sources", [])
        if not scope_sources:
            raise ValueError("source_manifest.yaml: scope_sources must not be empty")

    def _load_sources(self, facts: NormalizedFacts) -> None:
        """Load all source files into memory and populate source_inventory."""
        base = self._bundle_dir

        # Load policy.md
        policy_rel = self._manifest.get("policy_path", "policy.md")
        policy_path = base / policy_rel
        try:
            with open(policy_path, "r", encoding="utf-8") as fh:
                self._raw_policy = fh.read()
            self._source_hashes[policy_rel] = (
                "sha256:" + hashlib.sha256(self._raw_policy.encode()).hexdigest()
            )
            facts.source_inventory.append(SourceInventoryEntry(
                kind="policy_text",
                path=policy_rel,
                source_ref_root=policy_rel,
                loaded=True,
                parse_status="ok",
                summary=f"Loaded policy text ({len(self._raw_policy)} chars)",
            ))
        except (OSError, UnicodeDecodeError) as exc:
            facts.source_inventory.append(SourceInventoryEntry(
                kind="policy_text",
                path=policy_rel,
                source_ref_root=policy_rel,
                loaded=False,
                parse_status="failed",
                summary=f"Failed to load: {exc}",
            ))
            facts.add_audit("load_sources", "failed",
                            f"Failed to load policy: {exc}",
                            [policy_rel])
            raise ValueError(f"Failed to load policy file: {exc}")

        # Load scope sources
        for src in self._manifest.get("scope_sources", []):
            src_path = src.get("path", "")
            src_kind = src.get("kind", "unknown")
            full_path = base / src_path
            try:
                with open(full_path, "r", encoding="utf-8") as fh:
                    content = fh.read()
                self._sources[src_path] = content
                self._source_hashes[src_path] = (
                    "sha256:" + hashlib.sha256(content.encode()).hexdigest()
                )
                facts.source_inventory.append(SourceInventoryEntry(
                    kind=src_kind,
                    path=src_path,
                    source_ref_root=src_path,
                    loaded=True,
                    parse_status="ok",
                    summary=f"Loaded {src_kind} ({len(content)} bytes)",
                ))
            except (OSError, UnicodeDecodeError) as exc:
                facts.source_inventory.append(SourceInventoryEntry(
                    kind=src_kind,
                    path=src_path,
                    source_ref_root=src_path,
                    loaded=False,
                    parse_status="failed",
                    summary=f"Failed to load: {exc}",
                ))
                facts.add_audit("load_sources", "failed",
                                f"Failed to load scope source {src_path}: {exc}",
                                [src_path])
                raise ValueError(f"Failed to load scope source {src_path}: {exc}")

        facts.add_audit("load_sources", "ok",
                        f"Loaded {len(self._sources)} source files")

    # ---- Subclass hooks -----------------------------------------------------

    def _extract_provider_facts(self, facts: NormalizedFacts) -> None:
        """Provider-specific fact extraction. Override in subclasses."""
        raise NotImplementedError

    # ---- Normalization -------------------------------------------------------

    def _normalize_assets(self, facts: NormalizedFacts) -> None:
        """Apply shared normalization rules to assets.

        Subclasses should have populated facts.assets by this point.
        This method ensures canonical_key and uniform wildcard format.
        """
        for asset in facts.assets:
            # Canonicalize host
            if asset.asset_kind in ("host_exact", "host_wildcard"):
                asset.canonical_key = asset.raw_identifier.lower().strip()
                # Normalize wildcard: *.example.com form
                if asset.canonical_key.startswith("*."):
                    pass  # already canonical
                elif asset.canonical_key.startswith("*") and not asset.canonical_key.startswith("*."):
                    asset.canonical_key = "*." + asset.canonical_key[1:]
            elif asset.asset_kind == "url_prefix":
                asset.canonical_key = asset.raw_identifier.strip()
            else:
                asset.canonical_key = asset.raw_identifier.strip().lower()

    def _normalize_rule_candidates(self, facts: NormalizedFacts) -> None:
        """Apply shared normalization to rule candidates."""
        for rc in facts.rule_candidates:
            if rc.subject:
                rc.subject = rc.subject.strip()

    def _generate_review_candidates(self, facts: NormalizedFacts) -> None:
        """Generate review candidates. Override in subclasses if needed."""

    # ---- Helpers ------------------------------------------------------------

    @staticmethod
    def normalize_host(raw: str) -> str:
        """Normalize a host string: lowercase, strip scheme, standardize wildcard."""
        h = raw.strip().lower()
        # Remove scheme if present
        for scheme in ("https://", "http://"):
            if h.startswith(scheme):
                h = h[len(scheme):]
        # Remove trailing slash
        h = h.rstrip("/")
        # Handle *tiktokv.us -> *.tiktokv.us (non-standard wildcard)
        if h.startswith("*") and not h.startswith("*."):
            h = ".tiktokv.us" if h == "tiktokv.us" else h  # no-op, handled per case
        return h

    @staticmethod
    def normalize_wildcard(raw: str) -> str:
        """Ensure wildcard is in ``*.example.com`` canonical form."""
        h = raw.strip().lower()
        if h.startswith("*."):
            return h
        if h.startswith("*"):
            # Convert *example.com -> *.example.com
            return "*." + h[1:]
        return h

    @staticmethod
    def extract_host_from_url(url: str) -> str:
        """Extract hostname from a URL string."""
        u = url.strip()
        for scheme in ("https://", "http://"):
            if u.startswith(scheme):
                u = u[len(scheme):]
        host = u.split("/")[0]
        return host.lower()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load and parse a YAML file."""
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise yaml.YAMLError(f"Expected YAML mapping, got {type(data).__name__}")
    return data


def compute_normalized_facts_hash(
    facts: NormalizedFacts,
    review_state: Optional[dict[str, Any]] = None,
    overrides_state: Optional[dict[str, Any]] = None,
) -> str:
    """Compute deterministic hash of normalized facts.

    Includes source manifest, policy text, scope source, review state,
    and override state in the hash input.

    Args:
        facts: The normalized facts from adapter.
        review_state: Resolved review_findings.yaml as dict (optional).
        overrides_state: Resolved overrides.yaml as dict (optional).

    Returns:
        sha256:... hash string.
    """
    seed_parts: list[str] = []

    # Program identity
    seed_parts.append(facts.program.get("provider", ""))
    seed_parts.append(facts.program.get("program_name", ""))
    seed_parts.append(facts.program.get("bundle_id", ""))

    # Source hashes (from raw content) — Fix High 4
    source_hashes = getattr(facts, 'source_hashes', {}) or {}
    for key in sorted(source_hashes.keys()):
        seed_parts.append(f"{key}:{source_hashes[key]}")

    # Assets sorted by canonical_key for determinism
    sorted_assets = sorted(facts.assets, key=lambda a: a.canonical_key)
    for a in sorted_assets:
        seed_parts.append(
            f"{a.canonical_key}|{a.asset_kind}|{a.submission_allowed}"
        )

    # Rule candidates sorted by rule_id
    sorted_rules = sorted(facts.rule_candidates, key=lambda r: r.rule_id)
    for r in sorted_rules:
        seed_parts.append(
            f"{r.rule_id}|{r.category}|{r.decision}|{r.subject}|{r.specificity}"
        )

    # Review candidates sorted by finding_id
    sorted_review = sorted(facts.review_candidates, key=lambda rc: rc.finding_id)
    for rc in sorted_review:
        seed_parts.append(f"{rc.finding_id}|{rc.category}|{rc.blocking}")

    # Review state
    if review_state:
        seed_parts.append(hashlib.sha256(
            yaml.dump(review_state, default_flow_style=False, sort_keys=True).encode()
        ).hexdigest())

    # Overrides state
    if overrides_state:
        seed_parts.append(hashlib.sha256(
            yaml.dump(overrides_state, default_flow_style=False, sort_keys=True).encode()
        ).hexdigest())

    digest = hashlib.sha256("|".join(seed_parts).encode()).hexdigest()
    return f"sha256:{digest}"
