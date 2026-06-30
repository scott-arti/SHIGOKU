"""Takeover provider matrix — data model, loader, and fingerprint helpers.

Per plan section 4.6, this module provides:
  - ``ProviderEntry``: structured per-provider takeover data.
  - ``ProviderMatrixLoader``: YAML-based loader for the provider matrix.
  - ``TakeoverProviderMatrix``: in-memory lookup facade.
  - Fingerprint helpers: ``match_provider_by_cname``, ``match_provider_by_error_token``.
  - Tool-chain resolver: ``resolve_tool_chain``.
"""
from __future__ import annotations

import yaml
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Data model ───────────────────────────────────────────────────────────

@dataclass
class ProviderEntry:
    """A single provider's takeover fingerprint and claim data.

    Mirrors the YAML schema defined in
    ``config/providers/takeover_provider_matrix.yaml``.
    """
    provider_id: str
    fingerprint_domains: List[str] = field(default_factory=list)
    error_tokens: List[str] = field(default_factory=list)
    claim_prerequisites: List[str] = field(default_factory=list)
    verification_urls: List[str] = field(default_factory=list)
    tool_preference: List[str] = field(default_factory=list)
    false_positive_twins: List[str] = field(default_factory=list)
    hitl_checkpoint_types: List[str] = field(default_factory=list)
    supports_auto_confirm: bool = False
    rollback_target: Optional[str] = None


# ── Loader ───────────────────────────────────────────────────────────────

class ProviderMatrixLoader:
    """Load the takeover provider matrix from a YAML file.

    Expected YAML shape::

        version: "1.0.0"
        updated_at: "2026-06-25"
        source_note: "Initial provider matrix"
        providers:
          - provider_id: aws_s3
            fingerprint_domains: [...]
            error_tokens: [...]
            ...
    """

    def __init__(self):
        self.entries: Dict[str, ProviderEntry] = {}
        self.matrix_version: str = ""
        self.matrix_updated_at: str = ""
        self.matrix_source_note: str = ""

    def load(self, filepath: str) -> None:
        """Load and parse the provider matrix YAML into memory.

        Raises ``ValueError`` if required metadata fields (version,
        updated_at, source_note) are missing, or if a duplicate
        ``provider_id`` is encountered.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # ── Validate mandatory top-level metadata ──
        version = data.get("version")
        if not version or not str(version).strip():
            raise ValueError(
                "Provider matrix is missing required top-level field 'version'"
            )
        updated_at = data.get("updated_at")
        if not updated_at or not str(updated_at).strip():
            raise ValueError(
                "Provider matrix is missing required top-level field 'updated_at'"
            )
        source_note = data.get("source_note")
        if source_note is None:
            raise ValueError(
                "Provider matrix is missing required top-level field 'source_note'"
            )

        self.matrix_version = str(version).strip()
        self.matrix_updated_at = str(updated_at).strip()
        self.matrix_source_note = str(source_note).strip()

        providers = data.get("providers", [])
        if not isinstance(providers, list):
            raise ValueError(
                f"Invalid provider matrix: expected 'providers' list, got {type(providers).__name__}"
            )

        for raw in providers:
            pid = str(raw.get("provider_id", "")).strip()
            if not pid:
                logger.warning("Skipping provider entry with empty provider_id")
                continue
            if pid in self.entries:
                raise ValueError(f"Duplicate provider_id in matrix: {pid}")

            entry = ProviderEntry(
                provider_id=pid,
                fingerprint_domains=_str_list(raw.get("fingerprint_domains")),
                error_tokens=_str_list(raw.get("error_tokens")),
                claim_prerequisites=_str_list(raw.get("claim_prerequisites")),
                verification_urls=_str_list(raw.get("verification_urls")),
                tool_preference=_str_list(raw.get("tool_preference")),
                false_positive_twins=_str_list(raw.get("false_positive_twins")),
                hitl_checkpoint_types=_str_list(raw.get("hitl_checkpoint_types")),
                supports_auto_confirm=bool(raw.get("supports_auto_confirm", False)),
                rollback_target=raw.get("rollback_target"),
            )
            self.entries[pid] = entry

        logger.info("Loaded %d provider(s) from %s", len(self.entries), filepath)


# ── Lookup facade ────────────────────────────────────────────────────────

class TakeoverProviderMatrix:
    """In-memory lookup facade for the provider matrix."""

    def __init__(self, loader: ProviderMatrixLoader):
        self._entries = loader.entries

    def get_provider(self, provider_id: str) -> Optional[ProviderEntry]:
        """Look up a provider by its canonical ``provider_id``."""
        return self._entries.get(provider_id)

    def list_provider_ids(self) -> List[str]:
        """Return all known provider IDs."""
        return sorted(self._entries.keys())

    def find_by_fingerprint_domain(self, cname: str) -> Optional[ProviderEntry]:
        """Find a provider whose ``fingerprint_domains`` appears in *cname*."""
        cname_lower = cname.lower()
        for entry in self._entries.values():
            for domain in entry.fingerprint_domains:
                if domain.lower() in cname_lower:
                    return entry
        return None

    def find_by_error_token(self, body: str) -> Optional[ProviderEntry]:
        """Find a provider whose ``error_tokens`` appear in *body*."""
        for entry in self._entries.values():
            for token in entry.error_tokens:
                if token in body:
                    return entry
        return None


# ── Fingerprint helpers (module-level convenience) ───────────────────────

def match_provider_by_cname(
    cname: str,
    matrix: TakeoverProviderMatrix,
) -> Optional[ProviderEntry]:
    """Match a CNAME against the provider matrix and return the first hit."""
    return matrix.find_by_fingerprint_domain(cname)


def match_provider_by_error_token(
    body: str,
    matrix: TakeoverProviderMatrix,
) -> Optional[ProviderEntry]:
    """Match an HTTP response body against provider error tokens."""
    return matrix.find_by_error_token(body)


_DEFAULT_TOOL_CHAIN = ["subjack", "subzy", "manual_curl"]


def resolve_tool_chain(
    provider_id: str,
    matrix: TakeoverProviderMatrix,
) -> List[str]:
    """Return the ordered tool chain for a given provider.

    Falls back to ``_DEFAULT_TOOL_CHAIN`` when the provider is unknown
    or has no explicit ``tool_preference``.
    """
    entry = matrix.get_provider(provider_id)
    if entry and entry.tool_preference:
        return list(entry.tool_preference)
    return list(_DEFAULT_TOOL_CHAIN)


# ── internal helpers ─────────────────────────────────────────────────────

def _str_list(raw: object) -> List[str]:
    """Normalise a YAML value into a list of non-empty strings."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(s).strip() for s in raw if s is not None and str(s).strip()]
    return []
