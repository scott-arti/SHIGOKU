"""
Recon Importer: 過去Recon成果物の安全な取り込みとfreshness/provenance判定

Provides:
- ImportedReconArtifact / ImportedReconBundle data contracts
- load_imported_recon_dir() for reading and normalising import directories
- Freshness scoring integration with recipe_loader.compute_freshness_score

Usage:
    from src.core.engine.recon_importer import load_imported_recon_dir

    bundle = load_imported_recon_dir(Path("recon_export/"), target="example.com")
    if bundle.accepted:
        # Access bundle.normalized_results for PhaseGate/master_conductor
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.engine.recipe_loader import compute_freshness_score

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_FRESHNESS_THRESHOLD = 0.2
"""Threshold below which an artifact is considered stale."""

SUPPORTED_ARTIFACT_KINDS = frozenset({
    "recon_state",
    "subs_txt",
    "httpx_json",
    "httpx_jsonl",
    "takeover_candidates",
    "step8_classification",
})

FAIL_CLOSED_REASON_CODES = frozenset({
    "missing_dir",
    "empty_artifact",
    "malformed_json",
    "target_mismatch",
    "unknown_artifact",
    "stale_artifact",
})


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass
class ImportedReconArtifact:
    """A single imported recon artifact with freshness and provenance data."""

    path: Path
    kind: str  # one of SUPPORTED_ARTIFACT_KINDS
    exists: bool = False
    size: int = 0
    mtime: Optional[float] = None
    freshness_score: float = 0.0
    provenance: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    reason_codes: List[str] = field(default_factory=list)
    informational_only: bool = False
    data: Optional[Any] = None  # parsed content


@dataclass
class ImportedReconBundle:
    """Aggregated result of loading an import directory."""

    import_dir: Path
    target: Optional[str] = None
    artifacts: List[ImportedReconArtifact] = field(default_factory=list)
    rejected_artifacts: List[ImportedReconArtifact] = field(default_factory=list)
    normalized_results: Dict[str, Any] = field(default_factory=dict)
    all_rejected: bool = False
    import_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def accepted(self) -> bool:
        return not self.all_rejected and len(self.normalized_results) > 0

    @property
    def accepted_artifacts(self) -> List[ImportedReconArtifact]:
        return [
            a for a in self.artifacts
            if a.exists and not any(c in FAIL_CLOSED_REASON_CODES for c in a.reason_codes)
        ]

    @property
    def stale_artifacts(self) -> List[ImportedReconArtifact]:
        return [a for a in self.artifacts if "stale_artifact" in a.reason_codes]


# ---------------------------------------------------------------------------
# Artifact kind detection
# ---------------------------------------------------------------------------

_ARTIFACT_KIND_PATTERNS: Dict[str, str] = {
    "recon_state.json": "recon_state",
    "takeover_candidates.json": "takeover_candidates",
}

_KIND_FROM_SUFFIX: Dict[str, str] = {
    ".jsonl": "httpx_jsonl",
}


def _detect_kind(filepath: Path) -> str:
    """Detect artifact kind from filename patterns."""
    fname = filepath.name.lower()

    if fname in _ARTIFACT_KIND_PATTERNS:
        return _ARTIFACT_KIND_PATTERNS[fname]

    if fname.endswith("_subs.txt"):
        return "subs_txt"

    if fname == "httpx.json":
        return "httpx_json"

    for suffix, kind in _KIND_FROM_SUFFIX.items():
        if fname.endswith(suffix):
            return kind

    # step8 classification: *_classified_results.json or similar
    if "_classified" in fname and fname.endswith(".json"):
        return "step8_classification"
    if "step8" in fname and fname.endswith(".json"):
        return "step8_classification"
    if "results" in fname and fname.endswith(".json"):
        return "step8_classification"

    return "unknown_artifact"


# ---------------------------------------------------------------------------
# Core loading function
# ---------------------------------------------------------------------------

def load_imported_recon_dir(
    import_dir: Path,
    target: Optional[str] = None,
    freshness_threshold: float = DEFAULT_FRESHNESS_THRESHOLD,
) -> ImportedReconBundle:
    """Load and normalise a directory of past recon artifacts.

    Args:
        import_dir: Directory containing recon artifacts.
        target: Expected target hostname (checked against recon_state.json).
        freshness_threshold: Score below which artifacts are considered stale.

    Returns:
        ImportedReconBundle with accepted/rejected artifacts and normalised results.
    """
    import_dir = import_dir.expanduser().resolve()
    bundle = ImportedReconBundle(import_dir=import_dir, target=target)

    if not import_dir.is_dir():
        rejected = ImportedReconArtifact(
            path=import_dir,
            kind="unknown_artifact",
            exists=False,
            reason_codes=["missing_dir"],
            warnings=[f"Import directory does not exist: {import_dir}"],
            informational_only=True,
        )
        bundle.rejected_artifacts.append(rejected)
        bundle.all_rejected = True
        logger.warning("Import directory missing: %s", import_dir)
        return bundle

    # Scan for supported files
    for fp in sorted(import_dir.iterdir()):
        if not fp.is_file():
            continue

        kind = _detect_kind(fp)
        artifact = _load_single_artifact(fp, kind, target, freshness_threshold)
        bundle.artifacts.append(artifact)

        if not artifact.exists:
            bundle.rejected_artifacts.append(artifact)
        elif artifact.reason_codes:
            rejected_codes = artifact.reason_codes
            if any(c in FAIL_CLOSED_REASON_CODES for c in rejected_codes):
                bundle.rejected_artifacts.append(artifact)

    # Normalise results from accepted artifacts
    if any(a.exists and a.data is not None and not a.informational_only for a in bundle.artifacts):
        bundle.normalized_results = _normalize_bundle(bundle)
    else:
        bundle.all_rejected = True
        logger.warning("All imported artifacts were rejected for target=%s", target)

    return bundle


# ---------------------------------------------------------------------------
# Single artifact loading
# ---------------------------------------------------------------------------

def _load_single_artifact(
    fp: Path,
    kind: str,
    target: Optional[str],
    freshness_threshold: float,
) -> ImportedReconArtifact:
    """Load, parse, and score a single artifact file.

    Fail-closed: any critical issue is recorded in reason_codes and
    the artifact is marked as rejected rather than silently ignored.
    """
    stat = fp.stat()
    artifact = ImportedReconArtifact(
        path=fp,
        kind=kind,
        exists=True,
        size=stat.st_size,
        mtime=stat.st_mtime,
        provenance={
            "source_path": str(fp),
            "source_mtime": stat.st_mtime,
            "source_kind": kind,
            "import_time": datetime.now(timezone.utc).isoformat(),
        },
    )

    # ---- Fail-closed: unknown kind ----
    if kind not in SUPPORTED_ARTIFACT_KINDS:
        artifact.reason_codes.append("unknown_artifact")
        artifact.warnings.append(f"Unsupported artifact kind: {kind}")
        artifact.informational_only = True
        return artifact

    # ---- Fail-closed: empty artifact ----
    if stat.st_size == 0:
        artifact.reason_codes.append("empty_artifact")
        artifact.warnings.append(f"Empty artifact: {fp}")
        artifact.informational_only = True
        return artifact

    # ---- Parse ----
    try:
        raw = fp.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError) as exc:
        artifact.reason_codes.append("malformed_json")
        artifact.warnings.append(f"Read error for {fp}: {exc}")
        artifact.informational_only = True
        return artifact

    if kind in ("recon_state", "takeover_candidates", "step8_classification", "httpx_json"):
        try:
            artifact.data = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as exc:
            artifact.reason_codes.append("malformed_json")
            artifact.warnings.append(f"JSON parse error for {fp}: {exc}")
            artifact.informational_only = True
            return artifact

    elif kind in ("subs_txt", "httpx_jsonl"):
        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        artifact.data = lines
        if not lines:
            artifact.reason_codes.append("empty_artifact")
            artifact.warnings.append(f"No non-empty lines in {fp}")
            artifact.informational_only = True
            return artifact

    # ---- Target mismatch check (only for recon_state) ----
    if kind == "recon_state" and target and isinstance(artifact.data, dict):
        state_target = artifact.data.get("target", "")
        if state_target and str(state_target).strip().lower() != target.strip().lower():
            artifact.reason_codes.append("target_mismatch")
            artifact.warnings.append(
                f"Target mismatch: recon_state has '{state_target}', expected '{target}'"
            )

    # ---- Freshness scoring ----
    _apply_freshness(artifact, freshness_threshold)

    return artifact


# ---------------------------------------------------------------------------
# Freshness scoring
# ---------------------------------------------------------------------------

def _apply_freshness(artifact: ImportedReconArtifact, threshold: float) -> None:
    """Compute freshness score for an artifact and mark stale if below threshold.

    Uses ``compute_freshness_score`` from recipe_loader as a general-purpose
    recency estimator.  Because imported artifacts may not carry the exact
    ``first_seen_dead`` / ``last_seen_dead`` timestamps, we derive a surrogate
    from mtime when possible.
    """
    if artifact.mtime is None:
        artifact.freshness_score = 0.0
        artifact.reason_codes.append("stale_artifact")
        artifact.informational_only = True
        return

    mtime_dt = datetime.fromtimestamp(artifact.mtime, tz=timezone.utc)

    # Reuse recipe_loader's compute_freshness_score with mtime as single signal
    score = compute_freshness_score(
        first_seen_dead=mtime_dt,
        last_seen_dead=mtime_dt,
        last_dns_probe=None,
        last_http_probe=None,
    )
    artifact.freshness_score = score

    if score < threshold:
        artifact.reason_codes.append("stale_artifact")
        if "stale_artifact" in FAIL_CLOSED_REASON_CODES:
            artifact.informational_only = True


# ---------------------------------------------------------------------------
# Normalisation: artifacts → category dict compatible with ReconState.results
# ---------------------------------------------------------------------------

def _normalize_bundle(bundle: ImportedReconBundle) -> Dict[str, Any]:
    """Convert accepted artifact data into a category dict.

    The output shape matches what ``ReconState.results`` and
    ``MasterConductor._create_attack_tasks_from_recon`` expect:

        {category: {file, count, description}}

    Duplicate URLs/hosts are de-duplicated.
    """
    results: Dict[str, Any] = {}

    for artifact in bundle.artifacts:
        if artifact.data is None:
            continue
        if artifact.informational_only:
            continue
        if any(c in FAIL_CLOSED_REASON_CODES for c in artifact.reason_codes):
            continue

        if artifact.kind == "recon_state":
            _normalize_recon_state(artifact, results)
        elif artifact.kind == "subs_txt":
            _normalize_subs(artifact, results)
        elif artifact.kind == "takeover_candidates":
            _normalize_takeover(artifact, results)
        elif artifact.kind == "step8_classification":
            _normalize_step8(artifact, results)
        elif artifact.kind in ("httpx_json", "httpx_jsonl"):
            _normalize_httpx(artifact, results)

    return results


def _normalize_recon_state(artifact: ImportedReconArtifact, results: Dict[str, Any]) -> None:
    """Extract subdomains/enpoints from a recon_state.json artifact."""
    data = artifact.data
    if not isinstance(data, dict):
        return

    live_subs = data.get("live_subs", []) or []
    if live_subs:
        _add_category_results(results, "recon_live_subs", live_subs, artifact.path)

    tech_stack = data.get("tech_stack", []) or []
    if tech_stack:
        results.setdefault("tech_stack", {"file": str(artifact.path), "count": 0, "items": []})
        existing = set(results["tech_stack"].get("items", []))
        for tech in tech_stack:
            if str(tech) not in existing:
                results["tech_stack"]["items"].append(str(tech))
                existing.add(str(tech))
        results["tech_stack"]["count"] = len(results["tech_stack"]["items"])


def _normalize_subs(artifact: ImportedReconArtifact, results: Dict[str, Any]) -> None:
    """Extract subdomains from a *_subs.txt artifact."""
    lines = artifact.data
    if not isinstance(lines, list):
        return
    _add_category_results(results, "subdomains", lines, artifact.path)


def _normalize_takeover(artifact: ImportedReconArtifact, results: Dict[str, Any]) -> None:
    """Extract takeover candidates."""
    data = artifact.data
    if not isinstance(data, list):
        return
    candidates = []
    for item in data:
        if isinstance(item, dict):
            sub = item.get("subdomain", "")
            if sub:
                candidates.append(str(sub))
        elif isinstance(item, str):
            candidates.append(item)
    if candidates:
        _add_category_results(results, "takeover_candidates", candidates, artifact.path)


def _normalize_step8(artifact: ImportedReconArtifact, results: Dict[str, Any]) -> None:
    """Merge step8 classification results directly into the category dict."""
    data = artifact.data
    if not isinstance(data, dict):
        return

    for category, value in data.items():
        if isinstance(value, dict):
            count = value.get("count", 0)
            file_path = value.get("file", "")
            description = value.get("description", "")
            if count > 0 or file_path:
                results[category] = {
                    "file": file_path,
                    "count": count,
                    "description": description,
                }


def _normalize_httpx(artifact: ImportedReconArtifact, results: Dict[str, Any]) -> None:
    """Extract HTTP endpoints from httpx output."""
    if artifact.kind == "httpx_json" and isinstance(artifact.data, dict):
        urls = _extract_urls_from_httpx_dict(artifact.data)
        if urls:
            _add_category_results(results, "http_endpoints", urls, artifact.path)
    elif artifact.kind == "httpx_jsonl" and isinstance(artifact.data, list):
        urls: List[str] = []
        for line in artifact.data:
            if not isinstance(line, str):
                continue
            try:
                obj = json.loads(line)
                url = _extract_url_from_httpx_entry(obj)
                if url:
                    urls.append(url)
            except (json.JSONDecodeError, ValueError):
                continue
        if urls:
            _add_category_results(results, "http_endpoints", urls, artifact.path)


def _extract_urls_from_httpx_dict(data: Dict[str, Any]) -> List[str]:
    """Extract URLs from an httpx JSON dict (single object or keyed by URL)."""
    urls: List[str] = []
    # Try keyed-by-url format
    for key, value in data.items():
        url = _extract_url_from_httpx_entry(value if isinstance(value, dict) else {})
        if url:
            urls.append(url)
            continue
        # Fallback: key itself might be the URL
        if key.startswith("http"):
            urls.append(key)
    return urls


def _extract_url_from_httpx_entry(entry: Any) -> Optional[str]:
    """Extract a URL string from a single httpx JSON entry."""
    if not isinstance(entry, dict):
        return None
    url = entry.get("url", "") or entry.get("host", "") or entry.get("input", "")
    return str(url).strip() if url else None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _add_category_results(
    results: Dict[str, Any],
    category: str,
    items: List[str],
    source_path: Path,
) -> None:
    """Deduplicate items and merge into the results dict."""
    existing_entry = results.get(category, {"file": str(source_path), "count": 0, "items": []})
    existing_items = set(existing_entry.get("items", []))

    new_count = 0
    for item in items:
        normalized = _normalize_host(item)
        if normalized and normalized not in existing_items:
            existing_items.add(normalized)
            new_count += 1

    existing_entry["count"] = existing_entry.get("count", 0) + new_count
    existing_entry["items"] = sorted(existing_items)
    existing_entry["file"] = str(source_path)
    results[category] = existing_entry


def _normalize_host(value: str) -> str:
    """Normalize a URL or hostname to a comparable form."""
    value = value.strip().rstrip("/").lower()
    # Strip common schemes
    for prefix in ("https://", "http://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    # Strip port if default
    return value
