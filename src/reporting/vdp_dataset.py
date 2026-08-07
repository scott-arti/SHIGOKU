"""
SGK-2026-0423 Lane B — evaluation-data boundary (reporting layer).

Dataset manifests, hidden holdout boundary, leakage detection and frozen
threshold artifacts for the VDP hidden-holdout evaluation (plan §2, §6).

Design rules (plan §2.2 / §11):
- Product-agnostic: normalization and payload classification use GENERIC
  syntax markers only; never product names, known URLs or known payloads of
  a specific target.
- The holdout label artifact is a SEPARATE artifact from the TRAINING gate's
  ``_load_labels_manifest`` format (``src/reporting/vdp_gates.py``). Formats
  stay distinct: training labels map hypothesis_id -> expected class; holdout
  labels carry class-level url/payload/product-name lists.
- No secrets are ever stored; manifests carry only sha256 digests.
- All hashes use canonical JSON (sorted keys) via
  ``src.core.models.vdp_contract.canonical_json_bytes`` so that byte output
  is deterministic across writers.

Import boundary (SGK-2026-0422 rule): this module imports ONLY
``src.core.models.vdp_contract`` and other ``src.reporting`` modules —
never ``src.core.engine``.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel

from src.core.models.vdp_contract import canonical_json_bytes

# ---------------------------------------------------------------------------
# Dataset splits and manifest
# ---------------------------------------------------------------------------


class DatasetSplit(str, Enum):
    """Dataset split kinds for the evaluation-data boundary."""

    DEVELOPMENT = "development"
    VALIDATION = "validation"
    HIDDEN_HOLDOUT = "hidden_holdout"
    REAL = "real"


class DatasetItem(BaseModel):
    """One fixture file referenced by a dataset manifest."""

    file_id: str
    path: str
    sha256: str
    split: str


class DatasetManifestV1(BaseModel):
    """Versioned dataset manifest (plan §2.1).

    ``manifest_hash`` is the sha256 of the canonical JSON (sorted keys) of
    every other field; ``build_manifest`` computes it automatically and
    ``verify_manifest`` re-checks it (tamper detection).
    """

    schema_version: int = 1
    manifest_hash: str = ""
    input_hash: str
    generator: str
    split_rules: Dict[str, Any]
    eval_version: str
    created_at: str
    sets: Dict[str, List[DatasetItem]]

    def compute_manifest_hash(self) -> str:
        """sha256 over canonical JSON of all fields EXCEPT manifest_hash."""
        payload = self.to_dict()
        payload.pop("manifest_hash", None)
        return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "DatasetManifestV1":
        return cls.model_validate(d)


class DatasetManifestError(Exception):
    """Raised when a manifest is missing, malformed or has an unsupported
    schema version. Structural problems are errors; content problems
    (hash/file mismatches) are reported by ``verify_manifest``."""


def build_manifest(
    *,
    input_hash: str,
    generator: str,
    split_rules: Dict[str, Any],
    eval_version: str,
    created_at: str,
    sets: Dict[str, List[DatasetItem]],
) -> DatasetManifestV1:
    """Build a manifest and set its ``manifest_hash`` automatically."""
    manifest = DatasetManifestV1(
        input_hash=input_hash,
        generator=generator,
        split_rules=split_rules,
        eval_version=eval_version,
        created_at=created_at,
        sets=sets,
    )
    manifest.manifest_hash = manifest.compute_manifest_hash()
    return manifest


def load_manifest(path: str | os.PathLike) -> DatasetManifestV1:
    """Load a dataset manifest. Raises DatasetManifestError when the file is
    missing, not JSON, malformed, or has ``schema_version != 1``."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetManifestError(f"cannot load manifest {p}: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise DatasetManifestError(f"manifest {p} must be a JSON object")
    if data.get("schema_version") != 1:
        raise DatasetManifestError(
            f"unsupported manifest schema_version={data.get('schema_version')!r} "
            f"(expected 1)"
        )
    try:
        return DatasetManifestV1.from_dict(data)
    except Exception as exc:  # pydantic ValidationError and friends
        raise DatasetManifestError(f"manifest {p} is malformed: {type(exc).__name__}") from exc


class ManifestVerificationResult(BaseModel):
    """Result of ``verify_manifest``; reasons are deterministic strings."""

    valid: bool
    reasons: List[str]


def verify_manifest(path: str | os.PathLike) -> ManifestVerificationResult:
    """Verify a dataset manifest (plan §2.1, §8 dataset tests).

    1. recomputed ``manifest_hash`` matches the stored one;
    2. every listed file exists and its sha256 matches the manifest
       (tamper detection);
    3. split keys are valid ``DatasetSplit`` values and
       development/validation/hidden_holdout are non-empty when claimed
       (``real`` may be empty).

    Unloadable manifests (missing/malformed/wrong schema) raise
    ``DatasetManifestError`` — schema problems are structural errors, not
    verification failures.
    """
    manifest = load_manifest(path)
    reasons: List[str] = []

    if manifest.manifest_hash != manifest.compute_manifest_hash():
        reasons.append("manifest_hash_mismatch")

    valid_splits = {s.value for s in DatasetSplit}
    for split_name, items in manifest.sets.items():
        if split_name not in valid_splits:
            reasons.append(f"invalid_split:{split_name}")
            continue
        if not items and split_name != DatasetSplit.REAL.value:
            reasons.append(f"split_empty:{split_name}")
        for item in items:
            p = Path(item.path)
            if not p.exists():
                reasons.append(f"missing_file:{item.file_id}")
                continue
            try:
                digest = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError as exc:
                reasons.append(f"unreadable_file:{item.file_id}:{type(exc).__name__}")
                continue
            if digest != item.sha256:
                reasons.append(f"sha256_mismatch:{item.file_id}")

    return ManifestVerificationResult(valid=not reasons, reasons=reasons)


# ---------------------------------------------------------------------------
# Semantic duplicate detection (plan §2.1: same endpoint structure / payload
# family / target-name substitution must not leak across sets)
# ---------------------------------------------------------------------------


class DuplicatePair(BaseModel):
    """A semantic duplicate between two manifest items in the form
    ``<split>:<file_id>``. ``kind`` is one of
    ``endpoint_structure`` | ``payload_family`` | ``target_name_substitution``."""

    left: str
    right: str
    kind: str


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DIGIT_RUN_RE = re.compile(r"\d+")
_URL_SCHEME_RE = re.compile(r"^(?:[a-z][a-z0-9+.-]*://)?([^/?#]*)(.*)$")


def normalize_endpoint_structure(url: str) -> str:
    """Deterministic, product-agnostic endpoint structure for a URL.

    - lowercases the input;
    - strips the scheme and host (host replaced with ``<HOST>``) — the
      ``<HOST>`` token acts as a wildcard in duplicate comparison, so
      target-name substitution (same path structure on a different host) is
      still detected;
    - strips the port and userinfo;
    - drops the fragment;
    - replaces digit runs in the path with ``<N>``;
    - sorts query parameter names and replaces every query value with
      ``<VAL>``.

    Input is expected to be a URL string; non-URL input normalizes to the
    bare host wildcard form.
    """
    text = url.strip().lower()
    if not text:
        return ""
    text = text.split("#", 1)[0]
    match = _URL_SCHEME_RE.match(text)
    netloc = match.group(1) or "" if match else ""
    rest = match.group(2) or "" if match else text
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    netloc = netloc.split(":", 1)[0]  # strip port
    path, _, query = rest.partition("?")
    path = _DIGIT_RUN_RE.sub("<N>", path)
    structure = "<HOST>" + path
    if query:
        names = []
        for pair in query.split("&"):
            if not pair:
                continue
            name = pair.split("=", 1)[0]
            names.append(f"{name}=<VAL>")
        structure += "?" + "&".join(sorted(names))
    return structure


def payload_family_signature(payload: str) -> str:
    """Classify a payload string into a GENERIC syntax-marker family.

    The markers are pure syntax signals — quote character, script tag,
    semicolon, SQL keyword — and NEVER target/product names (plan §11).
    Check order is fixed::

        contains "'"       -> "sqli:quote"
        contains "<script" -> "xss:script"
        contains ";"       -> "cmd:semicolon"
        contains "SELECT"  -> "sqli:select"
        otherwise          -> "none"
    """
    if not isinstance(payload, str):
        return "none"
    if "'" in payload:
        return "sqli:quote"
    if "<script" in payload:
        return "xss:script"
    if ";" in payload:
        return "cmd:semicolon"
    if "SELECT" in payload:
        return "sqli:select"
    return "none"


def _iter_urls(text: str) -> List[str]:
    """All http(s) URLs found in a text blob (trailing punctuation stripped)."""
    return [m.group(0).rstrip(".,;:!?)]}>\"'") for m in _URL_RE.finditer(text)]


def _item_signature(item: DatasetItem) -> Optional[tuple]:
    """Derive ``(endpoint_structure, payload_family, host)`` from the item's
    file content: the first URL in the file is the endpoint, the whole file
    content is the payload source. Returns None for unreadable files or
    files without any URL (they cannot participate in structure matching;
    ``verify_manifest`` is the authoritative existence/tamper check)."""
    p = Path(item.path)
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    urls = _iter_urls(content)
    if not urls:
        return None
    raw = urls[0]
    try:
        from urllib.parse import urlsplit

        host = (urlsplit(raw).hostname or "").lower()
    except ValueError:
        host = ""
    return (normalize_endpoint_structure(raw), payload_family_signature(content), host)


def semantic_duplicates(
    manifest: DatasetManifestV1,
    *,
    across_sets_only: bool = True,
) -> List[DuplicatePair]:
    """Detect semantic duplicates between manifest items (plan §2.1).

    Two items are duplicates when their normalized endpoint structures are
    equal (``<HOST>`` is a wildcard, so the same path structure matches
    regardless of host — target-name substitution) AND their payload family
    signatures are equal.

    ``kind`` is:
    - ``target_name_substitution`` — structures equal, hosts differ;
    - ``endpoint_structure`` — structures equal, same known host;
    - ``payload_family`` — structures equal but at least one host is
      unknown (no URL host could be parsed); the shared payload family is
      the only concrete signal.

    With ``across_sets_only=True`` (default) only pairs from DIFFERENT sets
    are reported; False also reports pairs inside the same set. Pair order
    and left/right assignment are deterministic (first-occurrence order).
    """
    entries: List[tuple] = []
    for split_name, items in manifest.sets.items():
        for item in items:
            signature = _item_signature(item)
            if signature is None:
                continue
            entries.append((item, signature, split_name))

    duplicates: List[DuplicatePair] = []
    for a_idx in range(len(entries)):
        for b_idx in range(a_idx + 1, len(entries)):
            item_a, (struct_a, family_a, host_a), split_a = entries[a_idx]
            item_b, (struct_b, family_b, host_b), split_b = entries[b_idx]
            if across_sets_only and split_a == split_b:
                continue
            if not struct_a or struct_a != struct_b or family_a != family_b:
                continue
            if host_a and host_b and host_a != host_b:
                kind = "target_name_substitution"
            elif host_a and host_b:
                kind = "endpoint_structure"
            else:
                kind = "payload_family"
            duplicates.append(DuplicatePair(
                left=f"{split_a}:{item_a.file_id}",
                right=f"{split_b}:{item_b.file_id}",
                kind=kind,
            ))
    return duplicates


# ---------------------------------------------------------------------------
# Hidden holdout technical boundary (plan §2.1)
# ---------------------------------------------------------------------------


class HoldoutBoundaryError(Exception):
    """Raised when a hidden-holdout access boundary is violated or the
    holdout label artifact is missing/malformed/overly permissive."""


class HiddenHoldoutBoundary:
    """Technical access boundary for the hidden holdout artifact.

    Lane G (SGK-2026-0423 audit-fix wave 2): the boundary is a REAL OS
    boundary, not an app-level convention. The artifact must be a regular
    file (no symlink) with owner-only mode owned by a user DIFFERENT from
    the runtime uid — so the runtime process's read is denied by the kernel
    (EACCES), not by application code. The runtime has no read path at all
    (``runtime_context=True`` always raises); evaluation/ops reads go
    through the privileged container channel.
    """

    @staticmethod
    def assert_os_isolation(
        holdout_path: str | os.PathLike,
        *,
        runtime_uid: Optional[int] = None,
    ) -> None:
        """Assert the OS actually isolates the artifact from the runtime.

        - ``runtime_uid`` defaults to the current process euid (the runtime);
        - the artifact must be a REGULAR file and NOT a symlink (``lstat``)
          else ``HoldoutBoundaryError("holdout_not_regular_file")``;
        - the mode must be owner-only (``mode & 0o077 == 0``) else
          ``HoldoutBoundaryError("holdout_labels_permission_too_broad")``;
        - the owner MUST differ from the runtime uid else
          ``HoldoutBoundaryError("holdout_same_owner_as_runtime")`` — a
          same-user file, even 0600, is readable by the runtime and is no
          boundary at all.
        """
        runtime_uid = runtime_uid if runtime_uid is not None else os.geteuid()
        try:
            st = os.lstat(holdout_path)
        except OSError as exc:
            raise HoldoutBoundaryError(
                f"holdout_labels_missing:{type(exc).__name__}"
            ) from exc
        if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise HoldoutBoundaryError("holdout_not_regular_file")
        if st.st_mode & 0o077:
            raise HoldoutBoundaryError("holdout_labels_permission_too_broad")
        if st.st_uid == runtime_uid:
            raise HoldoutBoundaryError("holdout_same_owner_as_runtime")

    @staticmethod
    def _validate_labels_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a parsed holdout label artifact (shared by both
        loaders): ``urls`` / ``payloads`` / ``product_names`` lists plus the
        optional ``ground_truth`` list (defaults to []). Ground-truth
        entries are normalized to ``class`` / ``capability`` / ``method`` /
        ``endpoint`` strings (product-independent vocabulary); non-dict
        entries are dropped."""
        if not isinstance(data, dict) or not isinstance(data.get("class"), dict):
            raise HoldoutBoundaryError("holdout_labels_malformed:missing_class")
        klass = data["class"]
        normalized: Dict[str, Any] = {
            "urls": [str(u) for u in (klass.get("urls") or [])],
            "payloads": [str(p) for p in (klass.get("payloads") or [])],
            "product_names": [str(n) for n in (klass.get("product_names") or [])],
            "ground_truth": [],
        }
        ground_truth = data.get("ground_truth")
        if ground_truth:
            entries = []
            for entry in ground_truth:
                if not isinstance(entry, dict):
                    continue
                entries.append({
                    "class": str(entry.get("class") or ""),
                    "capability": str(entry.get("capability") or ""),
                    "method": str(entry.get("method") or ""),
                    "endpoint": str(entry.get("endpoint") or ""),
                })
            normalized["ground_truth"] = entries
        return normalized

    @staticmethod
    def load_holdout_labels(
        path: str | os.PathLike,
        *,
        runtime_context: bool = False,
    ) -> Dict[str, Any]:
        """Load the holdout label artifact (plan §2.2).

        Expected shape::

            {"class": {"urls": [...], "payloads": [...], "product_names": [...]},
             "ground_truth": [{"class": ..., "capability": ..., "method": ...,
                               "endpoint": ...}, ...]}   # optional

        Fail-closed checks:
        - ``runtime_context=True`` ALWAYS raises
          ``HoldoutBoundaryError("holdout_runtime_read_forbidden")`` — the
          runtime has no read path by construction;
        - missing file / malformed JSON / missing ``class`` dict ->
          ``HoldoutBoundaryError``;
        - file mode must be owner-only (``mode & 0o077 == 0``) else
          ``HoldoutBoundaryError("holdout_labels_permission_too_broad")``;
        - ``assert_os_isolation(path)``: the artifact must be a regular
          non-symlink file owned by a user DIFFERENT from the current
          process — a same-owner 0600 file is rejected for evaluation too
          (evaluation must go through a privileged channel).

        Returns the normalized dict with ``urls`` / ``payloads`` /
        ``product_names`` / ``ground_truth`` lists (missing keys default to
        empty lists — additive-safe).
        """
        if runtime_context:
            raise HoldoutBoundaryError("holdout_runtime_read_forbidden")
        p = Path(path)
        try:
            fstat = p.stat()
        except OSError as exc:
            raise HoldoutBoundaryError(
                f"holdout_labels_missing:{type(exc).__name__}"
            ) from exc
        if fstat.st_mode & 0o077:
            raise HoldoutBoundaryError("holdout_labels_permission_too_broad")
        HiddenHoldoutBoundary.assert_os_isolation(path)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise HoldoutBoundaryError(
                f"holdout_labels_malformed:{type(exc).__name__}"
            ) from exc
        return HiddenHoldoutBoundary._validate_labels_dict(data)

    @staticmethod
    def load_holdout_labels_via_container(
        host_path: str | os.PathLike,
        *,
        container_image: str = "alpine:3",
    ) -> Dict[str, Any]:
        """Load the holdout label artifact through a local container as
        root (ops/eval tooling — NEVER called by the runtime).

        The parent directory is bind-mounted read-only into a local
        container and the file is read as root, whose CAP_DAC_OVERRIDE can
        read owner-only artifacts owned by any user. A docker failure raises
        ``HoldoutBoundaryError("holdout_container_read_failed")``; the
        content is then validated via ``_validate_labels_dict``.
        """
        p = Path(host_path)
        parent = str(p.parent)
        name = p.name
        mount = "/holdout"
        try:
            completed = subprocess.run(
                ["docker", "run", "--rm", "-v", f"{parent}:{mount}:ro",
                 container_image, "sh", "-c", f"cat {mount}/{name}"],
                capture_output=True, check=True, timeout=120,
            )
        except (OSError, subprocess.CalledProcessError,
                subprocess.TimeoutExpired) as exc:
            raise HoldoutBoundaryError(
                f"holdout_container_read_failed:{type(exc).__name__}"
            ) from exc
        try:
            data = json.loads(completed.stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise HoldoutBoundaryError(
                "holdout_container_read_failed:malformed_json"
            ) from exc
        return HiddenHoldoutBoundary._validate_labels_dict(data)

    @staticmethod
    def assert_runtime_cannot_read(
        holdout_dir: str | os.PathLike,
        runtime_root: Optional[str | os.PathLike] = None,
    ) -> None:
        """Assert the holdout directory is NOT inside the runtime workspace.

        When ``runtime_root`` is given and the holdout path resolves inside
        it, raise ``HoldoutBoundaryError("holdout_inside_runtime_workspace")``
        (a technical access boundary: the runtime must not be able to read
        the holdout). With ``runtime_root=None`` no comparison is possible
        and the check is a no-op.
        """
        if runtime_root is None:
            return
        holdout_resolved = Path(holdout_dir).resolve()
        root_resolved = Path(runtime_root).resolve()
        if holdout_resolved.is_relative_to(root_resolved):
            raise HoldoutBoundaryError("holdout_inside_runtime_workspace")


# ---------------------------------------------------------------------------
# Runtime leakage scan (plan §2.2, §4.1: hidden label inflow is No-Go)
# ---------------------------------------------------------------------------


class LeakageHit(BaseModel):
    """One detected leakage of a holdout label into runtime-derived text."""

    kind: str  # "known_url" | "product_name" | "expected_payload"
    source_index: int
    matched: str


def scan_runtime_inputs_for_leakage(
    runtime_texts: List[str],
    labels: Dict[str, Any],
) -> List[LeakageHit]:
    """Scan runtime-derived texts for holdout label leakage.

    ``labels`` is the holdout class dict (``urls`` / ``payloads`` /
    ``product_names`` lists; keys may be missing).

    Match rules:
    - ``known_url``: label URL is a substring of the text, OR a URL inside
      the text has the same normalized endpoint structure as the label URL
      (scheme/host/port substitution still detected — URL-parse match);
    - ``expected_payload``: case-sensitive substring match;
    - ``product_name``: case-insensitive substring match.

    Order is deterministic: texts in index order; within a text, url labels,
    then payload labels, then product-name labels, each in list order.
    Exact duplicate hits (same kind/index/matched) are emitted once.
    """
    urls = [str(u) for u in (labels.get("urls") or []) if str(u).strip()]
    payloads = [str(p) for p in (labels.get("payloads") or []) if str(p).strip()]
    product_names = [str(n) for n in (labels.get("product_names") or []) if str(n).strip()]

    hits: List[LeakageHit] = []
    seen = set()

    def _add(kind: str, source_index: int, matched: str) -> None:
        key = (kind, source_index, matched)
        if key in seen:
            return
        seen.add(key)
        hits.append(LeakageHit(kind=kind, source_index=source_index, matched=matched))

    for index, text in enumerate(runtime_texts):
        if not isinstance(text, str):
            continue
        for label in urls:
            if label in text:
                _add("known_url", index, label)
                continue
            normalized_label = normalize_endpoint_structure(label)
            if normalized_label and any(
                normalize_endpoint_structure(candidate) == normalized_label
                for candidate in _iter_urls(text)
            ):
                _add("known_url", index, label)
        for label in payloads:
            if label in text:
                _add("expected_payload", index, label)
        for label in product_names:
            if label.lower() in text.lower():
                _add("product_name", index, label)
    return hits


# ---------------------------------------------------------------------------
# Frozen thresholds (plan §6: fixed before holdout viewing, no single
# composite score)
# ---------------------------------------------------------------------------


class ThresholdMetric(BaseModel):
    """One frozen threshold: required value of a named metric.

    ``direction`` (additive, Lane J-1): "minimum" requires value >= bound,
    "maximum" requires value <= bound. Old artifacts without the field
    default to "minimum"; the holdout runner applies a legacy fallback so
    the historical upper-bound families (``false_promotion_rate:*``,
    ``untested_rate``) keep their semantics.
    """

    name: str
    value: float
    formula: str
    target_set: str
    direction: Literal["minimum", "maximum"] = "minimum"


class ThresholdArtifact(BaseModel):
    """Versioned, pre-frozen threshold artifact (plan §6 / §9).

    Contains every metric SEPARATELY — there is intentionally no single
    composite score that could let a safety violation be offset by good
    scores elsewhere.
    """

    schema_version: int = 1
    eval_version: str
    decided_at: str
    metrics: List[ThresholdMetric]

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ThresholdArtifact":
        return cls.model_validate(d)


def thresholds_fingerprint(thresholds: ThresholdArtifact) -> str:
    """sha256 of the canonical JSON of the whole threshold artifact."""
    return hashlib.sha256(canonical_json_bytes(thresholds.to_dict())).hexdigest()


def freeze_thresholds(
    *,
    eval_version: str,
    decided_at: str,
    metrics: List[ThresholdMetric],
) -> ThresholdArtifact:
    """Freeze a threshold artifact for an evaluation version.

    ``metrics`` are ``ThresholdMetric`` instances; the optional per-metric
    ``direction`` field (minimum | maximum) is passed through unchanged.
    """
    return ThresholdArtifact(
        eval_version=eval_version,
        decided_at=decided_at,
        metrics=metrics,
    )


def load_thresholds(path: str | os.PathLike) -> ThresholdArtifact:
    """Load a frozen threshold artifact (additive reader: unknown fields are
    ignored; malformed JSON or non-object input raises ValueError)."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"threshold artifact {p} must be a JSON object")
    return ThresholdArtifact.from_dict(data)
