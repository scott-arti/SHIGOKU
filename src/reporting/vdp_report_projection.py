"""
Shared VDP report projection helpers — SGK-2026-0422 (reporting layer).

All three Haddix formatters consume the same immutable
``VdpCanonicalSummary`` via these helpers so they produce identical ID sets,
counts and reason codes. No formatter performs its own confirmed/candidate
re-judgement for canonical VDP sessions.

Also provides:
- the machine-readable ``vdp_canonical_index_v1`` embedding/extraction used
  by the consistency checker (T6),
- the additive ``vdp_diagnostic_index_v1`` embedding/extraction for the
  ``vdp_diagnostics_v1`` telemetry section (SGK-2026-0425 M2),
- a secret scan for report content,
- atomic report promotion (temp -> verify -> os.replace) so a partial report
  is never left under the official filename.

These helpers never call network / browser / OOB / task queue /
MasterConductor.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.models.vdp_contract import (
    redact_secrets_deep,
)
from src.reporting.vdp_canonical import (
    VdpCanonicalSummary,
    VDP_CANONICAL_INDEX_VERSION,
    build_vdp_canonical_index,
)

_INDEX_BLOCK_START = "<!-- vdp_canonical_index_v1:start -->"
_INDEX_BLOCK_END = "<!-- vdp_canonical_index_v1:end -->"

# SGK-2026-0425 M2: additive diagnostic index (plan §5.2). Independent from
# the canonical index block; both may coexist in one report.
VDP_DIAGNOSTIC_INDEX_VERSION = "vdp_diagnostic_index_v1"
_DIAGNOSTIC_INDEX_BLOCK_START = "<!-- vdp_diagnostic_index_v1:start -->"
_DIAGNOSTIC_INDEX_BLOCK_END = "<!-- vdp_diagnostic_index_v1:end -->"

# SGK-2026-0426 W3: additive fail-closed run-outcome marker. A session whose
# VDP follow-up stage failed (attempts=0) must NEVER be presented as a normal
# completion report; the marker makes the failure machine-readable for the
# report/session consistency checker (vdp_run_failed_not_reflected).
VDP_RUN_FAILED_MARKER_VERSION = "vdp_run_failed_v1"
_RUN_FAILED_BLOCK_START = "<!-- vdp_run_failed:start -->"
_RUN_FAILED_BLOCK_END = "<!-- vdp_run_failed:end -->"

# Known secret markers used by the report secret scan (additive).
_SECRET_PATTERNS = [
    re.compile(r"Bearer\s+[a-zA-Z0-9._\-+/=]{10,}", re.IGNORECASE),
    re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"),
    re.compile(r"sk-(?:live|test|proj|svcacct|admin)-?[a-zA-Z0-9_-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:password|passwd|pass)[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:X-API-Key|X-Auth-Token):\s*\S+", re.IGNORECASE),
    re.compile(r"(?:Set-Cookie|Proxy-Authorization):\s*\S+", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Funnel / verdict projection (shared by all formatters)
# ---------------------------------------------------------------------------


def format_vdp_funnel_markdown(summary: VdpCanonicalSummary) -> List[str]:
    """Render the evidence funnel (plan §4.1) with drop reasons.

    Observations are shown as IDs only (content is not stored in the
    session); missing content is surfaced via compatibility reasons.
    """
    funnel = summary.funnel
    lines: List[str] = ["## VDP Evidence Funnel", ""]
    lines.append(
        "| Stage | Count |"
    )
    lines.append("|-------|-------|")
    for label, key in (
        ("Observations", "observations"),
        ("Hypotheses", "hypotheses"),
        ("Attempted", "attempted"),
        ("Responded", "responded"),
        ("Followed-up", "followed_up"),
        ("Confirmed", "confirmed"),
        ("Refuted", "refuted"),
        ("Untested", "untested"),
    ):
        lines.append(f"| {label} | {getattr(funnel, key, 0)} |")
    lines.append("")
    if funnel.drop_reasons:
        lines.append("### Drop Reasons (from previous stage)")
        lines.append("")
        lines.append("| Reason Code | Count |")
        lines.append("|-------------|-------|")
        for code, count in sorted(funnel.drop_reasons.items()):
            lines.append(f"| `{code}` | {count} |")
        lines.append("")
    if summary.compatibility_reasons:
        lines.append("### Compatibility Notes")
        lines.append("")
        for reason in summary.compatibility_reasons:
            lines.append(f"- `{reason}`")
        lines.append("")
    return lines


def format_vdp_verdicts_markdown(summary: VdpCanonicalSummary) -> List[str]:
    """Render verdict details with back-references (plan §4.3).

    Confirmed verdicts show verdict_id / hypothesis_id / evidence IDs /
    reason codes. Raw finding labels are never trusted for canonical
    sessions — only canonical verdicts are shown.
    """
    if not summary.verdicts:
        return []
    lines: List[str] = ["## VDP Verdicts", ""]
    lines.append(
        "| Verdict ID | Hypothesis ID | Status | Evidence IDs | Reason Codes |"
    )
    lines.append(
        "|------------|---------------|--------|--------------|--------------|"
    )
    for verdict in summary.verdicts:
        evidence_ids = ", ".join(verdict.evaluated_evidence_ids) or "-"
        reason_codes = ", ".join(verdict.reason_codes) or "-"
        lines.append(
            f"| `{verdict.verdict_id}` | `{verdict.hypothesis_id}` | "
            f"{verdict.status} | {evidence_ids} | {reason_codes} |"
        )
    lines.append("")
    return lines


def format_vdp_provenance_markdown(summary: VdpCanonicalSummary) -> List[str]:
    """Render observation provenance (IDs only) and NextAction trace."""
    lines: List[str] = []
    if summary.observation_ids:
        lines.append("## VDP Observation Provenance")
        lines.append("")
        lines.append("観測本文はsessionに保存されないため、IDと欠落理由のみを表示する。")
        lines.append("")
        for oid in summary.observation_ids:
            lines.append(f"- `{oid}`")
        lines.append("")
    if summary.next_actions:
        lines.append("## VDP Next Actions")
        lines.append("")
        lines.append("| Next Action ID | Verdict ID | Evidence Gap | Class |")
        lines.append("|----------------|------------|--------------|-------|")
        for na in summary.next_actions:
            lines.append(
                f"| `{na.next_action_id}` | `{na.verdict_id}` | "
                f"{na.evidence_gap} | {na.action_class} |"
            )
        lines.append("")
    return lines


def render_vdp_section_markdown(summary: VdpCanonicalSummary) -> List[str]:
    """Full canonical VDP report section (funnel + verdicts + provenance)."""
    lines: List[str] = []
    lines.extend(format_vdp_funnel_markdown(summary))
    lines.extend(format_vdp_verdicts_markdown(summary))
    lines.extend(format_vdp_provenance_markdown(summary))
    return lines


# ---------------------------------------------------------------------------
# Machine-readable canonical index (same serializer for all formatters)
# ---------------------------------------------------------------------------


def embed_vdp_canonical_index(markdown: str, summary: VdpCanonicalSummary) -> str:
    """Embed the canonical index block into a Markdown report.

    The block is a deterministic JSON payload wrapped in HTML comments so the
    consistency checker can extract it without parsing human Markdown.
    """
    index = build_vdp_canonical_index(summary)
    block = (
        f"{_INDEX_BLOCK_START}\n"
        f"{json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2)}\n"
        f"{_INDEX_BLOCK_END}"
    )
    # Replace an existing block if present; otherwise append.
    if _INDEX_BLOCK_START in markdown:
        head = markdown.split(_INDEX_BLOCK_START, 1)[0]
        tail = markdown.split(_INDEX_BLOCK_END, 1)[1] if _INDEX_BLOCK_END in markdown else ""
        return f"{head}{block}\n{tail}"
    return f"{markdown.rstrip()}\n\n{block}\n"


def extract_vdp_canonical_index_from_report(report_text: str) -> Optional[Dict[str, Any]]:
    """Extract the embedded canonical index from a report (T6)."""
    if _INDEX_BLOCK_START not in report_text or _INDEX_BLOCK_END not in report_text:
        return None
    payload = report_text.split(_INDEX_BLOCK_START, 1)[1].split(_INDEX_BLOCK_END, 1)[0]
    try:
        data = json.loads(payload.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("index_version") != VDP_CANONICAL_INDEX_VERSION:
        return None
    return data


# ---------------------------------------------------------------------------
# Machine-readable diagnostic index (SGK-2026-0425 M2, plan §5.2)
#
# Hash/count-only projection of the additive ``vdp_diagnostics_v1`` session
# section. NO labels, URLs, payloads or event content — only hashes and
# counts, so the consistency checker can detect telemetry tampering without
# the report carrying sensitive material.
# ---------------------------------------------------------------------------


def _canonical_json(obj: Any) -> str:
    """Deterministic canonical JSON: sorted keys, no added whitespace."""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def build_vdp_diagnostic_index(
    diagnostics_section: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Build the ``vdp_diagnostic_index_v1`` payload from a session's
    ``vdp_diagnostics_v1`` section.

    Returns None when the section is absent (or not a dict) — additive-absent
    callers must not embed a block for a missing section.
    """
    if not isinstance(diagnostics_section, dict):
        return None
    events = diagnostics_section.get("events")
    if not isinstance(events, list):
        events = []

    stage_sets: Dict[str, Dict[str, int]] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        stage = ev.get("stage_id")
        if not isinstance(stage, str):
            continue
        outcome = ev.get("outcome")
        counts = stage_sets.setdefault(stage, {})
        key = str(outcome) if outcome is not None else ""
        counts[key] = counts.get(key, 0) + 1
    stage_sets = {
        stage: dict(sorted(counts.items()))
        for stage, counts in sorted(stage_sets.items())
    }

    # The summary digest covers the whole section minus the events list
    # (metadata, optional backpressure/duplicate blocks included).
    summary_section = dict(diagnostics_section)
    summary_section.pop("events", None)

    backpressure = diagnostics_section.get("backpressure_reasons")
    duplicate_counts = diagnostics_section.get("duplicate_event_counts")
    return {
        "index_version": VDP_DIAGNOSTIC_INDEX_VERSION,
        "taxonomy_version": str(diagnostics_section.get("taxonomy_version") or ""),
        "run_id": str(diagnostics_section.get("run_id") or ""),
        "events_count": len(events),
        "event_hash": "sha256:"
        + hashlib.sha256(_canonical_json(events).encode("utf-8")).hexdigest(),
        "stage_sets": stage_sets,
        "backpressure_reasons_count": (
            len(backpressure) if isinstance(backpressure, (list, tuple)) else 0
        ),
        "duplicate_event_counts_count": (
            len(duplicate_counts)
            if isinstance(duplicate_counts, (dict, list, tuple))
            else 0
        ),
        "summary_digest": "sha256:"
        + hashlib.sha256(_canonical_json(summary_section).encode("utf-8")).hexdigest(),
    }


def embed_vdp_diagnostic_index(
    markdown: str,
    diagnostics_section: Optional[Dict[str, Any]],
) -> str:
    """Embed the ``vdp_diagnostic_index_v1`` block into a Markdown report.

    When the section is absent NO block is added and the markdown is returned
    unchanged (additive-absent compatibility). An existing block is replaced;
    otherwise the block is appended.
    """
    index = build_vdp_diagnostic_index(diagnostics_section)
    if index is None:
        return markdown
    block = (
        f"{_DIAGNOSTIC_INDEX_BLOCK_START}\n"
        f"{json.dumps(index, ensure_ascii=False, sort_keys=True, indent=2)}\n"
        f"{_DIAGNOSTIC_INDEX_BLOCK_END}"
    )
    if _DIAGNOSTIC_INDEX_BLOCK_START in markdown:
        head = markdown.split(_DIAGNOSTIC_INDEX_BLOCK_START, 1)[0]
        tail = (
            markdown.split(_DIAGNOSTIC_INDEX_BLOCK_END, 1)[1]
            if _DIAGNOSTIC_INDEX_BLOCK_END in markdown
            else ""
        )
        return f"{head}{block}\n{tail}"
    return f"{markdown.rstrip()}\n\n{block}\n"


def extract_vdp_diagnostic_index_from_report(
    report_text: str,
) -> Optional[Dict[str, Any]]:
    """Extract the embedded ``vdp_diagnostic_index_v1`` from a report (M2).

    None when the markers are absent, the payload is not JSON, or the
    index_version differs.
    """
    if (
        _DIAGNOSTIC_INDEX_BLOCK_START not in report_text
        or _DIAGNOSTIC_INDEX_BLOCK_END not in report_text
    ):
        return None
    payload = report_text.split(_DIAGNOSTIC_INDEX_BLOCK_START, 1)[1].split(
        _DIAGNOSTIC_INDEX_BLOCK_END, 1
    )[0]
    try:
        data = json.loads(payload.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("index_version") != VDP_DIAGNOSTIC_INDEX_VERSION:
        return None
    return data


# ---------------------------------------------------------------------------
# SGK-2026-0426 W3: fail-closed run-outcome marker (additive)
# ---------------------------------------------------------------------------


def embed_vdp_run_failed_marker(
    markdown: str,
    run_outcome: Optional[str],
) -> str:
    """Embed the ``vdp_run_failed_v1`` marker block into a Markdown report.

    Only when ``run_outcome`` is non-empty (a failed run) — otherwise the
    markdown is returned unchanged (additive-absent: healthy/legacy reports
    keep their exact bytes). An existing block is replaced.
    """
    if not run_outcome:
        return markdown
    block = (
        f"{_RUN_FAILED_BLOCK_START}\n"
        f"{json.dumps({'marker_version': VDP_RUN_FAILED_MARKER_VERSION, 'run_outcome': str(run_outcome)}, ensure_ascii=False, sort_keys=True, indent=2)}\n"
        f"{_RUN_FAILED_BLOCK_END}"
    )
    if _RUN_FAILED_BLOCK_START in markdown:
        head = markdown.split(_RUN_FAILED_BLOCK_START, 1)[0]
        tail = (
            markdown.split(_RUN_FAILED_BLOCK_END, 1)[1]
            if _RUN_FAILED_BLOCK_END in markdown
            else ""
        )
        return f"{head}{block}\n{tail}"
    return f"{markdown.rstrip()}\n\n{block}\n"


def extract_vdp_run_failed_marker_from_report(
    report_text: str,
) -> Optional[Dict[str, Any]]:
    """Extract the embedded ``vdp_run_failed_v1`` marker; None when absent."""
    if (
        _RUN_FAILED_BLOCK_START not in report_text
        or _RUN_FAILED_BLOCK_END not in report_text
    ):
        return None
    payload = report_text.split(_RUN_FAILED_BLOCK_START, 1)[1].split(
        _RUN_FAILED_BLOCK_END, 1
    )[0]
    try:
        data = json.loads(payload.strip())
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict) or data.get("marker_version") != VDP_RUN_FAILED_MARKER_VERSION:
        return None
    return data


# ---------------------------------------------------------------------------
# Secret scan and atomic promotion
# ---------------------------------------------------------------------------


def scan_report_secrets(content: str) -> List[str]:
    """Scan report content for known secret patterns.

    Returns a list of matched pattern names (never the secret values).
    """
    found: List[str] = []
    for pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            found.append(pattern.pattern)
    return found


def atomic_write_report(
    output_path: Path,
    content: str,
    *,
    required_sections: Optional[List[str]] = None,
    secret_scan: bool = True,
) -> Path:
    """Atomically promote report content to ``output_path``.

    - writes to a temp file in the SAME directory,
    - re-verifies non-empty + required sections + secret absence,
    - promotes with ``os.replace`` only,
    - deletes the temp file on any failure — a partial report is NEVER left
      under the official filename.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not isinstance(content, str) or not content.strip():
        raise ValueError("refusing to promote an empty report")

    if required_sections:
        missing = [
            section for section in required_sections if section not in content
        ]
        if missing:
            raise ValueError(f"report missing required sections: {missing}")

    if secret_scan:
        matches = scan_report_secrets(content)
        if matches:
            raise ValueError(
                "refusing to promote report containing secret patterns "
                f"({len(matches)} pattern(s))"
            )

    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{output_path.name}.tmp_",
        suffix=".md",
        dir=str(output_path.parent),
    )
    tmp = Path(tmp_path)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp, output_path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return output_path


def write_manifest_json(
    manifest_path: Path,
    files: Dict[str, Path],
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Path:
    """Write a completion manifest AFTER all files have been promoted.

    The manifest records the sha256 of each file so consumers can verify
    that a file group is complete and unmodified.
    """
    manifest: Dict[str, Any] = {
        "schema_version": 1,
        "files": {},
    }
    for key, path in files.items():
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        manifest["files"][key] = {
            "path": str(Path(path).resolve()),
            "sha256": digest,
        }
    if extra:
        manifest.update(extra)
    manifest_path = Path(manifest_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return manifest_path


def verify_manifest(manifest_path: Path, files: Dict[str, Path]) -> Dict[str, Any]:
    """Verify a file group against its completion manifest.

    Returns {"ok": bool, "reason": str}. Consumers/gates/CLI MUST call this
    before treating a separated file group as an official artifact.
    """
    manifest_path = Path(manifest_path)
    if not manifest_path.exists():
        return {"ok": False, "reason": "manifest_missing"}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "reason": f"manifest_unreadable:{exc}"}
    recorded = manifest.get("files", {})
    if not isinstance(recorded, dict):
        return {"ok": False, "reason": "manifest_files_invalid"}
    for key, path in files.items():
        entry = recorded.get(key)
        if not isinstance(entry, dict):
            return {"ok": False, "reason": f"manifest_missing_entry:{key}"}
        target = Path(path)
        if not target.exists():
            return {"ok": False, "reason": f"file_missing:{key}"}
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != str(entry.get("sha256") or ""):
            return {"ok": False, "reason": f"hash_mismatch:{key}"}
    return {"ok": True, "reason": "manifest_verified"}


# Separated report group member suffixes (consumer-side manifest enforcement,
# SGK-2026-0422 audit I-07). The completion manifest is written LAST by the
# generator; consumers (gate / CLI / consistency) MUST verify it before
# treating any member file as an official artifact.
_SEPARATED_MEMBER_SUFFIXES = (
    "_submission.md",
    "_internal.md",
    "_internal.json",
    "_manifest.json",
)

# The completion manifest MUST record EXACTLY these three member files
# (audit I-07 round 4 / completion D10). A manifest that omits any of them
# is a partial group and must be rejected — trimming two entries must never
# make the remaining file pass verification.
_SEPARATED_GROUP_KEYS = ("submission", "internal_md", "internal_json")


def separated_group_manifest_for_report(report_path: Path | str) -> Optional[Path]:
    """Return the group manifest path when ``report_path`` is a member of a
    separated report group; None when it is a plain single-file report.

    A member is identified by filename: ``<stem>_submission.md``,
    ``<stem>_internal.md``, ``<stem>_internal.json`` or
    ``<stem>_manifest.json``. The manifest lives next to the member as
    ``<stem>_manifest.json``.
    """
    path = Path(report_path)
    name = path.name
    for suffix in _SEPARATED_MEMBER_SUFFIXES:
        if name.endswith(suffix):
            stem = name[: -len(suffix)]
            return path.parent / f"{stem}_manifest.json"
    return None


def verify_separated_group(report_path: Path | str) -> Dict[str, Any]:
    """Consumer-side enforcement for separated report groups.

    When ``report_path`` is a member of a separated group (submission /
    internal md / internal json / manifest), the group manifest MUST exist,
    MUST record EXACTLY the three member keys, MUST point at the paths
    derived from the group stem, and ALL three files MUST exist with
    matching sha256. A missing / modified / incomplete / trimmed manifest
    rejects the whole group — a partially promoted group (e.g. first
    os.replace succeeded, second failed) or a manifest whose entries were
    removed is NOT an official artifact (audit I-07 round 4 / D10).

    Returns {"ok": bool, "reason": str, "manifest": Optional[str]}.
    Plain single-file reports (not separated members) are unaffected.
    """
    manifest_path = separated_group_manifest_for_report(report_path)
    if manifest_path is None:
        return {"ok": True, "reason": "not_separated_artifact", "manifest": None}
    if not manifest_path.exists():
        return {
            "ok": False,
            "reason": "separated_manifest_missing",
            "manifest": str(manifest_path),
        }
    # Verify EVERY file the manifest records (all group members).
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return {
            "ok": False,
            "reason": f"separated_manifest_unreadable:{exc}",
            "manifest": str(manifest_path),
        }
    recorded = manifest.get("files", {})
    if not isinstance(recorded, dict) or not recorded:
        return {
            "ok": False,
            "reason": "separated_manifest_files_invalid",
            "manifest": str(manifest_path),
        }
    # D10: the manifest MUST record EXACTLY the three member files. A
    # trimmed manifest (e.g. only "submission" left) must never pass.
    if set(recorded.keys()) != set(_SEPARATED_GROUP_KEYS):
        return {
            "ok": False,
            "reason": "separated_manifest_keys_invalid",
            "manifest": str(manifest_path),
            "recorded_keys": sorted(str(k) for k in recorded.keys()),
        }
    # Do NOT trust manifest paths: derive the expected paths from the group
    # stem and require the manifest to point at exactly those paths.
    stem = manifest_path.name[: -len("_manifest.json")]
    expected_member_paths = {
        "submission": manifest_path.parent / f"{stem}_submission.md",
        "internal_md": manifest_path.parent / f"{stem}_internal.md",
        "internal_json": manifest_path.parent / f"{stem}_internal.json",
    }
    for key in _SEPARATED_GROUP_KEYS:
        entry = recorded.get(key)
        if not isinstance(entry, dict) or not entry.get("path"):
            return {
                "ok": False,
                "reason": f"separated_manifest_entry_invalid:{key}",
                "manifest": str(manifest_path),
            }
        recorded_path = Path(str(entry["path"]))
        if recorded_path.resolve() != expected_member_paths[key].resolve():
            return {
                "ok": False,
                "reason": f"separated_manifest_path_mismatch:{key}",
                "manifest": str(manifest_path),
            }
    # All three files must exist and match their recorded sha256.
    check = verify_manifest(manifest_path, expected_member_paths)
    if not check["ok"]:
        return {
            "ok": False,
            "reason": f"separated_{check['reason']}",
            "manifest": str(manifest_path),
        }
    return {"ok": True, "reason": "separated_manifest_verified", "manifest": str(manifest_path)}
