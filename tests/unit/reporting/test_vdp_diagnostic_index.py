"""
SGK-2026-0425 — additive ``vdp_diagnostic_index_v1`` report/session consistency
(M2, plan §5.2 / §11 test 25).

Covers:
- build_vdp_diagnostic_index: hash/count-only projection of a valid
  ``vdp_diagnostics_v1`` section (NO labels/URLs/payloads/reason text)
- embed/extract roundtrip alongside the untouched ``vdp_canonical_index_v1``
- tamper detection: event reason code -> event_hash; deleted event ->
  stage_sets/event_hash; summary metadata -> summary_digest; run_id
- additive-absent compatibility: old report/session with neither index stays
  consistent with NO reason codes
- fail-closed: session section present but report index absent ->
  vdp_diagnostic_report_index_missing; report index present but session
  section absent -> vdp_diagnostic_session_index_missing
- build(None) -> None; embed(None) adds no block
"""
from __future__ import annotations

import json
from pathlib import Path

from src.core.engine.vdp_diagnostic_trace import validate_diagnostic_section
from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.report_session_consistency import (
    verify_report_session_consistency,
)
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_report_projection import (
    build_vdp_diagnostic_index,
    embed_vdp_canonical_index,
    embed_vdp_diagnostic_index,
    extract_vdp_canonical_index_from_report,
    extract_vdp_diagnostic_index_from_report,
)

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session


def _event(event_id: str, stage_id: str, outcome: str = "reached",
           reason_codes=None, run_id: str = "run-0425-001") -> dict:
    return {
        "event_id": event_id,
        "run_id": run_id,
        "stage_id": stage_id,
        "outcome": outcome,
        "reason_codes": list(reason_codes or []),
        "predecessor_ids": [],
        "successor_ids": [],
        "opaque_asset_fingerprint": "fp-opaque-1",
        "producer_id": "producer-1",
        "agent_id": "agent-1",
        "tool_id": "tool-1",
        "recipe_id": "recipe-1",
        "budget_snapshot_hash": "budget-hash-1",
        "source_refs": [],
        "schema_version": 1,
        "taxonomy_version": "v2",
    }


def _diagnostic_section(run_id: str = "run-0425-001") -> dict:
    """A validate_diagnostic_section-valid section with S00..S03 events."""
    return {
        "schema_version": 1,
        "taxonomy_version": "v2",
        "diagnostic_active": True,
        "run_id": run_id,
        "events": [
            _event("evt-000", "S00", run_id=run_id),
            _event("evt-001", "S01", run_id=run_id),
            _event("evt-002", "S02", outcome="blocked",
                   reason_codes=["parse_rejected"], run_id=run_id),
            _event("evt-003", "S03", run_id=run_id),
        ],
        "backpressure_reasons": [
            {"reason": "queue_full", "event_count": 3, "stage_id": "S03"},
        ],
        "duplicate_event_counts": {"evt-000": 1},
    }


def _write_session(
    tmp_path: Path,
    seed: bytes,
    *,
    diagnostics: bool = True,
    run_id: str = "run-0425-001",
) -> tuple[Path, Ed25519EvidenceSigner]:
    signer = Ed25519EvidenceSigner(private_key=seed)
    session = _base_session(signer)
    if diagnostics:
        session["vdp_diagnostics_v1"] = _diagnostic_section(run_id=run_id)
    path = tmp_path / "session_diag.json"
    path.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
    return path, signer


def _write_report(
    tmp_path: Path,
    session_path: Path,
    signer: Ed25519EvidenceSigner,
    *,
    embed_diag: bool = True,
    tamper_event_hash: bool = False,
) -> Path:
    session = json.loads(session_path.read_text(encoding="utf-8"))
    summary = extract_vdp_canonical(
        session, public_key_provider=signer.public_key_provider()
    )
    content = "# SHIGOKU\n# Submission Report\n\nBody\n"
    content = embed_vdp_canonical_index(content, summary)
    if embed_diag:
        content = embed_vdp_diagnostic_index(
            content, session.get("vdp_diagnostics_v1")
        )
    report = tmp_path / "haddix_report_diag.md"
    report.write_text(content, encoding="utf-8")
    if tamper_event_hash:
        text = report.read_text(encoding="utf-8")
        text = text.replace('"event_hash": "sha256:', '"event_hash": "sha256:0')
        report.write_text(text, encoding="utf-8")
    return report


class TestBuildDiagnosticIndex:
    def test_section_is_m0_valid(self):
        result = validate_diagnostic_section(_diagnostic_section())
        assert result.passed, result.reason_codes

    def test_build_returns_none_when_absent(self):
        assert build_vdp_diagnostic_index(None) is None
        assert build_vdp_diagnostic_index("not-a-dict") is None

    def test_build_fields_hash_and_count_only(self):
        section = _diagnostic_section()
        index = build_vdp_diagnostic_index(section)
        assert index["index_version"] == "vdp_diagnostic_index_v1"
        assert index["taxonomy_version"] == "v2"
        assert index["run_id"] == "run-0425-001"
        assert index["events_count"] == 4
        assert index["event_hash"].startswith("sha256:")
        assert index["stage_sets"] == {
            "S00": {"reached": 1},
            "S01": {"reached": 1},
            "S02": {"blocked": 1},
            "S03": {"reached": 1},
        }
        assert index["backpressure_reasons_count"] == 1
        assert index["duplicate_event_counts_count"] == 1
        assert index["summary_digest"].startswith("sha256:")
        # NO labels / reason text / URLs / payloads in the index.
        assert "parse_rejected" not in json.dumps(index)
        assert "fp-opaque-1" not in json.dumps(index)

    def test_build_deterministic(self):
        a = build_vdp_diagnostic_index(_diagnostic_section())
        b = build_vdp_diagnostic_index(_diagnostic_section())
        assert a == b


class TestEmbedExtract:
    def test_roundtrip_with_both_indexes(self):
        section = _diagnostic_section()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("a1" * 32))
        summary = extract_vdp_canonical(
            _base_session(signer), public_key_provider=signer.public_key_provider()
        )
        md = "# SHIGOKU\n# Submission Report\n\nBody\n"
        md = embed_vdp_canonical_index(md, summary)
        md = embed_vdp_diagnostic_index(md, section)
        canon = extract_vdp_canonical_index_from_report(md)
        diag = extract_vdp_diagnostic_index_from_report(md)
        assert canon is not None
        assert canon["index_version"] == "vdp_canonical_index_v1"
        assert diag is not None
        assert diag["index_version"] == "vdp_diagnostic_index_v1"
        assert diag["events_count"] == 4
        assert diag["stage_sets"]["S02"] == {"blocked": 1}

    def test_extract_none_when_missing(self):
        assert extract_vdp_diagnostic_index_from_report("# no block\n") is None

    def test_extract_none_when_corrupt(self):
        report = (
            "<!-- vdp_diagnostic_index_v1:start -->\nnot json\n"
            "<!-- vdp_diagnostic_index_v1:end -->\n"
        )
        assert extract_vdp_diagnostic_index_from_report(report) is None

    def test_extract_none_when_wrong_version(self):
        report = (
            "<!-- vdp_diagnostic_index_v1:start -->\n"
            '{"index_version": "vdp_diagnostic_index_v2"}\n'
            "<!-- vdp_diagnostic_index_v1:end -->\n"
        )
        assert extract_vdp_diagnostic_index_from_report(report) is None

    def test_reembed_replaces_old_block(self):
        section = _diagnostic_section()
        md = embed_vdp_diagnostic_index("# R\n", section)
        md = embed_vdp_diagnostic_index(md, section)
        assert md.count("vdp_diagnostic_index_v1:start") == 1

    def test_embed_none_adds_no_block(self):
        md = "# R\nBody\n"
        assert embed_vdp_diagnostic_index(md, None) == md
        assert "vdp_diagnostic_index_v1" not in md


class TestDiagnosticConsistency:
    def test_valid_pair_consistent_and_compared(self, tmp_path):
        seed = bytes.fromhex("b1" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_report(tmp_path, session_path, signer)
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "consistent", result["reason_codes"]
        dc = result["diagnostic_comparison"]
        assert dc["vdp_diagnostic_mode"] == "diagnostic"
        assert dc["compared"] is True
        assert dc["reason_codes"] == []
        assert result["comparison"]["vdp_diagnostic"]["compared"] is True

    def test_event_reason_code_change_detected(self, tmp_path):
        seed = bytes.fromhex("b2" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_report(tmp_path, session_path, signer)
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["vdp_diagnostics_v1"]["events"][2]["reason_codes"] = [
            "field_dropped"
        ]
        tampered = tmp_path / "session_tampered.json"
        tampered.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
        result = verify_report_session_consistency(
            report,
            session_path=tampered,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert "vdp_diagnostic_event_hash_mismatch" in result["reason_codes"]

    def test_deleted_event_stage_set_detected(self, tmp_path):
        seed = bytes.fromhex("b3" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_report(tmp_path, session_path, signer)
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["vdp_diagnostics_v1"]["events"].pop(1)  # S01 disappears
        tampered = tmp_path / "session_tampered.json"
        tampered.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
        result = verify_report_session_consistency(
            report,
            session_path=tampered,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert "vdp_diagnostic_stage_set_mismatch" in result["reason_codes"]
        assert "vdp_diagnostic_event_hash_mismatch" in result["reason_codes"]

    def test_summary_metadata_change_detected(self, tmp_path):
        seed = bytes.fromhex("b4" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_report(tmp_path, session_path, signer)
        session = json.loads(session_path.read_text(encoding="utf-8"))
        session["vdp_diagnostics_v1"]["run_id"] = "run-other-999"
        tampered = tmp_path / "session_tampered.json"
        tampered.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
        result = verify_report_session_consistency(
            report,
            session_path=tampered,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert "vdp_diagnostic_summary_digest_mismatch" in result["reason_codes"]
        assert "vdp_diagnostic_run_id_mismatch" in result["reason_codes"]

    def test_tampered_report_index_detected(self, tmp_path):
        seed = bytes.fromhex("b5" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_report(
            tmp_path, session_path, signer, tamper_event_hash=True
        )
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert "vdp_diagnostic_event_hash_mismatch" in result["reason_codes"]

    def test_legacy_pair_additive_absent_compatible(self, tmp_path):
        """Old report/session with neither index: absent mode, NO reason
        codes, status unchanged (plan §11 test 25)."""
        legacy_session = tmp_path / "session_legacy.json"
        legacy_session.write_text(
            json.dumps({"task_queue": [], "completed_tasks": []}),
            encoding="utf-8",
        )
        legacy_report = tmp_path / "haddix_report_legacy.md"
        legacy_report.write_text(
            "# SHIGOKU\n# Submission Report\n\nConfirmed: 0 / Candidate: 0\n",
            encoding="utf-8",
        )
        result = verify_report_session_consistency(
            legacy_report, session_path=legacy_session
        )
        assert result["status"] == "consistent", result["reason_codes"]
        dc = result["diagnostic_comparison"]
        assert dc["vdp_diagnostic_mode"] == "absent"
        assert dc["compared"] is False
        assert not any(
            str(c).startswith("vdp_diagnostic") for c in result["reason_codes"]
        )

    def test_canonical_pair_without_diagnostics_absent(self, tmp_path):
        """A canonical pair predating M1 telemetry stays consistent: the
        diagnostic comparison is additive-absent."""
        seed = bytes.fromhex("b7" * 32)
        session_path, signer = _write_session(tmp_path, seed, diagnostics=False)
        report = _write_report(
            tmp_path, session_path, signer, embed_diag=False
        )
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "consistent", result["reason_codes"]
        assert result["diagnostic_comparison"]["vdp_diagnostic_mode"] == "absent"
        assert result["diagnostic_comparison"]["compared"] is False

    def test_session_section_but_report_index_absent_fail_closed(self, tmp_path):
        """A session with telemetry MUST have the machine-readable diagnostic
        index in the report — a missing index is fail-closed inconsistent."""
        seed = bytes.fromhex("b8" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_report(
            tmp_path, session_path, signer, embed_diag=False
        )
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert "vdp_diagnostic_report_index_missing" in result["reason_codes"]
        assert result["diagnostic_comparison"]["compared"] is False

    def test_report_index_but_session_section_absent(self, tmp_path):
        seed = bytes.fromhex("b9" * 32)
        session_path, signer = _write_session(tmp_path, seed, diagnostics=False)
        session = json.loads(session_path.read_text(encoding="utf-8"))
        summary = extract_vdp_canonical(
            session, public_key_provider=signer.public_key_provider()
        )
        content = embed_vdp_canonical_index(
            "# SHIGOKU\n# Submission Report\nBody\n", summary
        )
        content = embed_vdp_diagnostic_index(content, _diagnostic_section())
        report = tmp_path / "haddix_report_diag_only.md"
        report.write_text(content, encoding="utf-8")
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert "vdp_diagnostic_session_index_missing" in result["reason_codes"]
