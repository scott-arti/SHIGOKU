"""
SGK-2026-0422 — report/session consistency canonical index comparison (T6).

Covers:
- canonical report (embedded vdp_canonical_index_v1) vs session compares
  verdict ID sets, status counts, evidence IDs/hashes, summary digest
- legacy report (no index) keeps existing behavior (verification_level
  legacy, no canonical reason codes)
- mismatch -> inconsistent with vdp_* reason codes
- report/session mismatch -> No-Go is a gate decision (consistency status
  inconsistent drives it)
"""
from __future__ import annotations

import json
from pathlib import Path

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.report_session_consistency import (
    verify_report_session_consistency,
)
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_report_projection import embed_vdp_canonical_index

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session


def _write_session(tmp_path: Path, signer_seed: bytes) -> tuple[Path, Ed25519EvidenceSigner]:
    signer = Ed25519EvidenceSigner(private_key=signer_seed)
    session = _base_session(signer)
    path = tmp_path / "session_canonical.json"
    path.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
    return path, signer


def _write_canonical_report(
    tmp_path: Path,
    session_path: Path,
    signer: Ed25519EvidenceSigner,
    *,
    tamper: bool = False,
) -> Path:
    session = json.loads(session_path.read_text(encoding="utf-8"))
    summary = extract_vdp_canonical(
        session, public_key_provider=signer.public_key_provider()
    )
    report = tmp_path / "haddix_report_canonical.md"
    content = "# SHIGOKU\n# Submission Report\n\nBody\n"
    report.write_text(
        embed_vdp_canonical_index(content, summary), encoding="utf-8"
    )
    if tamper:
        text = report.read_text(encoding="utf-8")
        # Corrupt the embedded index: change one verdict id.
        text = text.replace('"ver-001"', '"ver-999"')
        report.write_text(text, encoding="utf-8")
    return report


class TestCanonicalConsistency:
    def test_consistent_canonical_pair(self, tmp_path):
        seed = bytes.fromhex("91" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_canonical_report(tmp_path, session_path, signer)
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "consistent", result["reason_codes"]
        comparison = result["comparison"]["vdp_canonical"]
        assert comparison["vdp_mode"] == "canonical"
        assert comparison["compared"] is True

    def test_tampered_report_index_inconsistent(self, tmp_path):
        seed = bytes.fromhex("92" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        report = _write_canonical_report(
            tmp_path, session_path, signer, tamper=True
        )
        result = verify_report_session_consistency(
            report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent"
        assert any(
            code.startswith("vdp_verdict_id_set_mismatch")
            for code in result["reason_codes"]
        ), result["reason_codes"]

    def test_legacy_session_with_legacy_report_stays_consistent(self, tmp_path):
        """A legacy session (no vdp_contract section) with a legacy report
        (no index) is the ONLY compat case — stays legacy/consistent."""
        legacy_session = tmp_path / "session_legacy.json"
        legacy_session.write_text(
            json.dumps({"task_queue": [], "completed_tasks": []}), encoding="utf-8"
        )
        legacy_report = tmp_path / "haddix_report_legacy.md"
        legacy_report.write_text(
            "# SHIGOKU\n# Submission Report\n\nConfirmed: 0 / Candidate: 0\n",
            encoding="utf-8",
        )
        result = verify_report_session_consistency(
            legacy_report, session_path=legacy_session
        )
        comparison = result["comparison"]["vdp_canonical"]
        assert comparison["vdp_mode"] == "legacy"
        assert comparison["compared"] is False
        assert result["status"] == "consistent", result["reason_codes"]
        assert not any(
            str(code).startswith("vdp_") for code in result["reason_codes"]
        )

    def test_canonical_session_with_indexless_report_is_inconsistent(self, tmp_path):
        """A canonical session with an index-less report is INCONSISTENT —
        the machine comparison could not run (completion D9, audit I-04).
        No silent legacy compatibility for canonical sessions."""
        seed = bytes.fromhex("94" * 32)
        session_path, signer = _write_session(tmp_path, seed)
        bare_report = tmp_path / "haddix_report_bare.md"
        bare_report.write_text("# SHIGOKU\n# Submission Report\n\nBody\n", encoding="utf-8")
        result = verify_report_session_consistency(
            bare_report,
            session_path=session_path,
            public_key_provider=signer.public_key_provider(),
        )
        assert result["status"] == "inconsistent", result["reason_codes"]
        assert "vdp_report_index_missing" in result["reason_codes"]
        comparison = result["comparison"]["vdp_canonical"]
        assert comparison["compared"] is False
