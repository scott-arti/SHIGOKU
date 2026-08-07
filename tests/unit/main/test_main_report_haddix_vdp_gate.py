"""
SGK-2026-0422 — main.py report path report/session consistency wiring (T6).

Audit I-07 (round 3): the main.py haddix and haddix-ja-en report paths must
measure report/session consistency on the ACTUAL generated report and pass
the real status/reason codes into the real VDP gate — a canonical index
missing/mismatch must become No-Go in the main path, never a hardcoded
"consistent".
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from src import main as main_module
from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session


def _write_canonical_session(project_dir: Path) -> Path:
    sessions_dir = project_dir / "sessions"
    sessions_dir.mkdir(parents=True, exist_ok=True)
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("91" * 32))
    session = _base_session(signer)
    # Align the session scenario coverage with what the report builder
    # computes for a session without completed tasks (all catalog scenarios
    # missing) so the legacy coverage comparison stays consistent.
    from src.main import _resolve_scn_catalog_for_report

    catalog_ids = sorted(
        {str(i.get("id", "")).strip().lower() for i in _resolve_scn_catalog_for_report()}
    )
    session["scenario_coverage"] = {
        "covered_count": 0,
        "required_count": len(catalog_ids),
        "missing_scenarios": catalog_ids,
        "required_scenarios": catalog_ids,
        "covered_scenarios": [],
    }
    session_file = sessions_dir / "session_20260803_090000.json"
    session_file.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
    return session_file


def _run_main_report(tmp_path, monkeypatch, *, fmt: str, project_name: str) -> Path:
    project_dir = tmp_path / "projects" / project_name
    _write_canonical_session(project_dir)

    class FakeProjectManager:
        def __init__(self, target):
            self.project_dir = tmp_path / "projects" / target

    monkeypatch.setattr("src.core.project.project_manager.ProjectManager", FakeProjectManager)
    monkeypatch.setattr(
        sys,
        "argv",
        ["shigoku", "--report", "--format", fmt, "--target", project_name],
    )
    main_module.main()
    return project_dir / "reports"


def test_main_haddix_canonical_index_missing_is_no_go(tmp_path, monkeypatch):
    """haddix path: canonical session whose generated report loses the
    machine-readable index -> measured consistency inconsistent -> real VDP
    gate No-Go (audit I-07)."""
    # Simulate the index-loss bug: the formatter must not embed the index.
    # (The main path must detect this and produce No-Go, not "consistent".)
    def _no_embed(markdown: str, summary) -> str:
        return markdown

    monkeypatch.setattr(
        "src.reporting.vdp_report_projection.embed_vdp_canonical_index",
        _no_embed,
    )
    reports_dir = _run_main_report(
        tmp_path, monkeypatch, fmt="haddix", project_name="demo-vdp-nogo"
    )
    gate_files = sorted(reports_dir.glob("haddix_gate_*.json"))
    assert gate_files, "gate JSON must be generated"
    gate = json.loads(gate_files[-1].read_text(encoding="utf-8"))
    assert gate["decision"] == "no_go", gate
    assert "report_session_inconsistent" in gate["reason_codes"], gate["reason_codes"]
    assert gate.get("gates", {}).get("report_session_consistency", {}).get(
        "consistency_status"
    ) == "inconsistent"


def test_main_haddix_canonical_index_present_is_consistent(tmp_path, monkeypatch):
    """haddix path: canonical session with the index embedded -> measured
    consistency is consistent (no fabricated No-Go)."""
    reports_dir = _run_main_report(
        tmp_path, monkeypatch, fmt="haddix", project_name="demo-vdp-ok"
    )
    gate_files = sorted(reports_dir.glob("haddix_gate_*.json"))
    assert gate_files
    gate = json.loads(gate_files[-1].read_text(encoding="utf-8"))
    # With the key unavailable the confirmed verdict is demoted to candidate,
    # so the real gate returns Hold — but the CONSISTENCY measurement must be
    # consistent, not a hardcoded value.
    assert gate.get("gates", {}).get("report_session_consistency", {}).get(
        "consistency_status"
    ) == "consistent"


def test_main_ja_en_canonical_index_missing_is_no_go(tmp_path, monkeypatch):
    """haddix-ja-en path: canonical index missing -> real VDP gate No-Go."""
    def _no_embed(markdown: str, summary) -> str:
        return markdown

    monkeypatch.setattr(
        "src.reporting.vdp_report_projection.embed_vdp_canonical_index",
        _no_embed,
    )
    reports_dir = _run_main_report(
        tmp_path, monkeypatch, fmt="haddix-ja-en", project_name="demo-jaen-vdp-nogo"
    )
    report_files = sorted(reports_dir.glob("haddix_report_*.md"))
    assert report_files
    content = report_files[-1].read_text(encoding="utf-8")
    assert "## Initial Release Gate" in content
    assert "**FAIL**" in content
    assert "report_session_inconsistent" in content
