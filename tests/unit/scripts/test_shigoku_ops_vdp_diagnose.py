"""
SGK-2026-0425 — ``shigoku-ops vdp diagnose`` CLI tests (M2, plan §11 tests
19/20/24, §17.2).

Covers:
- missing session -> exit 2 with a stderr reason, no artifact
- valid session (no report) -> exit 0, artifact JSON with coverage_note,
  stdout summary, empty stderr
- --report with a tampered diagnostic index -> consistency fails first,
  exit 2, verdict on stderr, artifact NOT written
- --report with a consistent pair -> exit 0
- output conflict: existing artifact with a different
  diagnostics_section_hash is refused (exit 2, file unchanged); the same
  hash is an idempotent success (no rewrite)
- the subparser has NO --labels / ground-truth argument
- JSON schema: schema_version / analysis / coverage_note
- unexpected runtime error -> exit 3
- VALIDATION_SUITES["ops_cli"] contains this test file
- secrets elsewhere in the session never reach the artifact (0 tokens)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.core.engine.vdp_diagnostic_trace import validate_diagnostic_section
from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_report_projection import (
    embed_vdp_canonical_index,
    embed_vdp_diagnostic_index,
)

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session
from tests.unit.reporting.test_vdp_diagnostic_index import _diagnostic_section

CLI = "scripts/shigoku_ops_cli.py"
REPO_ROOT = Path(__file__).resolve().parents[3]

COVERAGE_NOTE = "coverage_not_measurable_without_sealed_labels"


def _session_file(
    tmp_path: Path,
    *,
    run_id: str = "run-0425-001",
    name: str = "session_diag.json",
    with_secrets: bool = False,
) -> Path:
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
    session = _base_session(signer)
    section = _diagnostic_section(run_id=run_id)
    assert validate_diagnostic_section(section).passed
    session["vdp_diagnostics_v1"] = section
    if with_secrets:
        session["context"] = {
            "credentials": {
                "token": "sk-live-abcdefghijklmnopqrstuvwxyz123456",
                "password": "super-secret-password-1",
            },
        }
        session["deep"] = {
            "headers": {"Authorization": "Bearer abcdefghij1234567890XYZ"},
        }
        session["misc"] = {"note": "password=hunter2secret"}
    path = tmp_path / name
    path.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
    return path


def _report_file(
    tmp_path: Path, session_path: Path, *, tamper_diag_index: bool = False
) -> Path:
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
    session = json.loads(session_path.read_text(encoding="utf-8"))
    summary = extract_vdp_canonical(
        session, public_key_provider=signer.public_key_provider()
    )
    content = embed_vdp_canonical_index(
        "# SHIGOKU\n# Submission Report\nBody\n", summary
    )
    content = embed_vdp_diagnostic_index(
        content, session.get("vdp_diagnostics_v1")
    )
    path = tmp_path / "haddix_report_diag.md"
    path.write_text(content, encoding="utf-8")
    if tamper_diag_index:
        text = path.read_text(encoding="utf-8")
        text = text.replace('"event_hash": "sha256:', '"event_hash": "sha256:0')
        path.write_text(text, encoding="utf-8")
    return path


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run shigoku-ops with the dev/test public verification key configured
    so the CLI's consistency checker restores confirmed proofs."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    env = dict(os.environ)
    seed = bytes.fromhex("81" * 32)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    env["SHIGOKU_VDP_VERIFICATION_PUBLIC_KEY"] = pub.hex()
    return subprocess.run(
        [sys.executable, CLI, "--json", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )


def _load_cli_module():
    spec = importlib.util.spec_from_file_location("shigoku_ops_cli_mod", CLI)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class TestVdpDiagnoseCLI:
    def test_missing_session_exit_2(self, tmp_path):
        out = tmp_path / "out.json"
        result = _run_cli(
            "vdp", "diagnose",
            "--session", str(tmp_path / "nope.json"),
            "--output", str(out),
        )
        assert result.returncode == 2
        assert "session" in result.stderr.lower()
        assert not out.exists()

    def test_valid_session_writes_artifact(self, tmp_path):
        session = _session_file(tmp_path)
        out = tmp_path / "out.json"
        result = _run_cli(
            "vdp", "diagnose",
            "--session", str(session),
            "--output", str(out),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert result.stderr == ""
        assert "diagnostic:" in result.stdout
        artifact = json.loads(out.read_text(encoding="utf-8"))
        assert artifact["schema_version"] == 1
        assert artifact["command"] == "vdp diagnose"
        assert artifact["coverage_note"] == COVERAGE_NOTE
        assert artifact["analysis"]["coverage_note"] == COVERAGE_NOTE
        assert artifact["session_path"] == str(Path(session).resolve())
        assert artifact["report_path"] is None
        assert artifact["diagnostics_section_hash"].startswith("sha256:")
        assert artifact["analysis"]["lineages"][0]["first_failure"]["stage_id"] == "S02"

    def test_report_inconsistent_blocks_no_artifact(self, tmp_path):
        session = _session_file(tmp_path)
        report = _report_file(tmp_path, session, tamper_diag_index=True)
        out = tmp_path / "out.json"
        result = _run_cli(
            "vdp", "diagnose",
            "--session", str(session),
            "--report", str(report),
            "--output", str(out),
        )
        assert result.returncode == 2
        assert not out.exists()
        verdict = json.loads(result.stderr)
        assert verdict["status"] == "inconsistent"
        assert any(
            "vdp_diagnostic" in c for c in verdict["reason_codes"]
        ), verdict["reason_codes"]

    def test_report_consistent_pair_exit_0(self, tmp_path):
        session = _session_file(tmp_path)
        report = _report_file(tmp_path, session)
        out = tmp_path / "out.json"
        result = _run_cli(
            "vdp", "diagnose",
            "--session", str(session),
            "--report", str(report),
            "--output", str(out),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert out.exists()

    def test_output_conflict_refused_and_idempotent(self, tmp_path):
        session_a = _session_file(tmp_path, run_id="run-A", name="session_a.json")
        out = tmp_path / "out.json"
        first = _run_cli(
            "vdp", "diagnose",
            "--session", str(session_a),
            "--output", str(out),
        )
        assert first.returncode == 0, first.stdout + first.stderr
        original = out.read_bytes()

        session_b = _session_file(tmp_path, run_id="run-B", name="session_b.json")
        conflict = _run_cli(
            "vdp", "diagnose",
            "--session", str(session_b),
            "--output", str(out),
        )
        assert conflict.returncode == 2
        assert out.read_bytes() == original, "conflicting artifact must not change"
        assert "hash" in conflict.stderr.lower()

        same = _run_cli(
            "vdp", "diagnose",
            "--session", str(session_a),
            "--output", str(out),
        )
        assert same.returncode == 0, same.stdout + same.stderr
        assert out.read_bytes() == original, "idempotent run must not rewrite"

    def test_artifact_json_schema(self, tmp_path):
        session = _session_file(tmp_path)
        out = tmp_path / "out.json"
        result = _run_cli(
            "vdp", "diagnose",
            "--session", str(session),
            "--output", str(out),
        )
        assert result.returncode == 0
        artifact = json.loads(out.read_text(encoding="utf-8"))
        assert artifact["schema_version"] == 1
        assert "analysis" in artifact
        assert artifact["coverage_note"] == COVERAGE_NOTE
        assert "diagnostics_section_hash" in artifact
        assert "lineages" in artifact["analysis"]

    def test_no_labels_argument(self, tmp_path):
        """Plan §11 test 24: the artifact-only CLI has no --labels /
        ground-truth argument."""
        mod = _load_cli_module()
        top = mod.build_parser()
        vdp_parser = top._subparsers._group_actions[0].choices["vdp"]
        diagnose_parser = vdp_parser._subparsers._group_actions[0].choices["diagnose"]
        assert "--labels" not in diagnose_parser._option_string_actions
        assert "--ground-truth" not in diagnose_parser._option_string_actions
        assert "--session" in diagnose_parser._option_string_actions
        assert diagnose_parser._option_string_actions["--session"].required
        assert "--output" in diagnose_parser._option_string_actions
        assert diagnose_parser._option_string_actions["--output"].required

    def test_runtime_error_exit_3(self, tmp_path, monkeypatch):
        mod = _load_cli_module()
        session = _session_file(tmp_path)
        out = tmp_path / "out.json"
        args = argparse.Namespace(
            session=str(session),
            report=None,
            output=str(out),
            vdp_key_registry=None,
            json=True,
            json_envelope=False,
            domain="vdp",
            action="diagnose",
        )

        def _boom(*_a, **_k):
            raise RuntimeError("simulated analyzer failure")

        monkeypatch.setattr(mod, "analyze_observed_lineages", _boom)
        assert mod._run_vdp_diagnose(args) == 3
        assert not out.exists()

    def test_invalid_diagnostic_section_exit_2(self, tmp_path):
        mod = _load_cli_module()
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
        session = _base_session(signer)
        session["vdp_diagnostics_v1"] = "not-a-dict"
        path = tmp_path / "session_bad.json"
        path.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
        out = tmp_path / "out.json"
        args = argparse.Namespace(
            session=str(path),
            report=None,
            output=str(out),
            vdp_key_registry=None,
            json=True,
            json_envelope=False,
            domain="vdp",
            action="diagnose",
        )
        assert mod._run_vdp_diagnose(args) == 2
        assert not out.exists()

    def test_ops_cli_suite_registration(self, tmp_path):
        mod = _load_cli_module()
        assert (
            "tests/unit/scripts/test_shigoku_ops_vdp_diagnose.py"
            in mod.VALIDATION_SUITES["ops_cli"]
        )

    def test_artifact_contains_no_secrets(self, tmp_path):
        session = _session_file(tmp_path, with_secrets=True)
        out = tmp_path / "out.json"
        result = _run_cli(
            "vdp", "diagnose",
            "--session", str(session),
            "--output", str(out),
        )
        assert result.returncode == 0, result.stdout + result.stderr
        text = out.read_text(encoding="utf-8")
        for token in (
            "sk-live-abcdefghijklmnopqrstuvwxyz123456",
            "super-secret-password-1",
            "Bearer abcdefghij1234567890XYZ",
            "hunter2secret",
        ):
            assert token not in text
