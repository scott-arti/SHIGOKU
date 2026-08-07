"""
SGK-2026-0422 — shigoku-ops vdp gate CLI tests (T6).

Covers:
- vdp gate --profile training requires --labels; blocked otherwise
- vdp gate --profile real accepts --session; with --report continues only
  when consistency is consistent
- JSON output schema: status pass|fail|blocked; real adds decision
  go|hold|no_go
- exit codes: 0=pass/go, 2=blocked/hold/input-missing, 3=fail/no_go
- real profile never references confirmed_min/candidate_max
- existing report gate behavior unchanged (legacy wrapper)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.core.engine.master_conductor_session_service import (
    inject_vdp_section_to_session_payload,
)
from src.reporting.vdp_report_projection import embed_vdp_canonical_index

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session

CLI = "scripts/shigoku_ops_cli.py"


def _session_file(tmp_path: Path) -> Path:
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
    session = _base_session(signer)
    path = tmp_path / "session_vdp.json"
    path.write_text(json.dumps(session, ensure_ascii=False), encoding="utf-8")
    return path


def _report_file(tmp_path: Path, session_path: Path) -> Path:
    """A canonical report embedding the index derived from the session."""
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
    session = json.loads(session_path.read_text(encoding="utf-8"))
    from src.reporting.vdp_canonical import extract_vdp_canonical

    summary = extract_vdp_canonical(
        session, public_key_provider=signer.public_key_provider()
    )
    path = tmp_path / "haddix_report_canonical.md"
    path.write_text(
        embed_vdp_canonical_index("# SHIGOKU\n# Submission Report\nBody\n", summary),
        encoding="utf-8",
    )
    return path


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    """Run shigoku-ops with the dev/test public verification key configured
    so confirmed verdicts can be restored by the CLI (verifier boundary)."""
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
        cwd="/home/bbb/Documents/App/Shigoku",
    )


class TestVdpGateCLI:
    def test_training_without_labels_blocked_exit_2(self, tmp_path):
        session = _session_file(tmp_path)
        result = _run_cli(
            "vdp", "gate", "--profile", "training", "--session", str(session)
        )
        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert payload["status"] == "blocked"
        assert "training_labels_required" in payload["reason_codes"]
        assert payload["profile"] == "training"

    def test_training_with_labels_passes(self, tmp_path):
        session = _session_file(tmp_path)
        labels = tmp_path / "labels.json"
        labels.write_text(
            json.dumps(
                {"labels": [{"hypothesis_id": "hyp-001", "expected_class": "idor"}]}
            ),
            encoding="utf-8",
        )
        result = _run_cli(
            "vdp", "gate", "--profile", "training",
            "--session", str(session), "--labels", str(labels),
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["status"] == "pass"
        assert payload["gates"]["class_recall"]["recall"] == 1.0

    def test_real_profile_go(self, tmp_path):
        session = _session_file(tmp_path)
        result = _run_cli(
            "vdp", "gate", "--profile", "real", "--session", str(session)
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["profile"] == "real"
        assert payload["decision"] == "go"
        assert payload["status"] == "pass"

    def test_real_profile_with_consistent_report(self, tmp_path):
        session = _session_file(tmp_path)
        report = _report_file(tmp_path, session)
        result = _run_cli(
            "vdp", "gate", "--profile", "real",
            "--session", str(session), "--report", str(report),
        )
        assert result.returncode == 0
        payload = json.loads(result.stdout)
        assert payload["decision"] == "go"
        assert payload["consistency"]["status"] == "consistent"

    def test_real_profile_inconsistent_report_blocks(self, tmp_path):
        session = _session_file(tmp_path)
        # A report with a TAMPERED canonical index (verdict id differs from
        # the session) makes consistency inconsistent -> real profile blocks.
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
        session_data = json.loads(session.read_text(encoding="utf-8"))
        from src.reporting.vdp_canonical import extract_vdp_canonical

        summary = extract_vdp_canonical(
            session_data, public_key_provider=signer.public_key_provider()
        )
        bad_report = tmp_path / "haddix_report_tampered.md"
        content = embed_vdp_canonical_index(
            "# SHIGOKU\n# Submission Report\nBody\n", summary
        )
        bad_report.write_text(
            content.replace('"ver-001"', '"ver-999"'), encoding="utf-8"
        )
        result = _run_cli(
            "vdp", "gate", "--profile", "real",
            "--session", str(session), "--report", str(bad_report),
        )
        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert payload["status"] == "blocked"
        assert any("consistency" in c for c in payload["reason_codes"])

    def test_missing_session_blocked(self, tmp_path):
        result = _run_cli(
            "vdp", "gate", "--profile", "real", "--session", str(tmp_path / "nope.json")
        )
        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert "session_required_for_vdp_gate" in payload["reason_codes"]

    def test_real_profile_no_legacy_thresholds_in_json(self, tmp_path):
        session = _session_file(tmp_path)
        result = _run_cli(
            "vdp", "gate", "--profile", "real", "--session", str(session)
        )
        payload = json.loads(result.stdout)
        assert payload["policy"]["confirmed_min"] == "not_used"
        assert payload["policy"]["candidate_max"] == "not_used"

    def test_check_initial_release_gate_vdp_real_requires_report(self, tmp_path):
        """Audit I-05: check_initial_release_gate.py --profile vdp-real MUST
        verify report existence and run consistency — a missing report is
        blocked (exit 2), never pass/go."""
        import subprocess as _sp
        import sys as _sys

        session = _session_file(tmp_path)
        missing_report = tmp_path / "does_not_exist.md"
        result = _sp.run(
            [_sys.executable, "scripts/check_initial_release_gate.py",
             "--report", str(missing_report),
             "--session", str(session),
             "--profile", "vdp-real"],
            capture_output=True, text=True,
            env=dict(os.environ),
            cwd="/home/bbb/Documents/App/Shigoku",
        )
        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert payload["status"] == "blocked"
        assert "report_not_found_for_vdp_real" in payload["reason_codes"]

    def test_check_initial_release_gate_vdp_real_inconsistent_blocked(self, tmp_path):
        """Audit I-05: an inconsistent report for vdp-real is blocked, not Go."""
        import subprocess as _sp
        import sys as _sys

        session = _session_file(tmp_path)
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("81" * 32))
        session_data = json.loads(session.read_text(encoding="utf-8"))
        from src.reporting.vdp_canonical import extract_vdp_canonical

        summary = extract_vdp_canonical(
            session_data, public_key_provider=signer.public_key_provider()
        )
        bad_report = tmp_path / "haddix_report_tampered.md"
        content = embed_vdp_canonical_index(
            "# SHIGOKU\n# Submission Report\nBody\n", summary
        )
        bad_report.write_text(
            content.replace('"ver-001"', '"ver-999"'), encoding="utf-8"
        )
        result = _sp.run(
            [_sys.executable, "scripts/check_initial_release_gate.py",
             "--report", str(bad_report),
             "--session", str(session),
             "--profile", "vdp-real"],
            capture_output=True, text=True,
            env=dict(os.environ),
            cwd="/home/bbb/Documents/App/Shigoku",
        )
        assert result.returncode == 2
        payload = json.loads(result.stdout)
        assert payload["status"] == "blocked"
        assert any("consistency" in c for c in payload["reason_codes"])

    def test_exit_code_mapping(self, tmp_path):
        session = _session_file(tmp_path)
        go = _run_cli("vdp", "gate", "--profile", "real", "--session", str(session))
        assert go.returncode == 0

        blocked = _run_cli("vdp", "gate", "--profile", "training", "--session", str(session))
        assert blocked.returncode == 2

        # Force a no_go: tampered proof in the session verdict.
        signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("82" * 32))
        session_data = _base_session(signer)
        session_data["vdp_contract"]["verdicts"][0]["validation_proof"] = "ed25519:k:AA"
        path = tmp_path / "session_tampered.json"
        path.write_text(json.dumps(session_data, ensure_ascii=False), encoding="utf-8")
        no_go = _run_cli("vdp", "gate", "--profile", "real", "--session", str(path))
        assert no_go.returncode == 3
        assert json.loads(no_go.stdout)["decision"] == "no_go"


class TestVdpGateCLISeparatedManifest:
    """Audit I-07 (round 3): `vdp gate --report` must reject a separated
    report group without a verified manifest."""

    def _separated_group(self, tmp_path: Path):
        from src.reporting.haddix_submission_internal_formatter import (
            generate_separated_report_files,
        )

        return generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )

    def test_vdp_gate_rejects_missing_manifest(self, tmp_path):
        session = _session_file(tmp_path)
        artifacts = self._separated_group(tmp_path)
        Path(artifacts["manifest"]).unlink()
        result = _run_cli(
            "vdp", "gate", "--profile", "real",
            "--session", str(session),
            "--report", str(artifacts["submission"]),
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert "separated_manifest_missing" in payload["reason_codes"]

    def test_vdp_gate_accepts_verified_group(self, tmp_path):
        session = _session_file(tmp_path)
        artifacts = self._separated_group(tmp_path)
        result = _run_cli(
            "vdp", "gate", "--profile", "real",
            "--session", str(session),
            "--report", str(artifacts["submission"]),
        )
        payload = json.loads(result.stdout)
        assert not any(
            c.startswith("separated_") for c in payload["reason_codes"]
        ), payload["reason_codes"]


class TestExistingGateUnchanged:
    def test_report_gate_still_parses(self, tmp_path):
        """Existing report gate CLI surface remains available."""
        session = _session_file(tmp_path)
        report = tmp_path / "haddix_report_legacy.md"
        report.write_text(
            "# SHIGOKU\n# Submission Report\n\nConfirmed: 0 / Candidate: 0\n",
            encoding="utf-8",
        )
        result = _run_cli(
            "report", "gate", "--report", str(report), "--session", str(session)
        )
        # The legacy gate may fail on missing gate sections, but the CLI must
        # respond with a structured JSON (not a crash).
        assert result.returncode in (0, 2, 3)
        payload = json.loads(result.stdout)
        assert "status" in payload


class TestVdpKeyRegistryFlag:
    """SGK-2026-0423 close-out: --vdp-key-registry (public-key provider)."""

    @staticmethod
    def _load_cli_module():
        import importlib.util

        spec = importlib.util.spec_from_file_location("shigoku_ops_cli_mod", CLI)
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return mod

    def test_loader_valid_registry(self, tmp_path):
        mod = self._load_cli_module()
        pub = bytes.fromhex("22" * 32)
        reg = tmp_path / "registry.json"
        reg.write_text(
            json.dumps(
                {"schema_version": 1, "keys": {"k1": {"public_key": pub.hex()}}}
            ),
            encoding="utf-8",
        )
        assert mod._load_vdp_key_provider(str(reg)) == {"k1": pub}

    def test_loader_missing_malformed_or_empty_fail_closed(self, tmp_path):
        mod = self._load_cli_module()
        assert mod._load_vdp_key_provider(None) is None
        assert mod._load_vdp_key_provider(str(tmp_path / "missing.json")) is None
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        assert mod._load_vdp_key_provider(str(bad)) is None
        empty = tmp_path / "empty.json"
        empty.write_text(json.dumps({"schema_version": 1, "keys": {}}), encoding="utf-8")
        assert mod._load_vdp_key_provider(str(empty)) is None

    def test_cli_accepts_vdp_key_registry_flag(self, tmp_path):
        session = _session_file(tmp_path)
        reg = tmp_path / "registry.json"
        reg.write_text(
            json.dumps(
                {"schema_version": 1, "keys": {"k1": {"public_key": "22" * 32}}}
            ),
            encoding="utf-8",
        )
        result = _run_cli(
            "vdp", "gate", "--profile", "real", "--session", str(session),
            "--vdp-key-registry", str(reg),
        )
        # The flag must parse and the gate must answer with structured JSON.
        assert result.returncode in (0, 2, 3)
        payload = json.loads(result.stdout)
        assert "status" in payload
