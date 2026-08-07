"""
SGK-2026-0422 — separated report manifest tests (T4).

Covers:
- generate_separated_report_files promotes all 3 files atomically and writes
  the completion manifest LAST
- manifest verification: manifest exists / 3 files exist / hashes match
- partial promotion failure (second file fails) must NOT leave a file group
  treated as an official artifact — verify_manifest reports missing entry or
  missing manifest
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.haddix_submission_internal_formatter import (
    generate_separated_report_files,
)
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_report_projection import verify_manifest

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session
from tests.unit.reporting.test_vdp_formatter_projection import _finding_dict


def _summary():
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("61" * 32))
    return extract_vdp_canonical(
        _base_session(signer), public_key_provider=signer.public_key_provider()
    )


class TestSeparatedReportManifest:
    def test_successful_group_has_manifest_and_verifies(self, tmp_path):
        artifacts = generate_separated_report_files(
            findings=[_finding_dict("confirmed")],
            target="https://example.com",
            output_dir=tmp_path,
            vdp_canonical_summary=_summary(),
        )
        assert "manifest" in artifacts
        manifest_path = Path(artifacts["manifest"])
        assert manifest_path.exists()

        files = {
            "submission": artifacts["submission"],
            "internal_md": artifacts["internal_md"],
            "internal_json": artifacts["internal_json"],
        }
        for key, path in files.items():
            assert Path(path).exists(), f"{key} must exist"

        result = verify_manifest(manifest_path, files)
        assert result["ok"] is True, result["reason"]

    def test_manifest_is_written_last(self, tmp_path):
        """The manifest must be the newest of the four files (written last)."""
        artifacts = generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )
        manifest_mtime = Path(artifacts["manifest"]).stat().st_mtime
        for key in ("submission", "internal_md", "internal_json"):
            assert Path(artifacts[key]).stat().st_mtime <= manifest_mtime, (
                f"{key} must predate the manifest"
            )

    def test_delete_one_file_breaks_manifest(self, tmp_path):
        artifacts = generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )
        Path(artifacts["submission"]).unlink()
        files = {
            "submission": artifacts["submission"],
            "internal_md": artifacts["internal_md"],
            "internal_json": artifacts["internal_json"],
        }
        result = verify_manifest(Path(artifacts["manifest"]), files)
        assert result["ok"] is False
        assert "file_missing" in result["reason"]

    def test_tamper_file_breaks_manifest(self, tmp_path):
        artifacts = generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )
        Path(artifacts["internal_json"]).write_text("{}", encoding="utf-8")
        files = {
            "submission": artifacts["submission"],
            "internal_md": artifacts["internal_md"],
            "internal_json": artifacts["internal_json"],
        }
        result = verify_manifest(Path(artifacts["manifest"]), files)
        assert result["ok"] is False
        assert "hash_mismatch" in result["reason"]

    def test_manifest_missing_means_not_official(self, tmp_path):
        """Without a manifest, a file group is NOT an official artifact."""
        artifacts = generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )
        manifest_path = Path(artifacts["manifest"])
        manifest_path.unlink()
        files = {
            "submission": artifacts["submission"],
            "internal_md": artifacts["internal_md"],
            "internal_json": artifacts["internal_json"],
        }
        result = verify_manifest(manifest_path, files)
        assert result["ok"] is False
        assert result["reason"] == "manifest_missing"

    def test_canonical_index_in_internal_json(self, tmp_path):
        artifacts = generate_separated_report_files(
            findings=[_finding_dict("confirmed")],
            target="https://example.com",
            output_dir=tmp_path,
            vdp_canonical_summary=_summary(),
        )
        data = json.loads(Path(artifacts["internal_json"]).read_text(encoding="utf-8"))
        index = data.get("vdp_canonical_index_v1")
        assert index is not None
        assert index["index_version"] == "vdp_canonical_index_v1"
        assert index["verdict_counts"]["confirmed"] == 1

    def test_second_file_failure_leaves_no_official_group(self, tmp_path, monkeypatch):
        """Audit I-06: if promotion of the SECOND file fails, no manifest is
        written and the partial group is NOT an official artifact — consumers
        must not treat files without a manifest as official."""
        import os as _os

        real_replace = _os.replace
        call_count = {"n": 0}

        def _fail_on_second(src, dst):
            call_count["n"] += 1
            if call_count["n"] == 2:
                raise OSError("simulated second-file promotion failure")
            return real_replace(src, dst)

        monkeypatch.setattr(_os, "replace", _fail_on_second)
        with pytest.raises(OSError, match="second-file"):
            generate_separated_report_files(
                findings=[],
                target="https://example.com",
                output_dir=tmp_path,
            )
        monkeypatch.setattr(_os, "replace", real_replace)

        # No manifest → the group is not official; temp files cleaned.
        manifests = list(tmp_path.glob("*_manifest.json"))
        assert manifests == [], "manifest must not be written on partial failure"
        temps = list(tmp_path.glob(".haddix_*_submission.tmp_*")) + \
            list(tmp_path.glob(".haddix_*_internal_md.tmp_*")) + \
            list(tmp_path.glob(".haddix_*_internal_json.tmp_*"))
        assert temps == [], f"temp files must be cleaned: {temps}"

    def test_manifest_verification_is_consumer_requirement(self, tmp_path):
        """Audit I-06: a file group without a verified manifest must not be
        treated as official by consumers (gate/CLI/consistency path)."""
        artifacts = generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )
        manifest_path = Path(artifacts["manifest"])
        files = {
            "submission": artifacts["submission"],
            "internal_md": artifacts["internal_md"],
            "internal_json": artifacts["internal_json"],
        }
        assert verify_manifest(manifest_path, files)["ok"] is True

        # Simulate a consumer that ignores the manifest: deleting one file
        # while passing the stale path must be detected by verify_manifest.
        Path(artifacts["internal_json"]).unlink()
        assert verify_manifest(manifest_path, files)["ok"] is False


class TestConsumerManifestEnforcement:
    """Audit I-07 (round 3): separated artifacts must be manifest-verified by
    the ACTUAL CLI / gate / consistency consumers — a partial group without
    a manifest (or with a tampered member) is rejected, not consumed."""

    def _separated_group(self, tmp_path: Path):
        artifacts = generate_separated_report_files(
            findings=[],
            target="https://example.com",
            output_dir=tmp_path,
        )
        return artifacts

    def _run_cli(self, *args: str):
        import os
        import subprocess
        import sys

        return subprocess.run(
            [sys.executable, "scripts/shigoku_ops_cli.py", "--json", *args],
            capture_output=True,
            text=True,
            env=dict(os.environ),
            cwd="/home/bbb/Documents/App/Shigoku",
        )

    def test_report_gate_rejects_missing_manifest(self, tmp_path):
        """The actual `report gate` CLI rejects a submission member whose
        group manifest is missing (partial promotion is not official)."""
        artifacts = self._separated_group(tmp_path)
        Path(artifacts["manifest"]).unlink()
        result = self._run_cli(
            "report", "gate", "--report", str(artifacts["submission"])
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert payload["status"] == "fail"
        assert "separated_manifest_missing" in payload["reason_codes"]

    def test_report_gate_rejects_tampered_member(self, tmp_path):
        """The actual `report gate` CLI rejects a group whose member hash no
        longer matches the manifest."""
        artifacts = self._separated_group(tmp_path)
        Path(artifacts["internal_json"]).write_text("{}", encoding="utf-8")
        result = self._run_cli(
            "report", "gate", "--report", str(artifacts["submission"])
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert any("hash_mismatch" in c for c in payload["reason_codes"])

    def test_report_gate_rejects_trimmed_manifest(self, tmp_path):
        """Audit I-07 round 4: the actual CLI must reject a manifest with
        two of three entries removed (exit 3), not proceed past it."""
        artifacts = self._separated_group(tmp_path)
        manifest_path = Path(artifacts["manifest"])
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["files"] = {"submission": data["files"]["submission"]}
        manifest_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = self._run_cli(
            "report", "gate", "--report", str(artifacts["submission"])
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert "separated_manifest_keys_invalid" in payload["reason_codes"]

    def test_report_consistency_rejects_trimmed_manifest(self, tmp_path):
        """The actual `report consistency` CLI must reject a trimmed
        manifest with exit 3 (not fall through to processing)."""
        artifacts = self._separated_group(tmp_path)
        manifest_path = Path(artifacts["manifest"])
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["files"] = {"submission": data["files"]["submission"]}
        manifest_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = self._run_cli(
            "report", "consistency", "--report", str(artifacts["submission"])
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert "separated_manifest_keys_invalid" in payload["reason_codes"]

    def test_report_gate_accepts_verified_group(self, tmp_path):
        """A fully verified separated group is NOT rejected by the manifest
        gate (the underlying evaluation proceeds)."""
        artifacts = self._separated_group(tmp_path)
        result = self._run_cli(
            "report", "gate", "--report", str(artifacts["submission"])
        )
        payload = json.loads(result.stdout)
        assert not any(
            c.startswith("separated_") for c in payload["reason_codes"]
        ), payload["reason_codes"]

    def test_report_consistency_rejects_missing_manifest(self, tmp_path):
        """The actual `report consistency` CLI rejects a manifest-less group."""
        artifacts = self._separated_group(tmp_path)
        Path(artifacts["manifest"]).unlink()
        result = self._run_cli(
            "report", "consistency", "--report", str(artifacts["submission"])
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert "separated_manifest_missing" in payload["reason_codes"]

    def test_check_initial_release_gate_rejects_missing_manifest(self, tmp_path):
        """The actual check_initial_release_gate.py script rejects a
        manifest-less separated group before gate evaluation."""
        import os
        import subprocess
        import sys

        artifacts = self._separated_group(tmp_path)
        Path(artifacts["manifest"]).unlink()
        result = subprocess.run(
            [
                sys.executable,
                "scripts/check_initial_release_gate.py",
                "--report",
                str(artifacts["submission"]),
            ],
            capture_output=True,
            text=True,
            env=dict(os.environ),
            cwd="/home/bbb/Documents/App/Shigoku",
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert "separated_manifest_missing" in payload["reason_codes"]

    def test_check_initial_release_gate_rejects_trimmed_manifest(self, tmp_path):
        """The actual check_initial_release_gate.py script rejects a
        manifest with entries removed (exit 3, D10)."""
        import os
        import subprocess
        import sys

        artifacts = self._separated_group(tmp_path)
        manifest_path = Path(artifacts["manifest"])
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["files"] = {"submission": data["files"]["submission"]}
        manifest_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "scripts/check_initial_release_gate.py",
                "--report",
                str(artifacts["submission"]),
            ],
            capture_output=True,
            text=True,
            env=dict(os.environ),
            cwd="/home/bbb/Documents/App/Shigoku",
        )
        assert result.returncode == 3, result.stdout + result.stderr
        payload = json.loads(result.stdout)
        assert "separated_manifest_keys_invalid" in payload["reason_codes"]
