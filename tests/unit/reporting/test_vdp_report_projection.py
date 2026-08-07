"""
SGK-2026-0422 — shared VDP report projection helpers (T4).

Covers:
- funnel / verdict / provenance markdown from a canonical summary
- machine-readable vdp_canonical_index_v1 embedding + extraction
- secret scan rejects report content with known secret patterns
- atomic promotion: temp -> verify -> os.replace; partial report never left
  under the official filename (formatter exception / secret / empty /
  missing sections / write failure)
- completion manifest: written last, verified by consumers
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.core.engine.vdp_evidence_validator import Ed25519EvidenceSigner
from src.reporting.vdp_canonical import extract_vdp_canonical
from src.reporting.vdp_report_projection import (
    atomic_write_report,
    embed_vdp_canonical_index,
    extract_vdp_canonical_index_from_report,
    format_vdp_funnel_markdown,
    format_vdp_verdicts_markdown,
    render_vdp_section_markdown,
    scan_report_secrets,
    separated_group_manifest_for_report,
    verify_manifest,
    verify_separated_group,
    write_manifest_json,
)

from tests.unit.reporting.test_vdp_canonical_extractor import _base_session


def _summary():
    signer = Ed25519EvidenceSigner(private_key=bytes.fromhex("41" * 32))
    return extract_vdp_canonical(
        _base_session(signer), public_key_provider=signer.public_key_provider()
    )


class TestFunnelMarkdown:
    def test_funnel_renders_stages(self):
        lines = format_vdp_funnel_markdown(_summary())
        text = "\n".join(lines)
        assert "VDP Evidence Funnel" in text
        for stage in ("Observations", "Hypotheses", "Attempted", "Responded",
                      "Followed-up", "Confirmed", "Refuted", "Untested"):
            assert stage in text

    def test_compatibility_notes_rendered(self):
        text = "\n".join(format_vdp_funnel_markdown(_summary()))
        assert "Compatibility Notes" in text

    def test_verdicts_rendered_with_ids(self):
        lines = format_vdp_verdicts_markdown(_summary())
        text = "\n".join(lines)
        assert "VDP Verdicts" in text
        assert "ver-001" in text
        assert "hyp-001" in text
        assert "confirmed" in text.lower()

    def test_full_section_rendered(self):
        text = "\n".join(render_vdp_section_markdown(_summary()))
        assert "VDP Evidence Funnel" in text
        assert "VDP Verdicts" in text


class TestCanonicalIndexEmbedding:
    def test_embed_and_extract_roundtrip(self):
        summary = _summary()
        report = "# Test Report\n\nBody\n"
        embedded = embed_vdp_canonical_index(report, summary)
        extracted = extract_vdp_canonical_index_from_report(embedded)
        assert extracted is not None
        assert extracted["index_version"] == "vdp_canonical_index_v1"
        assert extracted["source_kind"] == "canonical_vdp"
        assert extracted["verdict_counts"]["confirmed"] == 1

    def test_extract_none_when_missing(self):
        assert extract_vdp_canonical_index_from_report("# No index\n") is None

    def test_extract_none_when_corrupt(self):
        report = (
            "<!-- vdp_canonical_index_v1:start -->\nnot json\n"
            "<!-- vdp_canonical_index_v1:end -->\n"
        )
        assert extract_vdp_canonical_index_from_report(report) is None

    def test_reembed_replaces_old_block(self):
        summary = _summary()
        report = embed_vdp_canonical_index("# R\n", summary)
        report = embed_vdp_canonical_index(report, summary)
        assert report.count("vdp_canonical_index_v1:start") == 1


class TestSecretScan:
    def test_clean_content_passes(self):
        assert scan_report_secrets("HTTP/1.1 200 OK\n\n{\"ok\":true}") == []

    def test_bearer_token_detected(self):
        matches = scan_report_secrets("Authorization: Bearer abcdefghij1234567890XYZ")
        assert matches, "Bearer token must be detected"

    def test_api_key_header_detected(self):
        matches = scan_report_secrets("X-API-Key: sk-live-abcdefghijklmnopqrstuvwxyz123456")
        assert matches, "API key header must be detected"

    def test_jwt_detected(self):
        matches = scan_report_secrets(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        assert matches, "JWT must be detected"


class TestAtomicWriteReport:
    def test_promotes_clean_content(self, tmp_path):
        out = tmp_path / "haddix_report_20260803_000000.md"
        atomic_write_report(out, "# SHIGOKU\n\n# Submission Report\nBody\n")
        assert out.exists()
        assert "Body" in out.read_text(encoding="utf-8")

    def test_empty_content_rejected_no_file(self, tmp_path):
        out = tmp_path / "haddix_report_x.md"
        with pytest.raises(ValueError, match="empty"):
            atomic_write_report(out, "   ")
        assert not out.exists()

    def test_missing_required_section_rejected(self, tmp_path):
        out = tmp_path / "haddix_report_x.md"
        with pytest.raises(ValueError, match="required sections"):
            atomic_write_report(
                out, "# SHIGOKU\n", required_sections=["# Submission Report"]
            )
        assert not out.exists()

    def test_secret_content_rejected_no_file(self, tmp_path):
        out = tmp_path / "haddix_report_x.md"
        with pytest.raises(ValueError, match="secret"):
            atomic_write_report(
                out, "# SHIGOKU\nAuthorization: Bearer abcdefghij1234567890XYZ\n"
            )
        assert not out.exists()

    def test_write_failure_leaves_no_official_file(self, tmp_path, monkeypatch):
        """If os.replace fails, the temp file is removed and no official file
        remains (partial report never promoted)."""
        import os as _os

        out = tmp_path / "haddix_report_x.md"

        real_replace = _os.replace

        def _failing_replace(src, dst):
            raise OSError("simulated replace failure")

        monkeypatch.setattr(_os, "replace", _failing_replace)
        with pytest.raises(OSError, match="simulated"):
            atomic_write_report(out, "# SHIGOKU\nBody\n")
        monkeypatch.setattr(_os, "replace", real_replace)

        assert not out.exists()
        leftovers = list(tmp_path.glob(f".{out.name}.tmp_*"))
        assert leftovers == [], f"temp files must be cleaned: {leftovers}"

    def test_success_overwrites_existing_file(self, tmp_path):
        out = tmp_path / "haddix_report_x.md"
        out.write_text("old", encoding="utf-8")
        atomic_write_report(out, "# SHIGOKU\nNew body\n")
        assert "New body" in out.read_text(encoding="utf-8")


class TestManifest:
    def test_manifest_roundtrip(self, tmp_path):
        files = {
            "submission": tmp_path / "a.md",
            "internal_md": tmp_path / "b.md",
            "internal_json": tmp_path / "c.json",
        }
        for path in files.values():
            path.write_text(f"content-{path.name}", encoding="utf-8")
        manifest = write_manifest_json(tmp_path / "manifest.json", files)
        assert manifest.exists()
        result = verify_manifest(manifest, files)
        assert result["ok"] is True

    def test_missing_manifest_fails(self, tmp_path):
        result = verify_manifest(
            tmp_path / "none.json", {"submission": tmp_path / "a.md"}
        )
        assert result["ok"] is False
        assert result["reason"] == "manifest_missing"

    def test_missing_file_fails(self, tmp_path):
        files = {"submission": tmp_path / "a.md"}
        files["submission"].write_text("x", encoding="utf-8")
        manifest = write_manifest_json(tmp_path / "m.json", files)
        files["submission"].unlink()
        result = verify_manifest(manifest, files)
        assert result["ok"] is False
        assert "file_missing" in result["reason"]

    def test_tampered_file_fails(self, tmp_path):
        files = {"submission": tmp_path / "a.md"}
        files["submission"].write_text("x", encoding="utf-8")
        manifest = write_manifest_json(tmp_path / "m.json", files)
        files["submission"].write_text("y", encoding="utf-8")
        result = verify_manifest(manifest, files)
        assert result["ok"] is False
        assert "hash_mismatch" in result["reason"]


class TestSeparatedGroupConsumerVerification:
    """Audit I-07 (round 3): consumer-side enforcement — a separated report
    group is official only when its completion manifest verifies."""

    def _make_group(self, tmp_path: Path):
        files = {
            "submission": tmp_path / "haddix_x_submission.md",
            "internal_md": tmp_path / "haddix_x_internal.md",
            "internal_json": tmp_path / "haddix_x_internal.json",
        }
        for path in files.values():
            path.write_text(f"content-{path.name}", encoding="utf-8")
        manifest = write_manifest_json(tmp_path / "haddix_x_manifest.json", files)
        return files, manifest

    def test_plain_report_not_a_separated_member(self, tmp_path):
        report = tmp_path / "haddix_report_20260803.md"
        report.write_text("body", encoding="utf-8")
        result = verify_separated_group(report)
        assert result["ok"] is True
        assert result["reason"] == "not_separated_artifact"

    def test_member_manifest_missing_rejected(self, tmp_path):
        files, manifest = self._make_group(tmp_path)
        manifest.unlink()
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert result["reason"] == "separated_manifest_missing"

    def test_verified_group_ok_from_any_member(self, tmp_path):
        files, manifest = self._make_group(tmp_path)
        for member in files.values():
            result = verify_separated_group(member)
            assert result["ok"] is True, (member, result)
            assert result["reason"] == "separated_manifest_verified"

    def test_manifest_itself_is_a_member(self, tmp_path):
        _files, manifest = self._make_group(tmp_path)
        result = verify_separated_group(manifest)
        assert result["ok"] is True

    def test_tampered_member_rejected(self, tmp_path):
        files, manifest = self._make_group(tmp_path)
        files["internal_json"].write_text("{}", encoding="utf-8")
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert "hash_mismatch" in result["reason"]

    def test_trimmed_manifest_two_entries_removed_rejected(self, tmp_path):
        """Audit I-07 round 4 / D10: removing two of the three manifest
        entries must NOT let the remaining file pass — the key set must be
        exactly {submission, internal_md, internal_json}."""
        files, manifest = self._make_group(tmp_path)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"] = {"submission": data["files"]["submission"]}
        manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert result["reason"] == "separated_manifest_keys_invalid"
        assert result.get("recorded_keys") == ["submission"]

    def test_trimmed_manifest_one_entry_removed_rejected(self, tmp_path):
        """Removing a single entry must also be rejected (D10: 3 files)."""
        files, manifest = self._make_group(tmp_path)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"].pop("internal_json")
        manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert result["reason"] == "separated_manifest_keys_invalid"

    def test_extra_manifest_key_rejected(self, tmp_path):
        """An unexpected extra key in the manifest is also invalid (the key
        set must match exactly, not merely contain the three members)."""
        files, manifest = self._make_group(tmp_path)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"]["extra"] = {"path": str(files["submission"]), "sha256": "x" * 64}
        manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert result["reason"] == "separated_manifest_keys_invalid"

    def test_manifest_path_mismatch_rejected(self, tmp_path):
        """The manifest must point at the paths derived from the group stem;
        a manifest redirecting a member elsewhere is tampered."""
        files, manifest = self._make_group(tmp_path)
        data = json.loads(manifest.read_text(encoding="utf-8"))
        decoy = tmp_path / "decoy_submission.md"
        decoy.write_text(files["submission"].read_text(encoding="utf-8"), encoding="utf-8")
        data["files"]["submission"]["path"] = str(decoy)
        manifest.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert result["reason"] == "separated_manifest_path_mismatch:submission"

    def test_missing_member_rejected(self, tmp_path):
        files, manifest = self._make_group(tmp_path)
        files["internal_md"].unlink()
        result = verify_separated_group(files["submission"])
        assert result["ok"] is False
        assert "file_missing" in result["reason"]

    def test_manifest_path_resolution(self, tmp_path):
        _files, manifest = self._make_group(tmp_path)
        assert separated_group_manifest_for_report(
            tmp_path / "haddix_x_submission.md"
        ) == manifest
        assert separated_group_manifest_for_report(
            tmp_path / "plain.md"
        ) is None
