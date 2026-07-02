"""Tests for recon_importer — past recon artifact loading, validation, and normalisation."""
import json
import os
import tempfile
import time
from pathlib import Path

import pytest

from src.core.engine.recon_importer import (
    ImportedReconArtifact,
    ImportedReconBundle,
    load_imported_recon_dir,
    FAIL_CLOSED_REASON_CODES,
)


# ---------------------------------------------------------------------------
# 1. missing import directory
# ---------------------------------------------------------------------------

def test_missing_import_dir():
    """load_imported_recon_dir on a nonexistent path returns all_rejected with missing_dir."""
    bundle = load_imported_recon_dir(Path("/nonexistent/import_dir"))
    assert bundle.all_rejected is True
    assert len(bundle.rejected_artifacts) == 1
    assert "missing_dir" in bundle.rejected_artifacts[0].reason_codes
    assert bundle.rejected_artifacts[0].exists is False


# ---------------------------------------------------------------------------
# 2. empty artifact
# ---------------------------------------------------------------------------

def test_empty_artifact():
    """A 0-byte recon_state.json should be rejected with empty_artifact reason code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "recon_state.json"
        filepath.write_text("")  # 0 bytes

        bundle = load_imported_recon_dir(Path(tmpdir))
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert artifact.size == 0
        assert "empty_artifact" in artifact.reason_codes
        assert artifact.informational_only is True
        assert len(bundle.rejected_artifacts) == 1


# ---------------------------------------------------------------------------
# 3. malformed JSON
# ---------------------------------------------------------------------------

def test_malformed_json():
    """A file containing invalid JSON should be rejected with malformed_json reason code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "recon_state.json"
        filepath.write_text("{this is not valid json")

        bundle = load_imported_recon_dir(Path(tmpdir))
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert "malformed_json" in artifact.reason_codes
        assert len(bundle.rejected_artifacts) == 1


# ---------------------------------------------------------------------------
# 4. fresh artifact accepted
# ---------------------------------------------------------------------------

def test_fresh_artifact_accepted():
    """A valid recon_state.json with recent mtime should have a high freshness score
    and be fully accepted into normalized_results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "recon_state.json"
        data = {
            "target": "example.com",
            "live_subs": ["sub.example.com", "sub2.example.com"],
        }
        filepath.write_text(json.dumps(data))

        bundle = load_imported_recon_dir(Path(tmpdir), target="example.com")
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert artifact.freshness_score >= 0.9
        assert artifact.informational_only is False
        assert bundle.all_rejected is False
        assert bundle.accepted is True
        assert "recon_live_subs" in bundle.normalized_results
        assert bundle.normalized_results["recon_live_subs"]["count"] == 2


# ---------------------------------------------------------------------------
# 5. stale artifact rejected (from attack input)
# ---------------------------------------------------------------------------

def test_stale_artifact_rejected_from_attack_input():
    """A recon_state.json with mtime set 100 days ago should be marked stale
    and informational_only."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "recon_state.json"
        data = {"target": "example.com", "live_subs": ["sub.example.com"]}
        filepath.write_text(json.dumps(data))
        # mtime 100 days ago
        stale_time = time.time() - (100 * 86400)
        os.utime(filepath, (stale_time, stale_time))

        bundle = load_imported_recon_dir(Path(tmpdir), target="example.com")
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert "stale_artifact" in artifact.reason_codes
        assert artifact.informational_only is True
        assert len(bundle.rejected_artifacts) == 1


# ---------------------------------------------------------------------------
# 6. duplicate normalisation
# ---------------------------------------------------------------------------

def test_duplicate_normalization():
    """Duplicate subdomain entries in a *_subs.txt file should be removed in
    the normalized results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "live_subs.txt"
        filepath.write_text(
            "sub.example.com\nsub.example.com\nother.example.com\n"
        )

        bundle = load_imported_recon_dir(Path(tmpdir), target="example.com")
        assert "subdomains" in bundle.normalized_results
        items = bundle.normalized_results["subdomains"]["items"]
        assert len(items) == 2  # duplicates removed
        assert "sub.example.com" in items
        assert "other.example.com" in items


# ---------------------------------------------------------------------------
# 7. target mismatch — fail closed
# ---------------------------------------------------------------------------

def test_target_mismatch_fail_closed():
    """recon_state.json with target 'wrong.com' but expected target 'example.com'
    should produce a target_mismatch reason code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "recon_state.json"
        data = {"target": "wrong.com", "live_subs": ["sub.wrong.com"]}
        filepath.write_text(json.dumps(data))

        bundle = load_imported_recon_dir(Path(tmpdir), target="example.com")
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert "target_mismatch" in artifact.reason_codes
        # target_mismatch is a fail-closed reason code, so it appears in rejected
        assert len(bundle.rejected_artifacts) == 1


# ---------------------------------------------------------------------------
# 8. partial reject does not discard the whole bundle
# ---------------------------------------------------------------------------

def test_partial_reject_does_not_discard_bundle():
    """One valid artifact alongside one empty artifact: the bundle should not be
    all_rejected, the valid one should be in accepted_artifacts, and the empty
    one should be in rejected_artifacts."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Valid artifact
        valid_path = Path(tmpdir) / "recon_state.json"
        valid_data = {"target": "example.com", "live_subs": ["sub.example.com"]}
        valid_path.write_text(json.dumps(valid_data))

        # Empty artifact (0 bytes, will get empty_artifact reason code)
        empty_path = Path(tmpdir) / "empty_subs.txt"
        empty_path.write_text("")

        bundle = load_imported_recon_dir(Path(tmpdir), target="example.com")
        assert bundle.all_rejected is False
        assert bundle.accepted is True
        assert len(bundle.accepted_artifacts) >= 1
        assert len(bundle.rejected_artifacts) >= 1

        rejected_names = [a.path.name for a in bundle.rejected_artifacts]
        assert "empty_subs.txt" in rejected_names

        accepted_names = [a.path.name for a in bundle.accepted_artifacts]
        assert "recon_state.json" in accepted_names


# ---------------------------------------------------------------------------
# 9. step8 classification results
# ---------------------------------------------------------------------------

def test_step8_classification_results():
    """A JSON file matching the step8 classification pattern should produce
    categorized entries in normalized_results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "my_classified_results.json"
        data = {
            "vulnerable_endpoints": {
                "count": 3,
                "file": "results.json",
                "description": "Vulnerable endpoints found",
            },
            "safe_endpoints": {
                "count": 10,
                "file": "results.json",
                "description": "Safe endpoints",
            },
        }
        filepath.write_text(json.dumps(data))

        bundle = load_imported_recon_dir(Path(tmpdir))
        assert bundle.all_rejected is False
        assert bundle.accepted is True
        assert "vulnerable_endpoints" in bundle.normalized_results
        assert "safe_endpoints" in bundle.normalized_results
        assert bundle.normalized_results["vulnerable_endpoints"]["count"] == 3
        assert bundle.normalized_results["safe_endpoints"]["count"] == 10


# ---------------------------------------------------------------------------
# 10. unknown artifact kind rejected
# ---------------------------------------------------------------------------

def test_unknown_artifact_kind_rejected():
    """A file with an unsupported name pattern should be rejected with
    unknown_artifact reason code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        filepath = Path(tmpdir) / "weird_stuff.xyz"
        filepath.write_text("some content")

        bundle = load_imported_recon_dir(Path(tmpdir))
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert "unknown_artifact" in artifact.reason_codes
        assert len(bundle.rejected_artifacts) == 1
