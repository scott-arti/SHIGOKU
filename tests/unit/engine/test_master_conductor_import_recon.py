"""Tests for MasterConductor import-recon integration (P2b).

Validates _load_import_recon_bundle() and _merge_imported_recon_results()
behaviour for imported recon directories, freshness scoring, and stale exclusion.
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.recon_importer import ImportedReconBundle, ImportedReconArtifact


# ── helpers ──────────────────────────────────────────────────────────────

def _new_mc(import_recon_dir=None, target="example.com"):
    """Minimal MasterConductor for testing import-recon integration."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        target_info={"target": target},
    )
    mc._import_recon_dir = import_recon_dir
    mc._import_recon_bundle = None
    return mc


def _write_recon_state(dir_path: Path, data: dict) -> Path:
    """Write a recon_state.json into *dir_path* and return the file path."""
    dir_path.mkdir(parents=True, exist_ok=True)
    file_path = dir_path / "recon_state.json"
    file_path.write_text(json.dumps(data, indent=2))
    return file_path


def _set_mtime_days_ago(file_path: Path, days: int) -> None:
    """Set the mtime of *file_path* to *days* days ago."""
    past = datetime.now(timezone.utc) - timedelta(days=days)
    ts = past.timestamp()
    os.utime(str(file_path), (ts, ts))


# ── test 1: import_recon_dir stored on MC ────────────────────────────────

def test_import_recon_stored_on_mc():
    """_import_recon_dir is stored when passed to MasterConductor."""
    mc = _new_mc(import_recon_dir="/tmp/test_recon")
    assert mc._import_recon_dir == "/tmp/test_recon"


def test_import_recon_stored_on_mc_none_default():
    """_import_recon_dir defaults to None when not provided."""
    mc = _new_mc()
    assert mc._import_recon_dir is None


# ── test 2: fresh recon → accepted artifacts → normalized_results ────────

def test_import_only_attack_tasks_generated():
    """Fresh recon_state.json produces accepted bundle with normalized_results."""
    with tempfile.TemporaryDirectory() as td:
        recon_dir = Path(td) / "recon_import"
        recon_file = _write_recon_state(
            recon_dir,
            {"target": "example.com", "live_subs": ["sub.example.com"]},
        )

        mc = _new_mc(import_recon_dir=str(recon_dir), target="example.com")

        bundle = mc._load_import_recon_bundle()

        # bundle is not None
        assert bundle is not None

        # bundle is accepted (not all rejected)
        assert bundle.accepted is True
        assert bundle.all_rejected is False
        assert len(bundle.accepted_artifacts) > 0

        # normalized_results has data from recon_state
        assert len(bundle.normalized_results) > 0
        assert "recon_live_subs" in bundle.normalized_results
        assert bundle.normalized_results["recon_live_subs"]["count"] >= 1


# ── test 3: stale recon → all excluded ──────────────────────────────────

def test_stale_all_excluded_no_attack_tasks():
    """Stale recon_state.json (old mtime) is informational-only, all_rejected."""
    with tempfile.TemporaryDirectory() as td:
        recon_dir = Path(td) / "recon_import"
        recon_file = _write_recon_state(
            recon_dir,
            {"target": "example.com", "live_subs": ["sub.example.com"]},
        )
        # Set mtime 100 days ago → freshness_score well below 0.2 threshold
        _set_mtime_days_ago(recon_file, 100)

        mc = _new_mc(import_recon_dir=str(recon_dir), target="example.com")

        bundle = mc._load_import_recon_bundle()

        # bundle is not None
        assert bundle is not None

        # bundle is not accepted (all rejected or empty)
        assert bundle.accepted is False
        assert bundle.all_rejected is True
        assert len(bundle.normalized_results) == 0

        # The single artifact should be stale
        assert len(bundle.artifacts) == 1
        artifact = bundle.artifacts[0]
        assert artifact.informational_only is True
        assert "stale_artifact" in artifact.reason_codes
        assert artifact.freshness_score < 0.2


# ── test 4: fresh recon merged → fresh preserved, imported annotated ─────

def test_fresh_recon_priority_merge():
    """Fresh results take precedence; imported categories get _source='imported'."""
    with tempfile.TemporaryDirectory() as td:
        recon_dir = Path(td) / "recon_import"
        _write_recon_state(
            recon_dir,
            {"target": "example.com", "live_subs": ["sub.example.com"]},
        )

        mc = _new_mc(import_recon_dir=str(recon_dir), target="example.com")

        fresh_input = {"existing_cat": {"count": 5, "file": "/fresh"}}
        result = mc._merge_imported_recon_results(fresh_input)

        # fresh category preserved exactly
        assert "existing_cat" in result
        assert result["existing_cat"]["count"] == 5
        assert result["existing_cat"]["file"] == "/fresh"

        # imported category added with _source annotation
        assert "recon_live_subs" in result
        assert result["recon_live_subs"]["_source"] == "imported"
        assert "_import_provenance" in result["recon_live_subs"]
        assert result["recon_live_subs"]["count"] >= 1


# ── test 5: no import_recon_dir → returns None ───────────────────────────

def test_import_recon_dir_none_returns_none():
    """_load_import_recon_bundle returns None when no import_recon_dir is set."""
    mc = _new_mc(import_recon_dir=None)
    bundle = mc._load_import_recon_bundle()
    assert bundle is None


# ── additional: missing directory → graceful ─────────────────────────────

def test_import_recon_dir_missing_directory():
    """Non-existent import_recon_dir returns a bundle with all_rejected=True."""
    mc = _new_mc(import_recon_dir="/nonexistent/recon/dir")
    bundle = mc._load_import_recon_bundle()

    # Should not be None — a bundle is returned even for missing dirs
    assert bundle is not None
    assert bundle.all_rejected is True
    assert bundle.accepted is False


# ── additional: caching behaviour ────────────────────────────────────────

def test_load_import_recon_bundle_caches_result():
    """Second call to _load_import_recon_bundle returns cached bundle."""
    with tempfile.TemporaryDirectory() as td:
        recon_dir = Path(td) / "recon_import"
        _write_recon_state(
            recon_dir,
            {"target": "example.com", "live_subs": ["sub.example.com"]},
        )

        mc = _new_mc(import_recon_dir=str(recon_dir), target="example.com")

        bundle1 = mc._load_import_recon_bundle()
        bundle2 = mc._load_import_recon_bundle()

        assert bundle1 is bundle2
        assert mc._import_recon_bundle is bundle1
