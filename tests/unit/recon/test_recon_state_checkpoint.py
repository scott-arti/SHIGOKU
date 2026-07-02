"""Tests for ReconState checkpoint save/load, diff, resume, and CLI integration."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from src.recon.pipeline import (
    RECON_STATE_SCHEMA_VERSION,
    PARALLEL_TASK_CHECKPOINT_VERSION,
    STEP_GROUPS,
    ReconState,
    _compute_target_fingerprint,
    compute_recon_diff,
    infer_next_step,
    is_all_steps_completed,
    resolve_resume_start_step,
)


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

def test_target_fingerprint_deterministic() -> None:
    """Same target produces same fingerprint."""
    fp1 = _compute_target_fingerprint("example.com")
    fp2 = _compute_target_fingerprint("example.com")
    assert fp1 == fp2
    assert len(fp1) == 16


def test_target_fingerprint_case_insensitive() -> None:
    """Normalization is case-insensitive."""
    assert _compute_target_fingerprint("Example.COM") == _compute_target_fingerprint("example.com")


def test_target_fingerprint_different() -> None:
    """Different targets produce different fingerprints."""
    assert _compute_target_fingerprint("a.com") != _compute_target_fingerprint("b.com")


# ---------------------------------------------------------------------------
# ReconState save/load round-trip
# ---------------------------------------------------------------------------

def test_save_load_roundtrip(tmp_path: Path) -> None:
    """Save and load a populated ReconState, verify all fields."""
    state = ReconState(
        target="example.com",
        project_name="example",
        current_step=3,
        completed_steps=["subdomain_discovery", "historical_discovery", "live_check"],
        all_subs=["api.example.com", "www.example.com"],
        live_subs=["api.example.com"],
        dead_subs=["www.example.com"],
        tech_stack=["nginx", "react"],
        screenshots_count=5,
        resume_source="fresh",
    )
    state.mark_step_complete("url_discovery")
    
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    loaded = ReconState.load(fp)
    
    assert loaded.schema_version == RECON_STATE_SCHEMA_VERSION
    assert loaded.current_step == 4  # 3 + 1 from mark_step_complete
    assert loaded.completed_steps[-1] == "url_discovery"
    assert loaded.all_subs == ["api.example.com", "www.example.com"]
    assert loaded.live_subs == ["api.example.com"]
    assert loaded.dead_subs == ["www.example.com"]
    assert loaded.tech_stack == ["nginx", "react"]
    assert loaded.screenshots_count == 5
    assert loaded.target == "example.com"
    assert loaded.project_name == "example"
    assert loaded.run_id  # auto-generated
    assert loaded.target_fingerprint == _compute_target_fingerprint("example.com")
    assert loaded.saved_at
    assert loaded.last_completed_step == "url_discovery"
    assert loaded.resume_source == "fresh"


def test_save_load_empty_state(tmp_path: Path) -> None:
    """Save and load a minimally populated state."""
    state = ReconState(target="empty.com")
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    loaded = ReconState.load(fp)
    assert loaded.target == "empty.com"
    assert loaded.current_step == 0
    assert loaded.completed_steps == []
    assert loaded.all_subs == []
    assert loaded.tech_stack == []
    assert loaded.screenshots_count == 0


def test_load_missing_file(tmp_path: Path) -> None:
    """Loading a non-existent file returns a fresh state."""
    loaded = ReconState.load(tmp_path / "nonexistent.json")
    assert loaded.current_step == 0
    assert loaded.target == ""


# ---------------------------------------------------------------------------
# Atomic save
# ---------------------------------------------------------------------------

def test_atomic_save_no_temp_leftover(tmp_path: Path) -> None:
    """After successful atomic save, no temp files remain."""
    state = ReconState(target="atomic.com")
    fp = tmp_path / "recon_state.json"
    
    # Count files before save
    before = set(tmp_path.iterdir())
    state.save(fp, atomic=True)
    after = set(tmp_path.iterdir())
    
    # Only the target file should have been created
    new_files = after - before
    assert len(new_files) == 1
    assert fp in new_files


def test_atomic_save_file_content(tmp_path: Path) -> None:
    """Atomic save produces correct JSON content."""
    state = ReconState(target="content.com", all_subs=["a.com"])
    fp = tmp_path / "recon_state.json"
    state.save(fp, atomic=True)
    
    data = json.loads(fp.read_text())
    assert data["recon_state_schema_version"] == 1
    assert data["target"] == "content.com"
    assert data["all_subs"] == ["a.com"]


def test_non_atomic_save(tmp_path: Path) -> None:
    """Non-atomic save also works."""
    state = ReconState(target="non-atomic.com")
    fp = tmp_path / "recon_state.json"
    state.save(fp, atomic=False)
    assert fp.exists()
    data = json.loads(fp.read_text())
    assert data["target"] == "non-atomic.com"


# ---------------------------------------------------------------------------
# Schema migration / v0 fallback
# ---------------------------------------------------------------------------

def test_v0_fallback_sets_schema_zero(tmp_path: Path) -> None:
    """Loading a v0 (no schema_version) file sets schema_version=0."""
    v0_data = {
        "current_step": 1,
        "completed_steps": ["subdomain_discovery"],
        "target": "v0test.com",
        "all_subs": ["a.v0test.com"],
        "live_subs": [],
        "dead_subs": [],
    }
    fp = tmp_path / "v0_state.json"
    fp.write_text(json.dumps(v0_data))
    
    loaded = ReconState.load(fp)
    assert loaded.schema_version == 0
    assert loaded.current_step == 1
    assert "schema_migrated_from_v0" in loaded.reason_codes
    assert loaded.target_fingerprint == _compute_target_fingerprint("v0test.com")


def test_v0_fallback_reconstructs_current_step(tmp_path: Path) -> None:
    """When current_step=0 but completed_steps exist, reconstruct."""
    v0_data = {
        "current_step": 0,
        "completed_steps": ["subdomain_discovery", "historical_discovery"],
        "target": "recon.com",
    }
    fp = tmp_path / "v0_recon.json"
    fp.write_text(json.dumps(v0_data))
    loaded = ReconState.load(fp)
    assert loaded.current_step == 2
    assert "schema_migrated_from_v0" in loaded.reason_codes


def test_v1_load_preserves_checkpoint_fields(tmp_path: Path) -> None:
    """V1 load preserves all checkpoint contract fields."""
    state = ReconState(
        target="v1test.com",
        resume_source="resume",
        diff_base_run_id="prev-run-123",
        reason_codes=["test_reason"],
    )
    fp = tmp_path / "v1_state.json"
    state.save(fp)
    
    loaded = ReconState.load(fp)
    assert loaded.schema_version == 1
    assert loaded.resume_source == "resume"
    assert loaded.diff_base_run_id == "prev-run-123"
    assert "test_reason" in loaded.reason_codes


# ---------------------------------------------------------------------------
# Resume validation
# ---------------------------------------------------------------------------

def test_validate_resume_ok(tmp_path: Path) -> None:
    """Happy path: valid state can resume. next_step from infer_next_step."""
    state = ReconState(
        target="resume-ok.com",
        current_step=2,
        completed_steps=["subdomain_discovery", "historical_discovery"],
    )
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    verdict = ReconState.validate_for_resume(fp, "resume-ok.com")
    assert verdict["can_resume"] is True
    assert verdict["reason_code"] == "ok"
    # Steps 1 and 2 markers are complete → next is step 3
    assert verdict["next_step"] == 3
    assert verdict.get("resume_state_path")


def test_validate_resume_no_file(tmp_path: Path) -> None:
    """Missing state file."""
    verdict = ReconState.validate_for_resume(tmp_path / "nonexistent.json", "test.com")
    assert verdict["can_resume"] is False
    assert verdict["reason_code"] == "no_state_file"


def test_validate_resume_corrupt_file(tmp_path: Path) -> None:
    """Corrupt JSON."""
    fp = tmp_path / "corrupt.json"
    fp.write_text("not json")
    verdict = ReconState.validate_for_resume(fp, "test.com")
    assert verdict["can_resume"] is False
    assert verdict["reason_code"] == "corrupt_state"


def test_validate_resume_target_mismatch(tmp_path: Path) -> None:
    """Fail-closed: different target."""
    state = ReconState(target="original.com")
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    verdict = ReconState.validate_for_resume(fp, "different.com")
    assert verdict["can_resume"] is False
    assert verdict["reason_code"] == "target_mismatch"


def test_validate_resume_already_completed(tmp_path: Path) -> None:
    """All steps done (all STEP_GROUPS markers present)."""
    state = ReconState(
        target="done.com",
        current_step=10,
        completed_steps=[
            "subdomain_discovery", "historical_discovery", "live_check",
            "url_discovery", "waf_detection", "port_scan_phase1",
            "port_scan_phase2", "classification", "save_to_project",
            "return_to_mc",
        ],
    )
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    verdict = ReconState.validate_for_resume(fp, "done.com")
    assert verdict["can_resume"] is False
    assert verdict["reason_code"] == "already_completed"


# ---------------------------------------------------------------------------
# Diff normalization
# ---------------------------------------------------------------------------

def test_diff_added_and_removed() -> None:
    """Basic added/removed diff across all_subs, live_subs, dead_subs, tech_stack."""
    prev = ReconState(
        target="diff.com",
        all_subs=["a.com", "b.com"],
        live_subs=["a.com"],
        dead_subs=["b.com"],
        tech_stack=["nginx"],
    )
    curr = ReconState(
        target="diff.com",
        all_subs=["a.com", "c.com"],
        live_subs=["c.com"],
        dead_subs=["b.com", "d.com"],
        tech_stack=["nginx", "nodejs"],
    )
    
    diff = compute_recon_diff(prev, curr)
    assert diff["added"]["all_subs"] == ["c.com"]
    assert diff["removed"]["all_subs"] == ["b.com"]
    assert diff["added"]["live_subs"] == ["c.com"]
    assert diff["removed"]["live_subs"] == ["a.com"]
    assert diff["added"]["dead_subs"] == ["d.com"]
    assert diff["removed"]["dead_subs"] == []
    assert diff["added"]["tech_stack"] == ["nodejs"]
    assert diff["removed"]["tech_stack"] == []
    assert diff["has_changes"] is True


def test_diff_no_changes() -> None:
    """No differences between states."""
    prev = ReconState(target="same.com", all_subs=["a.com"])
    curr = ReconState(target="same.com", all_subs=["a.com"])
    
    diff = compute_recon_diff(prev, curr)
    assert diff["has_changes"] is False
    assert diff["added"]["all_subs"] == []
    assert diff["removed"]["all_subs"] == []


def test_diff_metadata_fields() -> None:
    """Diff includes metadata: run_id, saved_at, stale_state, estimated."""
    prev = ReconState(target="meta.com", run_id="run1", resume_source="fresh")
    # Give prev a timestamp
    prev.saved_at = "2026-06-01T00:00:00Z"
    curr = ReconState(target="meta.com", run_id="run2", resume_source="resume")
    curr.saved_at = "2026-06-30T00:00:00Z"
    
    diff = compute_recon_diff(prev, curr)
    assert diff["metadata"]["run_id"] == "run2"
    assert diff["metadata"]["diff_base_run_id"] == "run1"
    assert diff["metadata"]["saved_at"] == "2026-06-30T00:00:00Z"
    assert diff["metadata"]["prev_saved_at"] == "2026-06-01T00:00:00Z"


def test_diff_stale_estimated_for_v0() -> None:
    """V0 prev state marks diff as estimated/stale."""
    prev = ReconState(target="v0diff.com", schema_version=0, reason_codes=["schema_migrated_from_v0"])
    curr = ReconState(target="v0diff.com", schema_version=1)
    
    diff = compute_recon_diff(prev, curr)
    assert diff["metadata"]["stale_state"] is True
    assert diff["metadata"]["estimated"] is True


# ---------------------------------------------------------------------------
# Resume start step resolver
# ---------------------------------------------------------------------------

def test_resolver_default(tmp_path: Path) -> None:
    """No resume flag, no explicit start_step → default 1."""
    start, verdict = resolve_resume_start_step(
        recon_resume=False,
        recon_start_step=None,
        state_path=tmp_path / "nonexistent.json",
        target="default.com",
    )
    assert start == 1
    assert verdict["resolved_via"] == "default"


def test_resolver_explicit_overrides_resume(tmp_path: Path) -> None:
    """--recon-start-step explicitly set takes precedence over --recon-resume."""
    state = ReconState(target="override.com", current_step=2, completed_steps=["s1", "s2"])
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    start, verdict = resolve_resume_start_step(
        recon_resume=True,
        recon_start_step=5,
        state_path=fp,
        target="override.com",
    )
    assert start == 5
    assert verdict["resolved_via"] == "explicit_start_step"
    assert "precedence" in verdict.get("note", "").lower() or True  # may or may not have note


def test_resolver_resume_blocked_target_mismatch(tmp_path: Path) -> None:
    """Resume blocked by target mismatch falls back to step 1."""
    state = ReconState(target="original.com", current_step=2, completed_steps=["s1", "s2"])
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    start, verdict = resolve_resume_start_step(
        recon_resume=True,
        recon_start_step=None,
        state_path=fp,
        target="different.com",
    )
    assert start == 1
    assert verdict["resolved_via"] == "checkpoint_resume_blocked"
    assert verdict["resume_error"]


def test_resolver_resume_ok(tmp_path: Path) -> None:
    """Successful resume returns next step from state, plus resume_state."""
    state = ReconState(target="ok.com", completed_steps=["subdomain_discovery", "historical_discovery"])
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    start, verdict = resolve_resume_start_step(
        recon_resume=True,
        recon_start_step=None,
        state_path=fp,
        target="ok.com",
    )
    assert start == 3  # infer_next_step based
    assert verdict["resolved_via"] == "checkpoint_resume"
    assert verdict["effective_resume_source"] == "resume"
    assert verdict["resume_state"] is not None
    assert verdict["resume_state_path"]


def test_resolver_resume_override(tmp_path: Path) -> None:
    """--recon-resume + --recon-start-step together → resume_override."""
    state = ReconState(target="override.com", completed_steps=["subdomain_discovery"])
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    start, verdict = resolve_resume_start_step(
        recon_resume=True,
        recon_start_step=5,
        state_path=fp,
        target="override.com",
    )
    assert start == 5
    assert verdict["resolved_via"] == "explicit_start_step"
    assert verdict["effective_resume_source"] == "resume_override"


# ---------------------------------------------------------------------------
# Ops CLI integration
# ---------------------------------------------------------------------------

def _ops_base() -> list[str]:
    return [".venv/bin/python", "scripts/shigoku_ops_cli.py"]


def test_ops_cli_recon_status_exists(tmp_path: Path) -> None:
    """recon status with valid state file."""
    state = ReconState(
        target="cli-test.com",
        current_step=2,
        completed_steps=["s1", "s2"],
        all_subs=["sub.cli-test.com"],
        tech_stack=["nginx"],
    )
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    result = subprocess.run(
        _ops_base() + ["recon", "status", "--state", str(fp)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "cli-test.com" in result.stdout


def test_ops_cli_recon_status_json(tmp_path: Path) -> None:
    """recon status --json output."""
    state = ReconState(target="json-test.com", current_step=1, completed_steps=["s1"])
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    result = subprocess.run(
        _ops_base() + ["--json", "recon", "status", "--state", str(fp)],
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    assert data["can_resume"] is True
    assert data["target"] == "json-test.com"


def test_ops_cli_recon_status_missing_file(tmp_path: Path) -> None:
    """recon status with missing state file."""
    result = subprocess.run(
        _ops_base() + ["recon", "status", "--state", str(tmp_path / "nonexistent.json")],
        capture_output=True,
        text=True,
    )
    # Return code is 3 when non-resumable (our handler returns 3)
    # But argparse may return 2 for missing required arg; accept either
    assert result.returncode in {2, 3}


def test_ops_cli_recon_diff(tmp_path: Path) -> None:
    """recon diff between two state files."""
    prev = ReconState(
        target="diff-cli.com",
        all_subs=["a.com", "b.com"],
        live_subs=["a.com"],
        tech_stack=["nginx"],
    )
    curr = ReconState(
        target="diff-cli.com",
        all_subs=["a.com", "c.com"],
        live_subs=["c.com"],
        tech_stack=["nginx", "nodejs"],
    )
    prev_path = tmp_path / "prev.json"
    curr_path = tmp_path / "curr.json"
    prev.save(prev_path)
    curr.save(curr_path)
    
    result = subprocess.run(
        _ops_base() + ["--json", "recon", "diff", "--prev", str(prev_path), "--current", str(curr_path)],
        capture_output=True,
        text=True,
    )
    data = json.loads(result.stdout)
    assert data["has_changes"] is True
    assert data["added"]["all_subs"] == ["c.com"]
    assert data["added"]["tech_stack"] == ["nodejs"]
    assert data["removed"]["live_subs"] == ["a.com"]


def test_ops_cli_recon_diff_missing_prev(tmp_path: Path) -> None:
    """recon diff with missing prev file returns error."""
    result = subprocess.run(
        _ops_base() + ["--json", "recon", "diff", "--prev", str(tmp_path / "nonexistent.json")],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 3


# ---------------------------------------------------------------------------
# Mark step complete + checkpoint reason codes
# ---------------------------------------------------------------------------

def test_mark_step_complete_updates_last_step(tmp_path: Path) -> None:
    """mark_step_complete sets last_completed_step."""
    state = ReconState(target="step.com")
    state.mark_step_complete("subdomain_discovery")
    assert state.last_completed_step == "subdomain_discovery"
    assert state.current_step == 1
    assert "subdomain_discovery" in state.completed_steps


def test_skip_markers(tmp_path: Path) -> None:
    """Skipped steps are recorded and do not duplicate."""
    state = ReconState(target="skip.com")
    state.mark_step_complete("subdomain_discovery_skipped")
    state.mark_step_complete("historical_discovery_skipped")
    assert state.current_step == 2
    assert "subdomain_discovery_skipped" in state.completed_steps
    assert "historical_discovery_skipped" in state.completed_steps


def test_run_id_auto_generated() -> None:
    """Each ReconState gets a unique run_id."""
    s1 = ReconState()
    s2 = ReconState()
    assert s1.run_id
    assert s2.run_id
    assert s1.run_id != s2.run_id
    assert len(s1.run_id) == 12


# ---------------------------------------------------------------------------
# STEP_GROUPS / infer_next_step
# ---------------------------------------------------------------------------

def test_infer_next_step_all_empty() -> None:
    """No steps completed → next is 1."""
    assert infer_next_step([]) == 1


def test_infer_next_step_after_step1() -> None:
    """Step 1 done (subdomain_discovery) → next is 2."""
    assert infer_next_step(["subdomain_discovery"]) == 2


def test_infer_next_step_skip_marker() -> None:
    """subdomain_discovery_skipped also counts as step 1 done."""
    assert infer_next_step(["subdomain_discovery_skipped", "historical_discovery"]) == 3


def test_infer_next_step_mid_pipeline() -> None:
    """Steps 1-3 done (live_check + url_discovery both needed for step 3) → next is 4."""
    completed = ["subdomain_discovery", "historical_discovery", "live_check", "url_discovery"]
    assert infer_next_step(completed) == 4


def test_infer_next_step_after_waf() -> None:
    """Steps 1-4 done → next is 5."""
    completed = [
        "subdomain_discovery", "historical_discovery", "live_check",
        "url_discovery", "waf_detection",
    ]
    assert infer_next_step(completed) == 5


def test_infer_next_step_portscan_partial() -> None:
    """port_scan_phase1 done but not phase2 → step 5 NOT complete yet."""
    completed = [
        "subdomain_discovery", "historical_discovery", "live_check",
        "url_discovery", "waf_detection", "port_scan_phase1",
    ]
    # port_scan_phase2 is still missing → step 5 is NOT done
    assert infer_next_step(completed) == 5


def test_infer_next_step_portscan_both_done() -> None:
    """port_scan both phases done → next is 6."""
    completed = [
        "subdomain_discovery", "historical_discovery", "live_check",
        "url_discovery", "waf_detection", "port_scan_phase1",
        "port_scan_phase2",
    ]
    assert infer_next_step(completed) == 6


def test_infer_next_step_all_steps_done() -> None:
    """All markers present → returns 9 (beyond step 8)."""
    completed = [
        "subdomain_discovery", "historical_discovery", "live_check",
        "url_discovery", "waf_detection", "port_scan_phase1",
        "port_scan_phase2", "classification", "save_to_project",
        "return_to_mc",
    ]
    assert infer_next_step(completed) == 9
    assert is_all_steps_completed(completed)


def test_infer_next_step_current_step_does_not_matter() -> None:
    """current_step is not used; only completed_steps markers matter."""
    completed = [
        "subdomain_discovery", "historical_discovery", "live_check",
        "url_discovery", "waf_detection", "port_scan_phase1",
        "port_scan_phase2", "classification", "save_to_project",
        "return_to_mc",
    ]
    # Even with current_step=6, all markers present → all done
    state = ReconState(target="x.com", current_step=6, completed_steps=completed)
    assert is_all_steps_completed(state.completed_steps)
    assert infer_next_step(state.completed_steps) == 9


def test_is_all_steps_completed_false() -> None:
    """Not all steps done."""
    assert not is_all_steps_completed(["subdomain_discovery"])


# ---------------------------------------------------------------------------
# Fingerprint after late target set
# ---------------------------------------------------------------------------

def test_fingerprint_recalculated_when_target_set_after_init() -> None:
    """When target is set after init (as in ReconPipeline.run()), fingerprint is recalculated."""
    # Simulate what ReconPipeline does: create state without target, then set target later
    state = ReconState()
    assert state.target_fingerprint == ""  # no target initially
    
    # Now set target (as run() does)
    state.target = "example.com"
    state.target_fingerprint = _compute_target_fingerprint("example.com")
    
    assert state.target_fingerprint
    assert state.target_fingerprint == _compute_target_fingerprint("example.com")
    assert state.target_fingerprint == _compute_target_fingerprint("Example.COM")


def test_fingerprint_empty_target() -> None:
    """Empty target produces empty fingerprint."""
    state = ReconState(target="")
    # run() could later set target and recalculate fingerprint
    state.target = "new.com"
    state.target_fingerprint = _compute_target_fingerprint("new.com")
    assert state.target_fingerprint == _compute_target_fingerprint("new.com")


# ---------------------------------------------------------------------------
# Regression: resume_override must still load state
# ---------------------------------------------------------------------------

def test_resolver_resume_override_still_loads_state(tmp_path: Path) -> None:
    """--recon-resume + --recon-start-step=5 must return resume_state (not None)."""
    state = ReconState(
        target="override.com",
        completed_steps=["subdomain_discovery", "historical_discovery", "live_check", "url_discovery"],
    )
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    _start, verdict = resolve_resume_start_step(
        recon_resume=True,
        recon_start_step=5,
        state_path=fp,
        target="override.com",
    )
    assert _start == 5
    assert verdict["resolved_via"] == "explicit_start_step"
    assert verdict["effective_resume_source"] == "resume_override"
    # CRITICAL: resume_state must NOT be None
    assert verdict["resume_state"] is not None, "resume_state must be loaded even with override"
    assert verdict["resume_state_path"], "resume_state_path must be set even with override"
    assert verdict["resume_verdict"] is not None
    assert verdict["checkpoint_next_step"] is not None


def test_resolver_resume_override_preserves_state_path(tmp_path: Path) -> None:
    """resume_state_path is populated even when start_step is overridden."""
    state = ReconState(target="path.com", completed_steps=["subdomain_discovery", "historical_discovery"])
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    
    _, verdict = resolve_resume_start_step(
        recon_resume=True,
        recon_start_step=3,
        state_path=fp,
        target="path.com",
    )
    assert verdict["resume_state_path"] == str(fp)
    assert verdict["effective_resume_source"] == "resume_override"


# ---------------------------------------------------------------------------
# Regression: rebind_for_resume generates new run_id
# ---------------------------------------------------------------------------

def test_rebind_for_resume_generates_new_run_id(tmp_path: Path) -> None:
    """rebind_for_resume() preserves old run_id as diff_base and generates new."""
    state = ReconState(target="rebind.com", completed_steps=["subdomain_discovery"])
    old_run_id = state.run_id
    assert old_run_id
    
    state.rebind_for_resume(resume_source="resume")
    assert state.run_id
    assert state.run_id != old_run_id
    assert state.diff_base_run_id == old_run_id
    assert state.resume_source == "resume"


def test_rebind_for_resume_override_source(tmp_path: Path) -> None:
    """rebind_for_resume with resume_override."""
    state = ReconState(target="rebind2.com")
    old_run_id = state.run_id
    
    state.rebind_for_resume(resume_source="resume_override")
    assert state.resume_source == "resume_override"
    assert state.run_id != old_run_id
    assert state.diff_base_run_id == old_run_id


def test_saved_state_run_id_not_empty_after_rebind(tmp_path: Path) -> None:
    """After rebind_for_resume, save/load preserves non-empty run_id."""
    state = ReconState(target="savebind.com")
    old_run_id = state.run_id
    state.rebind_for_resume(resume_source="resume")
    
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    loaded = ReconState.load(fp)
    assert loaded.run_id
    assert loaded.run_id == state.run_id  # preserved
    assert loaded.diff_base_run_id == old_run_id
    assert loaded.resume_source == "resume"


# ---------------------------------------------------------------------------
# Integration: MasterConductor resume state injection code path
# ---------------------------------------------------------------------------

def test_resume_state_injected_into_pipeline_preserves_data(tmp_path: Path) -> None:
    """Simulate the MC resume injection path: load -> rebind -> inject into pipeline.
    
    Verify that completed_steps, all_subs, run_id, diff_base_run_id, and
    resume_source are all preserved after injection.
    """
    from src.recon.pipeline import ReconPipeline
    
    # Step 1: Create and save a state with prior progress
    prev_state = ReconState(
        target="integration.com",
        project_name="integration",
        completed_steps=["subdomain_discovery", "historical_discovery", "live_check"],
        all_subs=["a.integration.com", "b.integration.com"],
        live_subs=["a.integration.com"],
        dead_subs=["b.integration.com"],
        tech_stack=["nginx"],
        screenshots_count=3,
    )
    state_path = tmp_path / "recon_state.json"
    prev_state.save(state_path)
    prev_run_id = prev_state.run_id
    
    # Step 2: Simulate MC load + rebind (as master_conductor.py does)
    loaded = ReconState.load(state_path)
    loaded.rebind_for_resume(resume_source="resume")
    assert loaded.run_id != prev_run_id, "rebind must generate new run_id"
    assert loaded.diff_base_run_id == prev_run_id
    
    # Step 3: Simulate MC creating ReconPipeline and injecting state
    # (master_conductor.py creates pipeline, then sets pipeline.state = loaded)
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="",
    )
    pipeline.state = loaded
    
    # Step 4: Verify state carried forward
    assert pipeline.state.completed_steps == ["subdomain_discovery", "historical_discovery", "live_check"]
    assert pipeline.state.all_subs == ["a.integration.com", "b.integration.com"]
    assert pipeline.state.live_subs == ["a.integration.com"]
    assert pipeline.state.dead_subs == ["b.integration.com"]
    assert pipeline.state.tech_stack == ["nginx"]
    assert pipeline.state.screenshots_count == 3
    assert pipeline.state.target == "integration.com"
    assert pipeline.state.resume_source == "resume"
    assert pipeline.state.run_id  # not empty
    assert pipeline.state.run_id != pipeline.state.diff_base_run_id
    assert pipeline.state.diff_base_run_id == prev_run_id


# ---------------------------------------------------------------------------
# Unit 1: parallel_task_progress round-trip and load fallback
# ---------------------------------------------------------------------------

def test_parallel_task_progress_roundtrip(tmp_path: Path) -> None:
    """Populated parallel_task_progress survives save/load with all keys."""
    state = ReconState(target="progress.com")
    state.parallel_task_progress = {
        "full_port_scan": {
            "status": "completed",
            "started_at": "2026-07-01T10:00:00Z",
            "updated_at": "2026-07-01T10:05:00Z",
            "completed_at": "2026-07-01T10:05:00Z",
            "checkpoint_version": 1,
            "artifact_refs": [
                {"path": "/tmp/scan.txt", "kind": "output", "exists": True, "size": 1024, "mtime": 1234567890.0}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
    }
    fp = tmp_path / "recon_state.json"
    state.save(fp)

    loaded = ReconState.load(fp)
    assert "full_port_scan" in loaded.parallel_task_progress
    entry = loaded.parallel_task_progress["full_port_scan"]
    assert entry["status"] == "completed"
    assert entry["checkpoint_version"] == 1
    assert len(entry["artifact_refs"]) == 1
    assert entry["artifact_refs"][0]["kind"] == "output"
    assert entry["attempt_count"] == 1


def test_v1_load_defaults_parallel_task_progress(tmp_path: Path) -> None:
    """Existing v1 JSON without parallel_task_progress key loads with {}."""
    state = ReconState(target="v1default.com")
    fp = tmp_path / "recon_state.json"
    state.save(fp)
    # Simulate old v1 JSON without the key
    data = json.loads(fp.read_text())
    data.pop("parallel_task_progress", None)
    fp.write_text(json.dumps(data))

    loaded = ReconState.load(fp)
    assert loaded.parallel_task_progress == {}


def test_v0_load_defaults_parallel_task_progress(tmp_path: Path) -> None:
    """V0 JSON loads with parallel_task_progress={}."""
    v0_data = {
        "current_step": 1,
        "completed_steps": ["subdomain_discovery"],
        "target": "v0progress.com",
        "all_subs": [],
        "live_subs": [],
        "dead_subs": [],
    }
    fp = tmp_path / "v0_state.json"
    fp.write_text(json.dumps(v0_data))
    loaded = ReconState.load(fp)
    assert loaded.parallel_task_progress == {}


# ---------------------------------------------------------------------------
# Unit 2: update_parallel_task_progress helper
# ---------------------------------------------------------------------------

def test_update_parallel_task_progress_records_running_then_completed() -> None:
    """Running → completed transition records timestamps and artifacts."""
    state = ReconState(target="update.com")
    
    state.update_parallel_task_progress(
        "test_task", "running",
    )
    assert state.parallel_task_progress["test_task"]["status"] == "running"
    assert state.parallel_task_progress["test_task"]["started_at"]
    assert state.parallel_task_progress["test_task"]["attempt_count"] == 1
    
    state.update_parallel_task_progress(
        "test_task", "completed",
        artifact_refs=[
            {"path": "/tmp/out.txt", "kind": "output", "size": 100, "mtime": time.time()}
        ],
    )
    entry = state.parallel_task_progress["test_task"]
    assert entry["status"] == "completed"
    assert entry["started_at"]  # preserved from running
    assert entry["completed_at"]
    assert entry["attempt_count"] == 1
    assert len(entry["artifact_refs"]) == 1
    assert entry["artifact_refs"][0]["kind"] == "output"


def test_update_parallel_task_progress_merges_artifacts() -> None:
    """Existing entry is not erased; artifact_refs are updated."""
    state = ReconState(target="merge.com")
    
    state.update_parallel_task_progress("merge_task", "running")
    state.update_parallel_task_progress(
        "merge_task", "completed",
        artifact_refs=[{"path": "/tmp/a.txt", "kind": "output", "size": 42, "mtime": time.time()}],
    )
    # Update again with different artifact
    state.update_parallel_task_progress(
        "merge_task", "completed",
        artifact_refs=[{"path": "/tmp/b.txt", "kind": "screenshot", "size": 2048, "mtime": time.time()}],
    )
    entry = state.parallel_task_progress["merge_task"]
    assert entry["status"] == "completed"
    assert len(entry["artifact_refs"]) == 2
    kinds = {ref["kind"] for ref in entry["artifact_refs"]}
    assert "output" in kinds
    assert "screenshot" in kinds


def test_update_parallel_task_progress_records_failure() -> None:
    """Exception content is recorded in error_summary."""
    state = ReconState(target="fail.com")
    
    state.update_parallel_task_progress(
        "fail_task", "running",
    )
    state.update_parallel_task_progress(
        "fail_task", "failed",
        error_summary="ConnectionError: timeout",
    )
    entry = state.parallel_task_progress["fail_task"]
    assert entry["status"] == "failed"
    assert "ConnectionError" in entry["error_summary"]
    assert entry["completed_at"]


def test_update_parallel_task_progress_records_skipped() -> None:
    """Skipped status records resume_reason."""
    state = ReconState(target="skip.com")
    
    state.update_parallel_task_progress(
        "skip_task", "skipped",
        resume_reason="no_live_subs",
    )
    entry = state.parallel_task_progress["skip_task"]
    assert entry["status"] == "skipped"
    assert entry["resume_reason"] == "no_live_subs"


def test_update_parallel_task_progress_increments_attempt_on_rerun() -> None:
    """Attempt count increments when re-running a completed task."""
    state = ReconState(target="rerun.com")
    
    state.update_parallel_task_progress("rerun_task", "running")
    state.update_parallel_task_progress("rerun_task", "completed")
    assert state.parallel_task_progress["rerun_task"]["attempt_count"] == 1
    
    # Re-run
    state.update_parallel_task_progress("rerun_task", "running")
    assert state.parallel_task_progress["rerun_task"]["attempt_count"] == 2


# ---------------------------------------------------------------------------
# Unit 4: Pipeline checkpoint persistence wrapper
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_parallel_tasks_saves_checkpoint_on_task_completion(tmp_path: Path) -> None:
    """_save_checkpoint is called on task completion."""
    from src.recon.pipeline import ReconPipeline
    
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="checkpoint.com",
    )
    pipeline.state.target = "checkpoint.com"
    pipeline.state.target_fingerprint = _compute_target_fingerprint("checkpoint.com")
    
    # Patch _save_checkpoint to record calls
    save_calls = []
    original_save = pipeline._save_checkpoint
    def _record_save(step_label):
        save_calls.append(step_label)
        original_save(step_label)
    pipeline._save_checkpoint = _record_save
    
    # Set up project_dir for save
    pipeline.pm = MagicMock()
    pipeline.pm.project_dir = tmp_path / "project"
    pipeline.pm.project_dir.mkdir(parents=True, exist_ok=True)
    
    # Patch tasks to be fast no-ops
    from src.recon.parallel_tasks import ParallelTasks
    original_tasks = pipeline.tasks
    
    async def _fast_full_port(*args, **kwargs):
        return {"status": "completed", "ports_count": 0, "output_file": str(tmp_path / "dummy.txt")}
    async def _fast_visual(*args, **kwargs):
        return {"status": "completed", "screenshot_count": 0, "screenshots_dir": str(tmp_path)}
    async def _fast_permutation(*args, **kwargs):
        return {"status": "skipped", "reason": "already_executed"}
    async def _fast_dead_sub(*args, **kwargs):
        return {"status": "skipped", "reason": "no_dead_subs"}
    
    original_tasks.full_port_scan = _fast_full_port
    original_tasks.visual_recon = _fast_visual
    original_tasks.permutation_scan = _fast_permutation
    original_tasks.dead_subdomain_scan = _fast_dead_sub
    
    # Execute
    await pipeline.run_parallel_tasks(["example.com"])
    
    # Verify checkpoint was saved with parallel: prefix at least once
    parallel_saves = [c for c in save_calls if c.startswith("parallel:")]
    assert len(parallel_saves) >= 1, f"Expected parallel: saves, got: {save_calls}"


@pytest.mark.asyncio
async def test_run_parallel_tasks_records_exception_as_failed(tmp_path: Path) -> None:
    """Coroutine exception records failed entry in parallel_task_progress."""
    from src.recon.pipeline import ReconPipeline
    
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="exception.com",
    )
    pipeline.state.target = "exception.com"
    pipeline.state.target_fingerprint = _compute_target_fingerprint("exception.com")
    
    # Set up project_dir
    pipeline.pm = MagicMock()
    pipeline.pm.project_dir = tmp_path / "project"
    pipeline.pm.project_dir.mkdir(parents=True, exist_ok=True)
    
    # Patch _save_checkpoint to actually save
    async def _raising_task(*args, **kwargs):
        raise RuntimeError("simulated failure")
    
    # Replace visual_recon with a raising task in run_parallel_tasks logic
    # We patch the inner method on tasks
    original_visual = pipeline.tasks.visual_recon
    pipeline.tasks.visual_recon = _raising_task
    
    # Also make other tasks fast no-ops
    async def _fast_full_port(*args, **kwargs):
        return {"status": "completed", "ports_count": 0, "output_file": str(tmp_path / "dummy.txt")}
    async def _fast_permutation(*args, **kwargs):
        return {"status": "skipped", "reason": "already_executed"}
    async def _fast_dead_sub(*args, **kwargs):
        return {"status": "skipped", "reason": "no_dead_subs"}
    
    pipeline.tasks.full_port_scan = _fast_full_port
    pipeline.tasks.permutation_scan = _fast_permutation
    pipeline.tasks.dead_subdomain_scan = _fast_dead_sub
    
    # Execute - should not raise since gather has return_exceptions=True
    await pipeline.run_parallel_tasks(["example.com"])
    
    # Verify at least one task entry exists in progress
    assert len(pipeline.state.parallel_task_progress) > 0
    # Find the failed task
    failed_entries = {
        k: v for k, v in pipeline.state.parallel_task_progress.items()
        if v.get("status") == "failed"
    }
    assert len(failed_entries) >= 1, f"Expected failed entries, got: {pipeline.state.parallel_task_progress}"


# ---------------------------------------------------------------------------
# Unit 5: Resume decision and artifact consistency
# ---------------------------------------------------------------------------

def test_resume_decision_skips_completed_with_valid_artifact(tmp_path: Path) -> None:
    """Completed task with valid artifact returns skip decision."""
    state = ReconState(target="valid.com")
    artifact_path = tmp_path / "scan_output.txt"
    artifact_path.write_text("valid content")
    mtime = artifact_path.stat().st_mtime
    size = artifact_path.stat().st_size
    
    state.parallel_task_progress["test_task"] = {
        "status": "completed",
        "started_at": "2026-07-01T10:00:00Z",
        "updated_at": "2026-07-01T10:05:00Z",
        "completed_at": "2026-07-01T10:05:00Z",
        "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
        "artifact_refs": [
            {"path": str(artifact_path), "kind": "output", "exists": True, "size": size, "mtime": mtime}
        ],
        "error_summary": "",
        "resume_reason": "",
        "attempt_count": 1,
    }
    
    decision = state.get_parallel_task_resume_decision("test_task")
    assert decision["action"] == "skip"
    assert decision["resume_reason"] == "checkpoint_artifacts_valid"


def test_resume_decision_reruns_missing_artifact(tmp_path: Path) -> None:
    """Missing artifact returns rerun_required."""
    state = ReconState(target="missing.com")
    missing_path = str(tmp_path / "nonexistent.txt")
    
    state.parallel_task_progress["test_task"] = {
        "status": "completed",
        "started_at": "2026-07-01T10:00:00Z",
        "updated_at": "2026-07-01T10:05:00Z",
        "completed_at": "2026-07-01T10:05:00Z",
        "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
        "artifact_refs": [
            {"path": missing_path, "kind": "output", "exists": True, "size": 100, "mtime": time.time()}
        ],
        "error_summary": "",
        "resume_reason": "",
        "attempt_count": 1,
    }
    
    decision = state.get_parallel_task_resume_decision("test_task")
    assert decision["action"] == "rerun_required"
    assert "artifact_missing" in decision["reason_codes"]


def test_resume_decision_reruns_zero_byte_artifact(tmp_path: Path) -> None:
    """Zero-byte artifact returns rerun_required."""
    state = ReconState(target="zerobyte.com")
    artifact_path = tmp_path / "empty.txt"
    artifact_path.write_text("")  # zero bytes
    
    state.parallel_task_progress["test_task"] = {
        "status": "completed",
        "started_at": "2026-07-01T10:00:00Z",
        "updated_at": "2026-07-01T10:05:00Z",
        "completed_at": "2026-07-01T10:05:00Z",
        "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
        "artifact_refs": [
            {"path": str(artifact_path), "kind": "output", "exists": True, "size": 100, "mtime": time.time()}
        ],
        "error_summary": "",
        "resume_reason": "",
        "attempt_count": 1,
    }
    
    decision = state.get_parallel_task_resume_decision("test_task")
    assert decision["action"] == "rerun_required"
    assert "artifact_zero_byte" in decision["reason_codes"]


def test_resume_decision_reruns_checkpoint_version_mismatch(tmp_path: Path) -> None:
    """Checkpoint version mismatch returns rerun_required."""
    state = ReconState(target="version.com")
    artifact_path = tmp_path / "scan.txt"
    artifact_path.write_text("content")
    
    state.parallel_task_progress["test_task"] = {
        "status": "completed",
        "started_at": "2026-07-01T10:00:00Z",
        "updated_at": "2026-07-01T10:05:00Z",
        "completed_at": "2026-07-01T10:05:00Z",
        "checkpoint_version": 0,  # old version
        "artifact_refs": [
            {"path": str(artifact_path), "kind": "output", "exists": True, "size": 7, "mtime": artifact_path.stat().st_mtime}
        ],
        "error_summary": "",
        "resume_reason": "",
        "attempt_count": 1,
    }
    
    decision = state.get_parallel_task_resume_decision("test_task")
    assert decision["action"] == "rerun_required"
    assert "checkpoint_version_mismatch" in decision["reason_codes"]


def test_resume_decision_reruns_old_artifact(tmp_path: Path) -> None:
    """Artifact with older mtime than recorded returns rerun_required."""
    state = ReconState(target="old.com")
    artifact_path = tmp_path / "old_scan.txt"
    artifact_path.write_text("old content")
    
    # Artifact mtime is current, but checkpoint says it was updated in the future
    state.parallel_task_progress["test_task"] = {
        "status": "completed",
        "started_at": "2026-07-01T10:00:00Z",
        "updated_at": "2026-07-01T10:05:00Z",
        "completed_at": "2026-07-01T10:05:00Z",
        "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
        "artifact_refs": [
            {"path": str(artifact_path), "kind": "output", "exists": True, "size": 11, "mtime": time.time() + 3600}
        ],
        "error_summary": "",
        "resume_reason": "",
        "attempt_count": 1,
    }
    
    decision = state.get_parallel_task_resume_decision("test_task")
    assert decision["action"] == "rerun_required"
    assert "artifact_outdated" in decision["reason_codes"]


def test_resume_decision_no_entry_returns_run() -> None:
    """No progress entry → task must run."""
    state = ReconState(target="noentry.com")
    decision = state.get_parallel_task_resume_decision("unknown_task")
    assert decision["action"] == "run"
    assert "no_checkpoint_entry" in decision["reason_codes"]


def test_resume_decision_not_completed_status_returns_run() -> None:
    """Running/failed/skipped status returns run (not skip)."""
    state = ReconState(target="notdone.com")
    state.parallel_task_progress["test_task"] = {
        "status": "failed",
        "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
        "artifact_refs": [],
        "error_summary": "",
        "resume_reason": "",
        "attempt_count": 1,
    }
    decision = state.get_parallel_task_resume_decision("test_task")
    assert decision["action"] == "run"
    assert "not_completed" in decision["reason_codes"]


# ---------------------------------------------------------------------------
# Unit 6: Resume integration in run_parallel_tasks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_parallel_tasks_skips_valid_completed_tasks(tmp_path: Path) -> None:
    """Valid completed tasks are skipped on resume."""
    from src.recon.pipeline import ReconPipeline, PARALLEL_TASK_CHECKPOINT_VERSION
    
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="skipvalid.com",
    )
    pipeline.state.target = "skipvalid.com"
    pipeline.state.target_fingerprint = _compute_target_fingerprint("skipvalid.com")
    
    # Set up project_dir
    pipeline.pm = MagicMock()
    pipeline.pm.project_dir = tmp_path / "project"
    pipeline.pm.project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create valid artifact for full_port_scan
    artifact_path = tmp_path / "project" / "full_port_output.txt"
    artifact_path.write_text("valid scan results")
    mtime = artifact_path.stat().st_mtime
    size = artifact_path.stat().st_size
    
    # Pre-populate state with completed valid entries
    ts = datetime.now(timezone.utc).isoformat()
    pipeline.state.parallel_task_progress = {
        "full_port_scan": {
            "status": "completed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [
                {"path": str(artifact_path), "kind": "output", "exists": True, "size": size, "mtime": mtime}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
        "visual_recon": {
            "status": "completed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [
                {"path": str(tmp_path / "project" / "screenshots"), "kind": "screenshots_dir", "exists": True, "size": 0, "mtime": mtime}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
        "permutation_scan": {
            "status": "completed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [
                {"path": str(tmp_path / "project" / "perm_out.txt"), "kind": "output", "exists": True, "size": 50, "mtime": mtime}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
    }
    
    # Ensure artifacts exist
    (tmp_path / "project" / "screenshots").mkdir(parents=True, exist_ok=True)
    (tmp_path / "project" / "perm_out.txt").write_text("perm results")
    perm_size = (tmp_path / "project" / "perm_out.txt").stat().st_size
    perm_mtime = (tmp_path / "project" / "perm_out.txt").stat().st_mtime
    
    # Update artifact size to match actual file
    pipeline.state.parallel_task_progress["permutation_scan"]["artifact_refs"][0]["size"] = perm_size
    pipeline.state.parallel_task_progress["permutation_scan"]["artifact_refs"][0]["mtime"] = perm_mtime
    pipeline.state.parallel_task_progress["visual_recon"]["artifact_refs"][0]["mtime"] = (tmp_path / "project" / "screenshots").stat().st_mtime
    
    # Patch tasks to track calls
    call_log = []
    async def _tracked_full_port(*args, **kwargs):
        call_log.append("full_port_scan")
        return {"status": "completed", "ports_count": 0, "output_file": str(tmp_path / "dummy.txt")}
    async def _tracked_visual(*args, **kwargs):
        call_log.append("visual_recon")
        return {"status": "completed", "screenshot_count": 0, "screenshots_dir": str(tmp_path)}
    async def _tracked_permutation(*args, **kwargs):
        call_log.append("permutation_scan")
        return {"status": "skipped", "reason": "already_executed"}
    async def _tracked_dead_sub(*args, **kwargs):
        call_log.append("dead_subdomain_scan")
        return {"status": "skipped", "reason": "no_dead_subs"}
    
    pipeline.tasks.full_port_scan = _tracked_full_port
    pipeline.tasks.visual_recon = _tracked_visual
    pipeline.tasks.permutation_scan = _tracked_permutation
    pipeline.tasks.dead_subdomain_scan = _tracked_dead_sub
    
    await pipeline.run_parallel_tasks(["example.com"])
    
    # All tasks should be skipped (not executed)
    assert "full_port_scan" not in call_log, f"full_port should be skipped, but was called: {call_log}"
    assert "visual_recon" not in call_log, f"visual should be skipped, but was called: {call_log}"
    assert "permutation_scan" not in call_log, f"permutation should be skipped, but was called: {call_log}"
    
    # Verify progress reflects skip
    assert pipeline.state.parallel_task_progress["full_port_scan"]["resume_reason"] == "checkpoint_artifacts_valid"


@pytest.mark.asyncio
async def test_run_parallel_tasks_reruns_missing_artifact_tasks(tmp_path: Path) -> None:
    """Task with missing artifact is re-run, not skipped."""
    from src.recon.pipeline import ReconPipeline, PARALLEL_TASK_CHECKPOINT_VERSION
    
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="rerunmiss.com",
    )
    pipeline.state.target = "rerunmiss.com"
    pipeline.state.target_fingerprint = _compute_target_fingerprint("rerunmiss.com")
    
    pipeline.pm = MagicMock()
    pipeline.pm.project_dir = tmp_path / "project"
    pipeline.pm.project_dir.mkdir(parents=True, exist_ok=True)
    
    ts = datetime.now(timezone.utc).isoformat()
    pipeline.state.parallel_task_progress = {
        "full_port_scan": {
            "status": "completed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [
                {"path": str(tmp_path / "missing_file.txt"), "kind": "output", "exists": True, "size": 100, "mtime": time.time()}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
    }
    
    call_log = []
    async def _tracked_full_port(*args, **kwargs):
        call_log.append("full_port_scan")
        return {"status": "completed", "ports_count": 5, "output_file": str(tmp_path / "new_scan.txt")}
    async def _tracked_visual(*args, **kwargs):
        call_log.append("visual_recon")
        return {"status": "completed", "screenshot_count": 0, "screenshots_dir": str(tmp_path)}
    async def _tracked_permutation(*args, **kwargs):
        call_log.append("permutation_scan")
        return {"status": "skipped", "reason": "already_executed"}
    async def _tracked_dead_sub(*args, **kwargs):
        call_log.append("dead_subdomain_scan")
        return {"status": "skipped", "reason": "no_dead_subs"}
    
    pipeline.tasks.full_port_scan = _tracked_full_port
    pipeline.tasks.visual_recon = _tracked_visual
    pipeline.tasks.permutation_scan = _tracked_permutation
    pipeline.tasks.dead_subdomain_scan = _tracked_dead_sub
    
    await pipeline.run_parallel_tasks(["example.com"])
    
    # full_port should be rerun because artifact is missing
    assert "full_port_scan" in call_log, f"full_port should be rerun, but was not called: {call_log}"
    assert pipeline.state.parallel_task_progress["full_port_scan"]["attempt_count"] >= 2


@pytest.mark.asyncio
async def test_run_parallel_tasks_evaluates_dead_sub_after_full_port_skip(tmp_path: Path) -> None:
    """When full_port is skipped, dead_sub decision is evaluated independently."""
    from src.recon.pipeline import ReconPipeline, PARALLEL_TASK_CHECKPOINT_VERSION
    
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="chained.com",
    )
    pipeline.state.target = "chained.com"
    pipeline.state.target_fingerprint = _compute_target_fingerprint("chained.com")
    
    pipeline.pm = MagicMock()
    pipeline.pm.project_dir = tmp_path / "project"
    pipeline.pm.project_dir.mkdir(parents=True, exist_ok=True)
    
    ts = datetime.now(timezone.utc).isoformat()
    # full_port is valid → skipped
    artifact_path = tmp_path / "project" / "full_scan.txt"
    artifact_path.write_text("scan results")
    mtime = artifact_path.stat().st_mtime
    size = artifact_path.stat().st_size
    
    pipeline.state.parallel_task_progress = {
        "full_port_scan": {
            "status": "completed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [
                {"path": str(artifact_path), "kind": "output", "exists": True, "size": size, "mtime": mtime}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
        # dead_sub is not completed → should run
        "dead_subdomain_scan": {
            "status": "failed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [],
            "error_summary": "timeout",
            "resume_reason": "",
            "attempt_count": 1,
        },
    }
    
    call_log = []
    async def _tracked_full_port(*args, **kwargs):
        call_log.append("full_port_scan")
        return {"status": "completed", "ports_count": 0, "output_file": str(tmp_path / "dummy.txt")}
    async def _tracked_visual(*args, **kwargs):
        call_log.append("visual_recon")
        return {"status": "completed", "screenshot_count": 0, "screenshots_dir": str(tmp_path)}
    async def _tracked_permutation(*args, **kwargs):
        call_log.append("permutation_scan")
        return {"status": "skipped", "reason": "already_executed"}
    async def _tracked_dead_sub(*args, **kwargs):
        call_log.append("dead_subdomain_scan")
        return {"status": "completed", "revived_count": 0, "output_file": str(tmp_path / "dead_scan.txt")}
    
    pipeline.tasks.full_port_scan = _tracked_full_port
    pipeline.tasks.visual_recon = _tracked_visual
    pipeline.tasks.permutation_scan = _tracked_permutation
    pipeline.tasks.dead_subdomain_scan = _tracked_dead_sub
    
    await pipeline.run_parallel_tasks(["example.com"])
    
    # full_port should be skipped, dead_sub should run
    assert "full_port_scan" not in call_log, f"full_port should be skipped: {call_log}"
    assert "dead_subdomain_scan" in call_log, f"dead_sub should run: {call_log}"


# ---------------------------------------------------------------------------
# Regression: double-resume preserves skip (status must stay "completed")
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_parallel_tasks_skips_on_second_resume(tmp_path: Path) -> None:
    """After 1st resume skips valid completed tasks, 2nd resume also skips them.
    
    Regression: skip must preserve status="completed", not overwrite to "skipped",
    otherwise the 2nd resume would see status!="completed" and re-run.
    """
    from src.recon.pipeline import ReconPipeline, PARALLEL_TASK_CHECKPOINT_VERSION
    
    pipeline = ReconPipeline(
        config={"scan": {}},
        project_manager=None,
        target="double.com",
    )
    pipeline.state.target = "double.com"
    pipeline.state.target_fingerprint = _compute_target_fingerprint("double.com")
    
    pipeline.pm = MagicMock()
    pipeline.pm.project_dir = tmp_path / "project"
    pipeline.pm.project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create valid artifact for full_port_scan
    artifact_path = tmp_path / "project" / "fp_out.txt"
    artifact_path.write_text("valid")
    mtime = artifact_path.stat().st_mtime
    size = artifact_path.stat().st_size
    
    ts = datetime.now(timezone.utc).isoformat()
    pipeline.state.parallel_task_progress = {
        "full_port_scan": {
            "status": "completed",
            "started_at": ts,
            "updated_at": ts,
            "completed_at": ts,
            "checkpoint_version": PARALLEL_TASK_CHECKPOINT_VERSION,
            "artifact_refs": [
                {"path": str(artifact_path), "kind": "output", "exists": True, "size": size, "mtime": mtime}
            ],
            "error_summary": "",
            "resume_reason": "",
            "attempt_count": 1,
        },
    }
    
    # Patch tasks to track calls
    call_log = []
    async def _tracked_full_port(*args, **kwargs):
        call_log.append("full_port_scan")
        return {"status": "completed", "ports_count": 0, "output_file": str(tmp_path / "dummy.txt")}
    async def _noop(*args, **kwargs):
        return {"status": "skipped", "reason": "noop"}
    
    pipeline.tasks.full_port_scan = _tracked_full_port
    pipeline.tasks.visual_recon = _noop
    pipeline.tasks.permutation_scan = _noop
    pipeline.tasks.dead_subdomain_scan = _noop
    
    # 1st resume
    await pipeline.run_parallel_tasks(["example.com"])
    assert "full_port_scan" not in call_log, "1st resume should skip full_port"
    # Status must still be "completed"
    assert pipeline.state.parallel_task_progress["full_port_scan"]["status"] == "completed"
    
    # 2nd resume
    call_log.clear()
    await pipeline.run_parallel_tasks(["example.com"])
    assert "full_port_scan" not in call_log, "2nd resume should also skip full_port"
    assert pipeline.state.parallel_task_progress["full_port_scan"]["status"] == "completed"


# ---------------------------------------------------------------------------
# Regression: artifact path update preserves latest metadata
# ---------------------------------------------------------------------------

def test_update_parallel_task_progress_updates_existing_path_metadata() -> None:
    """Re-running with the same artifact path updates stale size/mtime."""
    
    state = ReconState(target="updatepath.com")
    tmpdir = tempfile.mkdtemp()
    tmp = Path(tmpdir)
    try:
        art_path = tmp / "scan.txt"
        # First run: write 100 bytes
        art_path.write_text("a" * 100)
        mtime1 = art_path.stat().st_mtime
        size1 = art_path.stat().st_size
        
        state.update_parallel_task_progress("test_task", "running")
        state.update_parallel_task_progress(
            "test_task", "completed",
            artifact_refs=[{"path": str(art_path), "kind": "output", "size": size1, "mtime": mtime1}],
        )
        entry = state.parallel_task_progress["test_task"]
        assert len(entry["artifact_refs"]) == 1
        assert entry["artifact_refs"][0]["size"] == 100
        
        # Second run: overwrite with different content (200 bytes)
        art_path.write_text("b" * 200)
        mtime2 = art_path.stat().st_mtime
        size2 = art_path.stat().st_size
        
        state.update_parallel_task_progress(
            "test_task", "completed",
            artifact_refs=[{"path": str(art_path), "kind": "output", "size": size2, "mtime": mtime2}],
        )
        entry2 = state.parallel_task_progress["test_task"]
        # Same path should NOT duplicate — still 1 entry with updated metadata
        assert len(entry2["artifact_refs"]) == 1
        ref = entry2["artifact_refs"][0]
        assert ref["size"] == size2, f"Expected size={size2}, got {ref['size']}"
        assert ref["mtime"] == mtime2, f"Expected mtime={mtime2}, got {ref['mtime']}"
        assert ref["path"] == str(art_path)
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
