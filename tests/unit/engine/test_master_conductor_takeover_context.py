"""Tests for MasterConductor takeover_candidates context injection (Step 7, SGK-2026-0283).

Per plan sections 3.4.2, 4.5, 4.7: _load_recipe_tasks() must load
takeover_candidates from ReconPipeline output and pass them to
match_recipes_to_context() so that signal-based takeover recipes
are actually selected.
"""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.recipe_loader import (
    RecipeLoader,
    Recipe,
    RecipeStep,
    TakeoverCandidate,
)
from src.core.engine.task_queue import DynamicTaskQueue
from src.core.domain.model.task import Task


# ── helpers ─────────────────────────────────────────────────────────────

def _make_candidate_dict(
    subdomain="dead.example.com",
    candidate_id="takeover_abc123",
    cname_chain=None,
    provider_guess=None,
):
    """Build a new-schema takeover_candidates.json entry (has candidate_id)."""
    now = datetime.now(timezone.utc)
    entry = {
        "candidate_id": candidate_id,
        "subdomain": subdomain,
        "status": "candidate",
        "observed_at": now.isoformat(),
        "first_seen_dead": now.isoformat(),
        "last_seen_dead": now.isoformat(),
        "last_dns_probe": now.isoformat(),
        "last_http_probe": None,
        "cname_chain": cname_chain or [],
        "provider_guess": provider_guess,
        "required_signals": {"dns_dead": True, "cname_dangling": bool(cname_chain)},
        "blocking_signals": [],
        "raw_evidence": {"dns": {}, "http": {}},
        "manual_claim_review_required": True,
    }
    return entry


def _make_legacy_entry(subdomain="nxdomain.example.com", status="NXDOMAIN"):
    """Build a legacy-format entry (no candidate_id, just subdomain + status)."""
    return {
        "subdomain": subdomain,
        "status": status,
    }


def _write_takeover_json(dir_path: Path, entries: list) -> Path:
    """Write a takeover_candidates.json to *dir_path* and return the file path."""
    dir_path.mkdir(parents=True, exist_ok=True)
    file_path = dir_path / "20260625_recon_takeover_candidates.json"
    file_path.write_text(json.dumps(entries, indent=2))
    return file_path


def _new_mc(
    recipe_loader=None,
    project_manager=None,
    target="example.com",
):
    """Minimal MasterConductor for testing takeover context injection."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(
        target_info={
            "target": target,
            "tech_stack": ["nginx", "react"],
        }
    )
    mc.task_queue = DynamicTaskQueue(max_memory_size=32)
    mc.recipe_loader = recipe_loader
    mc.project_manager = project_manager
    mc.llm_client = None
    return mc


# ── _build_takeover_candidates_from_recon  tests ─────────────────────────

def test_build_takeover_candidates_new_schema(tmp_path):
    """New-schema JSON (has candidate_id) is parsed into TakeoverCandidate objects."""
    entries = [
        _make_candidate_dict(
            subdomain="dead1.example.com",
            candidate_id="takeover_dead1",
            cname_chain=["dead1.example.com", "unclaimed.s3.amazonaws.com"],
            provider_guess="aws_s3",
        ),
        _make_candidate_dict(
            subdomain="dead2.example.com",
            candidate_id="takeover_dead2",
        ),
    ]
    takeover_file = _write_takeover_json(tmp_path, entries)

    mc = _new_mc()
    # Inject project_manager pointing to tmp_path
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert len(result) == 2
    assert isinstance(result[0], TakeoverCandidate)
    assert isinstance(result[1], TakeoverCandidate)

    # Verify first candidate
    c0 = result[0]
    assert c0.subdomain == "dead1.example.com"
    assert c0.candidate_id == "takeover_dead1"
    assert c0.cname_chain == ["dead1.example.com", "unclaimed.s3.amazonaws.com"]
    assert c0.provider_guess == "aws_s3"
    assert c0.first_seen_dead is not None
    assert c0.last_seen_dead is not None
    assert c0.required_signals["dns_dead"] is True


def test_build_takeover_candidates_legacy_format(tmp_path):
    """Legacy-format JSON (no candidate_id, just subdomain + status) is converted."""
    entries = [
        _make_legacy_entry("nxdomain.example.com", "NXDOMAIN"),
    ]
    takeover_file = _write_takeover_json(tmp_path, entries)

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert len(result) == 1
    c = result[0]
    assert c.subdomain == "nxdomain.example.com"
    # candidate_id should be auto-generated
    assert c.candidate_id is not None
    assert c.candidate_id != ""
    # first_seen_dead and last_seen_dead should be set to now
    assert c.first_seen_dead is not None
    assert c.last_seen_dead is not None
    # legacy entries should have dns_dead required signal
    assert c.required_signals.get("dns_dead") is True
    # no cname_chain in legacy format
    assert c.cname_chain == []
    assert c.provider_guess is None


def test_build_takeover_candidates_no_file_no_crash(tmp_path):
    """When no takeover_candidates.json exists, return empty list (no crash)."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(empty_dir))

    result = mc._build_takeover_candidates_from_recon()
    assert result == []


def test_build_takeover_candidates_no_project_manager_no_crash():
    """When project_manager is None, return empty list gracefully."""
    mc = _new_mc()
    mc.project_manager = None

    result = mc._build_takeover_candidates_from_recon()
    assert result == []


def test_build_takeover_candidates_malformed_json(tmp_path):
    """Malformed JSON (invalid syntax) returns empty list, does not crash."""
    bad_dir = tmp_path / "scans" / "raw"
    bad_dir.mkdir(parents=True, exist_ok=True)
    bad_file = bad_dir / "20260625_recon_takeover_candidates.json"
    bad_file.write_text("this is not valid json {{{{{")

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert result == []


def test_build_takeover_candidates_empty_file(tmp_path):
    """Empty JSON file returns empty list, does not crash."""
    entries = []
    takeover_file = _write_takeover_json(tmp_path, entries)

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert result == []


def test_build_takeover_candidates_mixed_schema(tmp_path):
    """A file with both new-schema and legacy entries handles each correctly."""
    entries = [
        _make_candidate_dict(subdomain="new.example.com", candidate_id="takeover_new"),
        _make_legacy_entry("legacy.example.com", "NXDOMAIN"),
    ]
    takeover_file = _write_takeover_json(tmp_path, entries)

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert len(result) == 2

    new_cand = [c for c in result if c.subdomain == "new.example.com"][0]
    legacy_cand = [c for c in result if c.subdomain == "legacy.example.com"][0]
    assert new_cand.candidate_id == "takeover_new"
    assert legacy_cand.cname_chain == []


def test_build_takeover_candidates_with_scan_raw_subdir(tmp_path):
    """File in scans/raw/ subdirectory is discovered."""
    scan_raw_dir = tmp_path / "scans" / "raw"
    entries = [_make_candidate_dict(subdomain="scan.example.com", candidate_id="takeover_scan")]
    _write_takeover_json(scan_raw_dir, entries)

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert len(result) == 1
    assert result[0].subdomain == "scan.example.com"


# ── _load_recipe_tasks takeover integration ────────────────────────────

def test_build_takeover_candidates_preserves_trace_fields(tmp_path):
    """New-schema JSON with trace fields (source_line, producer_step, session_id,
    artifact_hash) must hydrate into TakeoverCandidate."""
    entries = [
        _make_candidate_dict(
            subdomain="trace.example.com",
            candidate_id="takeover_trace",
            cname_chain=["trace.example.com", "unclaimed.s3.amazonaws.com"],
        ),
    ]
    # Inject trace metadata
    entries[0]["source_line"] = "takeover_candidates.json:42"
    entries[0]["producer_step"] = "recon.step3_live_check"
    entries[0]["session_id"] = "sess_20260625_001"
    entries[0]["artifact_hash"] = "sha256:abc123def456"
    _write_takeover_json(tmp_path, entries)

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert len(result) == 1
    tc = result[0]
    assert tc.source_line == "takeover_candidates.json:42"
    assert tc.producer_step == "recon.step3_live_check"
    assert tc.session_id == "sess_20260625_001"
    assert tc.artifact_hash == "sha256:abc123def456"


def test_build_takeover_candidates_missing_trace_fields_defaults_none(tmp_path):
    """When trace fields are missing from JSON, TakeoverCandidate fields default to None."""
    entries = [
        _make_candidate_dict(
            subdomain="no-trace.example.com",
            candidate_id="takeover_notrace",
        ),
    ]
    # Do not add trace fields
    _write_takeover_json(tmp_path, entries)

    mc = _new_mc()
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    result = mc._build_takeover_candidates_from_recon()
    assert len(result) == 1
    tc = result[0]
    assert tc.source_line is None
    assert tc.producer_step is None
    assert tc.session_id is None
    assert tc.artifact_hash is None


def test_load_recipe_tasks_includes_takeover_candidates_in_context(tmp_path):
    """_load_recipe_tasks() passes takeover_candidates from recon output to match_recipes_to_context."""
    scan_raw_dir = tmp_path / "scans" / "raw"
    entries = [
        _make_candidate_dict(
            subdomain="dangling.example.com",
            candidate_id="takeover_dangling",
            cname_chain=["dangling.example.com", "unclaimed.s3.amazonaws.com"],
        ),
    ]
    _write_takeover_json(scan_raw_dir, entries)

    # Set up RecipeLoader with takeover recipe
    loader = RecipeLoader()
    loader.recipes["subdomain_takeover"] = Recipe(
        name="subdomain_takeover",
        description="Takeover check",
        agent="swarm",
        trigger={"type": "signal", "required_signals": ["dns_dead", "cname_dangling"]},
        steps=[RecipeStep(id="s0", name="check", action="check_takeover")],
    )

    mc = _new_mc(recipe_loader=loader)
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    tasks = mc._load_recipe_tasks()
    # Should find at least one recipe task (takeover recipe)
    takeover_tasks = [t for t in tasks if "takeover" in t.name.lower()]
    assert len(takeover_tasks) >= 1, "Expected takeover recipe task when candidates exist"


def test_load_recipe_tasks_no_takeover_candidates_no_takeover_recipe(tmp_path):
    """When no takeover_candidates.json exists, takeover recipes are NOT selected."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    loader = RecipeLoader()
    loader.recipes["subdomain_takeover"] = Recipe(
        name="subdomain_takeover",
        description="Takeover check",
        agent="swarm",
        trigger={"type": "signal", "required_signals": ["dns_dead", "cname_dangling"]},
        steps=[RecipeStep(id="s0", name="check", action="check_takeover")],
    )

    mc = _new_mc(recipe_loader=loader)
    mc.project_manager = SimpleNamespace(project_dir=str(empty_dir))

    tasks = mc._load_recipe_tasks()
    takeover_tasks = [t for t in tasks if "takeover" in t.name.lower()]
    assert len(takeover_tasks) == 0, "Takeover recipe should NOT be selected without candidates"


def test_load_recipe_tasks_insufficient_signals_no_takeover_recipe(tmp_path):
    """A takeover candidate without cname_dangling signal should not match takeover recipe."""
    scan_raw_dir = tmp_path / "scans" / "raw"
    # Candidate has dns_dead but NO cname_dangling (no cname_chain)
    entries = [
        _make_candidate_dict(
            subdomain="dead.example.com",
            candidate_id="takeover_deadonly",
            cname_chain=[],  # no CNAME → no cname_dangling signal
        ),
    ]
    _write_takeover_json(scan_raw_dir, entries)

    loader = RecipeLoader()
    loader.recipes["subdomain_takeover"] = Recipe(
        name="subdomain_takeover",
        description="Takeover check",
        agent="swarm",
        trigger={"type": "signal", "required_signals": ["dns_dead", "cname_dangling"]},
        steps=[RecipeStep(id="s0", name="check", action="check_takeover")],
    )

    mc = _new_mc(recipe_loader=loader)
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    tasks = mc._load_recipe_tasks()
    takeover_tasks = [t for t in tasks if "takeover" in t.name.lower()]
    assert len(takeover_tasks) == 0, (
        "Takeover recipe should NOT match when cname_dangling signal is missing"
    )


def test_load_recipe_tasks_non_takeover_recipes_still_selected(tmp_path):
    """Non-takeover recipes (no signal trigger) are still selected regardless of takeover data."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    loader = RecipeLoader()
    # A generic recipe without signal trigger
    loader.recipes["generic_scan"] = Recipe(
        name="generic_scan",
        description="Generic scan",
        agent="swarm",
        trigger={},  # no signal trigger → unconditional match
        steps=[RecipeStep(id="s0", name="scan", action="scan")],
    )

    mc = _new_mc(recipe_loader=loader)
    mc.project_manager = SimpleNamespace(project_dir=str(empty_dir))

    tasks = mc._load_recipe_tasks()
    # Generic recipe should still be selected
    generic_tasks = [t for t in tasks if "generic" in t.name.lower()]
    assert len(generic_tasks) >= 1, "Non-takeover recipes should still be selected"


def test_load_recipe_tasks_task_params_include_selector_metadata(tmp_path):
    """Recipe tasks should include selector metadata (score, reasons, candidate_id)."""
    scan_raw_dir = tmp_path / "scans" / "raw"
    entries = [
        _make_candidate_dict(
            subdomain="dangling.example.com",
            candidate_id="takeover_meta",
            cname_chain=["dangling.example.com", "unclaimed.s3.amazonaws.com"],
        ),
    ]
    _write_takeover_json(scan_raw_dir, entries)

    loader = RecipeLoader()
    loader.recipes["subdomain_takeover"] = Recipe(
        name="subdomain_takeover",
        description="Takeover check",
        agent="swarm",
        trigger={"type": "signal", "required_signals": ["dns_dead", "cname_dangling"]},
        steps=[RecipeStep(id="s0", name="check", action="check_takeover")],
    )

    mc = _new_mc(recipe_loader=loader)
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    tasks = mc._load_recipe_tasks()
    takeover_tasks = [t for t in tasks if "takeover" in t.name.lower()]
    assert len(takeover_tasks) >= 1

    task = takeover_tasks[0]
    params = task.params
    assert "selector_score" in params
    assert "selector_reasons" in params
    assert "candidate_id" in params
    assert params["candidate_id"] == "takeover_meta"


# ── Gap 2: kill switch / feature flag tests ────────────────────────────

def test_kill_switch_skips_takeover_injection(tmp_path, monkeypatch):
    """When should_use_v2() returns False, _load_recipe_tasks skips takeover candidate loading."""
    scan_raw_dir = tmp_path / "scans" / "raw"
    entries = [
        _make_candidate_dict(
            subdomain="dangling.example.com",
            candidate_id="takeover_killswitch",
            cname_chain=["dangling.example.com", "unclaimed.s3.amazonaws.com"],
        ),
    ]
    _write_takeover_json(scan_raw_dir, entries)

    # Non-takeover recipe (no signal trigger)
    loader = RecipeLoader()
    loader.recipes["generic_scan"] = Recipe(
        name="generic_scan",
        description="Generic scan",
        agent="swarm",
        trigger={},
        steps=[RecipeStep(id="s0", name="scan", action="scan")],
    )
    # Takeover recipe (signal-triggered)
    loader.recipes["subdomain_takeover"] = Recipe(
        name="subdomain_takeover",
        description="Takeover check",
        agent="swarm",
        trigger={"type": "signal", "required_signals": ["dns_dead", "cname_dangling"]},
        steps=[RecipeStep(id="s0", name="check", action="check_takeover")],
    )

    mc = _new_mc(recipe_loader=loader)
    mc.project_manager = SimpleNamespace(project_dir=str(tmp_path))

    # Simulate kill switch / feature flag OFF
    monkeypatch.setattr(
        "src.core.engine.takeover_feature_flags.should_use_v2", lambda: False,
    )

    tasks = mc._load_recipe_tasks()

    # Non-takeover recipes should still be selected
    generic_tasks = [t for t in tasks if "generic" in t.name.lower()]
    assert len(generic_tasks) >= 1, "Non-takeover recipes should still be selected"

    # Takeover recipe should NOT be selected
    takeover_tasks = [t for t in tasks if "takeover" in t.name.lower()]
    assert len(takeover_tasks) == 0, (
        "Takeover recipe should NOT be selected when kill switch is active"
    )
