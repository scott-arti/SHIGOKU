"""
Unit tests for MasterConductor bug bounty bundle preflight (Phase 1: SGK-2026-0335).

Covers:
- Bug bounty mode preflight resolves bundle and stores context
- Bundle resolution failure blocks run start
- Non-bugbounty mode is unaffected
"""

from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.security.ethics_guard import get_ethics_guard

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bugbounty_guard"


# ---------------------------------------------------------------------------
# Bug bounty mode: bundle resolved -> context populated
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bb_mode_preflight_stores_bundle_context():
    """Bug bounty mode with valid bundle_dir stores context in target_info."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
        }
    )
    mc.workspace = None

    # Set a bundle_dir in context.target_info before dispatch
    bundle_dir = str(FIXTURES_DIR / "tiktok")
    mc.context.target_info["bundle_dir"] = bundle_dir

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    ctx = result.get("context", {}).get("target_info", {})
    assert ctx.get("bundle_id") == "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34"
    assert ctx.get("policy_id") == "bbp:hackerone:tiktok:2026-07-01T07:38:38Z"
    assert ctx.get("compiled_policy_hash") == "sha256:4be73cd4fa12c45175432e662478698a9c3441237ab8a611f2aee61733ed274d"
    assert ctx.get("compiled_guard_policy_path", "").endswith("compiled_guard_policy.yaml")
    assert ctx.get("scope_source") == "compiled_guard_policy"


@pytest.mark.asyncio
async def test_bb_mode_preflight_fireblocks_stores_context():
    """Bug bounty mode with Fireblocks bundle stores correct context."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "sb-console-api.fireblocks.io",
        }
    )
    mc.workspace = None

    bundle_dir = str(FIXTURES_DIR / "fireblocks")
    mc.context.target_info["bundle_dir"] = bundle_dir

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "sb-console-api.fireblocks.io"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    ctx = result.get("context", {}).get("target_info", {})
    assert ctx.get("bundle_id") == "bbp-bugcrowd-fireblocks-2026-02-12T13:49:31Z-ef56aa01"
    assert ctx.get("policy_id") == "bbp:bugcrowd:fireblocks:2026-02-12T13:49:31Z"
    assert ctx.get("compiled_policy_hash") == "sha256:9923746670e2d8d142440ce7e53c6504524ce0acf86d0d78b6ab4e0bbe635b20"
    assert ctx.get("scope_source") == "compiled_guard_policy"


# ---------------------------------------------------------------------------
# Bundle resolution failure -> fail-closed
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_bb_mode_bundle_resolution_failure_fail_closed():
    """Bug bounty mode with invalid bundle_dir returns fail-closed error."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
        }
    )
    mc.workspace = None

    # Non-existent bundle_dir
    mc.context.target_info["bundle_dir"] = "/nonexistent/bundle/dir"

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is False
    assert "Bundle preflight failed" in result.get("error", "")


# ---------------------------------------------------------------------------
# Non-bugbounty mode: legacy path unaffected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_bb_mode_unaffected():
    """Non-bugbounty mode does not trigger bundle preflight."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "CTF"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "ctf",
            "target": "localhost:3000",
        }
    )
    mc.workspace = None

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "localhost:3000"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    ctx = result.get("context", {}).get("target_info", {})
    # No bundle context in non-bugbounty mode
    assert ctx.get("bundle_id") is None
    assert ctx.get("scope_source") == "fast_path_auto"


@pytest.mark.asyncio
async def test_bb_mode_no_bundle_dir_fail_closed():
    """Bug bounty mode without bundle_dir fails closed (no fall-through)."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "localhost:3000",
        }
    )
    mc.workspace = None

    # No bundle_dir, program, or bundle_id set — must fail-closed
    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "localhost:3000"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    # Should fail-closed: bug bounty mode requires a bundle
    assert result.get("success") is False
    assert "Bundle preflight failed" in result.get("error", "")


@pytest.mark.asyncio
async def test_bb_mode_program_resolution():
    """Bug bounty mode with --program resolves bundle from workspace layout."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
            "program": "tiktok-test",
            "provider": "hackerone",
        }
    )
    mc.workspace = None

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    ctx = result.get("context", {}).get("target_info", {})
    assert ctx.get("bundle_id") == "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34"
    assert ctx.get("policy_id") == "bbp:hackerone:tiktok:2026-07-01T07:38:38Z"
    assert ctx.get("scope_source") == "compiled_guard_policy"


@pytest.mark.asyncio
async def test_bb_mode_bundle_id_resolution():
    """Bug bounty mode with --bundle-id resolves by searching active_bundle.json."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
            "bundle_id": "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34",
            "provider": "hackerone",
        }
    )
    mc.workspace = None

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    ctx = result.get("context", {}).get("target_info", {})
    assert ctx.get("bundle_id") == "bbp-hackerone-tiktok-2026-07-01T07:38:38Z-ab12cd34"


@pytest.mark.asyncio
async def test_bb_mode_bundle_id_not_found():
    """Bug bounty mode with unknown bundle_id fails closed."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
            "bundle_id": "nonexistent-bundle-id",
        }
    )
    mc.workspace = None

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is False
    assert "Bundle preflight failed" in result.get("error", "")


@pytest.mark.asyncio
async def test_bb_mode_dispatch_gate_blocks_non_verify_scope():
    """_dispatch gate blocks non-verify_scope tasks when bundle is missing."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
        }
    )
    mc.workspace = None

    task = Task(
        id="task_002",
        name="Deep Reconnaissance",
        agent_type="recon_master",
        action="parallel_recon",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is False
    assert "Bundle preflight failed" in result.get("error", "")


@pytest.mark.asyncio
async def test_bb_mode_uppercase_fail_closed():
    """Uppercase 'BUGBOUNTY' must still trigger bundle preflight (case-insensitive)."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "BUGBOUNTY",
            "target": "www.tiktok.com",
        }
    )
    mc.workspace = None

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "www.tiktok.com"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is False
    assert "Bundle preflight failed" in result.get("error", "")


# ---------------------------------------------------------------------------
# SGK-2026-0339 regression: mode propagation / resolution centralization
#
# Root cause of the DVWA "5 tasks then abort" incident: interactive_bridge
# never persisted target_info["mode"], and the _dispatch site hardcoded the
# "bugbounty" default (while the scope fast-path used self.mode). A vulntest
# run therefore degraded to bugbounty at task_002 (recon) and the bundle
# preflight fail-closed on the bundle-less local target.
# ---------------------------------------------------------------------------


def test_resolve_current_mode_name_normalizes_variants():
    """_resolve_current_mode_name is the single source of truth and collapses
    BUG_BOUNTY/bug_bounty/BUGBOUNTY -> bugbounty, CTF -> ctf, etc."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(target_info={})

    # target_info["mode"] is authoritative when present.
    for raw, expected in [
        ("vulntest", "vulntest"),
        ("VULNTEST", "vulntest"),
        ("bugbounty", "bugbounty"),
        ("BUG_BOUNTY", "bugbounty"),
        ("bug-bounty", "bugbounty"),
        ("BugBounty", "bugbounty"),
        ("BUGBOUNTY", "bugbounty"),
        ("CTF", "ctf"),
        ("ctf", "ctf"),
    ]:
        mc.context.target_info["mode"] = raw
        assert mc._resolve_current_mode_name() == expected, f"raw={raw!r}"

    # Fallback to self.mode (normalized) when target_info has no mode.
    mc.context.target_info.pop("mode", None)
    mc.mode = "BUG_BOUNTY"
    assert mc._resolve_current_mode_name() == "bugbounty"
    mc.mode = "vulntest"
    assert mc._resolve_current_mode_name() == "vulntest"


@pytest.mark.asyncio
async def test_vulntest_mode_dispatch_gate_skips_bundle_preflight():
    """Regression: a vulntest run must NOT trigger the bugbounty bundle
    preflight at the _dispatch gate for non-verify_scope tasks (the exact
    task_002 recon path that aborted DVWA after 5 tasks)."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "vulntest"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "vulntest",
            "target": "localhost:4280",
        }
    )
    mc.workspace = None

    # Sentinel: the gate must never invoke the bundle resolver in vulntest.
    calls = {"count": 0}

    def _spy():
        calls["count"] += 1
        return {"_preflight_failed": True, "success": False, "error": "spy"}

    mc._try_resolve_bugbounty_bundle = _spy

    task = Task(
        id="task_002",
        name="Deep Reconnaissance",
        agent_type="recon_master",
        action="parallel_recon",
        params={"target": "localhost:4280"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        try:
            await mc._dispatch(task)
        except Exception:
            # Downstream dispatch may raise with a partially-constructed mc;
            # this regression is about the *gate*, not the dispatch body.
            pass
    finally:
        guard.scope = previous_scope

    assert calls["count"] == 0, (
        "vulntest mode must not invoke the bugbounty bundle preflight"
    )


# ============================================================================
# SGK-2026-0370: Guard-bridge in attack task creation
# ============================================================================


@pytest.mark.asyncio
async def test_guard_bridge_summary_stored_in_context():
    """When _create_attack_tasks_from_recon runs in bugbounty mode,
    the guard-bridge summary is stored in context.target_info for
    session/report persistence.  This test uses a minimal mock to
    avoid exercising the full task-creation machinery."""
    from unittest.mock import MagicMock, patch

    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "www.tiktok.com",
            "host": "www.tiktok.com",
        },
        discovered_assets=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
    )
    mc.workspace = None

    bundle_dir = str(FIXTURES_DIR / "tiktok")
    mc.context.target_info["bundle_dir"] = bundle_dir

    # Resolve bundle
    from src.core.security.compiled_guard_loader import (
        GuardLoadError,
        load_active_policy_from_bundle_dir,
    )
    result = load_active_policy_from_bundle_dir(bundle_dir=bundle_dir)
    assert not isinstance(result, GuardLoadError)

    mc.context.target_info["bundle_id"] = result.bundle_id
    mc.context.target_info["policy_id"] = result.policy_id
    mc.context.target_info["compiled_policy_hash"] = result.compiled_policy_hash
    mc.context.target_info["compiled_guard_policy_path"] = result.compiled_policy_path
    mc.context.target_info["scope_source"] = "compiled_guard_policy"

    # Mock PhaseGate
    mc.phase_gate = MagicMock()
    mc.phase_gate.can_create_task.return_value = (True, "OK")
    mc.phase_gate.can_create_attack_task.return_value = (True, "OK")
    from src.core.engine.phase_gate import Phase
    mc.phase_gate.get_phase_data.return_value = MagicMock(critical_findings=[])

    # Mock task queue and other deps that the fallback path accesses
    mc.task_queue = []
    mc.run_ledger_recorder = MagicMock()
    mc.run_ledger_recorder.record = MagicMock()
    mc._resolve_required_vuln_families = MagicMock(return_value=[])
    mc._collect_csrf_seed_targets = MagicMock(return_value=([], {}))
    mc._collect_xss_seed_targets = MagicMock(return_value=([], {}))
    mc.plan_missing_link_probes = MagicMock(return_value={})

    mc._resolve_recon_file_path = MagicMock(return_value=None)
    mc._collect_history_replay_targets = MagicMock(return_value=[])

    recon_results = {
        "id_param": {
            "count": 2,
            "file": "/fake/recon.txt",
            "description": "ID parameter endpoints",
            "_import_provenance": {},
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    assert isinstance(tasks, list)

    # Verify guard-bridge summary was stored
    bridge_summary = mc.context.target_info.get("_guard_bridge_summary")
    assert bridge_summary is not None, (
        "Guard-bridge summary must be stored in context for session/report persistence"
    )
    assert len(bridge_summary) > 0
    for entry in bridge_summary:
        assert "reason_origin" in entry
        assert "reason_codes" in entry
        assert "source_refs" in entry
        assert "compiled_guard_decision" in entry


@pytest.mark.asyncio
async def test_guard_bridge_out_of_scope_host_blocked():
    """Attack task for an out-of-scope host is blocked by the compiled guard,
    and the guard-bridge summary records the block with compiled_guard origin."""
    from unittest.mock import MagicMock

    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "BUGBOUNTY"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "target": "evil.example.com",
            "host": "evil.example.com",
        },
        discovered_assets=[],
        metrics={"estimated_cost": 0.0, "total_duration": 0},
    )
    mc.workspace = None

    bundle_dir = str(FIXTURES_DIR / "tiktok")
    mc.context.target_info["bundle_dir"] = bundle_dir

    from src.core.security.compiled_guard_loader import (
        GuardLoadError,
        load_active_policy_from_bundle_dir,
    )
    result = load_active_policy_from_bundle_dir(bundle_dir=bundle_dir)
    assert not isinstance(result, GuardLoadError)

    mc.context.target_info["bundle_id"] = result.bundle_id
    mc.context.target_info["policy_id"] = result.policy_id
    mc.context.target_info["compiled_policy_hash"] = result.compiled_policy_hash
    mc.context.target_info["compiled_guard_policy_path"] = result.compiled_policy_path
    mc.context.target_info["scope_source"] = "compiled_guard_policy"

    mc.phase_gate = MagicMock()
    mc.phase_gate.can_create_task.return_value = (True, "OK")
    mc.phase_gate.can_create_attack_task.return_value = (True, "OK")
    from src.core.engine.phase_gate import Phase
    mc.phase_gate.get_phase_data.return_value = MagicMock(critical_findings=[])

    mc.task_queue = []
    mc.run_ledger_recorder = MagicMock()
    mc.run_ledger_recorder.record = MagicMock()
    mc._resolve_required_vuln_families = MagicMock(return_value=[])
    mc._collect_csrf_seed_targets = MagicMock(return_value=([], {}))
    mc._collect_xss_seed_targets = MagicMock(return_value=([], {}))
    mc.plan_missing_link_probes = MagicMock(return_value={})
    mc._resolve_recon_file_path = MagicMock(return_value=None)
    mc._collect_history_replay_targets = MagicMock(return_value=[])

    recon_results = {
        "id_param": {
            "count": 1,
            "file": "/fake/recon.txt",
            "description": "ID parameter endpoint",
            "_import_provenance": {},
        },
    }

    tasks = mc._create_attack_tasks_from_recon(recon_results)
    assert isinstance(tasks, list)

    # Verify guard-bridge summary records the block
    bridge_summary = mc.context.target_info.get("_guard_bridge_summary")
    assert bridge_summary is not None

    any_blocked = any(
        entry.get("compiled_guard_decision") == "block" for entry in bridge_summary
    )
    assert any_blocked, (
        f"Expected at least one guard block for out-of-scope host. Summary: {bridge_summary}"
    )

    stats = mc.context.target_info.get("_guard_bridge_decision_stats", {})
    assert stats.get("guard_blocked", 0) > 0
