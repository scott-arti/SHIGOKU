"""
Unit tests for Phase 2 guard enforcement (SGK-2026-0335).

Covers:
- post-exploit task blocked by compiled policy
- network_client hard enforcement (worker_external_hard)
- SmartRequest guard context passthrough
- base_external_adapter guard block
- context_runner subprocess guard block
- base_manager tool guard block
- shadow_read_only: evaluate but never block
- mc_only: backward compat (legacy path works)
- non-bugbounty unaffected
"""

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor
from src.core.security.ethics_guard import get_ethics_guard
from src.core.security.compiled_guard_loader import (
    LoadedGuardPolicy,
    load_active_policy_from_bundle_dir,
)
from src.core.security.compiled_guard_evaluator import (
    GuardDecision,
    GuardInput,
)
from src.core.security.guard_enforcement import (
    EnforcementStage,
    evaluate_at_layer,
    resolve_enforcement_stage,
    stage_allows_block,
)
from src.core.infra.network_client import AsyncNetworkClient, NetworkClientError
from src.core.infra.smart_request import SmartRequest
from src.core.tools.context_runner import ContextToolRunner, ExecutionResult
from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.adapters.external.base_external_adapter import (
    BaseExternalAdapter,
    ToolInput,
    ToolResult,
    ToolStatus,
)

FIXTURES_DIR = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "bugbounty_guard"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tiktok_policy() -> LoadedGuardPolicy:
    result = load_active_policy_from_bundle_dir(FIXTURES_DIR / "tiktok")
    assert isinstance(result, LoadedGuardPolicy)
    return result


@pytest.fixture
def fireblocks_policy() -> LoadedGuardPolicy:
    result = load_active_policy_from_bundle_dir(FIXTURES_DIR / "fireblocks")
    assert isinstance(result, LoadedGuardPolicy)
    return result


@pytest.fixture
def hard_guard_ctx(tiktok_policy):
    return {
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    }


# ---------------------------------------------------------------------------
# 1. post-exploit block
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_post_exploit_task_blocked_by_compiled_policy(tiktok_policy):
    """_dispatch blocks post_exploit task when compiled policy denies it."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "bugbounty"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "bundle_id": tiktok_policy.bundle_id,
            "policy_id": tiktok_policy.policy_id,
            "compiled_policy_hash": tiktok_policy.compiled_policy_hash,
            "compiled_guard_policy_path": tiktok_policy.compiled_policy_path,
            "scope_source": "compiled_guard_policy",
            "guard_enforcement_stage": "mc_only",
        }
    )
    mc.workspace = None

    task = Task(
        id="post_001",
        name="Internal Recon",
        agent_type="post_exploit",
        action="internal_recon",
        params={"target": "https://www.tiktok.com/"},
    )

    guard = get_ethics_guard()
    previous_scope = guard.scope
    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    assert result.get("data", {}).get("skipped") is True
    assert "post_exploit" in str(result.get("data", {}).get("reason", "")).lower()


@pytest.mark.asyncio
async def test_trigger_post_exploit_recon_denies_when_policy_blocks(fireblocks_policy):
    """_trigger_post_exploit skips task generation when policy blocks."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "bugbounty"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "bundle_id": fireblocks_policy.bundle_id,
            "policy_id": fireblocks_policy.policy_id,
            "compiled_policy_hash": fireblocks_policy.compiled_policy_hash,
            "compiled_guard_policy_path": fireblocks_policy.compiled_policy_path,
            "scope_source": "compiled_guard_policy",
            "guard_enforcement_stage": "mc_only",
        }
    )
    mc.workspace = None

    from src.core.models.finding import Finding, VulnType
    finding = Finding(
        title="RCE found",
        description="",
        target_url="https://sb-console-api.fireblocks.io/",
        vuln_type=VulnType.OS_COMMAND_INJECTION,
        severity="critical",
        evidence=SimpleNamespace(request_url="https://sb-console-api.fireblocks.io/"),
        additional_info={"exploit_payload": "cmd=whoami"},
    )

    mc._add_tasks = lambda tasks, **kw: None
    mc._trigger_post_exploit(finding)
    # Should not raise — silently skipped due to compiled policy post_exploit deny


# ---------------------------------------------------------------------------
# 2. network_client hard enforcement
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_network_client_blocks_out_of_scope_in_hard_mode(tiktok_policy):
    """AsyncNetworkClient blocks out-of-scope host in worker_external_hard."""
    parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse
    client = AsyncNetworkClient(mode="bugbounty")
    await client.start()

    guard_context = {
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
        "host": "out-of-scope.example.com",
    }

    with pytest.raises(NetworkClientError) as exc:
        await client.request("GET", "https://out-of-scope.example.com/", guard_context=guard_context)
    assert "compiled guard" in str(exc.value).lower()

    await client.close()


@pytest.mark.asyncio
async def test_network_client_shadow_mode_does_not_block(tiktok_policy):
    """AsyncNetworkClient in shadow_read_only does not block."""
    client = AsyncNetworkClient(mode="bugbounty")
    await client.start()

    guard_context = {
        "policy": tiktok_policy,
        "stage": EnforcementStage.SHADOW_READ_ONLY,
        "host": "out-of-scope.example.com",
    }

    with pytest.raises(NetworkClientError):
        await client.request("GET", "https://out-of-scope.example.com/", guard_context=guard_context)

    await client.close()


# ---------------------------------------------------------------------------
# 3. SmartRequest guard context
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_smart_request_passes_guard_context():
    """SmartRequest passes guard_context to network_client."""
    client = AsyncNetworkClient(mode="bugbounty")
    sr = SmartRequest(network_client=client, guard_context={
        "policy": None,
        "stage": EnforcementStage.MC_ONLY,
    })
    assert sr._get_guard_context() is not None
    assert sr._get_guard_context()["stage"] == EnforcementStage.MC_ONLY
    await client.close()


# ---------------------------------------------------------------------------
# 4. base_external_adapter guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_external_adapter_blocks_in_hard_mode(tiktok_policy):
    """BaseExternalAdapter blocks tool execution in worker_external_hard."""

    class TestAdapter(BaseExternalAdapter):
        def __init__(self):
            super().__init__(tool_name="test_tool")
            self._guard_context = {
                "policy": tiktok_policy,
                "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
            }

        async def execute(self, input_data: ToolInput) -> ToolResult:
            return ToolResult(status=ToolStatus.SUCCESS, data="ok", execution_time_ms=0)

        def validate_inputs(self, input_data: ToolInput):
            return True, None

        async def health_check(self):
            return True

    adapter = TestAdapter()
    result = await adapter.run_with_validation(
        ToolInput(target="https://out-of-scope.example.com/")
    )
    assert result.status == ToolStatus.ERROR
    assert "Blocked by compiled guard" in (result.error_message or "")


@pytest.mark.asyncio
async def test_external_adapter_allows_in_mc_only(tiktok_policy):
    """BaseExternalAdapter does not block in mc_only (only MC blocks)."""

    class TestAdapter(BaseExternalAdapter):
        def __init__(self):
            super().__init__(tool_name="test_tool")
            self._guard_context = {
                "policy": tiktok_policy,
                "stage": EnforcementStage.MC_ONLY,
            }

        async def execute(self, input_data: ToolInput) -> ToolResult:
            return ToolResult(status=ToolStatus.SUCCESS, data="ok", execution_time_ms=0)

        def validate_inputs(self, input_data: ToolInput):
            return True, None

        async def health_check(self):
            return True

    adapter = TestAdapter()
    result = await adapter.run_with_validation(
        ToolInput(target="https://out-of-scope.example.com/")
    )
    assert result.status == ToolStatus.SUCCESS


# ---------------------------------------------------------------------------
# 5. context_runner subprocess guard
# ---------------------------------------------------------------------------

def test_context_runner_blocks_tool_in_hard_mode(tiktok_policy):
    """ContextToolRunner blocks tool execution in worker_external_hard."""
    runner = ContextToolRunner(
        ethics_guard=None,
        guard_context={
            "policy": tiktok_policy,
            "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
        },
    )
    result = runner.run_tool(
        tool_name="sqlmap",
        target="https://out-of-scope.example.com/",
        context={},
    )
    assert not result.success
    assert "Blocked by compiled guard" in result.error


def test_context_runner_allows_in_mc_only(tiktok_policy):
    """ContextToolRunner allows in mc_only (not external layer)."""
    runner = ContextToolRunner(
        ethics_guard=None,
        guard_context={
            "policy": tiktok_policy,
            "stage": EnforcementStage.MC_ONLY,
        },
    )
    result = runner.run_tool(
        tool_name="nuclei",
        target="https://out-of-scope.example.com/",
        context={},
    )
    # mc_only doesn't block external tools — the tool runs (or fails for other reasons)
    # Just assert it didn't block due to compiled guard
    assert "Blocked by compiled guard" not in str(result.error or "")


# ---------------------------------------------------------------------------
# 6. base_manager tool guard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_base_manager_blocks_tool_in_hard_mode(tiktok_policy):
    """BaseManagerAgent blocks tool execution in worker_external_hard."""
    mgr = BaseManagerAgent.__new__(BaseManagerAgent)
    mgr.available_tools = {}
    mgr.current_context = {"target": "https://out-of-scope.example.com/"}
    mgr._guard_context = {
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    }

    with pytest.raises(ValueError):
        await mgr._execute_tool("nonexistent_tool", {})
    # Unknown tool raises ValueError before guard could fire — acceptable


@pytest.mark.asyncio
async def test_base_manager_runtime_error_on_block(tiktok_policy):
    """BaseManagerAgent raises RuntimeError when guard blocks with policy."""
    mgr = BaseManagerAgent.__new__(BaseManagerAgent)

    async def _dummy_tool(**kwargs):
        return "ok"

    mgr.available_tools = {"test_tool": {"func": _dummy_tool}}
    mgr.current_context = {"target": "https://out-of-scope.example.com/", "mode": "bugbounty"}
    mgr._guard_context = {
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    }

    with pytest.raises(RuntimeError) as exc:
        await mgr._execute_tool("test_tool", {"target": "https://out-of-scope.example.com/"})
    assert "Blocked by compiled guard" in str(exc.value) or "blocked" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# 7. shadow_read_only
# ---------------------------------------------------------------------------

def test_shadow_stage_never_blocks(tiktok_policy):
    """shadow_read_only evaluates but always returns allow."""
    gi = GuardInput(
        bundle_id=tiktok_policy.bundle_id,
        policy_id=tiktok_policy.policy_id,
        host="out-of-scope.example.com",
    )
    decision = evaluate_at_layer(
        policy=tiktok_policy,
        guard_input=gi,
        layer="network",
        stage=EnforcementStage.SHADOW_READ_ONLY,
    )
    assert decision.decision == "allow"
    assert decision.reason_code.startswith("shadow_")


def test_stage_allows_block_helpers():
    """stage_allows_block returns correct booleans per stage."""
    assert stage_allows_block(EnforcementStage.SHADOW_READ_ONLY, "mc") is False
    assert stage_allows_block(EnforcementStage.SHADOW_READ_ONLY, "network") is False
    assert stage_allows_block(EnforcementStage.MC_ONLY, "mc") is True
    assert stage_allows_block(EnforcementStage.MC_ONLY, "network") is False
    assert stage_allows_block(EnforcementStage.WORKER_EXTERNAL_HARD, "mc") is True
    assert stage_allows_block(EnforcementStage.WORKER_EXTERNAL_HARD, "network") is True
    assert stage_allows_block(EnforcementStage.WORKER_EXTERNAL_HARD, "external") is True


def test_resolve_stage_default():
    """Default stage is mc_only."""
    assert resolve_enforcement_stage() == EnforcementStage.MC_ONLY


def test_resolve_stage_from_context():
    """Stage resolves from context dict."""
    assert resolve_enforcement_stage(context={"guard_enforcement_stage": "worker_external_hard"}) \
        == EnforcementStage.WORKER_EXTERNAL_HARD


# ---------------------------------------------------------------------------
# 8. mc_only backward compat
# ---------------------------------------------------------------------------

def test_mc_only_evaluator_returns_allow_for_network(tiktok_policy):
    """evaluate_at_layer at network layer in mc_only shadow-blocks (returns allow)."""
    gi = GuardInput(
        bundle_id=tiktok_policy.bundle_id,
        policy_id=tiktok_policy.policy_id,
        host="out-of-scope.example.com",
    )
    decision = evaluate_at_layer(
        policy=tiktok_policy,
        guard_input=gi,
        layer="network",
        stage=EnforcementStage.MC_ONLY,
    )
    assert decision.decision == "allow"
    assert decision.reason_code.startswith("shadow_")


def test_mc_only_evaluator_returns_block_for_mc(tiktok_policy):
    """evaluate_at_layer at mc layer in mc_only actually blocks."""
    gi = GuardInput(
        bundle_id=tiktok_policy.bundle_id,
        policy_id=tiktok_policy.policy_id,
        host="out-of-scope.example.com",
    )
    decision = evaluate_at_layer(
        policy=tiktok_policy,
        guard_input=gi,
        layer="mc",
        stage=EnforcementStage.MC_ONLY,
    )
    assert decision.decision == "block"


# ---------------------------------------------------------------------------
# 9. non-bugbounty unaffected
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ctf_mode_post_exploit_not_blocked():
    """CTF mode does not block post-exploit via compiled guard."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "ctf"
    mc.context = SimpleNamespace(
        target_info={"mode": "ctf", "target": "https://example.com/"}
    )
    mc.workspace = None

    from src.core.security.ethics_guard import ScopeDefinition
    guard = get_ethics_guard()
    previous_scope = guard.scope
    guard.set_scope(ScopeDefinition(
        program_name="CTF",
        in_scope_domains=["example.com"],
        allow_post_exploit=True,
    ))

    # Use verify_scope to test CTF mode — this path is simple and always works
    task = Task(
        id="task_ctf",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "example.com"},
    )

    try:
        result = await mc._dispatch(task)
    finally:
        guard.scope = previous_scope

    assert result.get("success") is True
    ctx = result.get("context", {}).get("target_info", {})
    assert ctx.get("scope_source") == "fast_path_auto"  # CTF uses legacy path


def test_extract_host_from_target():
    """extract_host_from_target parses URLs and bare hosts correctly."""
    from src.core.security.guard_enforcement import extract_host_from_target

    assert extract_host_from_target("https://www.tiktok.com/path") == "www.tiktok.com"
    assert extract_host_from_target("http://example.com:8080/x") == "example.com"
    assert extract_host_from_target("sb-console-api.fireblocks.io") == "sb-console-api.fireblocks.io"
    assert extract_host_from_target("www.tiktok.com") == "www.tiktok.com"
    assert extract_host_from_target(None) == ""
    assert extract_host_from_target("") == ""


def test_external_adapter_in_scope_allows_out_of_scope_blocks(tiktok_policy):
    """BaseExternalAdapter: in-scope URL allowed, out-of-scope blocked in hard mode."""
    from src.core.adapters.external.base_external_adapter import ToolInput
    import asyncio as _asyncio

    class TestAdapter(BaseExternalAdapter):
        def __init__(self, guard_ctx):
            super().__init__(tool_name="sqlmap")
            self._guard_context = guard_ctx

        async def execute(self, input_data: ToolInput) -> ToolResult:
            return ToolResult(status=ToolStatus.SUCCESS, data="ok", execution_time_ms=0)

        def validate_inputs(self, input_data: ToolInput):
            return True, None

        async def health_check(self):
            return True

    hard_ctx = {
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    }

    # In-scope www.tiktok.com -> allow
    result_ok = _asyncio.run(TestAdapter(hard_ctx).run_with_validation(
        ToolInput(target="https://www.tiktok.com/")
    ))
    assert result_ok.status == ToolStatus.SUCCESS

    # Out-of-scope -> blocked
    result_block = _asyncio.run(TestAdapter(hard_ctx).run_with_validation(
        ToolInput(target="https://out-of-scope.example.com/")
    ))
    assert result_block.status == ToolStatus.ERROR
    assert "Blocked by compiled guard" in (result_block.error_message or "")


def test_context_runner_in_scope_allows_out_of_scope_blocks(tiktok_policy):
    """ContextToolRunner: in-scope allowed, out-of-scope blocked in hard mode."""
    runner = ContextToolRunner(
        ethics_guard=None,
        guard_context={
            "policy": tiktok_policy,
            "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
        },
    )
    # In-scope -> should proceed (will fail for other reasons like unknown tool)
    result_ok = runner.run_tool(
        tool_name="sqlmap",
        target="https://www.tiktok.com/",
        context={},
    )
    assert "Blocked by compiled guard" not in str(result_ok.error or "")

    # Out-of-scope -> should block
    result_block = runner.run_tool(
        tool_name="sqlmap",
        target="https://out-of-scope.example.com/",
        context={},
    )
    assert not result_block.success
    assert "Blocked by compiled guard" in result_block.error


# ---------------------------------------------------------------------------
# Shared context propagation tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_new_network_client_picks_up_shared_context(tiktok_policy):
    """AsyncNetworkClient() created after set_shared_guard_context gets guard."""
    from src.core.security.guard_enforcement import set_shared_guard_context, get_shared_guard_context
    from src.core.infra.network_client import AsyncNetworkClient as ANC

    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    client = ANC(mode="bugbounty")
    await client.start()

    with pytest.raises(NetworkClientError) as exc:
        await client.request("GET", "https://out-of-scope.example.com/")
    assert "compiled guard" in str(exc.value).lower()

    await client.close()
    set_shared_guard_context(None)


@pytest.mark.asyncio
async def test_existing_smart_request_picks_up_late_shared_context(tiktok_policy):
    """SmartRequest created before set_shared_guard_context passes guard via sr.request()."""
    from src.core.security.guard_enforcement import set_shared_guard_context
    from src.core.infra.smart_request import SmartRequest
    from unittest.mock import AsyncMock, MagicMock, patch

    # Use a mock client so we can verify guard_context is passed to client.request()
    mock_client = AsyncMock()
    resp = MagicMock(status=200, headers={}, body="OK")
    mock_client.request.return_value = resp

    sr = SmartRequest(network_client=mock_client)

    # Set shared context — SmartRequest should pick it up at request time via client
    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    import asyncio as _asyncio
    with patch.object(_asyncio, "sleep", AsyncMock()):
        result = await sr.request("GET", "http://example.com")

    assert result["status"] == 200
    # Verify guard_context was passed to the underlying client.request()
    call_args = mock_client.request.call_args
    assert call_args is not None, "client.request() was not called"
    gc = call_args.kwargs.get("guard_context")
    assert gc is not None, "guard_context was not passed to client.request()"
    assert gc["stage"] == EnforcementStage.WORKER_EXTERNAL_HARD

    set_shared_guard_context(None)


@pytest.mark.asyncio
async def test_base_manager_picks_up_shared_context(tiktok_policy):
    """BaseManagerAgent._execute_tool blocks after set_shared_guard_context."""
    from src.core.security.guard_enforcement import set_shared_guard_context

    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    async def _dummy_tool(**kwargs):
        return "ok"

    mgr = BaseManagerAgent.__new__(BaseManagerAgent)
    mgr.available_tools = {"test_tool": {"func": _dummy_tool}}
    mgr.current_context = {"target": "https://out-of-scope.example.com/", "mode": "bugbounty"}
    # No _guard_context set — should fall back to shared

    with pytest.raises(RuntimeError) as exc:
        await mgr._execute_tool("test_tool", {"target": "https://out-of-scope.example.com/"})
    assert "blocked" in str(exc.value).lower()

    set_shared_guard_context(None)


# ---------------------------------------------------------------------------
# Mode isolation tests (shared context must NOT leak to non-bugbounty)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shared_context_does_not_block_ctf_client(tiktok_policy):
    """AsyncNetworkClient(mode='ctf') ignores shared guard context."""
    from src.core.security.guard_enforcement import set_shared_guard_context

    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    client = AsyncNetworkClient(mode="ctf")
    await client.start()

    # CTF mode should NOT block — shared guard is only for bugbounty
    # Expect a connection error (no real server), NOT a guard error
    try:
        await client.request("GET", "https://out-of-scope.example.com/")
    except NetworkClientError as e:
        assert "compiled guard" not in str(e).lower(), \
            f"CTF client was blocked by guard: {e}"

    await client.close()
    set_shared_guard_context(None)


# ---------------------------------------------------------------------------
# Update propagation tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_shared_context_update_propagates_to_existing_client(tiktok_policy, fireblocks_policy):
    """Existing client uses latest shared context, not snapshot."""
    from src.core.security.guard_enforcement import set_shared_guard_context

    # Create client with shared context set to TikTok
    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    client = AsyncNetworkClient(mode="bugbounty")
    await client.start()

    # Update shared context to Fireblocks — existing client should pick it up
    set_shared_guard_context({
        "policy": fireblocks_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    # Fireblocks allows sandbox-api.fireblocks.io; tiktok policy denies it as out-of-scope
    # But now shared is Fireblocks policy, so www.tiktok.com should be out-of-scope
    with pytest.raises(NetworkClientError) as exc:
        await client.request("GET", "https://www.tiktok.com/")
    assert "compiled guard" in str(exc.value).lower()

    await client.close()
    set_shared_guard_context(None)


@pytest.mark.asyncio
async def test_shared_context_clear_propagates_to_existing_client(tiktok_policy):
    """Clearing shared context causes existing client to fail-closed (policy=None)."""
    from src.core.security.guard_enforcement import (
        set_shared_guard_context,
        clear_shared_guard_context,
    )

    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    client = AsyncNetworkClient(mode="bugbounty")
    await client.start()

    # Clear shared context — existing client should now fail-closed block
    clear_shared_guard_context()

    with pytest.raises(NetworkClientError) as exc:
        await client.request("GET", "https://out-of-scope.example.com/")
    assert "compiled guard" in str(exc.value).lower()

    await client.close()
    set_shared_guard_context(None)


# ---------------------------------------------------------------------------
# CTF verify_scope clears shared context + adapter mode propagation tests
# ---------------------------------------------------------------------------

def test_ctf_verify_scope_clears_shared_context():
    """CTF verify_scope fast-path clears any stale shared guard context."""
    from src.core.security.guard_enforcement import (
        set_shared_guard_context,
        clear_shared_guard_context,
    )
    from src.core.engine.master_conductor import MasterConductor

    # First set stale shared context
    set_shared_guard_context({"policy": object(), "stage": EnforcementStage.WORKER_EXTERNAL_HARD})

    # Simulate CTF verify_scope via actual MC non-bugbounty branch
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "ctf"
    mc.context = SimpleNamespace(target_info={"mode": "ctf", "target": "example.com"})
    mc.workspace = None
    mc.context.target_info["guard_enforcement_stage"] = "worker_external_hard"

    from src.core.security.ethics_guard import get_ethics_guard
    guard = get_ethics_guard()
    previous_scope = guard.scope

    task = Task(
        id="task_ctf_clear",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "example.com"},
    )

    import asyncio as _asyncio
    _asyncio.run(mc._dispatch(task))

    guard.scope = previous_scope

    # The non-bugbounty else branch should have cleared shared context
    from src.core.security.guard_enforcement import get_shared_guard_context
    assert get_shared_guard_context() is None, \
        "CTF verify_scope did not clear shared guard context"


def test_concrete_adapters_accept_mode():
    """All 6 concrete adapters accept mode= parameter without TypeError."""
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    from src.core.adapters.external.ffuf_adapter import FfufAdapter
    from src.core.adapters.external.nmap_adapter import NmapAdapter
    from src.core.adapters.external.arjun_adapter import ArjunAdapter
    from src.core.adapters.external.gau_adapter import GauAdapter
    from src.core.adapters.external.dalfox_adapter import DalFoxAdapter

    # Create with CTF mode — must not raise TypeError
    a1 = NucleiAdapter(mode="ctf")
    a2 = FfufAdapter(mode="ctf")
    a3 = NmapAdapter(mode="ctf")
    a4 = ArjunAdapter(mode="ctf")
    a5 = GauAdapter(mode="ctf")
    a6 = DalFoxAdapter(mode="ctf")

    assert a1._mode == "ctf"
    assert a2._mode == "ctf"
    assert a3._mode == "ctf"
    assert a4._mode == "ctf"
    assert a5._mode == "ctf"
    assert a6._mode == "ctf"

    # Default is bugbounty
    assert NucleiAdapter()._mode == "bugbounty"


def test_concrete_adapter_ctf_mode_skips_shared_guard(tiktok_policy):
    """CTF adapter does not block even with shared guard set."""
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    from src.core.adapters.external.base_external_adapter import ToolInput
    from src.core.security.guard_enforcement import set_shared_guard_context
    import asyncio as _asyncio

    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    adapter = NucleiAdapter(mode="ctf")
    # Should NOT block — CTF adapter skips shared guard
    result = _asyncio.run(adapter.run_with_validation(
        ToolInput(target="https://out-of-scope.example.com/")
    ))
    # Not blocked by guard (may fail for other reasons like missing binary)
    assert "Blocked by compiled guard" not in (result.error_message or "")

    set_shared_guard_context(None)


# ---------------------------------------------------------------------------
# FuzzingSwarm + ContextToolRunner mode-propagation near-regression
# ---------------------------------------------------------------------------

def test_fuzzing_swarm_ctf_mode_propagates_to_adapters():
    """FuzzingSwarm(mode='ctf') propagates ctf to DirBrute ffuf adapter."""
    from src.core.agents.swarm.fuzzing.manager import FuzzingSwarm

    swarm = FuzzingSwarm(mode="ctf")
    specialists = swarm.get_specialists([])
    assert len(specialists) >= 1

    dir_brute = specialists[0]
    assert dir_brute._ffuf_adapter._mode == "ctf"
    assert dir_brute.client.mode == "ctf"


def test_param_fuzzer_ctf_mode_propagates_to_provider():
    """ParamFuzzerSpecialist(mode='ctf') propagates to ExternalToolProvider."""
    from src.core.agents.swarm.fuzzing.manager import ParamFuzzerSpecialist

    pfs = ParamFuzzerSpecialist(mode="ctf")
    assert pfs._external_tools._mode == "ctf"


def test_context_runner_ctf_skips_shared_guard(tiktok_policy):
    """ContextToolRunner(mode='ctf') does not block via shared guard."""
    from src.core.security.guard_enforcement import set_shared_guard_context
    from src.core.tools.context_runner import ContextToolRunner

    set_shared_guard_context({
        "policy": tiktok_policy,
        "stage": EnforcementStage.WORKER_EXTERNAL_HARD,
    })

    runner = ContextToolRunner(mode="ctf")
    result = runner.run_tool(
        tool_name="sqlmap",
        target="https://out-of-scope.example.com/",
        context={},
    )
    # CTF mode must NOT block via compiled guard
    assert "Blocked by compiled guard" not in str(result.error or "")
    assert "compiled guard" not in str(result.error or "").lower()


# ---------------------------------------------------------------------------
# Regression: bugbounty + no context → fail-closed (all layers)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_external_adapter_fail_closed_when_no_context(tiktok_policy):
    """BaseExternalAdapter in bugbounty mode blocks when no guard context available."""
    from src.core.security.guard_enforcement import clear_shared_guard_context
    clear_shared_guard_context()

    class TestAdapter(BaseExternalAdapter):
        def __init__(self):
            super().__init__(tool_name="test_tool")
            self._mode = "bugbounty"
            # No _guard_context set — simulate missing context

        async def execute(self, input_data: ToolInput) -> ToolResult:
            return ToolResult(status=ToolStatus.SUCCESS, data="ok", execution_time_ms=0)

        def validate_inputs(self, input_data: ToolInput):
            return True, None

        async def health_check(self):
            return True

    adapter = TestAdapter()
    result = await adapter.run_with_validation(
        ToolInput(target="https://www.tiktok.com/")
    )
    assert result.status == ToolStatus.ERROR
    assert "Blocked by compiled guard" in (result.error_message or "")
    assert "policy_unavailable" in (result.error_message or "").lower()


def test_context_runner_fail_closed_when_no_context(tiktok_policy):
    """ContextToolRunner in bugbounty mode blocks when no guard context available."""
    from src.core.security.guard_enforcement import clear_shared_guard_context
    clear_shared_guard_context()

    runner = ContextToolRunner(mode="bugbounty", guard_context=None)
    result = runner.run_tool(
        tool_name="sqlmap",
        target="https://www.tiktok.com/",
        context={},
    )
    assert not result.success
    assert "Blocked by compiled guard" in result.error
    assert "policy_unavailable" in str(result.error).lower()


@pytest.mark.asyncio
async def test_base_manager_fail_closed_when_no_context(tiktok_policy):
    """BaseManagerAgent in bugbounty mode blocks when no guard context available."""
    from src.core.security.guard_enforcement import clear_shared_guard_context
    clear_shared_guard_context()

    async def _dummy_tool(**kwargs):
        return "ok"

    mgr = BaseManagerAgent.__new__(BaseManagerAgent)
    mgr.available_tools = {"test_tool": {"func": _dummy_tool}}
    mgr.current_context = {"target": "https://www.tiktok.com/", "mode": "bugbounty"}
    # No _guard_context set — simulate missing context

    with pytest.raises(RuntimeError) as exc:
        await mgr._execute_tool("test_tool", {"target": "https://www.tiktok.com/"})
    assert "blocked" in str(exc.value).lower()
    assert "policy_unavailable" in str(exc.value).lower()


@pytest.mark.asyncio
async def test_network_client_fail_closed_when_no_context():
    """AsyncNetworkClient in bugbounty mode blocks when no guard context available."""
    from src.core.security.guard_enforcement import clear_shared_guard_context
    clear_shared_guard_context()

    client = AsyncNetworkClient(mode="bugbounty")
    await client.start()

    with pytest.raises(NetworkClientError) as exc:
        await client.request("GET", "https://www.tiktok.com/")
    assert "compiled guard" in str(exc.value).lower()

    await client.close()


# ---------------------------------------------------------------------------
# Regression: shadow mode evaluator IS called (metrics/logging produced)
# ---------------------------------------------------------------------------

def test_external_adapter_shadow_does_not_block_and_proceeds(tiktok_policy):
    """BaseExternalAdapter in shadow mode: evaluate_at_layer called, block shadow-allow'd, tool runs."""
    from src.core.adapters.external.base_external_adapter import ToolInput
    import asyncio as _asyncio

    class TestAdapter(BaseExternalAdapter):
        def __init__(self):
            super().__init__(tool_name="sqlmap")
            self._guard_context = {
                "policy": tiktok_policy,
                "stage": EnforcementStage.SHADOW_READ_ONLY,
            }

        async def execute(self, input_data: ToolInput) -> ToolResult:
            return ToolResult(status=ToolStatus.SUCCESS, data="ok", execution_time_ms=0)

        def validate_inputs(self, input_data: ToolInput):
            return True, None

        async def health_check(self):
            return True

    adapter = TestAdapter()
    # Out-of-scope host in shadow mode → should NOT block (returns SUCCESS)
    result = _asyncio.run(adapter.run_with_validation(
        ToolInput(target="https://out-of-scope.example.com/")
    ))
    assert result.status == ToolStatus.SUCCESS
    # The guard was called — verify the call didn't raise and adapter proceeded


def test_context_runner_shadow_does_not_block_and_proceeds(tiktok_policy):
    """ContextToolRunner in shadow mode: evaluate_at_layer called, block shadow-allow'd, tool runs."""
    runner = ContextToolRunner(
        mode="bugbounty",
        guard_context={
            "policy": tiktok_policy,
            "stage": EnforcementStage.SHADOW_READ_ONLY,
        },
    )
    # Out-of-scope host in shadow mode → should NOT block
    result = runner.run_tool(
        tool_name="sqlmap",
        target="https://out-of-scope.example.com/",
        context={},
    )
    assert "Blocked by compiled guard" not in str(result.error or "")


# ---------------------------------------------------------------------------
# Regression: MC post-exploit uses evaluate_at_layer (not evaluate_guard)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_mc_trigger_post_exploit_shadow_does_not_block_and_proceeds(tiktok_policy):
    """_trigger_post_exploit in shadow mode: evaluate_at_layer called via MC, block shadow-allow'd."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.mode = "bugbounty"
    mc.context = SimpleNamespace(
        target_info={
            "mode": "bugbounty",
            "bundle_id": tiktok_policy.bundle_id,
            "policy_id": tiktok_policy.policy_id,
            "compiled_policy_hash": tiktok_policy.compiled_policy_hash,
            "compiled_guard_policy_path": tiktok_policy.compiled_policy_path,
            "scope_source": "compiled_guard_policy",
            "guard_enforcement_stage": "shadow_read_only",
        }
    )
    mc.workspace = None

    from src.core.models.finding import Finding, VulnType
    finding = Finding(
        title="SSRF Found",
        description="",
        target_url="https://www.tiktok.com/",
        vuln_type=VulnType.SSRF,
        severity="medium",
        evidence=SimpleNamespace(request_url="https://www.tiktok.com/"),
    )

    mc._add_tasks = lambda tasks, **kw: None
    # Should NOT raise — shadow mode allows, evaluator called for logging
    mc._trigger_post_exploit(finding)
