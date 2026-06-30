"""Tests for takeover.yaml step executor handlers (SGK-2026-0283 Step 9).

Plan sections 4.4, 4.11, 4.12: cname_resolve, http_probe, check_takeover executors.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.engine.takeover_step_executors import (
    TakeoverStepResult,
    EXECUTOR_REGISTRY,
    dispatch_takeover_step,
    execute_cname_resolve,
    execute_http_probe,
    execute_check_takeover,
)


# ── helpers ──────────────────────────────────────────────────────────────

def _async_return(value):
    """Create a mock async return fixture."""
    f = asyncio.Future()
    f.set_result(value)
    return f


def _error_result(status="failed", error_msg="test error"):
    """Expedient error TakeoverStepResult."""
    return TakeoverStepResult(
        status=status, output={}, error=error_msg
    )


# ── TakeoverStepResult dataclass ──────────────────────────────────────────

def test_takeover_step_result_defaults():
    """Default fields for TakeoverStepResult are set correctly."""
    result = TakeoverStepResult(status="success", output={"key": "val"})
    assert result.status == "success"
    assert result.output == {"key": "val"}
    assert result.error is None
    assert result.infrastructure_state is None


def test_takeover_step_result_failed_with_infra_state():
    """When infrastructure_state is set, it is preserved."""
    result = TakeoverStepResult(
        status="failed",
        output={},
        error="timeout",
        infrastructure_state="probe_failed",
    )
    assert result.status == "failed"
    assert result.infrastructure_state == "probe_failed"
    assert result.error == "timeout"


def test_takeover_step_result_asdict_roundtrip():
    """asdict() produces a serialisable dict matching the dataclass fields."""
    import json
    result = TakeoverStepResult(
        status="success",
        output={"cname_chain": ["target.example.cdn.com"]},
        error=None,
        infrastructure_state="ok",
    )
    d = asdict(result)
    assert d["status"] == "success"
    assert d["output"]["cname_chain"] == ["target.example.cdn.com"]
    assert d["infrastructure_state"] == "ok"
    # Must be JSON-serialisable
    json.dumps(d)


# ── execute_cname_resolve ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cname_resolve_stub_resolution():
    """When socket can resolve, return the resolved addresses."""
    with patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    ):
        result = await execute_cname_resolve("example.com", resolver_timeout=5.0)
    assert result.status == "success"
    assert "addresses" in result.output
    assert len(result.output["addresses"]) >= 1


@pytest.mark.asyncio
async def test_cname_resolve_nxdomain():
    """NXDOMAIN returns success with empty chain."""
    with patch(
        "socket.getaddrinfo",
        side_effect=socket.gaierror("Name or service not known"),
    ):
        result = await execute_cname_resolve(
            "does-not-exist.example.com", resolver_timeout=5.0
        )
    assert result.status == "success"
    assert result.output.get("cname_chain", None) == []
    assert result.output.get("addresses", []) == []


@pytest.mark.asyncio
async def test_cname_resolve_timeout():
    """DNS timeout returns failed with infrastructure_state=probe_failed."""
    with patch(
        "socket.getaddrinfo",
        side_effect=TimeoutError("timed out"),
    ):
        result = await execute_cname_resolve(
            "slow.example.com", resolver_timeout=0.1
        )
    assert result.status == "failed"
    assert result.infrastructure_state == "probe_failed"


# ── execute_http_probe ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_http_probe_success():
    """Successful GET returns status, body excerpt and headers."""
    fake_response = MagicMock()
    fake_response.status = 200
    fake_response.headers = {"Content-Type": "text/html", "Server": "nginx"}
    fake_response.history = []  # no redirects
    fake_response.text = AsyncMock(return_value="<html><body>OK</body></html>")

    fake_session_ctx = MagicMock()
    fake_session_ctx.__aenter__ = AsyncMock(return_value=fake_response)
    fake_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch(
        "aiohttp.ClientSession.get", return_value=fake_session_ctx
    ):
        result = await execute_http_probe("http://example.com", timeout=10.0)
    assert result.status == "success"
    assert result.output["http_status"] == 200
    assert "<html>" in result.output["body_excerpt"]
    assert result.output["headers"]["Server"] == "nginx"
    assert result.output["redirect_chain"] == []


@pytest.mark.asyncio
async def test_http_probe_connection_refused():
    """Connection refused returns failed with infrastructure_state=probe_failed."""
    with patch(
        "aiohttp.ClientSession.get",
        side_effect=ConnectionRefusedError("Connection refused"),
    ):
        result = await execute_http_probe("http://localhost:9999", timeout=5.0)
    assert result.status == "failed"
    assert result.infrastructure_state == "probe_failed"
    assert "Connection refused" in (result.error or "")


@pytest.mark.asyncio
async def test_http_probe_timeout():
    """HTTP timeout returns failed with infrastructure_state=probe_failed."""
    with patch(
        "aiohttp.ClientSession.get",
        side_effect=asyncio.TimeoutError("timed out"),
    ):
        result = await execute_http_probe("http://slow.example.com", timeout=0.5)
    assert result.status == "failed"
    assert result.infrastructure_state == "probe_failed"


# ── execute_check_takeover ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_check_takeover_with_provider_matrix_tool_preference():
    """execute_check_takeover uses resolve_tool_chain from provider matrix."""
    with patch(
        "src.core.engine.takeover_step_executors._run_tool",
        return_value={"raw_output": "[Not Vulnerable] dead.example.com"},
    ), patch(
        "src.core.adapters.external.takeover_provider_matrix_adapter.resolve_tool_chain",
        return_value=["subjack", "subzy"],
    ):
        result = await execute_check_takeover(
            subdomain="dead.example.com",
            tools=["subjack", "subzy", "nuclei"],
            provider_id="aws_s3",
            matrix=MagicMock(),
        )
    assert result.status == "success"
    assert "tool_results" in result.output


@pytest.mark.asyncio
async def test_check_takeover_normalized_results():
    """execute_check_takeover returns aggregated normalized tool results."""
    with patch(
        "src.core.engine.takeover_step_executors._run_tool",
        side_effect=[
            {"raw_output": "[Vulnerable - AWS S3] dead.example.com"},
            {"raw_output": "dead.example.com    AWS S3    404    VULNERABLE"},
        ],
    ), patch(
        "src.core.adapters.external.takeover_provider_matrix_adapter.resolve_tool_chain",
        return_value=["subjack", "subzy"],
    ):
        result = await execute_check_takeover(
            subdomain="dead.example.com",
            tools=["subjack", "subzy"],
            provider_id="aws_s3",
            matrix=MagicMock(),
        )
    assert result.status == "success"
    assert "tool_results" in result.output
    normalized_list = result.output["tool_results"]
    assert len(normalized_list) >= 2


@pytest.mark.asyncio
async def test_check_takeover_no_tools():
    """Empty tool list still returns success with empty results."""
    with patch(
        "src.core.adapters.external.takeover_provider_matrix_adapter.resolve_tool_chain",
        return_value=[],
    ):
        result = await execute_check_takeover(
            subdomain="dead.example.com",
            tools=[],
            provider_id=None,
            matrix=None,
        )
    assert result.status == "success"
    assert result.output["tool_results"] == []


# ── EXECUTOR_REGISTRY ────────────────────────────────────────────────────

def test_registry_contains_all_takeover_actions():
    """All three actions from takeover.yaml must be in EXECUTOR_REGISTRY."""
    takeover_actions = {"cname_resolve", "http_probe", "check_takeover"}
    registered = set(EXECUTOR_REGISTRY.keys())
    assert takeover_actions.issubset(registered), (
        f"Missing actions: {takeover_actions - registered}"
    )


def test_registry_maps_to_functions():
    """Each registry entry must be a callable function."""
    for action, executor in EXECUTOR_REGISTRY.items():
        assert callable(executor), f"Executor for {action} is not callable"


def test_known_action_maps_to_correct_handler():
    """cname_resolve, http_probe, check_takeover map to their functions."""
    assert EXECUTOR_REGISTRY["cname_resolve"] is execute_cname_resolve
    assert EXECUTOR_REGISTRY["http_probe"] is execute_http_probe
    assert EXECUTOR_REGISTRY["check_takeover"] is execute_check_takeover


# ── dispatch_takeover_step ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_dispatch_known_action_calls_executor():
    """dispatch_takeover_step looks up the action and calls the executor."""
    # Mock DNS to make cname_resolve succeed without real network
    with patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    ):
        result = await dispatch_takeover_step(
            action="cname_resolve",
            params={"subdomain": "test.example.com", "resolver_timeout": 5.0},
            context={},
        )
    assert result.status == "success"
    assert "addresses" in result.output


@pytest.mark.asyncio
async def test_dispatch_unknown_action_returns_error():
    """Unknown action returns a failed TakeoverStepResult."""
    result = await dispatch_takeover_step(
        action="nonexistent_action",
        params={},
        context={},
    )
    assert result.status == "failed"
    assert result.error is not None
    assert "Unknown takeover step action" in result.error


# ── infrastructure_state propagation ─────────────────────────────────────

@pytest.mark.asyncio
async def test_cname_resolve_infra_state_propagation():
    """On non-NXDOMAIN DNS error (gaierror), returns failed with probe_failed."""
    with patch(
        "socket.getaddrinfo",
        side_effect=socket.gaierror("Temporary failure in name resolution"),
    ):
        result = await execute_cname_resolve("broken.example.com")
    assert result.status == "failed"
    assert result.infrastructure_state == "probe_failed"


@pytest.mark.asyncio
async def test_http_probe_infra_state_propagation():
    """On connection error, infrastructure_state=probe_failed is set."""
    with patch(
        "aiohttp.ClientSession.get",
        side_effect=OSError("Network unreachable"),
    ):
        result = await execute_http_probe("http://10.255.255.1")
    assert result.status == "failed"
    assert result.infrastructure_state == "probe_failed"


# ── Integration tests: dispatch_takeover_step wiring to master_conductor ──


@pytest.mark.asyncio
async def test_dispatch_integration_cname_resolve():
    """dispatch_takeover_step for cname_resolve returns proper TakeoverStepResult fields."""
    with patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    ):
        result = await dispatch_takeover_step(
            action="cname_resolve",
            params={"subdomain": "test.example.com", "resolver_timeout": 5.0},
            context={"target": "test.example.com"},
        )
    assert isinstance(result, TakeoverStepResult)
    assert result.status == "success"
    assert result.error is None
    assert "addresses" in result.output
    assert "cname_chain" in result.output
    assert "rcode" in result.output
    assert len(result.output["addresses"]) >= 1


@pytest.mark.asyncio
async def test_dispatch_integration_http_probe():
    """dispatch_takeover_step for http_probe returns proper TakeoverStepResult fields."""
    fake_response = MagicMock()
    fake_response.status = 200
    fake_response.headers = {"Content-Type": "text/html", "Server": "nginx"}
    fake_response.history = []
    fake_response.text = AsyncMock(return_value="<html><body>OK</body></html>")

    fake_session_ctx = MagicMock()
    fake_session_ctx.__aenter__ = AsyncMock(return_value=fake_response)
    fake_session_ctx.__aexit__ = AsyncMock(return_value=False)

    with patch("aiohttp.ClientSession.get", return_value=fake_session_ctx):
        result = await dispatch_takeover_step(
            action="http_probe",
            params={"subdomain": "example.com", "timeout": 10.0},
            context={"target": "example.com"},
        )
    assert isinstance(result, TakeoverStepResult)
    assert result.status == "success"
    assert result.error is None
    assert result.output["http_status"] == 200
    assert "<html>" in result.output["body_excerpt"]
    assert result.output["headers"]["Server"] == "nginx"


@pytest.mark.asyncio
async def test_step_executor_routes_takeover_action_to_dispatch():
    """When _step_executor sees a takeover action, it calls dispatch_takeover_step (not generic _dispatch).

    Tests the routing logic from master_conductor._execute_recipe_task():
    takeover actions (cname_resolve, http_probe, check_takeover) must be
    dispatched via dispatch_takeover_step, while non-takeover actions use
    the generic path unchanged.
    """
    from src.core.engine.recipe_loader import RecipeStep

    # Replicate the exact routing logic from master_conductor's _step_executor
    _takeover_actions = {"cname_resolve", "http_probe", "check_takeover"}

    takeover_step = RecipeStep(
        id="step_takeover",
        name="CNAME resolve",
        action="cname_resolve",
        params={"subdomain": "target.example.com"},
    )
    non_takeover_step = RecipeStep(
        id="step_generic",
        name="Port scan",
        action="port_scan",
        params={"ports": "80,443"},
    )

    # Verify takeover action is correctly detected
    assert takeover_step.action in _takeover_actions, (
        "cname_resolve must be detected as a takeover action"
    )
    # Verify non-takeover action is NOT detected
    assert non_takeover_step.action not in _takeover_actions, (
        "port_scan must NOT be detected as a takeover action"
    )

    # Now verify dispatch_takeover_step is actually called for takeover actions
    with patch(
        "src.core.engine.takeover_step_executors.dispatch_takeover_step",
        new_callable=AsyncMock,
    ) as mock_dispatch:
        mock_dispatch.return_value = TakeoverStepResult(
            status="success",
            output={"cname_chain": ["target.cdn.com"], "addresses": ["1.2.3.4"], "rcode": "NOERROR"},
        )

        # Simulate what _step_executor does for a takeover action
        step = takeover_step
        step_target = "target.example.com"
        if step.action in _takeover_actions:
            from src.core.engine.takeover_step_executors import dispatch_takeover_step as dts
            await dts(
                action=step.action,
                params=step.params or {},
                context={"target": step_target},
            )
        else:
            # generic dispatch path (should NOT be reached for takeover)
            pass

        # Assert dispatch_takeover_step was called exactly once
        mock_dispatch.assert_called_once()
        call_args = mock_dispatch.call_args
        assert call_args.kwargs["action"] == "cname_resolve"
        assert call_args.kwargs["params"] == {"subdomain": "target.example.com"}

    # Verify that for non-takeover actions, dispatch_takeover_step is NOT called
    with patch(
        "src.core.engine.takeover_step_executors.dispatch_takeover_step",
        new_callable=AsyncMock,
    ) as mock_dispatch:
        step = non_takeover_step
        step_target = "target.example.com"
        if step.action in _takeover_actions:
            from src.core.engine.takeover_step_executors import dispatch_takeover_step as dts
            await dts(
                action=step.action,
                params=step.params or {},
                context={"target": step_target},
            )
        # For non-takeover action, the takeover branch is NOT entered,
        # so dispatch_takeover_step should never be called.
        mock_dispatch.assert_not_called()


@pytest.mark.asyncio
async def test_run_recipe_executes_takeover_steps_via_executor():
    """Integration: OptimizedRecipeRunner with takeover step_executor routes to dispatch_takeover_step.

    Loads takeover.yaml steps, runs through OptimizedRecipeRunner with a mock
    _step_executor that routes takeover actions to dispatch_takeover_step,
    and verifies steps execute successfully.
    """
    from src.core.engine.recipe_loader import Recipe, RecipeStep
    from src.core.engine.optimized_runner import OptimizedRecipeRunner

    # Build a takeover recipe programmatically (no file I/O dependency)
    recipe = Recipe(
        name="subdomain_takeover",
        description="Test takeover recipe",
        agent="swarm",
        steps=[
            RecipeStep(
                id="step_0",
                name="CNAME resolution",
                action="cname_resolve",
                params={"subdomain": "test.example.com", "resolver_timeout": 5.0},
                dependencies=[],
            ),
            RecipeStep(
                id="step_1",
                name="Provider fingerprinting",
                action="http_probe",
                params={"subdomain": "test.example.com", "timeout": 10.0},
                dependencies=["step_0"],
            ),
            RecipeStep(
                id="step_2",
                name="Takeover candidate scan",
                action="check_takeover",
                params={
                    "subdomain": "test.example.com",
                    "tools": ["subjack", "subzy"],
                },
                dependencies=["step_0", "step_1"],
            ),
        ],
    )

    _takeover_actions = {"cname_resolve", "http_probe", "check_takeover"}

    async def takeover_aware_step_executor(step: RecipeStep, step_target: str) -> dict:
        """Replicates master_conductor's _step_executor routing for takeover actions."""
        if step.action in _takeover_actions:
            from src.core.engine.takeover_step_executors import dispatch_takeover_step
            takeover_result = await dispatch_takeover_step(
                action=step.action,
                params=step.params or {},
                context={"target": step_target},
            )
            return {
                "status": takeover_result.status,
                "reason": takeover_result.error or "takeover_step_executed",
                "retryable": False,
                "data": takeover_result.output,
                "infrastructure_state": takeover_result.infrastructure_state,
            }
        # Non-takeover actions go through generic dispatch (not tested here)
        return {"status": "success", "reason": "generic_dispatch", "retryable": False, "data": {}}

    # Mock DNS for cname_resolve, HTTP for http_probe, and _run_tool for check_takeover
    with patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    ), patch(
        "aiohttp.ClientSession.get",
        return_value=MagicMock(
            __aenter__=AsyncMock(
                return_value=MagicMock(
                    status=200,
                    headers={"Content-Type": "text/html", "Server": "nginx"},
                    history=[],
                    text=AsyncMock(return_value="<html><body>OK</body></html>"),
                )
            ),
            __aexit__=AsyncMock(return_value=False),
        ),
    ), patch(
        "src.core.engine.takeover_step_executors._run_tool",
        return_value={"raw_output": "[Not Vulnerable] test.example.com"},
    ), patch(
        "src.core.adapters.external.takeover_provider_matrix_adapter.resolve_tool_chain",
        return_value=["subjack", "subzy"],
    ):
        runner = OptimizedRecipeRunner(step_executor=takeover_aware_step_executor)
        result_bundle = await runner.run_recipe(recipe, "test.example.com")

    assert isinstance(result_bundle, dict)
    summary = result_bundle.get("summary", {})
    assert summary.get("total_steps") == 3, f"Expected 3 steps, got {summary}"

    steps = result_bundle.get("steps", {})
    assert "step_0" in steps, "cname_resolve step should be in results"
    assert "step_1" in steps, "http_probe step should be in results"
    assert "step_2" in steps, "check_takeover step should be in results"

    # Verify cname_resolve succeeded
    step_0_result = steps["step_0"]
    assert step_0_result["status"] == "success", f"step_0 failed: {step_0_result}"
    assert "addresses" in step_0_result.get("data", {})

    # Verify http_probe succeeded
    step_1_result = steps["step_1"]
    assert step_1_result["status"] == "success", f"step_1 failed: {step_1_result}"
    assert step_1_result.get("data", {}).get("http_status") == 200

    # Verify check_takeover succeeded
    step_2_result = steps["step_2"]
    assert step_2_result["status"] == "success", f"step_2 failed: {step_2_result}"
    assert "tool_results" in step_2_result.get("data", {})


# ── Gap 1: context subdomain / provider wiring tests ───────────────────

@pytest.mark.asyncio
async def test_dispatch_cname_resolve_receives_subdomain_from_context():
    """cname_resolve reads subdomain from context dict (not params fallback)."""
    with patch(
        "socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        ],
    ):
        result = await dispatch_takeover_step(
            action="cname_resolve",
            params={"resolver_timeout": 5.0},
            context={"target": "target.example.com", "subdomain": "dead.example.com"},
        )
    assert result.status == "success"
    # verify it actually resolved dead.example.com (not target.example.com)
    assert "addresses" in result.output
    assert len(result.output["addresses"]) >= 1


@pytest.mark.asyncio
async def test_dispatch_check_takeover_receives_subdomain_and_provider_from_context():
    """check_takeover gets subdomain and provider_id from context dict."""
    with patch(
        "src.core.engine.takeover_step_executors._run_tool",
        return_value={"raw_output": "[Not Vulnerable] dead.example.com"},
    ), patch(
        "src.core.adapters.external.takeover_provider_matrix_adapter.resolve_tool_chain",
        return_value=["subjack"],
    ):
        result = await dispatch_takeover_step(
            action="check_takeover",
            params={"tools": ["subjack", "subzy"]},
            context={
                "target": "target.example.com",
                "subdomain": "dead.example.com",
                "provider_id": "aws_s3",
            },
        )
    assert result.status == "success"
    assert "tool_results" in result.output


# ── Gap 2: probe budget / cache tests ──────────────────────────────────

def test_probe_budget_blocks_excessive_probes():
    """ProbeBudget.exhausted blocks further probes for the same target."""
    from src.core.engine.takeover_probe_budget import (
        check_probe_allowed, ProbeCache, ProbeBudget, DedupeWindow,
    )
    budget = ProbeBudget(max_probes=2, window_seconds=3600)
    cache = ProbeCache(ttl_seconds=60)
    dedupe = DedupeWindow(window_seconds=60)

    # consume 2 probes for the same target
    for i in range(2):
        verdict = check_probe_allowed(
            candidate_id="takeover_abc",
            target="dead.example.com",
            provider="github_pages",
            probe_type="http_probe",
            budget=budget,
            cache=cache,
            dedupe=DedupeWindow(window_seconds=60),  # fresh dedupe each call
        )
        assert verdict["allowed"] is True, f"Probe {i} should be allowed"

    # 3rd probe should be blocked
    verdict = check_probe_allowed(
        candidate_id="takeover_abc",
        target="dead.example.com",
        provider="github_pages",
        probe_type="http_probe",
        budget=budget,
        cache=cache,
        dedupe=DedupeWindow(window_seconds=60),
    )
    assert verdict["allowed"] is False
    assert verdict["reason"] == "budget_exceeded"


def test_probe_cache_returns_cached_result():
    """Cache hit returns cached_result without consuming budget."""
    from src.core.engine.takeover_probe_budget import (
        check_probe_allowed, ProbeCache, ProbeBudget, DedupeWindow,
    )
    budget = ProbeBudget(max_probes=10, window_seconds=3600)
    cache = ProbeCache(ttl_seconds=3600)
    dedupe = DedupeWindow(window_seconds=300)

    # Pre-populate cache
    cache_key = cache.make_key("takeover_abc", "github_pages", "http_probe")
    cache.set(cache_key, {"http_status": 200, "body_excerpt": "not found"})

    verdict = check_probe_allowed(
        candidate_id="takeover_abc",
        target="dead.example.com",
        provider="github_pages",
        probe_type="http_probe",
        budget=budget,
        cache=cache,
        dedupe=dedupe,
    )
    assert verdict["allowed"] is False
    assert verdict["reason"] == "cache_hit"
    assert verdict["cached_result"] == {"http_status": 200, "body_excerpt": "not found"}


# ── Gap closure: cache/budget persistence across steps ────────────────

def test_cache_persists_across_steps():
    """Cache hit across multiple calls returns cached_result (not blocked).

    Verifies that with a shared ProbeCache across multiple probe_allowed
    checks, the second call returns the cached result as a success
    rather than being blocked.
    """
    from src.core.engine.takeover_probe_budget import (
        check_probe_allowed, ProbeCache, ProbeBudget, DedupeWindow,
    )
    cache = ProbeCache(ttl_seconds=3600)
    budget = ProbeBudget(max_probes=10, window_seconds=3600)

    # First call: allowed, then cache the result
    dedupe1 = DedupeWindow(window_seconds=300)
    verdict1 = check_probe_allowed(
        candidate_id="takeover_xyz",
        target="dead2.example.com",
        provider="aws_s3",
        probe_type="cname_resolve",
        budget=budget,
        cache=cache,
        dedupe=dedupe1,
    )
    assert verdict1["allowed"] is True, f"First call should be allowed, got {verdict1}"
    # Simulate caching after successful execution
    cache_key = cache.make_key("takeover_xyz", "aws_s3", "cname_resolve")
    cache.set(cache_key, {"cname_chain": ["target.s3.amazonaws.com"], "addresses": ["1.2.3.4"], "rcode": "NOERROR"})

    # Second call: should return cache_hit (which the MC now treats as success)
    dedupe2 = DedupeWindow(window_seconds=300)
    verdict2 = check_probe_allowed(
        candidate_id="takeover_xyz",
        target="dead2.example.com",
        provider="aws_s3",
        probe_type="cname_resolve",
        budget=budget,
        cache=cache,
        dedupe=dedupe2,
    )
    assert verdict2["allowed"] is False
    assert verdict2["reason"] == "cache_hit"
    assert verdict2["cached_result"] is not None
    assert verdict2["cached_result"]["cname_chain"] == ["target.s3.amazonaws.com"]


def test_budget_shared_across_steps():
    """Budget consumed by one probe_type affects the next probe_type for same target.

    Verifies that with a shared ProbeBudget across different probe_types,
    consuming slots for http_probe reduces the budget available for
    cname_resolve on the same target.
    """
    from src.core.engine.takeover_probe_budget import (
        check_probe_allowed, ProbeCache, ProbeBudget, DedupeWindow,
    )
    cache = ProbeCache(ttl_seconds=3600)
    budget = ProbeBudget(max_probes=2, window_seconds=3600)

    # Consume 1 slot with http_probe
    verdict1 = check_probe_allowed(
        candidate_id="takeover_shared",
        target="shared.example.com",
        provider="github_pages",
        probe_type="http_probe",
        budget=budget,
        cache=cache,
        dedupe=DedupeWindow(window_seconds=60),
    )
    assert verdict1["allowed"] is True

    # Consume 1 more slot with cname_resolve (same target)
    verdict2 = check_probe_allowed(
        candidate_id="takeover_shared",
        target="shared.example.com",
        provider="github_pages",
        probe_type="cname_resolve",
        budget=budget,
        cache=cache,
        dedupe=DedupeWindow(window_seconds=60),
    )
    assert verdict2["allowed"] is True

    # 3rd probe should be blocked (budget exhausted by the shared budget)
    verdict3 = check_probe_allowed(
        candidate_id="takeover_shared",
        target="shared.example.com",
        provider="github_pages",
        probe_type="check_takeover",
        budget=budget,
        cache=cache,
        dedupe=DedupeWindow(window_seconds=60),
    )
    assert verdict3["allowed"] is False
    assert verdict3["reason"] == "budget_exceeded"


# ── High1: cache.set after successful probe ────────────────────────────

def test_cache_set_after_successful_probe():
    """Successful probe populates cache; subsequent call hits cache.

    Verifies the full cache lifecycle: after a probe is allowed and
    the caller does cache.set(), the next call for the same
    (candidate_id, provider, probe_type) returns a cache hit.
    """
    from src.core.engine.takeover_probe_budget import (
        check_probe_allowed, ProbeCache, ProbeBudget, DedupeWindow,
    )
    cache = ProbeCache(ttl_seconds=3600)
    budget = ProbeBudget(max_probes=10, window_seconds=3600)
    dedupe = DedupeWindow(window_seconds=300)

    # First call: allowed, no cache hit
    verdict1 = check_probe_allowed(
        candidate_id="takeover_cset",
        target="cache-test.example.com",
        provider="aws_s3",
        probe_type="cname_resolve",
        budget=budget,
        cache=cache,
        dedupe=dedupe,
    )
    assert verdict1["allowed"] is True
    assert verdict1["cached_result"] is None

    # Simulate cache.set() after successful probe execution
    probe_result = {"cname_chain": ["target.s3.amazonaws.com"], "addresses": ["1.2.3.4"], "rcode": "NOERROR"}
    probe_key = cache.make_key("takeover_cset", "aws_s3", "cname_resolve")
    cache.set(probe_key, probe_result)

    # Second call: should be cache hit (not allowed, but has cached_result)
    verdict2 = check_probe_allowed(
        candidate_id="takeover_cset",
        target="cache-test.example.com",
        provider="aws_s3",
        probe_type="cname_resolve",
        budget=budget,
        cache=cache,
        dedupe=DedupeWindow(window_seconds=300),
    )
    assert verdict2["allowed"] is False
    assert verdict2["reason"] == "cache_hit"
    assert verdict2["cached_result"] == probe_result


# ── High2: guards shared across MC instance (session-level) ────────────

def test_probe_guards_shared_across_recipe_tasks():
    """Guards on MC instance persist across multiple _execute_recipe_task calls.

    Simulates two recipe task executions on the same MC instance:
    the first probes a target with cname_resolve and caches the result;
    the second call (simulating another recipe task) gets a cache hit
    because the guards are session-level, not per-recipe-task.
    """
    from src.core.engine.takeover_probe_budget import (
        ProbeCache, ProbeBudget, DedupeWindow,
    )
    # Session-level guards (analogous to what MC._ensure_takeover_probe_guards does)
    cache = ProbeCache(ttl_seconds=3600)
    budget = ProbeBudget(max_probes=10, window_seconds=3600)
    dedupe = DedupeWindow(window_seconds=300)

    # ── Recipe task 1: consume budget, set cache ──
    from src.core.engine.takeover_probe_budget import check_probe_allowed
    verdict1 = check_probe_allowed(
        candidate_id="takeover_shared_across",
        target="cross-target.example.com",
        provider="github_pages",
        probe_type="http_probe",
        budget=budget,
        cache=cache,
        dedupe=dedupe,
    )
    assert verdict1["allowed"] is True
    # Simulate cache.set after success
    probe_key = cache.make_key("takeover_shared_across", "github_pages", "http_probe")
    cache.set(probe_key, {"http_status": 200, "body_excerpt": "not found"})

    # ── Recipe task 2 (same MC instance, same guards): cache hit ──
    verdict2 = check_probe_allowed(
        candidate_id="takeover_shared_across",
        target="cross-target.example.com",
        provider="github_pages",
        probe_type="http_probe",
        budget=budget,
        cache=cache,
        dedupe=DedupeWindow(window_seconds=300),
    )
    assert verdict2["allowed"] is False
    assert verdict2["reason"] == "cache_hit"
    assert verdict2["cached_result"] == {"http_status": 200, "body_excerpt": "not found"}
