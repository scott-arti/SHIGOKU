"""
Dispatch routing order and return schema matrix tests for MasterConductor._dispatch.

Part 1: Routing order tests — verify each branch is hit for the correct agent_type/params.
Part 2: Return schema matrix tests — verify returned dict shapes per branch.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.core.domain.model.task import Task
from src.core.engine.master_conductor import MasterConductor


def _new_mc():
    """Create a minimal MasterConductor instance via __new__ with required attributes."""
    mc = MasterConductor.__new__(MasterConductor)
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})
    mc.accumulated_context = {}
    mc.llm_client = MagicMock()
    mc.network_client = MagicMock()
    mc.workspace = None
    mc.recipe_loader = None
    mc.rag = None
    mc.agentic_rag = None
    mc.project_manager = None
    mc.phase_gate = MagicMock()
    mc.event_bus = MagicMock()
    return mc


def _worker_factory_returns_none():
    """Return a mock get_worker_factory whose create_worker returns None."""
    mock_factory = MagicMock()
    mock_factory.create_worker = MagicMock(return_value=None)
    return mock_factory


# =============================================================================
# Part 1: Routing Order Tests
# =============================================================================


@pytest.mark.asyncio
async def test_dispatch_routes_scope_parser_to_fast_path():
    """Task with agent_type='scope_parser', action='verify_scope' → fast path called, returns scope result."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={})

    task = Task(
        id="task_001",
        name="Scope Verification",
        agent_type="scope_parser",
        action="verify_scope",
        params={"target": "localhost:3000"},
    )

    # Mock the internal scope verification to avoid global side effects
    with patch(
        "src.core.engine.master_conductor._svc_dispatch_scope_verification_fast_path",
        return_value={
            "success": True,
            "task_id": task.id,
            "agent": "scope_parser",
            "data": {"target": "http://localhost:3000", "in_scope_domains": ["localhost"]},
            "context": {"target_info": {"host": "localhost"}},
            "findings": [],
        },
    ), patch(
        "src.core.security.ethics_guard.get_ethics_guard",
        return_value=MagicMock(),
    ):
        result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "scope_parser"
    assert "target" in result.get("data", {})


@pytest.mark.asyncio
async def test_dispatch_blocks_post_exploit_in_bugbounty():
    """Task agent_type='post_exploit' in bugbounty mode without allow_post_exploit → returns skip dict."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})

    task = Task(
        id="task_pe",
        name="Post Exploitation",
        agent_type="post_exploit",
        params={"target": "http://example.com"},
    )

    # Guard with no scope → falls back to settings.allow_post_exploit (defaults False)
    mock_guard = MagicMock()
    mock_guard.scope = None

    with patch(
        "src.core.security.ethics_guard.get_ethics_guard", return_value=mock_guard
    ):
        result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "post_exploit"
    assert result.get("data", {}).get("skipped") is True
    assert "Post-exploitation not allowed" in result.get("data", {}).get("reason", "")


@pytest.mark.asyncio
async def test_dispatch_allows_post_exploit_when_enabled():
    """With settings.allow_post_exploit=True, post_exploit task passes through guard."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})

    task = Task(
        id="task_pe2",
        name="Post Exploitation Allowed",
        agent_type="post_exploit",
        params={"target": "http://example.com"},
    )

    mock_guard = MagicMock()
    mock_guard.scope = None

    mock_worker = MagicMock()
    mock_worker.execute = MagicMock(
        return_value=SimpleNamespace(success=True, data={}, error=None, findings=[])
    )

    mock_factory = MagicMock()
    mock_factory.create_worker = MagicMock(return_value=mock_worker)

    with patch(
        "src.core.security.ethics_guard.get_ethics_guard", return_value=mock_guard
    ), patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.settings"
    ) as mock_settings:
        mock_settings.allow_post_exploit = True
        result = await mc._dispatch(task)

    # Must NOT be the skip dict — must have worker shape
    assert result.get("is_swarm") is True
    assert result.get("success") is True
    assert result.get("agent") == "post_exploit"


@pytest.mark.asyncio
async def test_dispatch_routes_to_worker_when_available():
    """When get_worker_factory returns a worker, it is used and returns with is_swarm=True."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})

    task = Task(
        id="task_w",
        name="Worker Task",
        agent_type="recon",
        params={"target": "http://example.com"},
    )

    mock_worker = MagicMock()
    mock_worker.execute = MagicMock(
        return_value=SimpleNamespace(success=True, data={"key": "val"}, error=None, findings=["f1"])
    )

    mock_factory = MagicMock()
    mock_factory.create_worker = MagicMock(return_value=mock_worker)

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ):
        result = await mc._dispatch(task)

    assert result.get("is_swarm") is True
    assert result.get("success") is True
    assert result.get("agent") == "recon"
    assert result.get("data") == {"key": "val"}
    assert result.get("findings") == ["f1"]
    mock_factory.create_worker.assert_called_once_with("recon")


@pytest.mark.asyncio
async def test_dispatch_routes_to_swarm_for_swarm_agent_type():
    """Task agent_type='swarm' → dispatched via swarm dispatcher."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc._get_loop = MagicMock(return_value=MagicMock())

    task = Task(
        id="task_sw",
        name="Swarm Task",
        agent_type="swarm",
        params={"target": "http://test.com", "tags": ["web"]},
    )

    mock_swarm_result = SimpleNamespace(
        status="success",
        swarm_name="test_swarm",
        findings=[],
        execution_log=[],
        total_specialists=1,
        successful_specialists=1,
    )

    mock_dispatcher = MagicMock()
    mock_dispatcher.dispatch = AsyncMock(return_value=mock_swarm_result)
    mock_dispatcher.set_recipe_loader = MagicMock()
    mock_dispatcher.set_rag = MagicMock()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.swarm_dispatcher.get_swarm_dispatcher", return_value=mock_dispatcher
    ):
        result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "test_swarm"
    assert "findings" in result
    assert "execution_log" in result.get("data", {})
    mock_dispatcher.dispatch.assert_called_once()


@pytest.mark.asyncio
async def test_dispatch_routes_to_cartographer():
    """Task agent_type='cartographer' → Cartographer is instantiated and used."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})

    task = Task(
        id="task_carto",
        name="Cartographer Task",
        agent_type="cartographer",
        params={"target": "http://test.com"},
    )

    fake_sitemap = MagicMock()
    fake_sitemap.nodes = ["n1", "n2", "n3"]
    fake_sitemap.get_endpoints = MagicMock(return_value=["http://a.com", "http://b.com"])

    mock_cartographer = MagicMock()
    mock_cartographer.map_site = AsyncMock(return_value=fake_sitemap)
    mock_cartographer.close = MagicMock()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.intel.cartographer.Cartographer", return_value=mock_cartographer
    ):
        result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "cartographer"
    assert "nodes_count" in result.get("data", {})
    assert "endpoints" in result.get("data", {})
    assert result.get("new_assets") == ["http://a.com", "http://b.com"]


@pytest.mark.asyncio
async def test_dispatch_routes_to_fingerprinter():
    """Task agent_type='fingerprinter' → Fingerprinter identifies technologies."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})

    task = Task(
        id="task_fp",
        name="Fingerprinter Task",
        agent_type="fingerprinter",
        params={"target": "http://test.com"},
    )

    fake_response = SimpleNamespace(
        is_success=True,
        body="<html>WordPress site</html>",
        headers={"Server": "nginx"},
    )

    mock_fingerprinter = MagicMock()
    mock_fingerprinter.identify = MagicMock(
        return_value=[SimpleNamespace(name="WordPress")]
    )

    mock_factory = _worker_factory_returns_none()
    mc.network_client.request = AsyncMock(return_value=fake_response)

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.intel.fingerprinter.Fingerprinter", return_value=mock_fingerprinter
    ):
        result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "fingerprinter"
    assert "technologies" in result.get("data", {})
    assert result.get("findings") == ["WordPress"]


@pytest.mark.asyncio
async def test_dispatch_skips_duplicate_recon():
    """When _recon_executed=True, recon_master task returns skip dict."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc._recon_executed = True

    task = Task(
        id="task_recon2",
        name="Duplicate Recon",
        agent_type="recon_master",
        params={"target": "http://test.com"},
    )

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ):
        result = await mc._dispatch(task)

    assert result.get("success") is True
    assert result.get("agent") == "recon_master"
    assert result.get("skipped") is True
    assert result.get("reason") == "Recon already executed"


@pytest.mark.asyncio
async def test_dispatch_routes_to_recipe():
    """Task action='run_recipe' → _execute_recipe_task is called."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})

    task = Task(
        id="task_recipe",
        name="Recipe Task",
        agent_type="any_agent",
        action="run_recipe",
        params={"recipe_name": "test_recipe", "target": "http://test.com"},
    )

    mock_factory = _worker_factory_returns_none()
    mc._execute_recipe_task = AsyncMock(
        return_value={"success": True, "task_id": task.id, "data": {}}
    )

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ):
        result = await mc._dispatch(task)

    mc._execute_recipe_task.assert_called_once_with(task)
    assert result.get("success") is True


@pytest.mark.asyncio
async def test_dispatch_routes_to_agentfactory_fallback():
    """Unknown agent_type falls through to AgentFactory.create_agent."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc.context.to_handoff_dict = MagicMock(return_value={})
    mc._augment_payload_with_findings = MagicMock(
        return_value=({"output": "agent result"}, [])
    )
    mc._get_context_auth_headers = MagicMock(return_value={})
    mc._get_context_cookie_string = MagicMock(return_value="")
    mc._resolve_task_target = MagicMock(return_value="http://test.com")

    task = Task(
        id="task_af",
        name="Agent Factory Fallback",
        agent_type="unknown_agent",
        params={"target": "http://test.com"},
    )

    mock_agent = MagicMock()
    mock_agent.execute = AsyncMock(return_value={"output": "agent result"})

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory_cls, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory_cls.create_agent = MagicMock(return_value=mock_agent)
        mock_cookies.set = MagicMock(return_value="token123")
        mock_cookies.reset = MagicMock()

        result = await mc._dispatch(task)

    assert mock_agent_factory_cls.create_agent.called
    assert result.get("success") is True
    assert result.get("task_id") == "task_af"
    assert result.get("agent") == "unknown_agent"
    assert "data" in result


# =============================================================================
# Part 2: Return Schema Matrix Tests
# =============================================================================


@pytest.mark.asyncio
async def test_dispatch_worker_return_schema():
    """Worker return dict has required keys: success, task_id, agent, data, error, findings, is_swarm."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})

    task = Task(
        id="task_schema_w",
        name="Worker Schema Test",
        agent_type="recon",
        params={"target": "http://example.com"},
    )

    worker_result = SimpleNamespace(
        success=True, data={"k": "v"}, error=None, findings=[]
    )
    mock_worker = MagicMock()
    mock_worker.execute = MagicMock(return_value=worker_result)

    mock_factory = MagicMock()
    mock_factory.create_worker = MagicMock(return_value=mock_worker)

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ):
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "error", "findings", "is_swarm"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )
    assert result["is_swarm"] is True


# =============================================================================
# Part 2: Return Schema Matrix Tests
# =============================================================================


@pytest.mark.asyncio
async def test_dispatch_swarm_return_schema():
    """Swarm return dict has required keys: success, task_id, agent, data, findings."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc._get_loop = MagicMock(return_value=MagicMock())

    task = Task(
        id="task_schema_sw",
        name="Swarm Schema Test",
        agent_type="swarm",
        params={"target": "http://test.com", "tags": ["web"]},
    )

    mock_swarm_result = SimpleNamespace(
        status="success",
        swarm_name="schema_swarm",
        findings=[],
        execution_log=[],
        total_specialists=0,
        successful_specialists=0,
    )

    mock_dispatcher = MagicMock()
    mock_dispatcher.dispatch = AsyncMock(return_value=mock_swarm_result)
    mock_dispatcher.set_recipe_loader = MagicMock()
    mock_dispatcher.set_rag = MagicMock()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.swarm_dispatcher.get_swarm_dispatcher", return_value=mock_dispatcher
    ):
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "findings"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


@pytest.mark.asyncio
async def test_dispatch_cartographer_return_schema():
    """Cartographer return has: success, task_id, agent, data, new_assets."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})

    task = Task(
        id="task_schema_carto",
        name="Cartographer Schema Test",
        agent_type="cartographer",
        params={"target": "http://test.com"},
    )

    fake_sitemap = MagicMock()
    fake_sitemap.nodes = ["n1"]
    fake_sitemap.get_endpoints = MagicMock(return_value=["http://a.com"])

    mock_cartographer = MagicMock()
    mock_cartographer.map_site = AsyncMock(return_value=fake_sitemap)
    mock_cartographer.close = MagicMock()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.intel.cartographer.Cartographer", return_value=mock_cartographer
    ):
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "new_assets"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


@pytest.mark.asyncio
async def test_dispatch_recon_master_return_schema():
    """Recon master return has: success, task_id, agent, data, new_assets."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc.project_manager = None
    mc.phase_gate = MagicMock()
    mc._create_attack_tasks_from_recon = MagicMock(return_value=[])
    mc._add_tasks = MagicMock()
    mc._recon_executed = False

    task = Task(
        id="task_schema_recon",
        name="Recon Schema Test",
        agent_type="recon_master",
        params={"target": "http://test.com", "start_step": 1, "end_step": 8},
    )

    fake_state = SimpleNamespace(
        live_subs=[],
        tech_stack=[],
        results={},
        current_step=8,
        screenshots_count=0,
    )

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.recon.pipeline.ReconPipeline"
    ) as mock_pipeline_cls, patch(
        "src.core.engine.master_conductor.asyncio.to_thread",
        new=AsyncMock(return_value=fake_state),
    ):
        mock_pipeline_cls.return_value = MagicMock()
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "new_assets"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


@pytest.mark.asyncio
async def test_dispatch_agentfactory_return_schema():
    """Agent factory fallback return has: success, task_id, agent, data, error, findings."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc.context.to_handoff_dict = MagicMock(return_value={})
    mc._augment_payload_with_findings = MagicMock(
        return_value=({"output": "ok"}, [])
    )
    mc._get_context_auth_headers = MagicMock(return_value={})
    mc._get_context_cookie_string = MagicMock(return_value="")
    mc._resolve_task_target = MagicMock(return_value="http://test.com")

    task = Task(
        id="task_schema_af",
        name="AgentFactory Schema Test",
        agent_type="unknown_agent",
        params={"target": "http://test.com"},
    )

    mock_agent = MagicMock()
    mock_agent.execute = AsyncMock(return_value={"output": "ok"})

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory.create_agent = MagicMock(return_value=mock_agent)
        mock_cookies.set = MagicMock(return_value="token123")
        mock_cookies.reset = MagicMock()

        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "findings"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


# =============================================================================
# Part 3: Cookie/Header Contextvar Reset Tests
# =============================================================================


@pytest.mark.asyncio
async def test_dispatch_resets_cookies_on_success():
    """AgentFactory fallback path: success path still calls cookie reset in finally."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://example.test"})
    mc.context.to_handoff_dict = MagicMock(return_value={})
    mc._augment_payload_with_findings = MagicMock(
        return_value=({"output": "ok"}, [])
    )
    mc._get_context_auth_headers = MagicMock(return_value={})
    mc._get_context_cookie_string = MagicMock(return_value="")
    mc._resolve_task_target = MagicMock(return_value="http://example.test")

    class DummyAgent:
        async def execute(self, target=None, params=None):
            return {"success": True, "data": {"ok": True}, "findings": []}

        async def close(self):
            pass

    agent = DummyAgent()
    fake_token = object()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory_cls, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory_cls.create_agent = MagicMock(return_value=agent)
        mock_cookies.set = MagicMock(return_value=fake_token)
        mock_cookies.reset = MagicMock()

        task = Task(
            id="t_cookie_success", name="cookie test",
            agent_type="test_agent", action="scan",
            params={"target": "http://example.test"},
        )
        result = await mc._dispatch(task)

    assert result["success"] is True
    mock_cookies.reset.assert_called_once_with(fake_token)


@pytest.mark.asyncio
async def test_dispatch_resets_cookies_on_agent_error():
    """Agent execute raises → finally still calls cookie reset, outer except catches."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://example.test"})
    mc.context.to_handoff_dict = MagicMock(return_value={})
    mc._get_context_auth_headers = MagicMock(return_value={})
    mc._get_context_cookie_string = MagicMock(return_value="")
    mc._resolve_task_target = MagicMock(return_value="http://example.test")

    class DummyAgent:
        async def execute(self, target=None, params=None):
            raise RuntimeError("agent exploded")

        async def close(self):
            pass

    agent = DummyAgent()
    fake_token = object()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory_cls, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory_cls.create_agent = MagicMock(return_value=agent)
        mock_cookies.set = MagicMock(return_value=fake_token)
        mock_cookies.reset = MagicMock()

        task = Task(
            id="t_cookie_error", name="cookie error test",
            agent_type="test_agent", action="scan",
            params={"target": "http://example.test"},
        )
        result = await mc._dispatch(task)

    assert result["success"] is False
    mock_cookies.reset.assert_called_once_with(fake_token)


@pytest.mark.asyncio
async def test_dispatch_resets_cookies_on_typeerror_fallback():
    """TypeError → agent retried without params → succeeds → cookie reset called."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://example.test"})
    mc.context.to_handoff_dict = MagicMock(return_value={})
    mc._augment_payload_with_findings = MagicMock(
        return_value=({"output": "ok"}, [])
    )
    mc._get_context_auth_headers = MagicMock(return_value={})
    mc._get_context_cookie_string = MagicMock(return_value="")
    mc._resolve_task_target = MagicMock(return_value="http://example.test")

    call_count = [0]

    class DummyAgent:
        async def execute(self, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise TypeError("unexpected keyword argument 'params'")
            return {"success": True, "data": {"ok": True}, "findings": []}

        async def close(self):
            pass

    agent = DummyAgent()
    fake_token = object()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory_cls, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory_cls.create_agent = MagicMock(return_value=agent)
        mock_cookies.set = MagicMock(return_value=fake_token)
        mock_cookies.reset = MagicMock()

        task = Task(
            id="t_typeerror", name="typeerror test",
            agent_type="test_agent", action="scan",
            params={"target": "http://example.test"},
        )
        result = await mc._dispatch(task)

    # TypeError fallback retried without params → succeeded
    assert result["success"] is True
    assert call_count[0] >= 2  # first raised, second (or later) succeeded
    mock_cookies.reset.assert_called_once_with(fake_token)


@pytest.mark.asyncio
async def test_dispatch_resets_cookies_on_import_error():
    """AgentFactory.create_agent raises ImportError → outer except handles it.

    Cookie set/reset never called because ImportError happens before cookie injection.
    """
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty"})

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory_cls, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory_cls.create_agent = MagicMock(
            side_effect=ImportError("No module named 'nonexistent'")
        )
        mock_cookies.set = MagicMock()
        mock_cookies.reset = MagicMock()

        task = Task(
            id="t_import", name="import error test",
            agent_type="nonexistent", action="scan",
            params={"target": "http://example.test"},
        )
        result = await mc._dispatch(task)

    assert result["success"] is False
    assert "Agent not found" in str(result.get("error", ""))
    # Cookie injection happens after AgentFactory.create_agent,
    # so set/reset are never reached on ImportError
    mock_cookies.set.assert_not_called()
    mock_cookies.reset.assert_not_called()


# =============================================================================
# Part 4: Recon Cleanup Tests
# =============================================================================


@pytest.mark.asyncio
async def test_recon_dispatch_isolated_loop_cleaned_up():
    """recon_master uses asyncio.to_thread for isolated event loop execution."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://example.test"})
    mc.project_manager = SimpleNamespace(project_dir="/tmp/test_recon", config={})
    mc._recon_executed = False
    mc._create_attack_tasks_from_recon = MagicMock(return_value=[])
    mc._add_tasks = MagicMock()

    fake_state = SimpleNamespace(
        live_subs=[],
        tech_stack=[],
        results={},
        current_step=5,
        screenshots_count=0,
    )

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.recon.pipeline.ReconPipeline"
    ) as mock_pipeline_cls, patch(
        "src.core.engine.master_conductor.asyncio.to_thread",
        new_callable=AsyncMock,
    ) as mock_to_thread:
        mock_pipeline = MagicMock()
        mock_pipeline_cls.return_value = mock_pipeline
        mock_to_thread.return_value = fake_state

        task = Task(
            id="t_recon_cleanup", name="recon cleanup",
            agent_type="recon_master", action="scan",
            params={"target": "http://example.test", "start_step": 1, "end_step": 3},
        )
        result = await mc._dispatch(task)

    assert result["success"] is True
    assert result["agent"] == "recon_master"
    mock_to_thread.assert_called_once()


@pytest.mark.asyncio
async def test_recon_dispatch_duplicate_skip_no_thread():
    """Duplicate recon execution is skipped; to_thread is never called."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://example.test"})
    mc._recon_executed = True

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.asyncio.to_thread"
    ) as mock_to_thread:
        task = Task(
            id="t_recon_dup", name="recon duplicate",
            agent_type="recon_master", action="scan",
            params={"target": "http://example.test"},
        )
        result = await mc._dispatch(task)

    assert result["success"] is True
    assert result.get("skipped") is True
    assert result.get("reason") == "Recon already executed"
    mock_to_thread.assert_not_called()


@pytest.mark.asyncio
async def test_recon_dispatch_error_no_dangling_loop():
    """recon to_thread raises → returns error dict, no dangling loop."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://example.test"})
    mc.project_manager = None
    mc._recon_executed = False

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.recon.pipeline.ReconPipeline"
    ) as mock_pipeline_cls, patch(
        "src.core.engine.master_conductor.asyncio.to_thread",
        new_callable=AsyncMock,
    ) as mock_to_thread:
        mock_pipeline = MagicMock()
        mock_pipeline_cls.return_value = mock_pipeline
        mock_to_thread.side_effect = RuntimeError("to_thread failed")

        task = Task(
            id="t_recon_err", name="recon error",
            agent_type="recon_master", action="scan",
            params={"target": "http://example.test"},
        )
        result = await mc._dispatch(task)

    assert result["success"] is False
    assert result["agent"] == "recon_master"
    assert "to_thread failed" in str(result.get("error", ""))


@pytest.mark.asyncio
async def test_dispatch_swarm_return_schema():
    """Swarm return dict has required keys: success, task_id, agent, data, findings."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc._get_loop = MagicMock(return_value=MagicMock())

    task = Task(
        id="task_schema_sw",
        name="Swarm Schema Test",
        agent_type="swarm",
        params={"target": "http://test.com", "tags": ["web"]},
    )

    mock_swarm_result = SimpleNamespace(
        status="success",
        swarm_name="schema_swarm",
        findings=[],
        execution_log=[],
        total_specialists=0,
        successful_specialists=0,
    )

    mock_dispatcher = MagicMock()
    mock_dispatcher.dispatch = AsyncMock(return_value=mock_swarm_result)
    mock_dispatcher.set_recipe_loader = MagicMock()
    mock_dispatcher.set_rag = MagicMock()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.swarm_dispatcher.get_swarm_dispatcher", return_value=mock_dispatcher
    ):
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "findings"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


@pytest.mark.asyncio
async def test_dispatch_cartographer_return_schema():
    """Cartographer return has: success, task_id, agent, data, new_assets."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})

    task = Task(
        id="task_schema_carto",
        name="Cartographer Schema Test",
        agent_type="cartographer",
        params={"target": "http://test.com"},
    )

    fake_sitemap = MagicMock()
    fake_sitemap.nodes = ["n1"]
    fake_sitemap.get_endpoints = MagicMock(return_value=["http://a.com"])

    mock_cartographer = MagicMock()
    mock_cartographer.map_site = AsyncMock(return_value=fake_sitemap)
    mock_cartographer.close = MagicMock()

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.intel.cartographer.Cartographer", return_value=mock_cartographer
    ):
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "new_assets"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


@pytest.mark.asyncio
async def test_dispatch_recon_master_return_schema():
    """Recon master return has: success, task_id, agent, data, new_assets."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc.project_manager = None
    mc.phase_gate = MagicMock()
    mc._create_attack_tasks_from_recon = MagicMock(return_value=[])
    mc._add_tasks = MagicMock()
    mc._recon_executed = False

    task = Task(
        id="task_schema_recon",
        name="Recon Schema Test",
        agent_type="recon_master",
        params={"target": "http://test.com", "start_step": 1, "end_step": 8},
    )

    fake_state = SimpleNamespace(
        live_subs=[],
        tech_stack=[],
        results={},
        current_step=8,
        screenshots_count=0,
    )

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.recon.pipeline.ReconPipeline"
    ) as mock_pipeline_cls, patch(
        "src.core.engine.master_conductor.asyncio.to_thread",
        new=AsyncMock(return_value=fake_state),
    ):
        mock_pipeline_cls.return_value = MagicMock()
        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "new_assets"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )


@pytest.mark.asyncio
async def test_dispatch_agentfactory_return_schema():
    """Agent factory fallback return has: success, task_id, agent, data, error, findings."""
    mc = _new_mc()
    mc.context = SimpleNamespace(target_info={"mode": "bugbounty", "target": "http://test.com"})
    mc.context.to_handoff_dict = MagicMock(return_value={})
    mc._augment_payload_with_findings = MagicMock(
        return_value=({"output": "ok"}, [])
    )
    mc._get_context_auth_headers = MagicMock(return_value={})
    mc._get_context_cookie_string = MagicMock(return_value="")
    mc._resolve_task_target = MagicMock(return_value="http://test.com")

    task = Task(
        id="task_schema_af",
        name="AgentFactory Schema Test",
        agent_type="unknown_agent",
        params={"target": "http://test.com"},
    )

    mock_agent = MagicMock()
    mock_agent.execute = AsyncMock(return_value={"output": "ok"})

    mock_factory = _worker_factory_returns_none()

    with patch(
        "src.core.swarm.worker.factory.get_worker_factory", return_value=mock_factory
    ), patch(
        "src.core.engine.master_conductor.AgentFactory"
    ) as mock_agent_factory, patch(
        "src.core.infra.network_client.current_scan_cookies"
    ) as mock_cookies:
        mock_agent_factory.create_agent = MagicMock(return_value=mock_agent)
        mock_cookies.set = MagicMock(return_value="token123")
        mock_cookies.reset = MagicMock()

        result = await mc._dispatch(task)

    required_keys = {"success", "task_id", "agent", "data", "findings"}
    assert required_keys.issubset(set(result.keys())), (
        f"Missing keys: {required_keys - set(result.keys())}"
    )
