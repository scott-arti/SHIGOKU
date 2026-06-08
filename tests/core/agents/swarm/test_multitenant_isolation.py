"""
Task 5 P2: cross-tenant isolation tests

project_id が異なる DiscoveryManagerAgent インスタンス間で
context / Worker config が混在しないことを確認する。
"""

import pytest
from unittest.mock import AsyncMock, patch

from src.core.agents.swarm.discovery.manager import DiscoveryManagerAgent
from src.core.agents.swarm.base_manager import BaseManagerAgent


def make_manager(project_id: str, session_id: str = "sess-test") -> DiscoveryManagerAgent:
    return DiscoveryManagerAgent(
        config={"model": "test-model"},
        project_id=project_id,
        session_id=session_id,
    )


# --- current_context 分離テスト ---

def test_project_id_isolated_per_instance():
    """異なる project_id が別インスタンスで混在しない"""
    m1 = make_manager("project-alpha")
    m2 = make_manager("project-beta")
    assert m1.current_context["project_id"] == "project-alpha"
    assert m2.current_context["project_id"] == "project-beta"
    assert m1.current_context is not m2.current_context


def test_session_id_isolated_per_instance():
    """異なる session_id が別インスタンスで混在しない"""
    m1 = make_manager("proj-x", session_id="session-001")
    m2 = make_manager("proj-x", session_id="session-002")
    assert m1.current_context["session_id"] == "session-001"
    assert m2.current_context["session_id"] == "session-002"


def test_auth_headers_do_not_leak_across_instances():
    """一方に auth_headers を設定しても他方に漏洩しない"""
    m1 = make_manager("proj-a")
    m2 = make_manager("proj-b")
    m1.current_context["auth_headers"] = {"Authorization": "Bearer token-a"}
    assert "auth_headers" not in m2.current_context


def test_history_isolated_per_instance():
    """history が別インスタンスで共有されない"""
    m1 = make_manager("proj-a")
    m2 = make_manager("proj-b")
    m1.history.append({"role": "user", "content": "test"})
    assert len(m2.history) == 0


# --- _worker_config 伝播テスト ---

def test_worker_config_carries_project_id():
    """_worker_config が current_context の project_id を含む"""
    m = make_manager("proj-c")
    cfg = m._worker_config()
    assert cfg["project_id"] == "proj-c"


def test_worker_config_carries_session_id():
    """_worker_config が current_context の session_id を含む"""
    m = make_manager("proj-d", session_id="sess-xyz")
    cfg = m._worker_config()
    assert cfg["session_id"] == "sess-xyz"


def test_worker_config_project_id_from_two_tenants_are_independent():
    """2テナントの _worker_config が互いに影響しない"""
    m1 = make_manager("tenant-1")
    m2 = make_manager("tenant-2")
    c1 = m1._worker_config()
    c2 = m2._worker_config()
    assert c1["project_id"] != c2["project_id"]
    assert c1 is not c2


def test_worker_config_agentconfig_model_preserved():
    """AgentConfig オブジェクトの model フィールドが _worker_config に含まれる"""
    from src.core.agents.base import AgentConfig

    agent_cfg = AgentConfig(
        name="TestManager",
        description="test",
        model="test-model-v2",
        instructions="",
        tools=[],
    )
    m = DiscoveryManagerAgent(
        config=agent_cfg,
        project_id="proj-e",
    )
    cfg = m._worker_config()
    assert cfg.get("model") == "test-model-v2"
    assert cfg.get("project_id") == "proj-e"


# --- _validate_context_schema テスト ---

def test_validate_context_schema_warns_on_missing_keys(caplog):
    """auth_headers 未設定時に warning が記録される"""
    import logging
    m = make_manager("proj-f")
    with caplog.at_level(logging.WARNING):
        m._validate_context_schema()
    assert any("auth_headers" in r.getMessage() for r in caplog.records)


def test_validate_context_schema_no_warning_when_complete(caplog):
    """全 ContextSchema キーが揃っている場合は warning が出ない"""
    import logging
    m = make_manager("proj-g", session_id="sess-g")
    m.current_context["auth_headers"] = {"Authorization": "Bearer tok"}
    with caplog.at_level(logging.WARNING):
        m._validate_context_schema()
    schema_warnings = [r for r in caplog.records if "ContextSchema" in r.getMessage()]
    assert len(schema_warnings) == 0


def test_validate_context_schema_no_warning_when_auth_headers_empty_dict(caplog):
    """auth_headers={} は有効値として扱い、欠落警告を出さない"""
    import logging
    m = make_manager("proj-h", session_id="sess-h")
    m.current_context["auth_headers"] = {}
    with caplog.at_level(logging.WARNING):
        m._validate_context_schema()
    schema_warnings = [r for r in caplog.records if "ContextSchema" in r.getMessage()]
    assert len(schema_warnings) == 0


# --- GraphQLNavigator への project_id 伝播 ---

@pytest.mark.asyncio
async def test_graphql_navigator_receives_project_id_in_config():
    """run_graphql_navigator が Worker に project_id を渡す"""
    from types import SimpleNamespace

    m = make_manager("tenant-nav")
    captured_config = {}

    async def _fake_run_as_tool(url):
        return {
            "introspection_enabled": False,
            "graphiql_enabled": False,
            "field_suggestions_enabled": False,
            "error_code": None,
            "internal_error_detail": "",
            "internal_error_category": "",
            "error_policy_version": "1",
            "latency_ms": 10,
            "schema_snippet": "",
            "evidence": [],
            "contract_version": "1.0.0",
        }

    def _fake_navigator_init(self_inner, config=None):
        captured_config.update(config or {})
        self_inner.config = config or {}
        self_inner._runtime = self_inner._build_runtime_config()
        self_inner._runtime_lock = __import__("asyncio").Lock()
        self_inner._inflight = 0
        self_inner._qps_timestamps = []
        self_inner._host_failures = {}
        self_inner._host_quarantine_until = {}
        self_inner._host_half_open_inflight = {}
        self_inner._error_category_window = []
        self_inner._last_alert_level = None
        self_inner._last_alert_at = 0.0

    from src.core.agents.swarm.discovery import graphql as gql_mod
    orig_init = gql_mod.GraphQLNavigator.__init__

    def _patched_init(self_inner, config=None):
        _fake_navigator_init(self_inner, config)
        self_inner.run_as_tool = _fake_run_as_tool.__get__(self_inner, type(self_inner))

    gql_mod.GraphQLNavigator.__init__ = _patched_init
    try:
        await m.run_graphql_navigator("http://example.test/graphql")
    finally:
        gql_mod.GraphQLNavigator.__init__ = orig_init

    assert captured_config.get("project_id") == "tenant-nav"
