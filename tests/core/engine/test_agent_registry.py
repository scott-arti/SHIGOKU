"""
Test Agent Registry: タグシステムのテスト
"""

import pytest
from src.core.engine.agent_registry import (
    get_agents_by_tag,
    get_tools_by_tag,
    get_agent_tags,
    get_tool_tags,
    is_agent_available,
    is_tool_available,
    normalize_agent_name,
)


class TestAgentRegistry:
    """エージェントレジストリのテスト"""
    
    def test_get_agents_by_tag_web(self):
        """Webタグでエージェントを取得"""
        agents = get_agents_by_tag("web")
        assert len(agents) > 0
        assert "reconbot" in agents
        assert "graphql_navigator" in agents
        assert "authninja" in agents
    
    def test_get_agents_by_tag_auth(self):
        """Authタグでエージェントを取得"""
        agents = get_agents_by_tag("auth")
        assert len(agents) > 0
        assert "authninja" in agents
        assert "jwt_inspector" in agents
        assert "oauthdancer" in agents
    
    def test_get_agents_by_tag_all(self):
        """Allタグで全エージェントを取得"""
        agents = get_agents_by_tag("all")
        assert len(agents) > 10  # 最低10種以上
    
    def test_get_tools_by_tag_recon(self):
        """Reconタグでツールを取得"""
        tools = get_tools_by_tag("recon")
        assert len(tools) > 0
        assert "ffuf" in tools
        assert "httpx" in tools
        assert "subfinder" in tools
    
    def test_get_tools_by_tag_exploit(self):
        """Exploitタグでツールを取得"""
        tools = get_tools_by_tag("exploit")
        assert len(tools) > 0
        assert "nuclei" in tools
        assert "sqlmap" in tools
    
    def test_get_agent_tags(self):
        """エージェントのタグリスト取得"""
        tags = get_agent_tags("graphql_navigator")
        assert "web" in tags
        assert "api" in tags
        assert "all" in tags
    
    def test_get_agent_tags_unknown(self):
        """存在しないエージェントのタグ"""
        tags = get_agent_tags("unknown_agent")
        assert tags == ["all"]
    
    def test_get_tool_tags(self):
        """ツールのタグリスト取得"""
        tags = get_tool_tags("ffuf")
        assert "web" in tags
        assert "recon" in tags
    
    def test_get_tool_tags_unknown(self):
        """存在しないツールのタグ"""
        tags = get_tool_tags("unknown_tool")
        assert tags == ["all"]
    
    def test_is_agent_available_web(self):
        """Webコンテキストでエージェント利用可否"""
        assert is_agent_available("reconbot", "web") is True
        assert is_agent_available("authninja", "web") is True
    
    def test_is_agent_available_all(self):
        """Allタグエージェントは常に利用可"""
        assert is_agent_available("thoughtagent", "web") is True
        assert is_agent_available("thoughtagent", "auth") is True
    
    def test_is_tool_available_recon(self):
        """Reconコンテキストでツール利用可否"""
        assert is_tool_available("ffuf", "recon") is True
        assert is_tool_available("httpx", "recon") is True
        assert is_tool_available("sqlmap", "recon") is False
    
    def test_is_tool_available_exploit(self):
        """Exploitコンテキストでツール利用可否"""
        assert is_tool_available("nuclei", "exploit") is True
        assert is_tool_available("sqlmap", "exploit") is True
        assert is_tool_available("ffuf", "exploit") is False

    def test_normalize_agent_name_bizlogicswarm_alias(self):
        """BizLogicSwarm が bizlogic に正規化される"""
        assert normalize_agent_name("BizLogicSwarm") == "bizlogic"
