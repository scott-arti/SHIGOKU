import pytest
from unittest.mock import MagicMock, patch
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.base import Task

@pytest.mark.asyncio
async def test_injection_manager_tool_registration():
    """InjectionManagerAgent が正しくツールを登録しているかテスト"""
    config = MagicMock()
    config.get.return_value = 1 # Semaphore 用
    
    # InjectionManagerAgent を生成
    agent = InjectionManagerAgent(config=config)
    
    # Specialists を直接モックして差し込む
    agent.specialists = {
        "sqli": MagicMock(),
        "xss": MagicMock(),
        "lfi": MagicMock(),
        "redirect": MagicMock(),
        "cmd_ssrf": MagicMock()
    }
    
    # ツール登録を実行
    agent._register_manager_tools()
    
    # 登録されたツール名を確認
    registered_tools = list(agent.available_tools.keys())
    
    assert "sqli_scan" in registered_tools
    assert "xss_scan" in registered_tools
    assert "lfi_scan" in registered_tools
    assert "open_redirect_scan" in registered_tools
    assert "cmd_ssrf_scan" in registered_tools

@pytest.mark.asyncio
async def test_injection_manager_dispatch_phase1_flow():
    """Phase 1 のスキャンフローとコンテキストへの反映を確認"""
    config = MagicMock()
    config.get.return_value = 1 # Semaphore 用
    agent = InjectionManagerAgent(config=config)
    
    # 既存の findings をセット
    agent.current_context["findings"] = []
    
    task = Task(
        id="test_task",
        name="Scan example.com for SQLi",
        target="http://example.com/page?id=1",
        tags=["sqli"],
        params={
            "targets": ["http://example.com/page?id=1"],
            "phase1_early_return_on_findings": True,
        }
    )
    
    # _process_single_url をモックして結果を返すようにする
    mock_result = {
        "findings_count": 1,
        "vuln_type": "sqli",
        "findings": [MagicMock(title="SQL Injection found")]
    }
    
    async def _mock_process_single_url(*_args, **_kwargs):
        agent.current_context["findings"].extend(mock_result["findings"])
        return mock_result

    with patch.object(agent, "_process_single_url", side_effect=_mock_process_single_url):
        result = await agent.dispatch(task)
        
        assert result.status in {"success", "partial_success"}
        assert len(result.findings) > 0
        assert result.findings[0].title == "SQL Injection found"
