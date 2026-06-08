import pytest
from unittest.mock import AsyncMock, MagicMock
from src.core.intelligence.agentic_rag import AgenticRAGFeedbackLoop

@pytest.mark.asyncio
async def test_agentic_rag_feedback_loop_success():
    """自信がある場合に1回で終了することを確認"""
    mock_rag = AsyncMock()
    mock_rag.retrieve.return_value = ["context 1"]
    
    mock_llm = AsyncMock()
    mock_llm.ask_json.return_value = {
        "confidence": 0.9,
        "is_sufficient": True,
        "suggested_query": None
    }
    
    rag_loop = AgenticRAGFeedbackLoop(mock_rag, mock_llm, threshold=0.7)
    results = await rag_loop.retrieve_with_feedback("target", "initial recon")
    
    assert results == ["context 1"]
    assert mock_rag.retrieve.call_count == 1

@pytest.mark.asyncio
async def test_agentic_rag_feedback_loop_retry():
    """自信がない場合に再検索が行われることを確認"""
    mock_rag = AsyncMock()
    mock_rag.retrieve.side_effect = [
        ["initial context"],
        ["improved context"]
    ]
    
    mock_llm = AsyncMock()
    mock_llm.ask_json.side_effect = [
        # 1回目：自信なし
        {
            "confidence": 0.3,
            "is_sufficient": False,
            "suggested_query": "better query"
        },
        # 2回目：自信あり
        {
            "confidence": 0.8,
            "is_sufficient": True,
            "suggested_query": None
        }
    ]
    
    rag_loop = AgenticRAGFeedbackLoop(mock_rag, mock_llm, threshold=0.7)
    results = await rag_loop.retrieve_with_feedback("target", "initial recon")
    
    assert len(results) == 2
    assert "improved context" in results
    assert mock_rag.retrieve.call_count == 2
    assert mock_rag.retrieve.call_args_list[1][0][0] == "better query"

@pytest.mark.asyncio
async def test_swarm_manager_early_exit_logic():
    """SwarmManager が CRITICAL 検知時に後続をスキップすることを確認"""
    from src.core.agents.swarm.base import SwarmManager, Specialist
    from src.core.models.finding import Finding, Severity, VulnType
    
    # モックの作成
    mock_specialist_1 = AsyncMock(spec=Specialist)
    mock_specialist_1.name = "crit_finder"
    # CRITICAL 脆弱性を返す
    mock_finding = Finding(
        vuln_type=VulnType.SQLI,
        target_url="http://example.com",
        title="SQLi", 
        severity=Severity.CRITICAL, 
        description="Critical flaw", 
        source_agent="crit_finder"
    )
    mock_specialist_1.run_with_timeout.return_value = [mock_finding]
    mock_specialist_1.get_execution_time.return_value = 0.1
    
    mock_specialist_2 = AsyncMock(spec=Specialist)
    mock_specialist_2.name = "skipped_worker"
    
    # 抽象クラスの具象化回避ハックとインスタンス生成
    SwarmManager.__abstractmethods__ = frozenset()
    manager = SwarmManager(config={"max_concurrent_tasks": 1})
    manager.name = "test_manager"
    manager._specialists.append(mock_specialist_1)
    manager._specialists.append(mock_specialist_2)
    manager.get_specialists = MagicMock(return_value=[mock_specialist_1, mock_specialist_2])
    
    task = MagicMock()
    task.params = {"adaptive_skip_enabled": True}
    task.tags = ["target_domain"]
    
    result = await manager.dispatch(task)
    
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    # 2つ目のスペシャリストは呼ばれていないはず
    assert mock_specialist_2.run_with_timeout.call_count == 0
