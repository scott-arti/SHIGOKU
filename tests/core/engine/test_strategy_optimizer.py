import pytest
from unittest.mock import MagicMock
from src.core.engine.strategy_optimizer import StrategyOptimizer
from src.core.engine.task_queue import DynamicTaskQueue

@pytest.fixture
def mock_queue():
    queue = DynamicTaskQueue()
    # High value
    queue.add(MagicMock(id="t1", name="Admin", agent_type="auth", priority=10, params={"target": "http://example.com/admin"}))
    queue.add(MagicMock(id="t2", name="API", agent_type="discovery", priority=10, params={"target": "http://example.com/api/v1"}))
    # Low value
    queue.add(MagicMock(id="t3", name="Image", agent_type="discovery", priority=10, params={"target": "http://example.com/logo.png"}))
    queue.add(MagicMock(id="t4", name="CSS", agent_type="discovery", priority=10, params={"target": "http://example.com/style.css"}))
    # Neutral
    queue.add(MagicMock(id="t5", name="Home", agent_type="discovery", priority=10, params={"target": "http://example.com/"}))
    return queue

def test_should_review():
    optimizer = StrategyOptimizer(config={"strategy_review_interval": 5})
    assert optimizer.should_review(5) is True
    assert optimizer.should_review(4) is False
    
    optimizer.last_review_step = 5
    assert optimizer.should_review(9) is False
    assert optimizer.should_review(10) is True

def test_review_strategy_bug_bounty(mock_queue):
    optimizer = StrategyOptimizer(config={"mode": "BUG_BOUNTY"})
    # KnowledgeGraph は現状 Any なので Mock で渡す
    kg = MagicMock()
    
    result = optimizer.review_strategy(mock_queue, kg, current_step=10)
    
    assert result["pruned"] == 2  # png and css
    assert result["boosted"] == 2  # admin and api
    assert len(mock_queue) == 3  # 5 - 2
    
    # 優先度順に並んでいるはず
    t1 = mock_queue.pop()
    assert "admin" in t1.params["target"]
    assert t1.priority >= 500

def test_review_strategy_ctf(mock_queue):
    # CTFモードでのキーワード追加確認
    mock_queue.add(MagicMock(id="t6", name="Flag", agent_type="discovery", priority=10, params={"target": "http://example.com/flag.txt"}))
    
    optimizer = StrategyOptimizer(config={"mode": "CTF"})
    kg = MagicMock()
    
    result = optimizer.review_strategy(mock_queue, kg, current_step=10)
    
    # flag.txt がブースト対象に含まれていること
    assert any("flag.txt" in asset for asset in result["high_value_assets"])
    assert result["boosted"] == 3  # admin, api, flag
