import pytest
from unittest.mock import MagicMock, patch
from src.core.engine.master_conductor import MasterConductor
import src.core.engine.swarm_dispatcher as sd

@pytest.fixture(autouse=True)
def reset_dispatcher():
    """SwarmDispatcher のシングルトンをリセット"""
    sd._dispatcher = None
    yield
    sd._dispatcher = None

@pytest.mark.asyncio
async def test_shared_session_propagation():
    """MasterConductor から共有セッションが正しく伝搬されることを確認"""
    
    # 依存コンポーネントのモック
    mock_graph = MagicMock()
    mock_pm = MagicMock()
    mock_pm.config = {"mode": "BUG_BOUNTY"}
    
    with patch('src.core.infra.network_client.AsyncNetworkClient') as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value = mock_client
        
        # MasterConductor 初期化 (これにより共有クライアントが作成される)
        mc = MasterConductor(graph=mock_graph, project_manager=mock_pm)
        
        assert mc.network_client is mock_client
        
        # SwarmDispatcher の取得
        dispatcher = sd.get_swarm_dispatcher(network_client=mc.network_client)
        assert dispatcher.network_client is mock_client
        
        # Swarm の作成とクライアント注入の確認
        # SwarmDispatcher の内部インポートをパッチ
        with patch('src.core.agents.swarm.auth.AuthSwarm') as mock_auth_class:
            mock_swarm = MagicMock()
            # set_network_client メソッドを明示的に定義（hasattr対策）
            def mock_set(client): pass
            mock_swarm.set_network_client = MagicMock(side_effect=mock_set)
            mock_auth_class.return_value = mock_swarm
            
            # _get_or_create_swarm を通じて注入
            swarm = dispatcher._get_or_create_swarm("auth")
            
            # set_network_client が呼ばれているはず
            assert mock_swarm.set_network_client.called, "set_network_client should be called"

@pytest.mark.asyncio
async def test_strategy_optimizer_pruning():
    """StrategyOptimizer の高度な間引きロジックを検証"""
    from src.core.engine.strategy_optimizer import StrategyOptimizer
    from src.core.engine.task_queue import DynamicTaskQueue
    from src.core.domain.model.task import Task
    
    optimizer = StrategyOptimizer(config={"mode": "BUG_BOUNTY"})
    queue = DynamicTaskQueue()
    
    # 低価値アセット
    t1 = Task(id="t1", name="test1", agent_type="scanner", params={"target": "http://example.com/logo.png"})
    t2 = Task(id="t2", name="test2", agent_type="scanner", params={"target": "http://example.com/index.php?id=1"})
    # 重複パス（かつ非インジェクション）
    t3 = Task(id="t3", name="test3", agent_type="scanner", params={"target": "http://example.com/index.php?id=2"})
    
    queue.add(t1)
    queue.add(t2)
    queue.add(t3)
    
    # 分析
    result = optimizer.review_strategy(queue, None, 10)
    
    # logo.png と 重複した index.php (t3) が間引かれるはず
    # 注意: t2 と t3 は同じ base_path ("index.php") を持つ。
    # 最初の t2 は seen_paths に入り、t3 が間引き対象になる。
    assert "http://example.com/logo.png" in result["low_value_assets"]
    assert "http://example.com/index.php?id=2" in result["low_value_assets"]
    # t2 は低価値ではない（PHPファイルなので）
    assert "http://example.com/index.php?id=1" not in result["low_value_assets"]
