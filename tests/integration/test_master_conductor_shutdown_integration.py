import sys
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

# ----------------------------------------------------------------
# モジュールレベルのモック注入 (インポート前に実行必須)
# ----------------------------------------------------------------
sys.modules["neo4j"] = MagicMock()
sys.modules["bs4"] = MagicMock()
sys.modules["aiofiles"] = MagicMock()

# 内部モジュールのモック
sys.modules["src.core.engine.recipe_loader"] = MagicMock()
sys.modules["src.core.engine.strategy_optimizer"] = MagicMock()
sys.modules["src.core.engine.task_queue"] = MagicMock()
sys.modules["src.core.engine.context_propagator"] = MagicMock()
sys.modules["src.core.engine.context_designer"] = MagicMock()
sys.modules["src.core.engine.critical_path_analyzer"] = MagicMock()
sys.modules["src.core.wordlist.wordlist_manager"] = MagicMock()
sys.modules["src.core.notifications.notifier"] = MagicMock()
sys.modules["src.tools.custom.notify"] = MagicMock()
sys.modules["src.core.engine.flag_watcher"] = MagicMock()
sys.modules["src.core.models.task_execution_log"] = MagicMock()
sys.modules["src.core.models.decision_trace"] = MagicMock()
sys.modules["src.core.engine.phase_gate"] = MagicMock()
sys.modules["src.core.infra.event_bus"] = MagicMock()
sys.modules["src.core.infra.async_writer"] = MagicMock()
sys.modules["src.core.learning.findings_repository"] = MagicMock()

# MasterConductor のインポート (モック注入後)
from src.core.engine.master_conductor import MasterConductor


@pytest.fixture
def mock_mc():
    """MasterConductor のインスタンス生成（最小構成）"""
    # 依存関係をさらにモック化してインスタンス化エラーを防ぐ
    with patch("src.core.engine.master_conductor.KnowledgeGraph"), \
         patch("src.core.engine.master_conductor.get_findings_repository"), \
         patch("src.core.engine.master_conductor.AsyncDatabaseWriter") as MockWriter, \
         patch("asyncio.create_task"):
         
        # Writer の stop メソッドを AsyncMock に
        mock_writer_instance = MockWriter.return_value
        mock_writer_instance.stop = AsyncMock()

        mc = MasterConductor()
        # save_session をモック (ファイル操作回避)
        mc.save_session = MagicMock()
        
        return mc


@pytest.mark.asyncio
async def test_shutdown_calls_swarm_dispatcher_close(mock_mc):
    """shutdown() 時に SwarmDispatcher.close() が呼ばれることを確認"""
    
    # SwarmDispatcher のモック設定
    mock_module = sys.modules["src.core.engine.swarm_dispatcher"] = MagicMock()
    mock_dispatcher = AsyncMock()
    mock_module.get_swarm_dispatcher.return_value = mock_dispatcher
    
    # shutdown() 実行
    await mock_mc._async_shutdown()
    
    # SwarmDispatcher.close() が呼ばれたか確認
    mock_dispatcher.close.assert_called_once()


@pytest.mark.asyncio
async def test_shutdown_resilient_to_dispatcher_error(mock_mc):
    """SwarmDispatcher.close() でエラーが発生してもシャットダウンが完了することを確認"""
    
    # SwarmDispatcher のモック設定
    mock_module = sys.modules["src.core.engine.swarm_dispatcher"] = MagicMock()
    mock_dispatcher = AsyncMock()
    mock_dispatcher.close.side_effect = RuntimeError("Dispatcher close error")
    mock_module.get_swarm_dispatcher.return_value = mock_dispatcher
    
    # shutdown() が例外を投げずに完了すること
    await mock_mc._async_shutdown()
    
    # _shutdown_requested フラグが立っていることを確認
    assert mock_mc._shutdown_requested is True
