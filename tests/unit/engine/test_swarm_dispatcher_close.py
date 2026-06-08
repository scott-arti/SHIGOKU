"""SwarmDispatcher.close() のユニットテスト"""
import pytest
from unittest.mock import AsyncMock, MagicMock
from src.core.engine.swarm_dispatcher import SwarmDispatcher


@pytest.mark.asyncio
async def test_close_releases_all_swarms():
    """全 Swarm インスタンスが close() されることを確認"""
    dispatcher = SwarmDispatcher()
    
    # モック Swarm を登録
    mock_swarm_1 = AsyncMock()
    mock_swarm_2 = AsyncMock()
    dispatcher._swarm_pool = {
        "injection": mock_swarm_1,
        "auth": mock_swarm_2,
    }
    
    # close() 実行
    await dispatcher.close()
    
    # 各 Swarm の close() が呼ばれたか確認
    mock_swarm_1.close.assert_called_once()
    mock_swarm_2.close.assert_called_once()
    
    # インスタンス辞書がクリアされたか確認
    assert len(dispatcher._swarm_pool) == 0


@pytest.mark.asyncio
async def test_close_continues_on_error():
    """一部の Swarm でエラーが発生しても継続することを確認"""
    dispatcher = SwarmDispatcher()
    
    # Swarm1 はエラー、Swarm2 は正常
    mock_swarm_1 = AsyncMock()
    mock_swarm_1.close.side_effect = RuntimeError("Test error")
    mock_swarm_2 = AsyncMock()
    
    dispatcher._swarm_pool = {
        "injection": mock_swarm_1,
        "auth": mock_swarm_2,
    }
    
    # close() 実行（エラーで落ちないこと）
    await dispatcher.close()
    
    # Swarm2 も close() されたか確認
    mock_swarm_2.close.assert_called_once()
    assert len(dispatcher._swarm_pool) == 0


def test_determine_swarms_routes_idor_candidate_to_logic():
    """idor_candidate を含むタグで LogicSwarm も選択されることを確認"""
    dispatcher = SwarmDispatcher()

    swarms = dispatcher.determine_swarms(["sqli_candidate", "idor_candidate"])

    assert "injection" in swarms
    assert "logic" in swarms
