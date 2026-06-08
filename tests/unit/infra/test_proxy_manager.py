"""
ProxyManager ユニットテスト

プロキシリスト管理、ローテーション、スコアリングアルゴリズムを検証
"""

import os
import pytest
from src.core.infra.proxy_manager import (
    ProxyChainManager,
    ProxyNode,
    create_proxy_manager,
)


class TestProxyNode:
    """ProxyNode のテスト"""
    
    def test_initial_state(self):
        """初期状態"""
        node = ProxyNode(url="http://p1")
        assert node.is_active is True
        assert node.score == 100.0
        assert node.fail_count == 0
    
    def test_mark_success(self):
        """成功計測"""
        node = ProxyNode(url="http://p1")
        
        node.mark_success(latency_ms=100)
        assert node.success_count == 1
        assert node.latency == 100.0
        
        node.mark_success(latency_ms=200)
        # 移動平均: 100*0.8 + 200*0.2 = 80 + 40 = 120
        assert node.latency == 120.0
    
    def test_mark_failure_penalty(self):
        """失敗ペナルティ"""
        node = ProxyNode(url="http://p1")
        initial_score = node.score
        
        node.mark_failure()
        assert node.fail_count == 1
        assert node.score < initial_score
        
        # 連続失敗で無効化
        for _ in range(5):
            node.mark_failure()
        
        assert node.is_active is False


class TestProxyChainManager:
    """ProxyChainManager のテスト"""
    
    @pytest.mark.asyncio
    async def test_add_proxies(self):
        """プロキシ追加"""
        manager = ProxyChainManager()
        await manager.add_proxies(["http://p1", "http://p2"])
        
        assert len(manager.proxies) == 2
        assert manager.get_proxy() in ["http://p1", "http://p2"]
    
    def test_get_proxy_filtering(self):
        """無効なプロキシは返されない"""
        manager = ProxyChainManager(["http://good", "http://bad"])
        
        # bad を無効化
        bad_node = manager._proxy_map["http://bad"]
        bad_node.is_active = False
        
        # 何度呼んでも good しか返らないはず
        for _ in range(10):
            assert manager.get_proxy() == "http://good"
    
    def test_fallback_when_all_inactive(self):
        """全滅時は救済措置が働く"""
        manager = ProxyChainManager(["http://p1"])
        node = manager.proxies[0]
        node.is_active = False
        
        # 強制的に取得
        proxy = manager.get_proxy()
        assert proxy == "http://p1"
    
    @pytest.mark.asyncio
    async def test_load_from_file(self, tmp_path):
        """ファイルロード"""
        p_file = tmp_path / "proxies.txt"
        p_file.write_text("http://p1\n# Comment\nhttp://p2\n")
        
        manager = ProxyChainManager()
        await manager.load_from_file(str(p_file))
        
        assert len(manager.proxies) == 2
        assert "http://p1" in manager._proxy_map
        assert "http://p2" in manager._proxy_map
    
    @pytest.mark.asyncio
    async def test_report_success_failure(self):
        """成功・失敗報告の連携"""
        manager = ProxyChainManager(["http://p1"])
        
        await manager.report_failure("http://p1")
        node = manager._proxy_map["http://p1"]
        assert node.fail_count == 1
        
        await manager.report_success("http://p1", latency_ms=50)
        assert node.fail_count == 0  # 成功でリセット
        assert node.success_count == 1
