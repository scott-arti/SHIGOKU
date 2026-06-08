"""
MasterConductor のバグ修正用テストケース

Bug #1: Fail-Closed修正の検証
"""
import pytest
from unittest.mock import Mock
from src.core.engine.master_conductor import MasterConductor


class TestBugFix1_Fail_Closed:
    """Bug #1: Fail-Closedセキュリティ修正のテスト"""
    
    def test_hitl_callback_crash_returns_false(self):
        """HITLコールバック例外時にFalseを返す（Fail-Closed）"""
        conductor = MasterConductor()
        
        # コールバックを設定（例外を投げる）
        def crashing_callback(hitl_info):
            raise RuntimeError("Callback crashed")
        
        conductor.human_approval_callback = crashing_callback
        
        hitl_info = {"reason": "test", "severity": "critical"}
        result = conductor.request_human_approval(hitl_info)
        
        # 例外発生時はFalseを返すべき（Fail-Closed）
        assert result is False
    
    def test_hitl_no_callback_returns_true(self):
        """コールバックがない場合はTrueを返す（自動承認）"""
        conductor = MasterConductor()
        conductor.human_approval_callback = None
        
        hitl_info = {"reason": "test"}
        result = conductor.request_human_approval(hitl_info)
        
        assert result is True
    
    def test_hitl_callback_normal_returns_callback_result(self):
        """正常なコールバックは結果をそのまま返す"""
        conductor = MasterConductor()
        
        # 承認するコールバック
        conductor.human_approval_callback = lambda info: True
        assert conductor.request_human_approval({"reason": "test"}) is True
        
        # 拒否するコールバック
        conductor.human_approval_callback = lambda info: False
        assert conductor.request_human_approval({"reason": "test"}) is False
