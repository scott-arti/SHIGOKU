"""
CriticalPathAnalyzer ユニットテスト

Findingの内容に基づいて、正しいCriticalAction（優先度引き上げ等）が生成されるかを検証。
"""

import pytest
from src.core.engine.critical_path_analyzer import CriticalPathAnalyzer, CriticalAction

class TestCriticalPathAnalyzer:
    
    @pytest.fixture
    def analyzer(self):
        return CriticalPathAnalyzer()
    
    def test_admin_panel_trigger(self, analyzer):
        """Admin Panel 発見時のトリガー挙動"""
        finding = {
            "target": "http://example.com/admin/login",
            "evidence": "Admin Dashboard",
            "type": "content_discovery"
        }
        
        actions = analyzer.analyze(finding)
        
        assert len(actions) > 0
        action = actions[0]
        assert action.action_type == "boost_priority"
        assert "auth" in action.target_filter["tags"]
        assert action.params["priority"] == 999
        assert "admin" in action.reason.lower()

    def test_jwt_trigger(self, analyzer):
        """JWT 発見時のトリガー挙動"""
        finding = {
            "target": "http://example.com/api",
            "evidence": "Authorization: Bearer eyJhbGciOi...",
            "type": "jwt_token"
        }
        
        actions = analyzer.analyze(finding)
        
        assert len(actions) > 0
        action = actions[0]
        assert "jwt_attack" in action.target_filter["tags"]
        assert action.params["priority"] == 950

    def test_no_trigger(self, analyzer):
        """クリティカルでない発見"""
        finding = {
            "target": "http://example.com/about",
            "evidence": "Welcome to our site",
            "type": "content_discovery"
        }
        
        actions = analyzer.analyze(finding)
        assert len(actions) == 0

    def test_multiple_triggers(self, analyzer):
        """複数キーワードにマッチする場合"""
        finding = {
            "target": "http://example.com/admin/upload",
            "evidence": "Upload file here",
            "type": "file_upload"
        }
        
        actions = analyzer.analyze(finding)
        # admin と upload の両方にマッチする可能性がある
        
        boosted_tags = []
        for action in actions:
            boosted_tags.extend(action.target_filter["tags"])
            
        assert "admin_bypass" in boosted_tags
        assert "file_upload" in boosted_tags
