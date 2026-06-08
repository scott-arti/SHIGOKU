"""
Adaptive Payload Adjuster ユニットテスト
"""
import pytest
from src.core.attack.adaptive_adjuster import (
    AdaptivePayloadAdjuster,
    PayloadContext,
    AdjustmentAction,
    create_adaptive_adjuster,
)


class TestAdaptivePayloadAdjuster:
    """AdaptivePayloadAdjuster テストクラス"""

    @pytest.fixture
    def adjuster(self):
        return create_adaptive_adjuster()

    def test_detect_context_html(self, adjuster):
        """HTMLコンテキスト検出"""
        hint = '<div class="container"><span>content</span></div>'
        result = adjuster._detect_context(hint)
        assert result == PayloadContext.HTML_TAG

    def test_detect_context_javascript(self, adjuster):
        """JavaScriptコンテキスト検出"""
        hint = 'function test() { var x = 1; }'
        result = adjuster._detect_context(hint)
        assert result == PayloadContext.JAVASCRIPT

    def test_detect_context_sql(self, adjuster):
        """SQLコンテキスト検出"""
        hint = "SELECT id, name FROM users WHERE active = 1"
        result = adjuster._detect_context(hint)
        assert result == PayloadContext.SQL

    def test_detect_context_json(self, adjuster):
        """JSONコンテキスト検出 - application/jsonヘッダー"""
        hint = 'Content-Type: application/json'
        result = adjuster._detect_context(hint)
        assert result == PayloadContext.JSON

    def test_action_encode_url(self, adjuster):
        """URLエンコードアクション"""
        payload = "<script>alert(1)</script>"
        result = adjuster._action_encode(payload, PayloadContext.URL)
        assert "%" in result

    def test_action_encode_javascript(self, adjuster):
        """JavaScriptエンコードアクション"""
        payload = "<script>"
        result = adjuster._action_encode(payload, PayloadContext.JAVASCRIPT)
        # Unicodeエスケープ
        assert "\\u" in result

    def test_action_escape(self, adjuster):
        """エスケープバイパスアクション"""
        payload = "<script>alert('xss')</script>"
        result = adjuster._action_escape(payload)
        # 少なくとも1文字がエスケープされる
        assert result != payload

    def test_action_break_string_js(self, adjuster):
        """JavaScript文字列分割"""
        payload = "alert"
        result = adjuster._action_break_string(payload, PayloadContext.JAVASCRIPT)
        # +で結合された形式
        assert "+" in result or result == payload

    def test_action_break_string_sql(self, adjuster):
        """SQL文字列分割"""
        payload = "admin"
        result = adjuster._action_break_string(payload, PayloadContext.SQL)
        # CONCAT形式
        assert "CONCAT" in result or result == payload

    def test_action_change_case(self, adjuster):
        """大小文字変更アクション"""
        payload = "script"
        result = adjuster._action_change_case(payload)
        assert result.lower() == payload.lower()
        assert any(c.isupper() for c in result)

    def test_action_add_comment_sql(self, adjuster):
        """SQLコメント挿入"""
        payload = "SELECT"
        result = adjuster._action_add_comment(payload, PayloadContext.SQL)
        # コメントが挿入される
        assert len(result) > len(payload)

    def test_adjust_returns_list(self, adjuster):
        """adjustメソッドがリストを返す"""
        payload = "<script>alert(1)</script>"
        results = adjuster.adjust(payload, response_hint="<html>")
        assert isinstance(results, list)

    def test_adjust_with_detected_context(self, adjuster):
        """明示的コンテキストでの調整"""
        payload = "SELECT * FROM users"
        results = adjuster.adjust(
            payload,
            detected_context=PayloadContext.SQL,
        )
        assert len(results) > 0
        # 全てがSQLコンテキスト
        for r in results:
            assert r.context == PayloadContext.SQL

    def test_adjust_from_error_length(self, adjuster):
        """長さ制限エラーからの調整"""
        payload = "a" * 200
        error = "Input value is too long, maximum 100 characters allowed"
        
        results = adjuster.adjust_from_error(payload, error)
        assert len(results) > 0
        # TRUNCATEアクションが含まれる
        assert any(AdjustmentAction.TRUNCATE in r.actions for r in results)

    def test_adjust_from_error_blocked(self, adjuster):
        """WAFブロックエラーからの調整"""
        payload = "<script>alert(1)</script>"
        error = "Request blocked by firewall"
        
        results = adjuster.adjust_from_error(payload, error)
        assert len(results) > 0

    def test_learn_success(self, adjuster):
        """成功パターン学習"""
        adjuster.learn_success(
            original="<script>",
            successful="<ScRiPt>",
            context=PayloadContext.HTML_TAG,
        )
        assert len(adjuster.learned_patterns) > 0

    def test_get_summary(self, adjuster):
        """サマリー取得"""
        adjuster.adjust("<script>", response_hint="<html>")
        
        summary = adjuster.get_summary()
        assert "total_adjustments" in summary
        assert "by_context" in summary
        assert "by_action" in summary
