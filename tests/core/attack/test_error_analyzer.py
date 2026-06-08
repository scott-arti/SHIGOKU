"""
Error Message Analyzer ユニットテスト
"""
import pytest
from src.core.attack.error_analyzer import (
    ErrorMessageAnalyzer,
    ErrorCategory,
    create_error_analyzer,
)


class TestErrorMessageAnalyzer:
    """ErrorMessageAnalyzer テストクラス"""

    @pytest.fixture
    def analyzer(self):
        return create_error_analyzer()

    def test_categorize_validation(self, analyzer):
        """バリデーションエラーカテゴリ判定"""
        result = analyzer._categorize_error(
            "Email is invalid", status_code=400
        )
        assert result == ErrorCategory.VALIDATION

    def test_categorize_authentication(self, analyzer):
        """認証エラーカテゴリ判定"""
        result = analyzer._categorize_error(
            "Invalid credentials", status_code=401
        )
        assert result == ErrorCategory.AUTHENTICATION

    def test_categorize_waf(self, analyzer):
        """WAFエラーカテゴリ判定"""
        result = analyzer._categorize_error(
            "Request blocked by WAF", status_code=403
        )
        assert result == ErrorCategory.WAF

    def test_categorize_server(self, analyzer):
        """サーバーエラーカテゴリ判定"""
        result = analyzer._categorize_error(
            "Internal server error", status_code=500
        )
        assert result == ErrorCategory.SERVER

    def test_detect_tech_stack_django(self, analyzer):
        """Django検出"""
        message = "CSRF verification failed. Request aborted."
        result = analyzer._detect_tech_stack(message, None)
        assert "Django" in result

    def test_detect_tech_stack_mysql(self, analyzer):
        """MySQL検出"""
        message = "MySQLSyntaxError: You have an error in your SQL syntax"
        result = analyzer._detect_tech_stack(message, None)
        assert "MySQL" in result

    def test_detect_tech_stack_from_headers(self, analyzer):
        """ヘッダーからの検出"""
        headers = {"Server": "nginx/1.18.0"}
        result = analyzer._detect_tech_stack("Error", headers)
        assert "Nginx" in result

    def test_extract_validation_rules_length(self, analyzer):
        """長さルール抽出"""
        message = "Password must be at least 8 characters"
        rules = analyzer._extract_validation_rules(message)
        assert len(rules) > 0
        assert any("length" in r.rule_type for r in rules)

    def test_extract_validation_rules_type(self, analyzer):
        """型ルール抽出"""
        message = "Age must be an integer"
        rules = analyzer._extract_validation_rules(message)
        assert len(rules) > 0
        assert any("type" in r.rule_type for r in rules)

    def test_extract_hints_sql(self, analyzer):
        """SQLインジェクションヒント抽出"""
        message = "SQL syntax error near 'SELECT * FROM'"
        hints = analyzer._extract_hints(message)
        assert len(hints) > 0
        assert any("SQL injection" in h for h in hints)

    def test_extract_hints_path(self, analyzer):
        """パス情報漏洩ヒント抽出"""
        message = "Error in /var/www/app/models/user.py at line 42"
        hints = analyzer._extract_hints(message)
        assert len(hints) > 0
        assert any("path" in h.lower() for h in hints)

    def test_extract_hints_version(self, analyzer):
        """バージョン情報ヒント抽出"""
        message = "Apache Tomcat Version: 9.0.50"
        hints = analyzer._extract_hints(message)
        assert len(hints) > 0
        assert any("version" in h.lower() for h in hints)

    def test_generate_bypass_suggestions_waf(self, analyzer):
        """WAFバイパス提案生成"""
        suggestions = analyzer._generate_bypass_suggestions(
            ErrorCategory.WAF, []
        )
        assert len(suggestions) > 0
        # ケース変更が含まれる
        assert any("ケース" in s for s in suggestions)

    def test_analyze_full(self, analyzer):
        """統合分析テスト"""
        analysis = analyzer.analyze(
            error_message="MySQLSyntaxError: You have an error in your SQL syntax",
            status_code=500,
            headers={"Server": "Apache/2.4.41"},
        )
        
        assert analysis.category == ErrorCategory.DATABASE or analysis.category == ErrorCategory.SERVER
        assert "MySQL" in analysis.tech_stack
        assert len(analysis.hints) > 0

    def test_analyze_for_payload_feedback(self, analyzer):
        """ペイロードフィードバック分析"""
        feedback = analyzer.analyze_for_payload_feedback(
            error_message="Request blocked by firewall",
            payload="<script>alert(1)</script>",
        )
        
        assert "should_change_case" in feedback
        assert "detected_filter" in feedback
        assert feedback["detected_filter"] is True

    def test_get_summary(self, analyzer):
        """サマリー取得"""
        analyzer.analyze("Test error", status_code=400)
        
        summary = analyzer.get_summary()
        assert "total_analyzed" in summary
        assert "by_category" in summary
        assert "detected_tech_stack" in summary
