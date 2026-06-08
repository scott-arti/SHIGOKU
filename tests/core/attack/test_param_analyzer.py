"""
Parameter Semantic Analyzer ユニットテスト
"""
import pytest
from src.core.attack.param_analyzer import (
    ParameterSemanticAnalyzer,
    ParameterRole,
    AttackVector,
    create_semantic_analyzer,
)


class TestParameterSemanticAnalyzer:
    """ParameterSemanticAnalyzer テストクラス"""

    @pytest.fixture
    def analyzer(self):
        return create_semantic_analyzer()

    def test_detect_role_user_id(self, analyzer):
        """ユーザーID役割検出"""
        assert analyzer._detect_role("user_id") == ParameterRole.USER_ID
        assert analyzer._detect_role("uid") == ParameterRole.USER_ID
        assert analyzer._detect_role("id") == ParameterRole.USER_ID

    def test_detect_role_file_path(self, analyzer):
        """ファイルパス役割検出"""
        assert analyzer._detect_role("file") == ParameterRole.FILE_PATH
        assert analyzer._detect_role("path") == ParameterRole.FILE_PATH
        assert analyzer._detect_role("filename") == ParameterRole.FILE_PATH

    def test_detect_role_url(self, analyzer):
        """URL役割検出"""
        assert analyzer._detect_role("url") == ParameterRole.URL
        assert analyzer._detect_role("href") == ParameterRole.URL
        assert analyzer._detect_role("target") == ParameterRole.URL

    def test_detect_role_search(self, analyzer):
        """検索クエリ役割検出"""
        assert analyzer._detect_role("q") == ParameterRole.SEARCH_QUERY
        assert analyzer._detect_role("search") == ParameterRole.SEARCH_QUERY
        assert analyzer._detect_role("query") == ParameterRole.SEARCH_QUERY

    def test_detect_role_redirect(self, analyzer):
        """リダイレクト役割検出"""
        assert analyzer._detect_role("redirect") == ParameterRole.REDIRECT
        assert analyzer._detect_role("next") == ParameterRole.REDIRECT
        assert analyzer._detect_role("goto") == ParameterRole.REDIRECT

    def test_detect_role_unknown(self, analyzer):
        """不明な役割"""
        assert analyzer._detect_role("xyz123") == ParameterRole.UNKNOWN

    def test_detect_value_type_integer(self, analyzer):
        """整数型検出"""
        assert analyzer._detect_value_type("123") == "integer"
        assert analyzer._detect_value_type("0") == "integer"

    def test_detect_value_type_email(self, analyzer):
        """メール型検出"""
        assert analyzer._detect_value_type("test@example.com") == "email"

    def test_detect_value_type_url(self, analyzer):
        """URL型検出"""
        assert analyzer._detect_value_type("https://example.com") == "url"
        assert analyzer._detect_value_type("http://localhost") == "url"

    def test_detect_value_type_json(self, analyzer):
        """JSON型検出"""
        assert analyzer._detect_value_type('{"key": "value"}') == "json"
        assert analyzer._detect_value_type('[1, 2, 3]') == "json"

    def test_detect_value_type_path(self, analyzer):
        """パス型検出"""
        assert analyzer._detect_value_type("/etc/passwd") == "path"
        assert analyzer._detect_value_type("../../etc/passwd") == "path"

    def test_suggest_vectors_file_path(self, analyzer):
        """ファイルパスへの攻撃ベクター提案"""
        vectors = analyzer._suggest_vectors(
            ParameterRole.FILE_PATH, "string", "test.txt"
        )
        assert AttackVector.LFI in vectors

    def test_suggest_vectors_url(self, analyzer):
        """URLへの攻撃ベクター提案"""
        vectors = analyzer._suggest_vectors(
            ParameterRole.URL, "url", "https://example.com"
        )
        assert AttackVector.SSRF in vectors

    def test_suggest_vectors_search(self, analyzer):
        """検索への攻撃ベクター提案"""
        vectors = analyzer._suggest_vectors(
            ParameterRole.SEARCH_QUERY, "string", "test"
        )
        assert AttackVector.SQLI in vectors
        assert AttackVector.XSS in vectors

    def test_analyze_single(self, analyzer):
        """単一パラメータ分析"""
        result = analyzer.analyze("user_id", "123")
        
        assert result.name == "user_id"
        assert result.role == ParameterRole.USER_ID
        assert result.value_type == "integer"
        assert AttackVector.IDOR in result.suggested_vectors

    def test_analyze_all(self, analyzer):
        """複数パラメータ分析"""
        params = {
            "id": "123",
            "url": "https://example.com",
            "q": "search term",
        }
        results = analyzer.analyze_all(params)
        
        assert len(results) == 3

    def test_prioritize_parameters(self, analyzer):
        """パラメータ優先度付け"""
        params = {
            "name": "test",
            "file": "/etc/passwd",
            "page": "1",
        }
        prioritized = analyzer.prioritize_parameters(params)
        
        # fileが最優先
        assert prioritized[0][0] == "file"

    def test_get_high_value_targets(self, analyzer):
        """高価値ターゲット取得"""
        params = {
            "name": "test",
            "file": "/etc/passwd",
            "redirect": "https://evil.com",
            "page": "1",
        }
        targets = analyzer.get_high_value_targets(params)
        
        assert "file" in targets
        assert "redirect" in targets
        assert "page" not in targets

    def test_generate_notes_idor(self, analyzer):
        """IDOR注意事項生成"""
        notes = analyzer._generate_notes(
            "user_id", "123", ParameterRole.USER_ID, "integer"
        )
        assert len(notes) > 0
        assert any("IDOR" in n for n in notes)

    def test_generate_notes_admin(self, analyzer):
        """Admin注意事項生成"""
        notes = analyzer._generate_notes(
            "is_admin", "false", ParameterRole.ADMIN, "boolean"
        )
        assert len(notes) > 0
        assert any("escalation" in n.lower() for n in notes)

    def test_get_summary(self, analyzer):
        """サマリー取得"""
        analyzer.analyze("id", "123")
        analyzer.analyze("q", "test")
        
        summary = analyzer.get_summary()
        assert "total_analyzed" in summary
        assert summary["total_analyzed"] == 2
        assert "by_role" in summary
        assert "by_vector" in summary
