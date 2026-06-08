"""
L1 Unit Tests for SmartGraphQLHunter
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock

from src.core.agents.swarm.injection.smart_graphql import SmartGraphQLHunter
from src.core.models.finding import Finding, Severity, VulnType, Evidence


class TestSmartGraphQLHunter:
    """SmartGraphQLHunter のユニットテスト"""

    @pytest.fixture
    def hunter(self):
        return SmartGraphQLHunter()

    @pytest.fixture
    def mock_analysis_result(self):
        """Mock GraphQL analysis result with introspection enabled"""
        mock = Mock()
        mock.introspection_enabled = True
        mock.graphiql_enabled = False
        mock.field_suggestions_enabled = False
        mock.is_large_schema = False
        mock.schema = None
        mock.queries = ["getUser", "getPassword"]
        mock.mutations = ["deleteUser"]
        mock.sensitive_fields = ["Query.getPassword"]
        mock.suggested_fields = []
        mock.attack_vectors = ["Introspection enabled", "Sensitive fields detected"]
        return mock

    @pytest.fixture
    def mock_analysis_result_no_vuln(self):
        """Mock GraphQL analysis result with no vulnerabilities"""
        mock = Mock()
        mock.introspection_enabled = False
        mock.graphiql_enabled = False
        mock.field_suggestions_enabled = False
        mock.is_large_schema = False
        mock.schema = None
        mock.queries = []
        mock.mutations = []
        mock.sensitive_fields = []
        mock.suggested_fields = []
        mock.attack_vectors = []
        return mock

    @pytest.mark.asyncio
    async def test_run_as_tool_returns_vulnerable_when_introspection_enabled(
        self, hunter, mock_analysis_result
    ):
        """Introspection有効時にvulnerable=Trueを返す"""
        from src.core.agents.swarm.injection.smart_graphql import GraphQLAnalyzer
        with patch.object(
            GraphQLAnalyzer, 'analyze_async', new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.return_value = mock_analysis_result
            
            result = await hunter.run_as_tool("http://test.com/graphql")
            
            assert result["vulnerable"] is True
            assert result["findings_count"] == 1
            assert result["introspection_enabled"] is True
            assert result["has_sensitive_fields"] is True

    @pytest.mark.asyncio
    async def test_run_as_tool_returns_not_vulnerable_when_disabled(
        self, hunter, mock_analysis_result_no_vuln
    ):
        """Introspection無効時にvulnerable=Falseを返す"""
        from src.core.agents.swarm.injection.smart_graphql import GraphQLAnalyzer
        with patch.object(
            GraphQLAnalyzer, 'analyze_async', new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.return_value = mock_analysis_result_no_vuln
            
            result = await hunter.run_as_tool("http://test.com/graphql")
            
            assert result["vulnerable"] is False
            assert result["findings_count"] == 0

    @pytest.mark.asyncio
    async def test_run_as_tool_detects_graphiql(self, hunter):
        """GraphiQL検出時にgraphiql_enabled=Trueを返す"""
        from src.core.agents.swarm.injection.smart_graphql import GraphQLAnalyzer
        mock_result = Mock()
        mock_result.introspection_enabled = False
        mock_result.graphiql_enabled = True
        mock_result.field_suggestions_enabled = False
        mock_result.is_large_schema = False
        mock_result.schema = None
        mock_result.queries = []
        mock_result.mutations = []
        mock_result.sensitive_fields = []
        mock_result.suggested_fields = []
        mock_result.attack_vectors = []

        with patch.object(
            GraphQLAnalyzer, 'analyze_async', new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.return_value = mock_result
            
            result = await hunter.run_as_tool("http://test.com/graphql")
            
            assert result["vulnerable"] is True
            assert result["graphiql_enabled"] is True

    @pytest.mark.asyncio
    async def test_run_as_tool_detects_field_suggestions(self, hunter):
        """Field Suggestions検出時にfield_suggestions_enabled=Trueを返す"""
        from src.core.agents.swarm.injection.smart_graphql import GraphQLAnalyzer
        mock_result = Mock()
        mock_result.introspection_enabled = False
        mock_result.graphiql_enabled = False
        mock_result.field_suggestions_enabled = True
        mock_result.is_large_schema = False
        mock_result.schema = None
        mock_result.queries = []
        mock_result.mutations = []
        mock_result.sensitive_fields = []
        mock_result.suggested_fields = ["getUser", "getPassword"]
        mock_result.attack_vectors = []

        with patch.object(
            GraphQLAnalyzer, 'analyze_async', new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.return_value = mock_result
            
            result = await hunter.run_as_tool("http://test.com/graphql")
            
            assert result["vulnerable"] is True
            assert result["field_suggestions_enabled"] is True
            assert result["suggested_fields"] == ["getUser", "getPassword"]

    def test_convert_to_findings_returns_high_severity_with_sensitive_fields(self, hunter):
        """機密フィールドありの場合HIGH severityを返す"""
        result = {
            "vulnerable": True,
            "introspection_enabled": True,
            "graphiql_enabled": False,
            "field_suggestions_enabled": False,
            "is_large_schema": False,
            "sensitive_fields": ["Query.getPassword", "Query.adminSecret"],
            "suggested_fields": [],
            "mutations": ["deleteUser"],
            "attack_vectors": ["Introspection enabled"],
            "queries_count": 2,
            "mutations_count": 1,
            "has_sensitive_fields": True,
        }
        
        findings = hunter._convert_to_findings(result, "http://test.com/graphql")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].vuln_type == VulnType.GRAPHQL_INTROSPECTION

    def test_convert_to_findings_returns_medium_severity_without_sensitive(self, hunter):
        """機密フィールドなしの場合MEDIUM severityを返す"""
        result = {
            "vulnerable": True,
            "introspection_enabled": True,
            "graphiql_enabled": False,
            "field_suggestions_enabled": False,
            "is_large_schema": False,
            "sensitive_fields": [],
            "suggested_fields": [],
            "mutations": [],
            "attack_vectors": [],
            "queries_count": 2,
            "mutations_count": 0,
            "has_sensitive_fields": False,
        }
        
        findings = hunter._convert_to_findings(result, "http://test.com/graphql")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_convert_to_findings_returns_high_with_graphiql(self, hunter):
        """GraphiQLありの場合HIGH severityを返す"""
        result = {
            "vulnerable": True,
            "introspection_enabled": False,
            "graphiql_enabled": True,
            "field_suggestions_enabled": False,
            "is_large_schema": False,
            "sensitive_fields": [],
            "suggested_fields": [],
            "mutations": [],
            "attack_vectors": [],
            "queries_count": 0,
            "mutations_count": 0,
            "has_sensitive_fields": False,
        }
        
        findings = hunter._convert_to_findings(result, "http://test.com/graphql")
        
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_convert_to_findings_returns_empty_when_not_vulnerable(self, hunter):
        """脆弱性なしの場合空リストを返す"""
        result = {
            "vulnerable": False,
            "introspection_enabled": False,
        }
        
        findings = hunter._convert_to_findings(result, "http://test.com/graphql")
        
        assert findings == []

    def test_poc_html_contains_escaped_url(self, hunter):
        """PoC HTMLにエスケープされたURLが含まれる"""
        result = {
            "vulnerable": True,
            "introspection_enabled": True,
            "graphiql_enabled": False,
        }
        
        # URL with quotes that need escaping
        poc_html = hunter._generate_poc_html_safe('http://test.com/graphql?foo="bar"', result)
        
        # URL should be escaped (html.escape converts quotes to &quot;)
        assert "&quot;" in poc_html  # quote=True escapes quotes
        assert "GraphQL" in poc_html
        assert "testIntrospection" in poc_html or "Introspection" in poc_html

    def test_poc_html_escapes_special_chars(self, hunter):
        """特殊文字がエスケープされる"""
        result = {
            "vulnerable": True,
            "introspection_enabled": True,
        }
        
        # URL with special characters that need escaping
        poc_html = hunter._generate_poc_html_safe("http://test.com/graphql?x=<script>", result)
        
        # Check that URL query parameter is properly escaped in the HTML content
        # (the <code> block should contain &lt;script&gt; not <script>)
        assert "&lt;script&gt;" in poc_html
        # And that the URL context uses escaped version
        assert "graphql?x=&lt;script&gt;" in poc_html or "graphql?x=&lt;" in poc_html

    def test_meta_keys_excludes_control_params(self, hunter):
        """META_KEYSがcontrol paramsを除外する"""
        control_params = {"scan_profile", "profile", "_auth", "_context"}
        
        # All control params should be in META_KEYS
        for param in control_params:
            assert param in hunter.META_KEYS

    @pytest.mark.asyncio
    async def test_run_as_tool_handles_exception(self, hunter):
        """例外発生時に適切なエラーレスポンスを返す"""
        from src.core.agents.swarm.injection.smart_graphql import GraphQLAnalyzer
        with patch.object(
            GraphQLAnalyzer, 'analyze_async', new_callable=AsyncMock
        ) as mock_analyze:
            mock_analyze.side_effect = Exception("Test error")
            
            result = await hunter.run_as_tool("http://test.com/graphql")
            
            assert result["vulnerable"] is False
            assert result["findings_count"] == 0
            assert "error" in result
