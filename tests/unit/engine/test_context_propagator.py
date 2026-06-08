"""
ContextPropagator ユニットテスト

タスク結果からのコンテキスト抽出をテスト
"""

import pytest

from src.core.engine.context_propagator import (
    ContextPropagator,
    create_context_propagator,
)
from src.core.engine.task_queue import TaskContext


class TestContextPropagator:
    """ContextPropagator のテスト"""
    
    @pytest.fixture
    def propagator(self) -> ContextPropagator:
        return ContextPropagator()
    
    # ==========================================
    # トークン抽出
    # ==========================================
    
    def test_extract_jwt(self, propagator: ContextPropagator):
        """JWT トークン抽出"""
        result = {
            "response": "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        }
        
        context = propagator.extract(result)
        
        assert "jwt" in context.auth_tokens
        assert context.auth_tokens["jwt"].startswith("eyJ")
    
    def test_extract_bearer_token(self, propagator: ContextPropagator):
        """Bearer トークン抽出"""
        result = {
            "headers": "Authorization: Bearer abc123def456ghi789"
        }
        
        context = propagator.extract(result)
        
        assert "bearer" in context.auth_tokens
    
    def test_extract_api_key(self, propagator: ContextPropagator):
        """API キー抽出"""
        result = {
            "config": "api_key=demo_api_key_for_unit_test_123456"
        }
        
        context = propagator.extract(result)
        
        assert "api_key" in context.auth_tokens
    
    def test_extract_session_id(self, propagator: ContextPropagator):
        """セッションID抽出"""
        result = {
            "cookies": "PHPSESSID=abc123def456ghi789jkl012"
        }
        
        context = propagator.extract(result)
        
        assert "session" in context.auth_tokens
    
    # ==========================================
    # 重要パス検出
    # ==========================================
    
    def test_detect_admin_panel(self, propagator: ContextPropagator):
        """Admin パネル検出"""
        result = {
            "urls": ["https://example.com/admin/dashboard"]
        }
        
        context = propagator.extract(result)
        
        assert "admin_panel" in context.critical_findings
    
    def test_detect_graphql(self, propagator: ContextPropagator):
        """GraphQL エンドポイント検出"""
        result = {
            "response": "Endpoint: https://api.example.com/graphql"
        }
        
        context = propagator.extract(result)
        
        assert "graphql" in context.critical_findings
    
    def test_detect_swagger(self, propagator: ContextPropagator):
        """Swagger 検出"""
        result = {
            "body": "Found at /swagger/index.html"
        }
        
        context = propagator.extract(result)
        
        assert "swagger" in context.critical_findings
    
    def test_detect_debug_endpoint(self, propagator: ContextPropagator):
        """デバッグエンドポイント検出"""
        result = {
            "path": "/debug/pprof"
        }
        
        context = propagator.extract(result)
        
        assert "debug_endpoint" in context.critical_findings
    
    def test_detect_git_exposed(self, propagator: ContextPropagator):
        """.git 公開検出"""
        result = {
            "url": "https://example.com/.git/config"
        }
        
        context = propagator.extract(result)
        
        assert "git_exposed" in context.critical_findings
    
    # ==========================================
    # エンドポイント抽出
    # ==========================================
    
    def test_extract_endpoints(self, propagator: ContextPropagator):
        """URL 抽出"""
        result = {
            "links": "Found: https://api.example.com/v1/users and https://api.example.com/v1/orders"
        }
        
        context = propagator.extract(result)
        
        assert len(context.discovered_endpoints) == 2
        assert "https://api.example.com/v1/users" in context.discovered_endpoints
    
    def test_extract_endpoints_with_scope(self):
        """スコープ制限付きURL抽出"""
        propagator = ContextPropagator(base_domain="example.com")
        
        result = {
            "links": "https://example.com/api and https://other.com/api"
        }
        
        context = propagator.extract(result)
        
        # example.com のみ
        assert len(context.discovered_endpoints) == 1
        assert "example.com" in context.discovered_endpoints[0]
    
    def test_no_duplicate_endpoints(self, propagator: ContextPropagator):
        """エンドポイント重複排除"""
        result = {
            "text": "https://example.com/api https://example.com/api https://example.com/api"
        }
        
        context = propagator.extract(result)
        
        assert len(context.discovered_endpoints) == 1
    
    # ==========================================
    # パラメータ抽出
    # ==========================================
    
    def test_extract_params(self, propagator: ContextPropagator):
        """クエリパラメータ抽出"""
        result = {
            "url": "https://example.com/search?query=test&page=1&limit=10"
        }
        
        context = propagator.extract(result)
        
        assert "query" in context.discovered_params
        assert "page" in context.discovered_params
        assert "limit" in context.discovered_params
    
    # ==========================================
    # 技術スタック検出
    # ==========================================
    
    def test_detect_php(self, propagator: ContextPropagator):
        """PHP 検出"""
        result = {
            "headers": "X-Powered-By: PHP/8.1"
        }
        
        context = propagator.extract(result)
        
        assert "php" in context.tech_stack
    
    def test_detect_express(self, propagator: ContextPropagator):
        """Express.js 検出"""
        result = {
            "headers": "X-Powered-By: Express"
        }
        
        context = propagator.extract(result)
        
        assert "nodejs" in context.tech_stack
    
    def test_detect_wordpress(self, propagator: ContextPropagator):
        """WordPress 検出"""
        result = {
            "body": '<link href="/wp-content/themes/theme/style.css">'
        }
        
        context = propagator.extract(result)
        
        assert "wordpress" in context.tech_stack
    
    def test_detect_laravel(self, propagator: ContextPropagator):
        """Laravel 検出"""
        result = {
            "cookies": "laravel_session=abc123; XSRF-TOKEN=xyz789"
        }
        
        context = propagator.extract(result)
        
        assert "laravel" in context.tech_stack
    
    # ==========================================
    # 構造化データからの抽出
    # ==========================================
    
    def test_extract_from_new_assets(self, propagator: ContextPropagator):
        """new_assets からエンドポイント抽出"""
        result = {
            "new_assets": [
                "https://api.example.com/v2/new-endpoint",
                "https://api.example.com/v2/another",
            ]
        }
        
        context = propagator.extract(result)
        
        assert len(context.discovered_endpoints) == 2
    
    def test_extract_from_findings(self, propagator: ContextPropagator):
        """findings から critical_findings 抽出"""
        result = {
            "findings": [
                {"type": "admin_access", "severity": "high"},
                {"type": "graphql_introspection", "severity": "medium"},
            ]
        }
        
        context = propagator.extract(result)
        
        assert "admin_panel" in context.critical_findings
        assert "graphql" in context.critical_findings
    
    def test_extract_from_tokens_field(self, propagator: ContextPropagator):
        """tokens フィールドから直接抽出"""
        result = {
            "tokens": {"jwt": "eyJ...", "bearer": "abc123"}
        }
        
        context = propagator.extract(result)
        
        assert context.auth_tokens["jwt"] == "eyJ..."
        assert context.auth_tokens["bearer"] == "abc123"
    
    # ==========================================
    # 空結果
    # ==========================================
    
    def test_empty_result(self, propagator: ContextPropagator):
        """空の結果から空コンテキスト"""
        context = propagator.extract({})
        
        assert context.is_empty() is True
    
    def test_no_matches(self, propagator: ContextPropagator):
        """マッチなしで空コンテキスト"""
        result = {
            "message": "Hello, World!",
            "number": 42,
        }
        
        context = propagator.extract(result)
        
        assert context.is_empty() is True


class TestCreateContextPropagator:
    """create_context_propagator ヘルパーのテスト"""
    
    def test_create_default(self):
        """デフォルト設定での作成"""
        propagator = create_context_propagator()
        
        assert isinstance(propagator, ContextPropagator)
        assert propagator.base_domain is None
    
    def test_create_with_domain(self):
        """ドメイン指定での作成"""
        propagator = create_context_propagator(base_domain="example.com")
        
        assert propagator.base_domain == "example.com"
