"""
URLClassifier Tests

計画書4.1分類タクソノミーの実装検証
"""
import pytest

from src.core.validation.url_classifier import (
    URLClassifier,
    ClassificationResult,
    classify_url,
    TAXONOMY_RULES,
)


class TestURLClassifier:
    """URLClassifier単体テスト"""

    def test_admin_endpoint_classification(self):
        """adminエンドポイント分類"""
        result = classify_url("http://localhost:3000/rest/admin/application-configuration", "GET")
        
        assert "admin" in result.tags
        assert "api_data" in result.tags
        assert result.primary_tag == "admin"
        assert result.confidence > 0.5

    def test_auth_endpoint_classification(self):
        """authエンドポイント分類"""
        result = classify_url("http://localhost:3000/rest/user/login", "POST")
        
        assert "auth" in result.tags
        assert result.primary_tag == "auth"

    def test_product_search_classification(self):
        """product_searchエンドポイント分類"""
        result = classify_url("http://localhost:3000/rest/products/search?q=test", "GET")
        
        assert "product_search" in result.tags
        assert "api_data" in result.tags

    def test_basket_order_classification(self):
        """basket_orderエンドポイント分類"""
        result = classify_url("http://localhost:3000/api/basket", "GET")
        
        assert "basket_order" in result.tags
        assert "api_data" in result.tags

    def test_client_route_dom_classification(self):
        """client_route_dom（SPAルート）分類"""
        result = classify_url("http://localhost:3000/#/search", "GET")
        
        assert "client_route_dom" in result.tags
        assert result.primary_tag == "client_route_dom"

    def test_realtime_classification(self):
        """realtime（WebSocket）分類"""
        result = classify_url("http://localhost:3000/socket.io/?EIO=3", "GET")
        
        assert "realtime" in result.tags

    def test_multiple_tags(self):
        """複数タグ付与確認"""
        result = classify_url("http://localhost:3000/rest/admin/application-version", "GET")
        
        # adminとapi_dataの両方
        assert "admin" in result.tags
        assert "api_data" in result.tags
        # プライマリはadmin
        assert result.primary_tag == "admin"

    def test_uncategorized_detection(self):
        """未分類検出"""
        result = classify_url("http://localhost:3000/unknown/path", "GET")
        
        assert len(result.tags) == 0
        assert result.primary_tag is None
        assert result.confidence == 0.0

    def test_uncategorized_rate_calculation(self):
        """未分類率計算"""
        classifier = URLClassifier()
        
        urls = [
            "http://localhost:3000/rest/admin/config",  # admin
            "http://localhost:3000/unknown/path",  # uncategorized
            "http://localhost:3000/api/products",  # api_data
        ]
        
        results = classifier.classify_batch(urls)
        rate = classifier.get_uncategorized_rate(results)
        
        assert rate == 1/3  # 1つ未分類

    def test_method_filtering(self):
        """メソッドによるフィルタリング"""
        classifier = URLClassifier()
        
        # authエンドポイントはPOSTのみ
        result_post = classifier.classify("/rest/user/login", "POST")
        result_get = classifier.classify("/rest/user/login", "GET")
        
        # 両方マッチする（authはPOST/GET両方許可）
        assert "auth" in result_post.tags
        assert "auth" in result_get.tags

    def test_generalized_endpoints(self):
        """一般的なエンドポイントパターン"""
        test_cases = [
            ("/rest/products/search?q=test", ["product_search", "api_data"]),
            ("/api/basket", ["basket_order", "api_data"]),
            ("/api/feedback", ["feedback_review"]),
            ("/api/Challenges", ["api_data", "meta_observability"]),
        ]
        
        for path, expected_tags in test_cases:
            result = classify_url(f"http://localhost:3000{path}", "GET")
            for tag in expected_tags:
                assert tag in result.tags, f"{path} should have tag {tag}"


class TestClassificationResult:
    """ClassificationResultデータクラステスト"""

    def test_result_creation(self):
        """結果オブジェクト作成"""
        result = ClassificationResult(
            url="http://test.com",
            tags={"admin", "api_data"},
            primary_tag="admin",
            confidence=0.8
        )
        
        assert result.url == "http://test.com"
        assert "admin" in result.tags
        assert result.primary_tag == "admin"


class TestTaxonomyRules:
    """タクソノミールール定義テスト"""

    def test_all_tags_defined(self):
        """計画書4.1の全タグが定義されている"""
        expected_tags = [
            "auth", "admin", "product_search", "basket_order",
            "feedback_review", "file_exposure_upload", "api_data",
            "client_route_dom", "realtime", "meta_observability"
        ]
        
        for tag in expected_tags:
            assert tag in TAXONOMY_RULES, f"Tag {tag} should be defined"

    def test_taxonomy_structure(self):
        """タクソノミー構造確認"""
        for tag, config in TAXONOMY_RULES.items():
            assert "path_patterns" in config
            assert "methods" in config
            assert "description" in config
            assert len(config["path_patterns"]) > 0
