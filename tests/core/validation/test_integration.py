"""
Integration Tests - URLClassifier + ReconPipeline, FindingValidator + InjectionManagerAgent

Phase A統合テスト
"""
import pytest
import asyncio
from unittest.mock import Mock, patch

from src.core.validation.url_classifier import URLClassifier, classify_url
from src.core.validation.finding_validator import FindingValidator, validate_finding


class TestURLClassifierIntegration:
    """URLClassifier統合テスト"""

    def test_juice_shop_admin_endpoints(self):
        """Juice Shop adminエンドポイント分類"""
        test_urls = [
            ("http://localhost:3000/rest/admin/application-configuration", "admin"),
            ("http://localhost:3000/rest/admin/application-version", "admin"),
        ]
        
        for url, expected_primary in test_urls:
            result = classify_url(url, "GET")
            assert expected_primary in result.tags, f"{url} should be tagged as {expected_primary}"

    def test_juice_shop_auth_endpoints(self):
        """Juice Shop authエンドポイント分類"""
        result = classify_url("http://localhost:3000/rest/user/login", "POST")
        
        assert "auth" in result.tags
        assert result.primary_tag == "auth"

    def test_juice_shop_product_search(self):
        """Juice Shop製品検索分類"""
        result = classify_url("http://localhost:3000/rest/products/search?q=test", "GET")
        
        assert "product_search" in result.tags
        assert "api_data" in result.tags

    def test_uncategorized_rate_for_juice_shop(self):
        """Juice Shopエンドポイントの未分類率計算"""
        classifier = URLClassifier()
        
        # Juice Shopの主要エンドポイント
        urls = [
            "http://localhost:3000/rest/admin/application-configuration",
            "http://localhost:3000/rest/user/login",
            "http://localhost:3000/rest/products/search",
            "http://localhost:3000/api/basket",
            "http://localhost:3000/#/search",
            "http://localhost:3000/unknown/path",
        ]
        
        results = classifier.classify_batch(urls)
        rate = classifier.get_uncategorized_rate(results)
        
        # 6件中1件のみ未分類（unknown/path）
        assert rate == 1/6


class TestFindingValidatorIntegration:
    """FindingValidator統合テスト"""

    def test_thought_only_finding_rejection(self):
        """thought-only findingは拒否される"""
        mock_finding = Mock()
        mock_finding.actions = []
        mock_finding.metadata = {
            "request_url": "http://test.com",
            "response_status": 200,
            "response_body_sample": "test",
        }
        mock_finding.target = "http://test.com"
        
        result = validate_finding(mock_finding)
        
        assert result.reject is True
        assert result.reason == "thought-only"

    def test_valid_finding_with_actions_accepted(self):
        """action付きfindingは採用される"""
        mock_finding = Mock()
        mock_finding.actions = [{"type": "probe", "payload": "test"}]
        mock_finding.metadata = {
            "request_url": "http://test.com",
            "response_status": 200,
            "response_body_sample": "test",
        }
        
        result = validate_finding(mock_finding)
        
        assert result.reject is False


class TestPhaseAReadiness:
    """Phase A実行準備テスト"""

    def test_url_classifier_taxonomy_completeness(self):
        """計画書4.1の10系統タクソノミーが完全に実装されている"""
        from src.core.validation.url_classifier import TAXONOMY_RULES
        
        required_tags = [
            "auth", "admin", "product_search", "basket_order",
            "feedback_review", "file_exposure_upload", "api_data",
            "client_route_dom", "realtime", "meta_observability"
        ]
        
        for tag in required_tags:
            assert tag in TAXONOMY_RULES, f"Tag {tag} must be defined in taxonomy"

    def test_finding_validator_required_keys(self):
        """FindingValidatorの必須キーが定義されている"""
        validator = FindingValidator()
        
        required_keys = {
            "request_url",
            "response_status",
            "response_body_sample"
        }
        
        assert validator.REQUIRED_EVIDENCE_KEYS == required_keys
