"""
Integration Tests - URLClassifier + ReconPipeline, FindingValidator + InjectionManagerAgent

Phase A統合テスト

SGK-2026-0443: FindingValidator セクションは新契約（HybridVerdict）に更新。
URLClassifier テストは無変更。
"""
import pytest
import asyncio
from unittest.mock import Mock, patch

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.url_classifier import URLClassifier, classify_url
from src.core.validation.finding_validator import (
    FindingValidator,
    VerdictState,
    validate_finding,
)


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
    """FindingValidator統合テスト（SGK-2026-0443 新契約）"""

    def test_validate_finding_returns_hybrid_verdict(self):
        """validate_finding は HybridVerdict を返す（AI 未実行 → needs_more）"""
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="Reflected payload in search response",
            description="Generic reflected-XSS style finding.",
            target_url="https://target.example/",
            evidence=Evidence(
                request_method="GET",
                request_url="https://target.example/search?q=probe",
                response_status=200,
                response_body='<html><script>alert(1)</script></html>',
            ),
            reproduction_steps=["Send the probe request", "Observe the reflected payload"],
            impact="Session hijack via reflected payload execution.",
        )

        result = validate_finding(finding)

        assert isinstance(result.state, VerdictState)
        assert result.state == VerdictState.NEEDS_MORE
        assert result.reason == "ai_judgement_pending"
        assert result.ai_judgement is None

    def test_legacy_validate_still_rejects_thought_only(self):
        """レガシー validate() は thought-only を拒否し続ける（manager 配線用）"""
        mock_finding = Mock()
        mock_finding.actions = []
        mock_finding.metadata = {
            "request_url": "http://test.com",
            "response_status": 200,
            "response_body_sample": "test",
        }
        mock_finding.target = "http://test.com"

        result = FindingValidator().validate(mock_finding)

        assert result.reject is True
        assert result.reason == "thought-only"

    def test_legacy_validate_accepts_action_finding(self):
        """レガシー validate() は action 付き finding を採用し続ける"""
        mock_finding = Mock()
        mock_finding.actions = [{"type": "probe", "payload": "test"}]
        mock_finding.metadata = {
            "request_url": "http://test.com",
            "response_status": 200,
            "response_body_sample": "test",
        }

        result = FindingValidator().validate(mock_finding)

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
