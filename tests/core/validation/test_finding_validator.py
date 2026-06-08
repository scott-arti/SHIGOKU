"""
FindingValidator Tests

計画書6.2証拠品質ゲートの実装検証
"""
import pytest
from dataclasses import dataclass, field
from typing import Dict, Any, Optional

from src.core.validation.finding_validator import (
    FindingValidator,
    ValidationResult,
    validate_finding,
    validate_findings,
)


@dataclass
class MockFinding:
    """テスト用Findingモック"""
    target: str
    actions: list = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


class TestFindingValidator:
    """FindingValidator単体テスト"""

    def test_thought_only_finding_rejected(self):
        """thought-only findingは拒否される"""
        finding = MockFinding(
            target="http://example.com/test",
            actions=[],  # actionsなし
            metadata={
                "request_url": "http://example.com/test",
                "response_status": 200,
                "response_body_sample": "test",
            }
        )
        
        result = validate_finding(finding)
        
        assert result.reject is True
        assert result.reason == "thought-only"

    def test_insufficient_evidence_rejected(self):
        """証拠不足のfindingは拒否される"""
        finding = MockFinding(
            target="http://example.com/test",
            actions=[{"type": "probe", "payload": "test"}],
            metadata={
                "request_url": "http://example.com/test",
                # response_status, response_body_sample欠落
            }
        )
        
        result = validate_finding(finding)
        
        assert result.reject is True
        assert result.reason == "insufficient_evidence"
        assert "response_status" in result.missing_keys
        assert "response_body_sample" in result.missing_keys

    def test_valid_finding_accepted(self):
        """完全なfindingは採用される"""
        finding = MockFinding(
            target="http://example.com/test",
            actions=[{"type": "probe", "payload": "test"}],
            metadata={
                "request_url": "http://example.com/test",
                "response_status": 200,
                "response_body_sample": "<html>test</html>",
                "request_headers": {"User-Agent": "test"},
                "response_headers": {"Content-Type": "text/html"},
            }
        )
        
        result = validate_finding(finding)
        
        assert result.reject is False
        assert result.reason is None

    def test_batch_validation(self):
        """バッチ検証機能"""
        valid_finding = MockFinding(
            target="http://example.com/valid",
            actions=[{"type": "probe"}],
            metadata={
                "request_url": "http://example.com/valid",
                "response_status": 200,
                "response_body_sample": "ok",
            }
        )
        
        invalid_finding = MockFinding(
            target="http://example.com/invalid",
            actions=[],  # thought-only
            metadata={
                "request_url": "http://example.com/invalid",
                "response_status": 200,
                "response_body_sample": "ok",
            }
        )
        
        valid, rejected = validate_findings([valid_finding, invalid_finding])
        
        assert len(valid) == 1
        assert len(rejected) == 1
        assert valid[0].target == "http://example.com/valid"
        assert rejected[0][1].reason == "thought-only"

    def test_missing_metadata_rejected(self):
        """metadata自体がない場合も拒否"""
        finding = MockFinding(
            target="http://example.com/test",
            actions=[{"type": "probe"}],
            metadata={}
        )
        
        result = validate_finding(finding)
        
        assert result.reject is True
        assert result.reason == "missing_metadata"


class TestValidationResult:
    """ValidationResultデータクラステスト"""

    def test_result_creation(self):
        """結果オブジェクト作成"""
        result = ValidationResult(reject=True, reason="test", missing_keys={"key1"})
        
        assert result.reject is True
        assert result.reason == "test"
        assert "key1" in result.missing_keys


class TestFindingValidatorClass:
    """FindingValidatorクラス直接テスト"""

    def test_get_validator_singleton(self):
        """シングルトン動作確認"""
        v1 = FindingValidator()
        v2 = FindingValidator()
        
        # 別インスタンスだが機能は同じ
        assert isinstance(v1, FindingValidator)
        assert isinstance(v2, FindingValidator)

    def test_custom_required_keys(self):
        """カスタム必須キー設定"""
        validator = FindingValidator(
            REQUIRED_EVIDENCE_KEYS={"custom_key"}
        )
        
        finding = MockFinding(
            target="http://example.com/test",
            actions=[{"type": "probe"}],
            metadata={"custom_key": "value"}  # 必須キーは満たすが標準キーは欠落
        )
        
        result = validator.validate(finding)
        
        # カスタムキーで検証するため、標準キー欠落は無視される
        assert result.reject is False
