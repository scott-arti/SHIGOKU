"""
FindingValidator Tests - SGK-2026-0443 shared hybrid confirmation contract

- Legacy-compat: instance validate() / validate_batch() semantics stay
  byte-identical (thought-only / missing_metadata / insufficient_evidence;
  batch splits valid/rejected) so the manager wiring gate
  (finding_validator_rejected) remains guarded.
- New contract: validate_finding / validate_findings return HybridVerdict;
  get_validator() stays a singleton.

Detailed hybrid state-transition tests (f1-f12) live in
test_hybrid_verdict_selfcheck.py.
"""
import pytest
from dataclasses import dataclass, field
from typing import Dict, Any

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.validation.finding_validator import (
    FindingValidator,
    ValidationResult,
    VerdictState,
    validate_finding,
    validate_findings,
    get_validator,
)


@dataclass
class MockFinding:
    """テスト用Findingモック（レガシー validate() 用）"""
    target: str
    actions: list = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    description: str = ""


def make_floor_pass_xss_finding() -> Finding:
    """機械フロアを通過する XSS finding（製品非依存 fixture）。"""
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected payload in search response",
        description="A generic reflected-XSS style finding.",
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


class TestFindingValidatorLegacyCompat:
    """レガシー API（manager.py 配線が依存）の互換性を固定するテスト"""

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

        result = FindingValidator().validate(finding)

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

        result = FindingValidator().validate(finding)

        assert result.reject is True
        assert result.reason == "insufficient_evidence"
        assert "response_status" in result.missing_keys
        assert "response_body_sample" in result.missing_keys

    def test_missing_metadata_rejected(self):
        """metadata自体がない場合も拒否"""
        finding = MockFinding(
            target="http://example.com/test",
            actions=[{"type": "probe"}],
            metadata={}
        )

        result = FindingValidator().validate(finding)

        assert result.reject is True
        assert result.reason == "missing_metadata"

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

        result = FindingValidator().validate(finding)

        assert result.reject is False
        assert result.reason is None

    def test_batch_validation_splits_valid_and_rejected(self):
        """バッチ検証機能（採用/不採用の分離）"""
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

        valid, rejected = FindingValidator().validate_batch(
            [valid_finding, invalid_finding]
        )

        assert len(valid) == 1
        assert len(rejected) == 1
        assert valid[0].target == "http://example.com/valid"
        assert rejected[0][1].reason == "thought-only"

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

    def test_required_and_recommended_keys_unchanged(self):
        """必須/推奨キーセットは従来どおり"""
        validator = FindingValidator()
        assert validator.REQUIRED_EVIDENCE_KEYS == {
            "request_url",
            "response_status",
            "response_body_sample",
        }
        assert validator.RECOMMENDED_EVIDENCE_KEYS == {
            "request_headers",
            "response_headers",
            "request_payload",
            "response_time_ms",
            "evidence_timestamp",
        }


class TestValidationResult:
    """ValidationResultデータクラステスト"""

    def test_result_creation(self):
        """結果オブジェクト作成"""
        result = ValidationResult(reject=True, reason="test", missing_keys={"key1"})

        assert result.reject is True
        assert result.reason == "test"
        assert "key1" in result.missing_keys


class TestHybridContract:
    """SGK-2026-0443 新契約（モジュール関数）"""

    def test_validate_finding_returns_hybrid_verdict(self):
        """validate_finding は HybridVerdict を返す（AI 未実行 → needs_more）"""
        finding = make_floor_pass_xss_finding()

        verdict = validate_finding(finding)

        assert isinstance(verdict.state, VerdictState)
        assert verdict.state == VerdictState.NEEDS_MORE
        assert verdict.reason == "ai_judgement_pending"
        assert verdict.ai_judgement is None
        assert verdict.reproduction.status == "not_run"
        # 遅延評価: rule 4 で早期退出するため再現チェックは未実施（走らせない）
        assert verdict.reproduction.reason == "reproduction_not_performed"
        assert verdict.mechanical_floor.payout_grade is True
        assert 0.0 <= verdict.promise_score <= 1.0

    def test_validate_findings_preserves_input_order(self):
        """validate_findings は入力順の HybridVerdict リストを返す"""
        first = make_floor_pass_xss_finding()
        second = make_floor_pass_xss_finding()
        second.title = "Second generic finding"

        verdicts = validate_findings([first, second])

        assert isinstance(verdicts, list)
        assert len(verdicts) == 2
        assert all(isinstance(v.state, VerdictState) for v in verdicts)
        assert verdicts[0].reason == "ai_judgement_pending"
        assert verdicts[1].reason == "ai_judgement_pending"

    def test_get_validator_singleton_unchanged(self):
        """get_validator() はシングルトンのまま"""
        v1 = get_validator()
        v2 = get_validator()

        assert v1 is v2
        assert isinstance(v1, FindingValidator)
