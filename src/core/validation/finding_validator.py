"""
Finding Validator - 証拠品質ゲート実装

アクション优先の判定ゲート: thought-only findingsを自動フィルタリングし、
request/response証跡付きのfindingのみを採用する。
"""
from dataclasses import dataclass, field
from typing import Set, Optional, Any


@dataclass
class ValidationResult:
    """検証結果"""
    reject: bool
    reason: Optional[str] = None
    missing_keys: Optional[Set[str]] = None


@dataclass
class FindingValidator:
    """
    Findingの証拠品質を検証するクラス
    
    アクション优先の判定ゲート:
    - thoughtのみのfindingは不採用
    - request/responseの実データが必要
    - 再送で再現可能であること
    """
    
    # 必須証拠キー
    REQUIRED_EVIDENCE_KEYS: Set[str] = field(
        default_factory=lambda: {
            "request_url",
            "response_status",
            "response_body_sample"
        }
    )
    
    # 推奨証拠キー（警告用）
    RECOMMENDED_EVIDENCE_KEYS: Set[str] = field(
        default_factory=lambda: {
            "request_headers",
            "response_headers",
            "request_payload",
            "response_time_ms",
            "evidence_timestamp"
        }
    )
    
    def validate(self, finding: Any) -> ValidationResult:
        """
        Findingの検証
        
        Args:
            finding: Findingオブジェクトまたは類似のdataclass
            
        Returns:
            ValidationResult: reject=Trueで不採用、reasonで理由を返す
        """
        # thought-onlyチェック
        if not hasattr(finding, 'actions') or not finding.actions:
            return ValidationResult(
                reject=True,
                reason="thought-only",
                missing_keys=None
            )
        
        # メタデータチェック
        if not hasattr(finding, 'metadata') or not finding.metadata:
            return ValidationResult(
                reject=True,
                reason="missing_metadata",
                missing_keys=self.REQUIRED_EVIDENCE_KEYS
            )
        
        # 必須キーの存在確認
        metadata_keys = set(finding.metadata.keys())
        missing_required = self.REQUIRED_EVIDENCE_KEYS - metadata_keys
        
        if missing_required:
            return ValidationResult(
                reject=True,
                reason="insufficient_evidence",
                missing_keys=missing_required
            )
        
        # 推奨キーの欠落確認（警告のみ、不採用にはしない）
        missing_recommended = self.RECOMMENDED_EVIDENCE_KEYS - metadata_keys
        if missing_recommended:
            # 警告ログは呼び出し側で出力
            pass
        
        return ValidationResult(reject=False)
    
    def validate_batch(self, findings: list) -> tuple:
        """
        複数findingのバッチ検証
        
        Args:
            findings: Findingオブジェクトのリスト
            
        Returns:
            (valid_findings, rejected_findings): 採用/不採用の分離結果
        """
        valid = []
        rejected = []
        
        for finding in findings:
            result = self.validate(finding)
            if result.reject:
                rejected.append((finding, result))
            else:
                valid.append(finding)
        
        return valid, rejected


# グローバルインスタンス（シングルトン風）
_default_validator: Optional[FindingValidator] = None


def get_validator() -> FindingValidator:
    """デフォルトバリデータ取得"""
    global _default_validator
    if _default_validator is None:
        _default_validator = FindingValidator()
    return _default_validator


def validate_finding(finding: Any, validator: Optional[FindingValidator] = None) -> ValidationResult:
    """グローバル関数: single finding検証"""
    v = validator or get_validator()
    return v.validate(finding)


def validate_findings(findings: list, validator: Optional[FindingValidator] = None) -> tuple:
    """グローバル関数: batch検証"""
    v = validator or get_validator()
    return v.validate_batch(findings)
