"""
Core Validation Module

証拠品質ゲートとURL分類機能を提供するモジュール
"""
from src.core.validation.finding_validator import (
    FindingValidator,
    ValidationResult,
    validate_finding,
    validate_findings,
    get_validator,
    VerdictState,
    HybridVerdict,
    AiJudgement,
    ReproductionOutcome,
    ReproductionChecker,
    NoopReproductionChecker,
    PoCJudge,
)
from src.core.validation.url_classifier import (
    URLClassifier,
    ClassificationResult,
    classify_url,
    classify_urls,
    get_classifier,
    TAXONOMY_RULES,
)

__all__ = [
    # Finding Validator
    "FindingValidator",
    "ValidationResult",
    "validate_finding",
    "validate_findings",
    "get_validator",
    # SGK-2026-0443 Hybrid Verdict (swarm-path advisory determination)
    "VerdictState",
    "HybridVerdict",
    "AiJudgement",
    "ReproductionOutcome",
    "ReproductionChecker",
    "NoopReproductionChecker",
    "PoCJudge",
    # URL Classifier
    "URLClassifier",
    "ClassificationResult",
    "classify_url",
    "classify_urls",
    "get_classifier",
    "TAXONOMY_RULES",
]
