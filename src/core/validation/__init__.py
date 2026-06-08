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
    # URL Classifier
    "URLClassifier",
    "ClassificationResult",
    "classify_url",
    "classify_urls",
    "get_classifier",
    "TAXONOMY_RULES",
]
