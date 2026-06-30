from __future__ import annotations

from src.core.detection.xss_detector import XSSDetectionEngine


def test_xss_detection_engine_does_not_expose_stored_xss_placeholder():
    """Stored XSS probing lives in stored_xss_detector.py, not this generic engine."""
    assert not hasattr(XSSDetectionEngine, "detect_stored_xss")
