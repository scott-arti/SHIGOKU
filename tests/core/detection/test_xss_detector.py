"""
XSSDetectionEngine unit tests.
"""
import pytest
from unittest.mock import AsyncMock, patch

from src.core.detection.xss_detector import XSSDetectionEngine


class _StoredXSSVerificationResult:
    executed = True
    evidence = {
        "method": "playwright_dialog",
        "url": "http://example.com/display",
        "dialog_message": "xss",
    }


class _StoredXSSNoExecResult:
    executed = False
    evidence = {}


class _MockStoredVerifier:
    def __init__(self, result):
        self._result = result
        self.calls = []

    async def verify_stored(self, url: str, payload: str, *, dialog_timeout: float = 3.0):
        self.calls.append({"url": url, "payload": payload, "dialog_timeout": dialog_timeout})
        return self._result

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_detect_stored_xss_opens_display_url_directly(monkeypatch):
    """
    detect_stored_xss opens display_url directly (without ?param=payload)
    and returns browser_confirmed=True when the stored payload fires.
    """
    engine = XSSDetectionEngine()
    mock_verifier = _MockStoredVerifier(_StoredXSSVerificationResult())

    monkeypatch.setattr(
        "src.core.detection.xss_detector.BrowserPoolXSSVerifier",
        lambda **kwargs: mock_verifier,
    )

    with patch(
        "src.core.agents.swarm.injection.stored_xss_detector.StoredXSSDetector._submit_form",
        new=AsyncMock(return_value=(True, "", {})),
    ):
        finding = await engine.detect_stored_xss(
            storage_url="http://example.com/store",
            display_url="http://example.com/display",
            param="q",
            payload="<script>alert(1)</script>",
        )

    assert finding is not None
    assert finding.type == "stored"
    assert finding.browser_confirmed is True
    assert finding.target == "http://example.com/display"
    assert finding.endpoint == "http://example.com/store"
    assert finding.param == "q"
    assert finding.payload == "<script>alert(1)</script>"

    assert len(mock_verifier.calls) == 1
    call = mock_verifier.calls[0]
    assert call["url"] == "http://example.com/display"
    assert "?q=" not in call["url"]
    assert call["payload"] == "<script>alert(1)</script>"


@pytest.mark.asyncio
async def test_detect_stored_xss_returns_none_when_no_execution(monkeypatch):
    """detect_stored_xss returns None when the stored payload does not fire."""
    engine = XSSDetectionEngine()
    mock_verifier = _MockStoredVerifier(_StoredXSSNoExecResult())

    monkeypatch.setattr(
        "src.core.detection.xss_detector.BrowserPoolXSSVerifier",
        lambda **kwargs: mock_verifier,
    )

    with patch(
        "src.core.agents.swarm.injection.stored_xss_detector.StoredXSSDetector._submit_form",
        new=AsyncMock(return_value=(True, "", {})),
    ):
        finding = await engine.detect_stored_xss(
            storage_url="http://example.com/store",
            display_url="http://example.com/display",
            param="q",
            payload="<script>alert(1)</script>",
        )

    assert finding is None


@pytest.mark.asyncio
async def test_detect_stored_xss_returns_none_on_submit_failure(monkeypatch):
    """detect_stored_xss returns None when payload submission fails."""
    engine = XSSDetectionEngine()
    mock_verifier = _MockStoredVerifier(_StoredXSSVerificationResult())

    monkeypatch.setattr(
        "src.core.detection.xss_detector.BrowserPoolXSSVerifier",
        lambda **kwargs: mock_verifier,
    )

    with patch(
        "src.core.agents.swarm.injection.stored_xss_detector.StoredXSSDetector._submit_form",
        new=AsyncMock(return_value=(False, "", {})),
    ):
        finding = await engine.detect_stored_xss(
            storage_url="http://example.com/store",
            display_url="http://example.com/display",
            param="q",
            payload="<script>alert(1)</script>",
        )

    assert finding is None
    assert len(mock_verifier.calls) == 0
