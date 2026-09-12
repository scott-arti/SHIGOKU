"""
SGK-2026-0481 — FileUploadSpecialist のアップロード経由保存型XSSモード単体テスト。

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性 XSS ペイロード）。
ブラウザ実物は起動しない（PlaywrightValidator をスタブ差し替え）。

- dialog 発火かつ observed == nonce → vuln_type=XSS の Finding を1件発行し、
  browser_execution(variant=stored/test_url/nonce/nonce_match=True)・impact・
  reproduction_steps を設定。
- 非発火 / nonce 不一致 / 取得不可 / ブラウザ例外 → Finding なし（fail-closed）。
"""
from unittest.mock import AsyncMock

import pytest

import src.core.agents.swarm.logic.file_upload as file_upload_module
from src.core.agents.swarm.logic.file_upload import FileUploadSpecialist
from src.core.domain.model.task import Task

TARGET_URL = "https://target.example/upload"
RETRIEVAL_URL = "https://target.example/uploads/probe_xss_fixed.html"
NONCE = "sgkaabbccddeeff"


class _FakeSecrets:
    @staticmethod
    def token_hex(n: int = 6) -> str:
        return NONCE[3:]


class _FiringValidator:
    """validate_xss が True を返し、dialog message を観測ログに積む。"""

    message = NONCE

    def __init__(self) -> None:
        self._last_observation_logs = [
            {"type": "dialog", "dialog_type": "alert", "message": self.message}
        ]

    async def validate_xss(self, url, timeout=10.0, cookies=None):
        self.last_url = url
        self.last_cookies = cookies
        return True


class _MismatchValidator(_FiringValidator):
    message = "someone-else-message"


class _SilentValidator:
    def __init__(self) -> None:
        self._last_observation_logs = []

    async def validate_xss(self, url, timeout=10.0, cookies=None):
        return False


class _RaisingValidator:
    def __init__(self) -> None:
        self._last_observation_logs = []

    async def validate_xss(self, url, timeout=10.0, cookies=None):
        raise RuntimeError("browser tool unavailable")


def _make_task(*, headers=None) -> Task:
    params = {
        "target": TARGET_URL,
        "param_name": "uploaded",
        "extra_params": {"Upload": "Upload"},
        "safe_only": True,
        "xss_via_upload": True,
    }
    if headers is not None:
        params["headers"] = headers
    return Task(
        id="stored-xss-upload-task",
        name="Stored XSS via Upload",
        agent_type="LogicSwarm",
        action="scan",
        phase="attack",
        target=TARGET_URL,
        params=params,
    )


def _patch_locate(monkeypatch, result=(RETRIEVAL_URL, NONCE)) -> dict:
    captured: dict = {}

    async def fake_locate(
        self, target_url, param_name="file", payload=None, extra_params=None, auth_headers=None
    ):
        captured["payload"] = payload
        captured["param_name"] = param_name
        captured["extra_params"] = extra_params
        captured["auth_headers"] = auth_headers
        return result

    monkeypatch.setattr(
        file_upload_module.FileUploadTester, "locate_uploaded", fake_locate
    )
    return captured


def _patch_validator(monkeypatch, validator_cls) -> None:
    import src.tools.browser.playwright_validator as playwright_validator_module

    monkeypatch.setattr(
        playwright_validator_module, "PlaywrightValidator", validator_cls
    )


async def _run(monkeypatch, validator_cls, *, locate_result=(RETRIEVAL_URL, NONCE)):
    _patch_locate(monkeypatch, locate_result)
    _patch_validator(monkeypatch, validator_cls)
    monkeypatch.setattr(file_upload_module, "secrets", _FakeSecrets())
    specialist = FileUploadSpecialist()
    specialist._client.close = AsyncMock()
    findings = await specialist.execute(
        _make_task(headers={"Cookie": "sid=abc; theme=dark"})
    )
    await specialist.close()
    return findings


class TestStoredXssViaUpload:
    @pytest.mark.asyncio
    async def test_dialog_nonce_match_emits_xss_finding(self, monkeypatch) -> None:
        captured = _patch_locate(monkeypatch)
        _patch_validator(monkeypatch, _FiringValidator)
        monkeypatch.setattr(file_upload_module, "secrets", _FakeSecrets())
        specialist = FileUploadSpecialist()
        specialist._client.close = AsyncMock()

        findings = await specialist.execute(_make_task(headers={"Cookie": "sid=abc"}))
        await specialist.close()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.vuln_type.value == "xss"
        assert finding.severity.value == "high"
        assert finding.source_agent == "FileUploadSpecialist"
        assert finding.impact
        assert len(finding.reproduction_steps) >= 3
        assert {"xss", "file_upload", "stored"}.issubset(set(finding.tags))

        browser_execution = finding.additional_info["browser_execution"]
        assert browser_execution["dialog_observed"] is True
        assert browser_execution["executor"] == "playwright"
        assert browser_execution["variant"] == "stored"
        assert browser_execution["parameter"] == "uploaded"
        assert browser_execution["test_url"] == RETRIEVAL_URL
        assert browser_execution["nonce"] == NONCE
        assert browser_execution["observed_dialog_message"] == NONCE
        assert browser_execution["nonce_match"] is True
        assert NONCE in browser_execution["payload"]

        assert finding.evidence.request_method == "GET"
        assert finding.evidence.request_url == RETRIEVAL_URL
        assert finding.evidence.response_status == 200
        for token in ("test_url=", "injected_nonce=", "observed_dialog_message=", "nonce_match=True"):
            assert token in finding.evidence.response_body
        assert NONCE in finding.evidence.response_body

        # アップロードした payload は nonce 入り良性 HTML（サーバ実行コードなし）。
        uploaded = captured["payload"]
        assert NONCE in uploaded.content.decode()
        assert "<?php" not in uploaded.content.decode()
        assert captured["param_name"] == "uploaded"

    @pytest.mark.asyncio
    async def test_dialog_not_fired_emits_nothing(self, monkeypatch) -> None:
        findings = await _run(monkeypatch, _SilentValidator)
        assert findings == []

    @pytest.mark.asyncio
    async def test_dialog_nonce_mismatch_emits_nothing(self, monkeypatch) -> None:
        findings = await _run(monkeypatch, _MismatchValidator)
        assert findings == []

    @pytest.mark.asyncio
    async def test_browser_exception_emits_nothing(self, monkeypatch) -> None:
        findings = await _run(monkeypatch, _RaisingValidator)
        assert findings == []

    @pytest.mark.asyncio
    async def test_retrieval_unavailable_emits_nothing(self, monkeypatch) -> None:
        findings = await _run(
            monkeypatch, _FiringValidator, locate_result=("", "")
        )
        assert findings == []


class TestCookieConversion:
    def test_cookie_header_to_playwright_cookies(self) -> None:
        cookies = FileUploadSpecialist._cookies_from_headers(
            {"Cookie": "sid=abc; theme=dark"}, "https://target.example/x"
        )
        assert cookies == [
            {"name": "sid", "value": "abc", "domain": "target.example", "path": "/"},
            {"name": "theme", "value": "dark", "domain": "target.example", "path": "/"},
        ]

    def test_missing_or_empty_cookie_yields_empty_list(self) -> None:
        assert FileUploadSpecialist._cookies_from_headers(None, TARGET_URL) == []
        assert (
            FileUploadSpecialist._cookies_from_headers({"Cookie": ""}, TARGET_URL) == []
        )
        assert FileUploadSpecialist._cookies_from_headers({"X": "y"}, TARGET_URL) == []
