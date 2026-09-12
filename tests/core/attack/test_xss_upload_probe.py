"""
SGK-2026-0481 — アップロード経由の保存型XSS: payload_manager / file_upload_tester
単体テスト。

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性 XSS ペイロード・
製品固有 token なし）。
- payload_manager.get_xss_probe_payload(nonce): nonce 入り良性 HTML・mime
  text/html・サーバ側実行コードなし。
- FileUploadTester.locate_uploaded: アップロード→保存先候補抽出→nonce 往復 GET で
  (retrieval_url, retrieval_marker) を確定。nonce 非出現/アップロード拒否は
  ("", "")（fail-closed）。
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.attack.file_upload_tester import FileUploadTester
from src.core.attack.payload_manager import PayloadManager
from src.core.infra.network_client import NetworkResponse

TARGET_URL = "https://target.example/upload"
NONCE = "sgk0123456789ab"


def _http_response(status: int, text: str) -> MagicMock:
    resp = MagicMock(spec=NetworkResponse)
    resp.status = status
    resp.text = text
    resp.headers = {}
    return resp


class TestXssProbePayload:
    def test_embeds_nonce_in_benign_html(self) -> None:
        manager = PayloadManager()
        payload = manager.get_xss_probe_payload(NONCE)

        assert payload.mime_type == "text/html"
        assert payload.filename.endswith(".html")
        assert payload.technique == "stored_xss_via_upload"
        content = payload.content.decode()
        assert NONCE in content
        assert "<img" in content
        assert f"onerror=alert('{NONCE}')" in content
        # サーバ側実行コードは含めない（非破壊・alert のみ）。
        assert "<?php" not in content
        # nonce は marker にも設定され、本文 nonce 一致で取得判定できる。
        assert payload.marker == NONCE

    def test_filename_is_unique_per_call(self) -> None:
        manager = PayloadManager()
        first = manager.get_xss_probe_payload(NONCE).filename
        second = manager.get_xss_probe_payload(NONCE).filename
        assert first != second


class TestLocateUploaded:
    @pytest.mark.asyncio
    async def test_nonce_roundtrip_confirms_retrieval_url(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock()
        client.close = AsyncMock()
        payload = PayloadManager().get_xss_probe_payload(NONCE)
        retrieval_url = f"https://target.example/uploads/{payload.filename}"
        client.request.side_effect = [
            _http_response(200, "upload form"),  # baseline GET
            _http_response(
                200, f"file successfully uploaded to /uploads/{payload.filename}"
            ),  # upload POST
            # 取得本文には nonce のみ（HTML 全体一致に依存しないことの証明）。
            _http_response(200, f"stored bytes: {NONCE}"),  # retrieval GET
        ]
        tester = FileUploadTester(client=client)

        url, marker = await tester.locate_uploaded(
            TARGET_URL, "file", payload, {}, {"Cookie": "sid=abc"}
        )

        assert url == retrieval_url
        assert marker == NONCE

    @pytest.mark.asyncio
    async def test_missing_nonce_fails_closed(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock()
        client.close = AsyncMock()
        payload = PayloadManager().get_xss_probe_payload(NONCE)
        client.request.side_effect = [
            _http_response(200, "upload form"),
            _http_response(
                200, f"file successfully uploaded to /uploads/{payload.filename}"
            ),
            _http_response(200, "<html>no stored file</html>"),
        ]
        tester = FileUploadTester(client=client)

        url, marker = await tester.locate_uploaded(TARGET_URL, "file", payload, {}, None)

        assert url == ""
        assert marker == ""

    @pytest.mark.asyncio
    async def test_rejected_upload_fails_closed(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock()
        client.close = AsyncMock()
        client.request.side_effect = [
            _http_response(200, "upload form"),
            _http_response(200, "invalid file type"),
        ]
        tester = FileUploadTester(client=client)
        payload = PayloadManager().get_xss_probe_payload(NONCE)

        url, marker = await tester.locate_uploaded(TARGET_URL, "file", payload, {}, None)

        assert url == ""
        assert marker == ""
