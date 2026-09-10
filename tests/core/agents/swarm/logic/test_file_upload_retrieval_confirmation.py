"""
SGK-2026-0480 — file_upload engine/tester/payload 単体テスト
（一意マーカー往復で本物証跡を記録する経路）。

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性マーカー）。
- payload_manager.get_probe_payload: 実行毎に一意なマーカー（marker フィールド＋
  content にそのまま含まれる・非実行のまま）。
- FileUploadTester._verify_retrieval: 取得本文に一意マーカー再出現 →
  retrieved=True ＋ retrieval_marker 記録（＋取得本文抜粋 telemetry）。
  非出現 → retrieved=False（マーカー記録なし）。
- FileUploadSpecialist.execute: retrieved＋retrieval_marker で impact /
  reproduction_steps / file_upload_evidence.retrieval_marker /
  evidence.response_body（取得本文抜粋入り）を設定。非取得は従来どおり付けない。
"""
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.core.agents.swarm.logic.file_upload import FileUploadSpecialist
from src.core.attack.file_upload_tester import FileUploadTester, UploadResult
from src.core.attack.path_predictor import SuggestedPath
from src.core.attack.payload_manager import PayloadManager, UploadPayload
from src.core.domain.model.task import Task
from src.core.infra.network_client import NetworkResponse

TARGET_URL = "https://target.example/upload"
RETRIEVAL_URL = "https://target.example/uploads/probe_fixed.jpg"
MARKER = "SHIGOKU_PROBE_0123456789abcdef"
FILENAME = "probe_fixed.jpg"


def _probe_payload() -> UploadPayload:
    return UploadPayload(
        filename=FILENAME,
        content=MARKER.encode(),
        mime_type="image/jpeg",
        technique="Safe Canary Upload Probe",
        marker=MARKER,
    )


def _http_response(status: int, text: str) -> MagicMock:
    resp = MagicMock(spec=NetworkResponse)
    resp.status = status
    resp.text = text
    resp.headers = {}
    return resp


# ---------------------------------------------------------------------------
# payload_manager — per-run unique marker
# ---------------------------------------------------------------------------


class TestPayloadManagerMarker:
    def test_probe_payload_carries_unique_marker(self) -> None:
        manager = PayloadManager()
        p1 = manager.get_probe_payload()
        p2 = manager.get_probe_payload()
        # 実行毎に一意なマーカー（同一固定文字列に退化しない）。
        assert p1.marker != p2.marker
        assert p1.marker.startswith("SHIGOKU_PROBE_")
        assert len(p1.marker) > len("SHIGOKU_PROBE_")
        # マーカー文字列が content にそのまま含まれる（後段が復元可能）。
        assert p1.marker.encode() == p1.content
        # 良性・非実行のまま（content はマーカーのみ・画像 MIME 指定）。
        assert p1.mime_type == "image/jpeg"
        assert p1.technique == "Safe Canary Upload Probe"


# ---------------------------------------------------------------------------
# FileUploadTester — retrieval marker round-trip
# ---------------------------------------------------------------------------


class TestFileUploadTesterRetrievalMarker:
    @pytest.mark.asyncio
    async def test_retrieval_match_records_marker(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock()
        client.close = AsyncMock()
        client.request.side_effect = [
            _http_response(200, "upload form"),                      # baseline GET
            _http_response(200, f"file successfully uploaded to {RETRIEVAL_URL}"),  # POST
            _http_response(200, f"stored canary prefix {MARKER} suffix"),           # GET retrieval
        ]
        tester = FileUploadTester(client=client)
        tester.payload_manager.get_probe_payload = lambda: _probe_payload()

        results = await tester.test_upload(
            target_url=TARGET_URL,
            aggressive=True,
            safe_only=True,
        )

        assert len(results) == 1
        res = results[0]
        assert res.retrieved is True
        assert res.retrieval_url == RETRIEVAL_URL
        assert res.retrieval_marker == MARKER
        excerpt = res.delivery_telemetry.get("retrieval_body_excerpt", "")
        assert isinstance(excerpt, str) and MARKER in excerpt

    @pytest.mark.asyncio
    async def test_retrieval_marker_absent_stays_false(self) -> None:
        """マーカー非出現 → retrieved=False のまま（retrieval_marker 空・
        fail-closed）。"""
        client = AsyncMock()
        client.request = AsyncMock()
        client.close = AsyncMock()
        client.request.side_effect = [
            _http_response(200, "upload form"),                      # baseline GET
            _http_response(200, f"file successfully uploaded to {RETRIEVAL_URL}"),  # POST
            _http_response(200, "<html>no stored file</html>"),      # GET retrieval (no marker)
        ]
        tester = FileUploadTester(client=client)
        tester.payload_manager.get_probe_payload = lambda: _probe_payload()

        results = await tester.test_upload(
            target_url=TARGET_URL,
            aggressive=True,
            safe_only=True,
        )

        assert len(results) == 1
        assert results[0].retrieved is False
        assert results[0].retrieval_marker == ""


# ---------------------------------------------------------------------------
# FileUploadSpecialist — engine Finding construction
# ---------------------------------------------------------------------------


def _upload_result(*, retrieved: bool, marker: str = "") -> UploadResult:
    return UploadResult(
        success=True,
        technique="Safe Canary Upload Probe",
        filename=FILENAME,
        mime_type="image/jpeg",
        status_code=200,
        response_body=f"Status: 200 stored at {RETRIEVAL_URL}",
        suggested_paths=[
            SuggestedPath(
                url=RETRIEVAL_URL,
                tier=0,
                reason="Upload response referenced the stored file path",
                score=95,
            )
        ],
        evidence=(
            f"Server accepted '{FILENAME}' using Safe Canary Upload Probe"
            + (f"; retrieved at {RETRIEVAL_URL}" if retrieved else "")
        ),
        retrieved=retrieved,
        retrieval_url=RETRIEVAL_URL if retrieved else "",
        retrieval_status=200 if retrieved else 0,
        retrieval_marker=marker,
        delivery_telemetry={
            "upload_status": 200,
            "body_length": 64,
            "content_type": "image/jpeg",
            "delivered": True,
        },
    )


def _make_task() -> Task:
    return Task(
        id="file-upload-confirm-task",
        name="File Upload Vulnerability Scan",
        agent_type="LogicSwarm",
        action="scan",
        phase="attack",
        target=TARGET_URL,
        params={
            "target": TARGET_URL,
            "param_name": "file",
            "extra_params": {"Submit": "Upload"},
            "safe_only": True,
        },
    )


class TestFileUploadSpecialistEvidence:
    @pytest.mark.asyncio
    async def test_retrieved_with_marker_sets_impact_and_repro(self, monkeypatch) -> None:
        async def fake_test_upload(self, **_kwargs):
            return [_upload_result(retrieved=True, marker=MARKER)]

        monkeypatch.setattr(
            "src.core.agents.swarm.logic.file_upload.FileUploadTester.test_upload",
            fake_test_upload,
        )
        specialist = FileUploadSpecialist()
        specialist._client.close = AsyncMock()
        findings = await specialist.execute(_make_task())
        await specialist.close()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.impact
        assert len(finding.reproduction_steps) >= 3
        upload_evidence = finding.additional_info["file_upload_evidence"]
        assert upload_evidence["retrieval_marker"] == MARKER
        assert finding.evidence.response_body
        assert MARKER in finding.evidence.response_body
        assert "Retrieval URL" in finding.evidence.response_body
        assert finding.confidence == 0.9

    @pytest.mark.asyncio
    async def test_not_retrieved_leaves_no_marker_evidence(self, monkeypatch) -> None:
        """retrieved=False は impact/repro/retrieval_marker を付けない
        （従来どおり・fail-closed）。"""
        async def fake_test_upload(self, **_kwargs):
            return [_upload_result(retrieved=False)]

        monkeypatch.setattr(
            "src.core.agents.swarm.logic.file_upload.FileUploadTester.test_upload",
            fake_test_upload,
        )
        specialist = FileUploadSpecialist()
        specialist._client.close = AsyncMock()
        findings = await specialist.execute(_make_task())
        await specialist.close()

        assert len(findings) == 1
        finding = findings[0]
        assert finding.impact == ""
        assert finding.reproduction_steps == []
        upload_evidence = finding.additional_info["file_upload_evidence"]
        assert "retrieval_marker" not in upload_evidence
        assert "Retrieval Marker" not in finding.evidence.response_body
        assert finding.confidence == 0.7
