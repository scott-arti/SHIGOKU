from unittest.mock import AsyncMock

import pytest

from src.core.agents.swarm.logic.file_upload import FileUploadSpecialist
from src.core.attack.file_upload_tester import UploadResult
from src.core.attack.path_predictor import SuggestedPath
from src.core.domain.model.task import Task


@pytest.mark.asyncio
async def test_file_upload_specialist_records_real_request_and_response_evidence(monkeypatch):
    captured_extra_params = {}

    async def fake_test_upload(self, **_kwargs):
        nonlocal captured_extra_params
        captured_extra_params = _kwargs.get("extra_params")
        return [
            UploadResult(
                success=True,
                technique="Safe Canary Upload Probe",
                filename="probe_fixed.jpg",
                mime_type="image/jpeg",
                status_code=200,
                response_body="../../hackable/uploads/probe_fixed.jpg successfully uploaded!",
                suggested_paths=[
                    SuggestedPath(
                        url="http://localhost:4280/hackable/uploads/probe_fixed.jpg",
                        tier=0,
                        reason="Upload response referenced the stored file path",
                        score=95,
                    )
                ],
                evidence=(
                    "Server accepted 'probe_fixed.jpg' using Safe Canary Upload Probe; "
                    "retrieved at http://localhost:4280/hackable/uploads/probe_fixed.jpg"
                ),
                retrieved=True,
                retrieval_url="http://localhost:4280/hackable/uploads/probe_fixed.jpg",
                retrieval_status=200,
                delivery_telemetry={
                    "upload_status": 200,
                    "body_length": 128,
                    "content_type": "text/html",
                    "delivered": True,
                    "retrieval_attempts": [
                        {
                            "url": "http://localhost:4280/hackable/uploads/probe_fixed.jpg",
                            "status": 200,
                            "body_length": 24,
                        }
                    ],
                },
            )
        ]

    monkeypatch.setattr(
        "src.core.agents.swarm.logic.file_upload.FileUploadTester.test_upload",
        fake_test_upload,
    )

    specialist = FileUploadSpecialist()
    specialist._client.close = AsyncMock()
    task = Task(
        id="upload-task",
        name="File Upload Vulnerability Scan",
        agent_type="LogicSwarm",
        action="scan",
        phase="attack",
        target="http://localhost:4280/vulnerabilities/upload/",
        params={
            "target": "http://localhost:4280/vulnerabilities/upload/",
            "param_name": "uploaded",
            "extra_params": '{"MAX_FILE_SIZE": "100000", "Upload": "Upload"}',
            "safe_only": True,
        },
    )

    findings = await specialist.execute(task)
    await specialist.close()

    assert len(findings) == 1
    evidence = findings[0].evidence
    assert evidence.response_status == 200
    assert "probe_fixed.jpg" in evidence.request_body
    assert "uploaded" in evidence.request_body
    assert "MAX_FILE_SIZE=100000" in evidence.request_body
    assert captured_extra_params == {"MAX_FILE_SIZE": "100000", "Upload": "Upload"}
    assert "retrieved at http://localhost:4280/hackable/uploads/probe_fixed.jpg" in evidence.response_body
