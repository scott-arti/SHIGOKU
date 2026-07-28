import pytest
import aiohttp
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.attack.file_upload_tester import FileUploadTester
from src.core.attack.payload_manager import UploadPayload
from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

@pytest.mark.parametrize(
    "extra_params_input",
    [
        {"submit": "UploadNow", "token": "secret123"},
        '{"submit": "UploadNow", "token": "secret123"}',
        "{'submit': 'UploadNow', 'token': 'secret123'}",
        "submit=UploadNow&token=secret123",
    ],
)
@pytest.mark.asyncio
async def test_file_upload_tester_extra_params(extra_params_input):
    # Mock AsyncNetworkClient
    mock_client = MagicMock(spec=AsyncNetworkClient)
    mock_client.request = AsyncMock()
    mock_client.close = AsyncMock()
    
    # Mock response
    mock_response = MagicMock(spec=NetworkResponse)
    mock_response.status = 200
    mock_response.text = "File successfully uploaded"
    mock_client.request.return_value = mock_response
    
    tester = FileUploadTester(client=mock_client)
    
    target_url = "http://example.com/upload"
    param_name = "file_input"
    # Run test_upload (which calls _upload_file)
    # We only care about the first call (baseline image upload) to verify params
    results = await tester.test_upload(
        target_url=target_url,
        param_name=param_name,
        extra_params=extra_params_input,
        aggressive=True,
        safe_only=True,
        verify_retrieval=False,
    )
    
    # Verify mock_client.request was called with the correct data
    # Now the FIRST call (call_args_list[0]) is a GET request for baseline
    # The SECOND call (call_args_list[1]) is the POST request for upload
    args_get, kwargs_get = mock_client.request.call_args_list[0]
    assert args_get[0] == "GET" or kwargs_get.get('method') == "GET"

    args_post, kwargs_post = mock_client.request.call_args_list[1]
    sent_data = kwargs_post.get('data')
    
    assert isinstance(sent_data, aiohttp.FormData)
    
    # Check fields in FormData
    fields = {f[0]['name']: f[2] for f in sent_data._fields}
    
    assert fields[param_name] == b"SHIGOKU_PROBE_IMAGE_DATA"
    assert fields["submit"] == "UploadNow"
    assert fields["token"] == "secret123"
    assert "Upload" not in fields  # Ensure hardcoded "Upload" is gone


@pytest.mark.asyncio
async def test_file_upload_safe_only_uses_canary_probe_and_records_retrieval():
    mock_client = MagicMock(spec=AsyncNetworkClient)
    mock_client.request = AsyncMock()
    mock_client.close = AsyncMock()

    baseline = MagicMock(spec=NetworkResponse)
    baseline.status = 200
    baseline.text = "upload form"

    upload_response = MagicMock(spec=NetworkResponse)
    upload_response.status = 200
    upload_response.text = "../../hackable/uploads/probe_fixed.jpg succesfully uploaded!"

    retrieval_response = MagicMock(spec=NetworkResponse)
    retrieval_response.status = 200
    retrieval_response.text = "SHIGOKU_PROBE_IMAGE_DATA"

    mock_client.request.side_effect = [baseline, upload_response, retrieval_response]

    tester = FileUploadTester(client=mock_client, katana_urls=["http://example.com/uploads/existing.jpg"])
    tester.payload_manager.get_probe_payload = lambda: UploadPayload(
        filename="probe_fixed.jpg",
        content=b"SHIGOKU_PROBE_IMAGE_DATA",
        mime_type="image/jpeg",
        technique="Safe Canary Upload Probe",
    )
    results = await tester.test_upload(
        target_url="http://example.com/vulnerabilities/upload/",
        param_name="uploaded",
        extra_params={"Upload": "Upload"},
        aggressive=True,
        safe_only=True,
    )

    assert len(results) == 1
    assert results[0].technique == "Safe Canary Upload Probe"
    assert results[0].retrieved is True
    assert results[0].retrieval_url == "http://example.com/hackable/uploads/probe_fixed.jpg"
    assert mock_client.request.call_args_list[2].args[1] == "http://example.com/hackable/uploads/probe_fixed.jpg"
    assert b"<?php" not in mock_client.request.call_args_list[1].kwargs["data"]._fields[0][2]
