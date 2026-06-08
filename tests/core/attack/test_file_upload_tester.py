import pytest
import aiohttp
from unittest.mock import AsyncMock, MagicMock, patch
from src.core.attack.file_upload_tester import FileUploadTester
from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

@pytest.mark.asyncio
async def test_file_upload_tester_extra_params():
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
    extra_params = {"submit": "UploadNow", "token": "secret123"}
    
    # Run test_upload (which calls _upload_file)
    # We only care about the first call (baseline image upload) to verify params
    results = await tester.test_upload(
        target_url=target_url,
        param_name=param_name,
        extra_params=extra_params,
        aggressive=True
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
    
    assert fields[param_name] == b"dummy_image_content"
    assert fields["submit"] == "UploadNow"
    assert fields["token"] == "secret123"
    assert "Upload" not in fields  # Ensure hardcoded "Upload" is gone
