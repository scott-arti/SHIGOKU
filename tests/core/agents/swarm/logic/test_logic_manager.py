import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import aiohttp
from src.core.agents.swarm.logic.manager import LogicManagerAgent
from src.core.agents.swarm.base import Task
from src.core.models.finding import Finding, VulnType, Severity

@pytest.mark.asyncio
async def test_logic_manager_initialization():
    """LogicManagerAgentの初期化とプロンプト読み込みテスト"""
    manager = LogicManagerAgent()
    assert manager.name == "LogicManager"
    assert manager.system_prompt_template == "agents/logic_manager.md"
    
    # Check if tools are registered
    assert "run_file_upload_check" in manager.available_tools
    assert "run_mass_assignment_check" in manager.available_tools
    assert "run_race_condition_check" in manager.available_tools

@pytest.mark.asyncio
async def test_logic_manager_file_upload_delegation():
    """
    LogicManagerAgentが LLM の指示に従って FileUploadSpecialist を呼び出すフローの検証
    """
    # 1. Mocking LLM
    mock_llm_response = MagicMock()
    mock_llm_response.choices = [MagicMock()]
    mock_llm_response.choices[0].message.content = (
        "Thought: The target URL indicates an upload endpoint. I should run the file upload check.\n"
        "Action: run_file_upload_check(url='http://localhost:4280/vulnerabilities/upload/')\n"
    )
    
    mock_llm_response_2 = MagicMock()
    mock_llm_response_2.choices = [MagicMock()]
    mock_llm_response_2.choices[0].message.content = "Thought: Specialist finished.\nFinal Answer: Found vulnerabilities."

    # 2. Setup Manager with Mocked LLM
    manager = LogicManagerAgent()
    # Inject a mock LLMClient that returns our prepared responses
    manager.llm = MagicMock()
    manager.llm.agenerate = AsyncMock(side_effect=[mock_llm_response, mock_llm_response_2])
    
    # 3. Setup Task
    task = Task(
        id="test-upload",
        name="Test Upload",
        target="http://localhost:4280/vulnerabilities/upload/",
        tags=["file_upload"]
    )
    
    # 4. Mock the Specialist execution inside the manager
    # We mock execute_with_retry on the specific specialist instance
    mock_specialist = AsyncMock()
    mock_finding = Finding(
        vuln_type=VulnType.FILE_UPLOAD,
        severity=Severity.MEDIUM,
        title="Test Vuln",
        description="Test",
        target_url=task.target
    )
    mock_specialist.execute_with_retry.return_value = [mock_finding]
    
    manager.specialists["file_upload"] = mock_specialist

    # 5. Run Dispatch
    result = await manager.dispatch(task)
    
    # 6. Verification
    assert result.status == "success"
    
    # Ensure LLM was called
    assert manager.llm.agenerate.called
    
    # Ensure the specialist was called with correct task
    mock_specialist.execute_with_retry.assert_called_once()
    called_task = mock_specialist.execute_with_retry.call_args[0][0]
    assert called_task.target == task.target
    assert called_task.name == "File Upload Check"

@pytest.mark.asyncio
async def test_logic_manager_form_analysis_workflow():
    """
    LogicManagerAgentが HTML を取得し、フォームを解析してから攻撃を実行するフローの検証
    """
    # 1. Mocking HTML content
    sample_html = """
    <html>
        <form action="/upload_target.php" method="POST">
            <input type="file" name="fileToUpload">
            <input type="hidden" name="token" value="abc123">
            <input type="submit" name="submit_btn" value="Upload Now">
        </form>
    </html>
    """
    
    # 2. Mocking LLM responses
    # First response: Call fetch_page_content
    mock_llm_response_1 = MagicMock()
    mock_llm_response_1.choices = [MagicMock()]
    mock_llm_response_1.choices[0].message.content = (
        "Thought: I need to analyze the form structure first.\n"
        "Action: fetch_page_content(url='http://localhost:4280/upload.php')\n"
    )
    
    # Second response: Call run_file_upload_check with parsed params
    mock_llm_response_2 = MagicMock()
    mock_llm_response_2.choices = [MagicMock()]
    mock_llm_response_2.choices[0].message.content = (
        "Thought: I see a file input named 'fileToUpload' and extra params 'token' and 'submit_btn'.\n"
        "Action: run_file_upload_check(url='http://localhost:4280/upload_target.php', param_name='fileToUpload', extra_params={'token': 'abc123', 'submit_btn': 'Upload Now'})\n"
    )
    
    # Third response: Final Answer
    mock_llm_response_3 = MagicMock()
    mock_llm_response_3.choices = [MagicMock()]
    mock_llm_response_3.choices[0].message.content = "Thought: Scan complete.\nFinal Answer: Done."

    # 3. Setup Manager and Mocks
    manager = LogicManagerAgent()
    manager.llm = MagicMock()
    manager.llm.agenerate = AsyncMock(side_effect=[mock_llm_response_1, mock_llm_response_2, mock_llm_response_3])
    
    # Mock fetch_page_content
    mock_fetch = AsyncMock(return_value=sample_html)
    manager.available_tools["fetch_page_content"]["func"] = mock_fetch
    
    # Mock specialist
    mock_specialist = AsyncMock()
    mock_specialist.execute_with_retry.return_value = []
    manager.specialists["file_upload"] = mock_specialist
    
    # 4. Run Task
    task = Task(id="test-form-analysis", name="Form Analysis", target="http://localhost:4280/upload.php", tags=["file_upload"])
    result = await manager.dispatch(task)
    
    # 5. Verification
    assert result.status == "success"
    
    # Verify fetch_page_content was called
    mock_fetch.assert_called_with(url='http://localhost:4280/upload.php')
    
    # Verify the specialist was called with PARSED params
    mock_specialist.execute_with_retry.assert_called_once()
    called_task = mock_specialist.execute_with_retry.call_args[0][0]
    
    assert called_task.target == "http://localhost:4280/upload_target.php"
    assert called_task.params["param_name"] == "fileToUpload"
    assert called_task.params["extra_params"]["token"] == "abc123"
    assert called_task.params["extra_params"]["token"] == "abc123"
    assert called_task.params["extra_params"]["submit_btn"] == "Upload Now"

@pytest.mark.asyncio
async def test_logic_manager_auth_propagation():
    """認証ヘッダーが fetch_page_content と Specialist に伝搬されることを検証"""
    auth_headers = {"Cookie": "PHPSESSID=session123; security=low"}
    
    # 1. Mock LLM
    mock_llm_response_1 = MagicMock()
    mock_llm_response_1.choices = [MagicMock()]
    mock_llm_response_1.choices[0].message.content = "Action: fetch_page_content(url='http://target/')"
    
    mock_llm_response_2 = MagicMock()
    mock_llm_response_2.choices = [MagicMock()]
    mock_llm_response_2.choices[0].message.content = "Action: run_file_upload_check(url='http://target/upload', param_name='file')"
    
    mock_llm_response_3 = MagicMock()
    mock_llm_response_3.choices = [MagicMock()]
    mock_llm_response_3.choices[0].message.content = "Final Answer: Done"

    manager = LogicManagerAgent()
    manager.llm = MagicMock()
    manager.llm.agenerate = AsyncMock(side_effect=[mock_llm_response_1, mock_llm_response_2, mock_llm_response_3])
    
    # Mock real network call in fetch_page_content by patching AsyncNetworkClient
    with patch("src.core.infra.network_client.AsyncNetworkClient") as mock_client_cls:
        mock_client = mock_client_cls.return_value
        m_resp = MagicMock()
        m_resp.text = "<html></html>"
        m_resp.status = 200
        mock_client.request = AsyncMock(return_value=m_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.close = AsyncMock()
        
        # Specialist mock
        mock_specialist = AsyncMock()
        mock_specialist.execute_with_retry.return_value = []
        manager.specialists["file_upload"] = mock_specialist
        
        # Run Task
        task = Task(
            id="auth-test", 
            name="Auth Test",
            target="http://target/", 
            params={"auth_headers": auth_headers}
        )
        await manager.dispatch(task)
        
        # Verification 1: fetch_page_content (AsyncNetworkClient.request) received headers
        # LogicManagerAgent.fetch_page_content call AsyncNetworkClient.request
        args_get, kwargs_get = mock_client.request.call_args_list[0]
        assert args_get[0] == "GET"
        assert kwargs_get.get('headers') == auth_headers

        # Verification 2: Specialist task received headers in params
        mock_specialist.execute_with_retry.assert_called_once()
        called_task = mock_specialist.execute_with_retry.call_args[0][0]
        assert called_task.params["headers"] == auth_headers
