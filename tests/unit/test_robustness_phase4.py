import pytest
from unittest.mock import MagicMock
from pathlib import Path
from src.recon.tool_runner import ToolRunner, ToolNotFoundError
from src.recon.pipeline import ReconPipeline

@pytest.mark.asyncio
async def test_tool_runner_not_found():
    """Verify ToolRunner raises ToolNotFoundError when tool is missing"""
    # Force dev_mode=False to allow subprocess call attempt
    runner = ToolRunner(dev_mode=False)
    
    with pytest.raises(ToolNotFoundError) as excinfo:
        await runner.run(["non_existent_tool_xyz_12345"], timeout=1)
    
    assert "Tool not found" in str(excinfo.value)
    assert "non_existent_tool_xyz_12345" in str(excinfo.value)

def test_pipeline_null_mc_safety():
    """Verify ReconPipeline handles missing MasterConductor gracefully"""
    # Initialize with MasterConductor=None
    pipeline = ReconPipeline(
        config={},
        project_manager=MagicMock(),
        target="example.com",
        master_conductor=None, # Explicitly None
        workspace_root=Path("/tmp")
    )
    
    # Should safely return None (not raise AttributeError)
    header = pipeline._get_cookie_header()
    assert header is None

def test_pipeline_null_context_safety():
    """Verify ReconPipeline handles MC with missing context gracefully"""
    mock_mc = MagicMock()
    mock_mc.context = None # Context missing
    
    pipeline = ReconPipeline(
        config={},
        project_manager=MagicMock(),
        target="example.com",
        master_conductor=mock_mc,
        workspace_root=Path("/tmp")
    )
    
    # Should safely return None
    header = pipeline._get_cookie_header()
    assert header is None


@pytest.mark.asyncio
async def test_tool_runner_uses_demo_provider_for_mock_output():
    """Verify ToolRunner delegates DEV_MODE mock behavior to the injected demo provider."""

    class DemoProviderStub:
        def get_command_output(self, cmd, mock_output=""):
            return "provider-output"

        def is_tool_available(self, tool_name):
            return True

        def check_tools(self, tools):
            return None

    runner = ToolRunner(dev_mode=True, demo_provider=DemoProviderStub())

    output = await runner.run(["subfinder", "-d", "example.com"], timeout=1)

    assert output == "provider-output"


@pytest.mark.asyncio
async def test_tool_runner_env_var_controls_demo_mode(monkeypatch):
    """Verify ToolRunner picks production or demo path from SHIGOKU_DEV_MODE."""

    monkeypatch.delenv("SHIGOKU_DEV_MODE", raising=False)
    prod_runner = ToolRunner()
    assert prod_runner.dev_mode is False

    monkeypatch.setenv("SHIGOKU_DEV_MODE", "true")
    demo_runner = ToolRunner()
    assert demo_runner.dev_mode is True
    assert await demo_runner.run(["subfinder", "-d", "example.com"], timeout=1) != ""
