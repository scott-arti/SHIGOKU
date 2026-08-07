"""Regression tests for ReconPipeline proxy-gate settings contracts."""

from unittest.mock import MagicMock, patch

import pytest

from src.core.config.settings import ScanSettings
from src.recon.pipeline import ReconPipeline


@pytest.mark.asyncio
async def test_run_accepts_pydantic_scan_settings_at_proxy_gate(tmp_path):
    """The proxy gate must use Settings' resolver, not dict access on ScanSettings."""
    pipeline = ReconPipeline(
        config={},
        project_manager=None,
        target="http://localhost:3000/#/",
        workspace_root=tmp_path,
    )
    configured_settings = MagicMock()
    configured_settings.scan = ScanSettings(proxy="")
    configured_settings.get_proxy_url.return_value = None

    with patch("src.recon.pipeline.settings", configured_settings):
        state = await pipeline.run(start_step=9, end_step=8)

    assert state is pipeline.state
    configured_settings.get_proxy_url.assert_called_once_with()
