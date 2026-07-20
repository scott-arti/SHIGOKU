"""Unit tests: specialist mode resolution from global Settings.

Verifies that injection specialists (SQLi, XSS, Cmd/SSRF, LFI) resolve
their operation mode from the global Settings when config does not provide
an explicit ``"mode"`` key, preventing Guard fail-close on vulntest runs.
"""

from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SETTINGS_PATH = "src.core.config.settings.get_settings"


def _make_settings_mock(mode: str):
    """Return a MagicMock whose .mode attribute is *mode*."""
    s = MagicMock()
    s.mode = mode
    return s


def _mock_safeguard():
    """Return a passthrough safeguard mock (never blocks)."""
    sg = MagicMock()
    sg.should_block.return_value = False
    sg.check_method.return_value = True
    sg.check_payload.return_value = True
    return sg


# ---------------------------------------------------------------------------
# SmartSQLiHunter mode resolution
# ---------------------------------------------------------------------------

class TestSmartSQLiMode:
    def test_mode_from_global_settings(self):
        """config={}, settings.mode='vulntest' → client.mode 'vulntest'."""
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        with patch(_SETTINGS_PATH, return_value=_make_settings_mock("vulntest")), \
             patch("src.core.agents.swarm.injection.smart_sqli.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartSQLiHunter(config={})

        assert specialist.smart_client.client.mode == "vulntest"

    def test_mode_from_config_overrides_global(self):
        """config={'mode': 'ctf'} wins over settings.mode='vulntest'."""
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        with patch(_SETTINGS_PATH, return_value=_make_settings_mock("vulntest")), \
             patch("src.core.agents.swarm.injection.smart_sqli.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartSQLiHunter(config={"mode": "ctf"})

        assert specialist.smart_client.client.mode == "ctf"

    def test_mode_fallback_to_bugbounty(self):
        """get_settings() raises → mode stays 'bugbounty' (fail-closed)."""
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        with patch(_SETTINGS_PATH, side_effect=Exception("unavailable")), \
             patch("src.core.agents.swarm.injection.smart_sqli.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartSQLiHunter(config={})

        assert specialist.smart_client.client.mode == "bugbounty"

    def test_default_no_config_no_settings(self):
        """config=None, no get_settings → mode stays 'bugbounty'."""
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        with patch(_SETTINGS_PATH, side_effect=Exception("unavailable")), \
             patch("src.core.agents.swarm.injection.smart_sqli.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartSQLiHunter(config=None)

        assert specialist.smart_client.client.mode == "bugbounty"

    def test_config_empty_mode_key_uses_settings(self):
        """config={'mode': ''} is falsy → falls back to settings."""
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter

        with patch(_SETTINGS_PATH, return_value=_make_settings_mock("vulntest")), \
             patch("src.core.agents.swarm.injection.smart_sqli.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartSQLiHunter(config={"mode": ""})

        # Empty string is falsy → should fall back to settings
        assert specialist.smart_client.client.mode == "vulntest"


# ---------------------------------------------------------------------------
# SmartXSSHunter mode resolution
# ---------------------------------------------------------------------------

class TestSmartXSSMode:
    def test_mode_from_global_settings(self):
        from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter

        with patch(_SETTINGS_PATH, return_value=_make_settings_mock("vulntest")), \
             patch("src.core.agents.swarm.injection.smart_xss.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartXSSHunter(config={})

        assert specialist.smart_client.client.mode == "vulntest"

    def test_fallback_to_bugbounty(self):
        from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter

        with patch(_SETTINGS_PATH, side_effect=Exception("unavailable")), \
             patch("src.core.agents.swarm.injection.smart_xss.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartXSSHunter(config={})

        assert specialist.smart_client.client.mode == "bugbounty"


# ---------------------------------------------------------------------------
# SmartCmdSSRFHunter mode resolution
# ---------------------------------------------------------------------------

class TestSmartCmdSSRFMode:
    def test_mode_from_global_settings(self):
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        with patch(_SETTINGS_PATH, return_value=_make_settings_mock("vulntest")), \
             patch("src.core.agents.swarm.injection.smart_cmd_ssrf.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartCmdSSRFHunter(config={})

        assert specialist.network_client.mode == "vulntest"

    def test_fallback_to_bugbounty(self):
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter

        with patch(_SETTINGS_PATH, side_effect=Exception("unavailable")), \
             patch("src.core.agents.swarm.injection.smart_cmd_ssrf.LLMClient", autospec=True), \
             patch("src.core.infra.proxy_manager.get_proxy_manager", return_value=None):
            specialist = SmartCmdSSRFHunter(config={})

        assert specialist.network_client.mode == "bugbounty"


# ---------------------------------------------------------------------------
# SmartLFIHunter mode resolution
# ---------------------------------------------------------------------------

class TestSmartLFIMode:
    def test_mode_from_global_settings(self):
        from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter

        with patch(_SETTINGS_PATH, return_value=_make_settings_mock("vulntest")), \
             patch("src.core.agents.swarm.injection.smart_lfi.LLMClient", autospec=True):
            specialist = SmartLFIHunter(config={})

        assert specialist.network_client.mode == "vulntest"

    def test_fallback_to_bugbounty(self):
        from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter

        with patch(_SETTINGS_PATH, side_effect=Exception("unavailable")), \
             patch("src.core.agents.swarm.injection.smart_lfi.LLMClient", autospec=True):
            specialist = SmartLFIHunter(config={})

        assert specialist.network_client.mode == "bugbounty"
