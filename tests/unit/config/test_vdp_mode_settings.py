"""
T-VDP-1 / T-VDP-2 / T-VDP-3 / T-VDP-4: VdpModeSettings config tests.

Tests:
  - T-VDP-1: vdp section missing → safe defaults
  - T-VDP-2: invalid mode values → silently coerced to "off" (fail-safe)
  - T-VDP-3: valid mode values pass through
  - T-VDP-4: YAML load integration via Settings
"""
import os
import pytest
from src.core.config.settings import VdpModeSettings, Settings


class TestVdpModeConfigDefaultSafe:
    """T-VDP-1: Safe defaults when vdp section is absent."""

    def test_default_mode_is_off(self):
        s = VdpModeSettings()
        assert s.mode == "off"

    def test_default_label_leakage_denylist_is_empty(self):
        s = VdpModeSettings()
        assert s.label_leakage_denylist == []

    def test_from_empty_dict_produces_defaults(self):
        """Empty dict → default safe values."""
        s = VdpModeSettings(**{})
        assert s.mode == "off"
        assert s.label_leakage_denylist == []


class TestVdpModeConfigInvalidFailSafe:
    """T-VDP-2: Invalid mode values → silently coerced to "off"."""

    def test_mode_enforce_failsafe_to_off(self):
        s = VdpModeSettings(mode="enforce")
        assert s.mode == "off"

    def test_mode_invalid_random_string_failsafe_to_off(self):
        s = VdpModeSettings(mode="invalid_value")
        assert s.mode == "off"

    def test_mode_empty_string_failsafe_to_off(self):
        s = VdpModeSettings(mode="")
        assert s.mode == "off"

    def test_mode_none_like_failsafe(self):
        """None or missing → defaults to 'off'."""
        s = VdpModeSettings()
        assert s.mode == "off"


class TestVdpModeConfigValid:
    """T-VDP-3: Valid mode values pass through."""

    def test_mode_record_only(self):
        s = VdpModeSettings(mode="record_only")
        assert s.mode == "record_only"

    def test_mode_shadow(self):
        s = VdpModeSettings(mode="shadow")
        assert s.mode == "shadow"

    def test_mode_off(self):
        s = VdpModeSettings(mode="off")
        assert s.mode == "off"

    def test_label_leakage_denylist_can_be_set(self):
        s = VdpModeSettings(mode="record_only", label_leakage_denylist=["acme_corp", "product_x"])
        assert s.mode == "record_only"
        assert s.label_leakage_denylist == ["acme_corp", "product_x"]

    def test_yaml_style_dict_parse(self):
        """Config passed as dict (YAML-like) parses correctly."""
        s = VdpModeSettings(**{
            "mode": "shadow",
            "label_leakage_denylist": ["secret_name"],
        })
        assert s.mode == "shadow"
        assert s.label_leakage_denylist == ["secret_name"]


class TestVdpModeSettingsFromYaml:
    """T-VDP-4: VdpModeSettings accessible via Settings (YAML load integration)."""

    def test_settings_default_vdp_mode_is_off(self):
        """Settings().vdp.mode defaults to 'off' when YAML lacks vdp section."""
        os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")
        settings = Settings()
        assert settings.vdp.mode == "off"
        assert settings.vdp.label_leakage_denylist == []

    def test_settings_vdp_field_is_vdpmode_instance(self):
        """Settings().vdp is a VdpModeSettings instance."""
        os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")
        settings = Settings()
        assert isinstance(settings.vdp, VdpModeSettings)

    def test_settings_vdp_construction_from_dict(self):
        """Settings(vdp={'mode': 'shadow'}) parses correctly."""
        os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")
        settings = Settings(vdp={"mode": "shadow"})
        assert settings.vdp.mode == "shadow"

    def test_settings_vdp_invalid_mode_failsafe(self):
        """Settings with invalid vdp.mode → 'off' (fail-safe)."""
        os.environ.setdefault("DEEPSEEK_API_KEY", "test-key")
        settings = Settings(vdp={"mode": "enforce"})
        assert settings.vdp.mode == "off"
