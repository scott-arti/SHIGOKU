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
from src.core.config.settings import (
    VdpModeSettings,
    Settings,
    VDP_STAGES,
    derive_stage_from_mode,
    is_enforce_stage,
    min_stage,
)


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


class TestVdpMode0421M3a:
    """SGK-2026-0421: readonly_enforce mode + kill switch + M3b/M3c never
    activatable without an explicit gate."""

    def test_readonly_enforce_is_valid(self):
        s = VdpModeSettings(mode="readonly_enforce")
        assert s.mode == "readonly_enforce"

    def test_kill_switch_defaults_off(self):
        s = VdpModeSettings()
        assert s.kill_switch is False

    def test_capability_rules_default_fail_closed(self):
        s = VdpModeSettings(mode="readonly_enforce")
        assert s.capability_rules == {}

    def test_capability_rules_allow_explicit_readonly_follow_up(self):
        s = VdpModeSettings(
            mode="readonly_enforce",
            capability_rules={"follow_up_probe": "allowed"},
        )
        assert s.capability_rules == {"follow_up_probe": "allowed"}

    def test_unknown_capability_level_fails_closed(self):
        s = VdpModeSettings(
            mode="readonly_enforce",
            capability_rules={"follow_up_probe": "not-a-level"},
        )
        assert s.capability_rules == {"follow_up_probe": "prohibited"}

    def test_kill_switch_parses(self):
        s = VdpModeSettings(mode="readonly_enforce", kill_switch=True)
        assert s.kill_switch is True

    def test_m3b_mode_value_fails_safe_to_off(self):
        # M3b (state-change enforce) has NO mode value in 0421 — any attempt
        # to set one fails closed to off.
        s = VdpModeSettings(mode="m3b")
        assert s.mode == "off"

    def test_m3c_mode_value_fails_safe_to_off(self):
        s = VdpModeSettings(mode="m3c")
        assert s.mode == "off"

    def test_chain_mode_value_fails_safe_to_off(self):
        s = VdpModeSettings(mode="chain_enforce")
        assert s.mode == "off"

    def test_m3b_cannot_be_activated_without_gate(self):
        # The only enforce mode available is readonly_enforce (M3a); there is
        # no configuration surface for M3b/M3c state-changing enforcement.
        allowed = {VdpModeSettings(mode=m).mode for m in
                   ("off", "record_only", "shadow", "readonly_enforce",
                    "m3b", "m3c", "chain_enforce", "enforce")}
        assert allowed == {"off", "record_only", "shadow", "readonly_enforce"}

    def test_yaml_mode_readonly_enforce_supported(self):
        from pydantic import ValidationError
        # Settings-level YAML integration for the new mode
        settings = Settings(vdp=VdpModeSettings(mode="readonly_enforce", kill_switch=False))
        assert settings.vdp.mode == "readonly_enforce"


class TestVdpMode0423StagedRollout:
    """SGK-2026-0423: stage ladder, flags, key provider config (additive,
    backward compatible with 0420/0421 mode vocabulary)."""

    def test_stage_defaults_empty(self):
        s = VdpModeSettings()
        assert s.stage == ""

    def test_stage_valid_values_pass_through(self):
        for stage in ("m0", "m1", "m2", "m3a", "m3b", "m3c", "m4"):
            s = VdpModeSettings(stage=stage)
            assert s.stage == stage

    def test_stage_invalid_fails_closed_to_empty(self):
        s = VdpModeSettings(stage="m9")
        assert s.stage == ""  # derive from mode → safe

    def test_stage_flags_unknown_keys_dropped(self):
        s = VdpModeSettings(stage_flags={"m3b": False, "m9": True})
        assert s.stage_flags == {"m3b": False}

    def test_stage_flags_default_empty(self):
        assert VdpModeSettings().stage_flags == {}

    def test_key_provider_default_env(self):
        assert VdpModeSettings().key_provider == "env"

    def test_key_provider_invalid_fails_closed_to_env(self):
        s = VdpModeSettings(key_provider="kms")
        assert s.key_provider == "env"

    def test_key_paths_default_empty(self):
        s = VdpModeSettings()
        assert s.key_file_path == ""
        assert s.key_registry_path == ""
        assert s.progression_records_path == ""
        assert s.thresholds_path == ""
        assert s.rollout_state_path == ""

    def test_derive_stage_from_mode(self):
        assert derive_stage_from_mode("off") == "m0"
        assert derive_stage_from_mode("record_only") == "m1"
        assert derive_stage_from_mode("shadow") == "m2"
        assert derive_stage_from_mode("readonly_enforce") == "m3a"
        assert derive_stage_from_mode("invalid") == "m0"

    def test_is_enforce_stage(self):
        for stage in ("m0", "m1", "m2"):
            assert is_enforce_stage(stage) is False
        for stage in ("m3a", "m3b", "m3c", "m4"):
            assert is_enforce_stage(stage) is True
        assert is_enforce_stage("bogus") is False

    def test_min_stage(self):
        assert min_stage("m2", "m3a") == "m2"
        assert min_stage("m3a", "m2") == "m2"
        assert min_stage("m4", "m4") == "m4"
        assert min_stage("bogus", "m3a") == "bogus"  # unknown → rank 0 (fail-closed)

    def test_stage_vocabulary_order(self):
        assert VDP_STAGES == ("m0", "m1", "m2", "m3a", "m3b", "m3c", "m4")
