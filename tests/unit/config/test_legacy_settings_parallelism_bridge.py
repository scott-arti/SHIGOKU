from __future__ import annotations

from src.config import Settings


def test_legacy_settings_exposes_parallelism_safe_defaults() -> None:
    settings = Settings(dev_mode=True)

    assert settings.parallelism.enabled is False
    assert settings.parallelism.kill_switch is False


def test_legacy_settings_parallelism_env_override(monkeypatch) -> None:
    monkeypatch.setenv("SHIGOKU_PARALLELISM__ENABLED", "true")
    monkeypatch.setenv("SHIGOKU_PARALLELISM__KILL_SWITCH", "true")

    settings = Settings(dev_mode=True)

    assert settings.parallelism.enabled is True
    assert settings.parallelism.kill_switch is True
