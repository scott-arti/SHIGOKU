from __future__ import annotations

from src.core.config.settings import Settings


def test_canonical_settings_loads_parallelism_from_yaml() -> None:
    settings = Settings(dev_mode=True)

    assert settings.parallelism.enabled is True
    assert settings.parallelism.kill_switch is False


def test_legacy_settings_parallelism_env_override(monkeypatch) -> None:
    monkeypatch.setenv("SHIGOKU_PARALLELISM__ENABLED", "true")
    monkeypatch.setenv("SHIGOKU_PARALLELISM__KILL_SWITCH", "true")

    settings = Settings(dev_mode=True)

    assert settings.parallelism.enabled is True
    assert settings.parallelism.kill_switch is True
