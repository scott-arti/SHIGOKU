"""
SGK-2026-0425 M0: diagnostics settings model.

Fail-closed defaults: diagnostics.enabled=false (existing behavior bit
identical), required=false (normal runs keep the existing path). Invalid
bound values fall back to sane defaults instead of crashing config load.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from src.core.config.settings import DiagnosticsSettings

_DEFAULT_MAX_EVENTS = 2000
_DEFAULT_MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
_DEFAULT_CHECKPOINT_INTERVAL = 500
_DEFAULT_QUEUE_CAPACITY = 5000


class TestDiagnosticsSettingsDefaults:
    def test_defaults_are_fail_closed(self):
        s = DiagnosticsSettings()
        assert s.enabled is False
        assert s.required is False
        assert s.max_events == _DEFAULT_MAX_EVENTS
        assert s.max_artifact_bytes == _DEFAULT_MAX_ARTIFACT_BYTES
        assert s.checkpoint_interval_events == _DEFAULT_CHECKPOINT_INTERVAL
        assert s.event_queue_capacity == _DEFAULT_QUEUE_CAPACITY


class TestDiagnosticsSettingsFailClosedBounds:
    def test_negative_max_events_falls_back(self):
        assert DiagnosticsSettings(max_events=-5).max_events == _DEFAULT_MAX_EVENTS

    def test_zero_max_events_falls_back(self):
        assert DiagnosticsSettings(max_events=0).max_events == _DEFAULT_MAX_EVENTS

    def test_bool_max_events_falls_back(self):
        # bool is an int subclass in Python — must not be accepted as a count.
        assert DiagnosticsSettings(max_events=True).max_events == _DEFAULT_MAX_EVENTS

    def test_negative_artifact_bytes_falls_back(self):
        assert (
            DiagnosticsSettings(max_artifact_bytes=-1).max_artifact_bytes
            == _DEFAULT_MAX_ARTIFACT_BYTES
        )

    def test_zero_checkpoint_interval_falls_back(self):
        assert (
            DiagnosticsSettings(checkpoint_interval_events=0).checkpoint_interval_events
            == _DEFAULT_CHECKPOINT_INTERVAL
        )

    def test_negative_queue_capacity_falls_back(self):
        assert (
            DiagnosticsSettings(event_queue_capacity=-100).event_queue_capacity
            == _DEFAULT_QUEUE_CAPACITY
        )


class TestDiagnosticsYamlConfig:
    def test_yaml_block_present_with_safe_defaults(self):
        cfg = yaml.safe_load(Path("config/shigoku.yaml").read_text(encoding="utf-8"))
        diagnostics = cfg["diagnostics"]
        assert diagnostics["enabled"] is False
        assert diagnostics["required"] is False

    def test_example_yaml_block_present_with_safe_defaults(self):
        cfg = yaml.safe_load(
            Path("config/shigoku.yaml.example").read_text(encoding="utf-8")
        )
        diagnostics = cfg["diagnostics"]
        assert diagnostics["enabled"] is False
        assert diagnostics["required"] is False
