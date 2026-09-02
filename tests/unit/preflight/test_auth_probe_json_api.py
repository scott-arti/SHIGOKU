"""SGK-2026-0468: JSON-API preflight auth probe classification.

An authenticated 2xx JSON-API response (credentials sent, JSON body, not a
login page, flag ``auth_probe_json_api_enabled`` turned on) must be classified
as AUTHENTICATED instead of falling to UNKNOWN. The flag defaults to off, so
existing behavior is byte-identical unless explicitly enabled.
"""

from types import SimpleNamespace

import pytest

from src.core.config.settings import Settings
from src.core.preflight.auth_probe import AuthProbe
from src.core.preflight.models import AuthClassification, AuthProbeResult


def _classify(
    monkeypatch,
    *,
    json_api_enabled: bool,
    status_code: int = 200,
    has_credentials: bool = True,
    is_json_api: bool = True,
    is_login_page: bool = False,
    has_authenticated_markers: bool = False,
) -> AuthClassification:
    # The classifier lazy-imports get_settings at call time, so patching
    # the module attribute is enough. Only the flag is consumed here.
    def _fake_get_settings():
        return SimpleNamespace(auth_probe_json_api_enabled=json_api_enabled)

    monkeypatch.setattr("src.core.config.settings.get_settings", _fake_get_settings)
    probe = AuthProbe()
    result = AuthProbeResult(
        classification=AuthClassification.UNKNOWN,
        status_code=status_code,
        is_login_page=is_login_page,
    )
    out = probe._classify_deterministic(
        result,
        has_login_markers=False,
        has_session_expired_markers=False,
        has_authenticated_markers=has_authenticated_markers,
        has_credentials=has_credentials,
        is_json_api=is_json_api,
    )
    return out.classification


def test_json_api_authenticated_2xx_with_credentials_flag_on(monkeypatch):
    classification = _classify(
        monkeypatch,
        json_api_enabled=True,
        status_code=200,
        has_credentials=True,
        is_json_api=True,
        is_login_page=False,
        has_authenticated_markers=False,
    )
    assert classification == AuthClassification.AUTHENTICATED


def test_json_api_authenticated_flag_off_keeps_unknown(monkeypatch):
    classification = _classify(
        monkeypatch,
        json_api_enabled=False,
        status_code=200,
        has_credentials=True,
        is_json_api=True,
        is_login_page=False,
        has_authenticated_markers=False,
    )
    assert classification == AuthClassification.UNKNOWN


def test_json_api_public_without_credentials_flag_on_keeps_unknown(monkeypatch):
    classification = _classify(
        monkeypatch,
        json_api_enabled=True,
        status_code=200,
        has_credentials=False,
        is_json_api=True,
        is_login_page=False,
        has_authenticated_markers=False,
    )
    assert classification == AuthClassification.UNKNOWN


def test_html_authenticated_page_unchanged_flag_independent(monkeypatch):
    classification = _classify(
        monkeypatch,
        json_api_enabled=False,
        status_code=200,
        has_credentials=True,
        is_json_api=True,
        is_login_page=False,
        has_authenticated_markers=True,
    )
    assert classification == AuthClassification.AUTHENTICATED


def test_401_unchanged_session_expired(monkeypatch):
    classification = _classify(
        monkeypatch,
        json_api_enabled=True,
        status_code=401,
        has_credentials=True,
        is_json_api=True,
        is_login_page=False,
        has_authenticated_markers=False,
    )
    assert classification == AuthClassification.SESSION_EXPIRED


def test_settings_default_flag_off():
    assert Settings().auth_probe_json_api_enabled is False
