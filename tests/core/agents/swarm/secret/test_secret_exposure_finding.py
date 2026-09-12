"""SGK-2026-0483: SecretExposure の確定可能 Finding 生成（manager.py）。

製品非依存・合成 fixture のみ（実在の秘密値は含まない。合成の偽値を与え、
それが evidence に生のまま残らない＝値 redact されることを確認する）。
"""
from types import SimpleNamespace

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.agents.swarm.secret.manager import (
    SecretExposure,
    _matched_credential_keys,
    _redact_secret_values,
)
from src.core.models.finding import VulnType

_URL = "http://target.example/.env"
# 合成の偽の値（実秘密ではない）。これらが evidence に残ってはならない。
_FAKE_PW = "fakepw_value_123"
_FAKE_MONGO = "fakemongo_9"
_CONTENT = (
    "DB_NAME=appdb\n"
    "DB_USER=appuser\n"
    f"DB_PASSWORD={_FAKE_PW}\n"
    "SERVER_PORT=8080\n"
    f"MONGO_DB_PASSWORD={_FAKE_MONGO}\n"
)


def _task() -> Task:
    return Task(id="t-secret", name="secret-scan", target=_URL, tags=["js_file"])


def _resp(content_type: str = "application/octet-stream") -> SimpleNamespace:
    return SimpleNamespace(headers={"Content-Type": content_type})


def test_build_finding_when_credentials_served():
    spec = SecretExposure()
    finding = spec._build_secret_exposure_finding(
        _task(), _URL, 200, _CONTENT, _resp()
    )
    assert finding is not None
    assert finding.vuln_type == VulnType.SECRET_LEAK
    assert finding.evidence.request_method == "GET"
    assert finding.evidence.request_url == _URL
    assert finding.evidence.response_status == 200
    sec = finding.additional_info["secret_exposure_evidence"]
    assert sec["retrieved_url"] == _URL
    assert sec["response_status"] == 200
    assert "DB_PASSWORD" in sec["matched_keys"]


def test_built_finding_is_payout_grade():
    spec = SecretExposure()
    finding = spec._build_secret_exposure_finding(
        _task(), _URL, 200, _CONTENT, _resp()
    )
    result = evaluate_payout_grade(finding.to_dict())
    assert result.payout_grade is True
    assert result.marker == "secret_exposed"


def test_no_secret_value_persisted_in_finding():
    spec = SecretExposure()
    finding = spec._build_secret_exposure_finding(
        _task(), _URL, 200, _CONTENT, _resp()
    )
    blob = (
        finding.evidence.response_body
        + finding.additional_info["secret_exposure_evidence"]["served_body"]
        + finding.additional_info["poc_response"]
    )
    # 合成の偽値であっても、値は redact されて残らないこと。
    assert _FAKE_PW not in blob
    assert _FAKE_MONGO not in blob
    # キー（変数名）は証拠として残ること。
    assert "DB_PASSWORD" in blob


def test_no_finding_without_credential():
    spec = SecretExposure()
    content = "HOST=db\nPORT=5432\nFEATURE=on\n"
    finding = spec._build_secret_exposure_finding(
        _task(), _URL, 200, content, _resp()
    )
    assert finding is None


def test_redact_keeps_keys_drops_values():
    redacted = _redact_secret_values(_CONTENT)
    assert _FAKE_PW not in redacted
    assert _FAKE_MONGO not in redacted
    assert "DB_PASSWORD=<redacted len=" in redacted
    assert "DB_USER=appuser" in redacted  # 非資格情報行は保持


def test_matched_keys_includes_pem():
    content = (
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
    )
    assert "PRIVATE KEY" in _matched_credential_keys(content)
