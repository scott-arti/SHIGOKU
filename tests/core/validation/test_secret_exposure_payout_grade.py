"""SGK-2026-0483: enumerated secret exposure の payout-grade 発火/fail-closed。

製品非依存・合成 fixture のみ（実在の秘密値は一切含まない。値は redact 済みの
形で与える＝照合はキー側パターン）。既存マーカー（ssrf）の非回帰も確認する。
"""
from src.core.agents.swarm.injection.payout_grade import (
    _match_firing_marker,
    evaluate_payout_grade,
)

# 値は redact 済みの保存形（実秘密なし）。照合はキー側（*PASSWORD= 等）。
_SERVED = (
    "DB_NAME=<redacted len=6>\n"
    "DB_USER=<redacted len=7>\n"
    "DB_PASSWORD=<redacted len=12>\n"
    "SERVER_PORT=<redacted len=4>\n"
    "MONGO_DB_PASSWORD=<redacted len=9>\n"
)
_URL = "http://target.example/.env"


def _finding(**info_override) -> dict:
    sec = {
        "retrieved_url": _URL,
        "response_status": 200,
        "served_body": _SERVED,
        "matched_keys": ["DB_PASSWORD", "MONGO_DB_PASSWORD"],
    }
    sec.update(info_override.pop("secret_exposure_evidence", {}))
    info = {"secret_exposure_evidence": sec}
    info.update(info_override)
    return {
        "vuln_type": "secret_leak",
        "evidence": {
            "request_method": "GET",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _SERVED,
        },
        "impact": "公開URLで資格情報が配信されている。",
        "reproduction_steps": ["GET /.env", "応答本文に *PASSWORD= が含まれる"],
        "additional_info": info,
    }


def test_fires_secret_exposed_when_complete():
    result = evaluate_payout_grade(_finding())
    assert result.payout_grade is True
    assert result.marker == "secret_exposed"


def test_pem_private_key_fires():
    served = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "<redacted private key material>\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    f = _finding(secret_exposure_evidence={"served_body": served})
    f["evidence"]["response_body"] = served
    result = evaluate_payout_grade(f)
    assert result.payout_grade is True
    assert result.marker == "secret_exposed"


def test_fail_closed_no_credential_pattern():
    # 資格情報を含まない公開ファイル（設定のみ）は確定に上げない。
    served = "HOST=db\nPORT=5432\nFEATURE_FLAG=on\n"
    info = {
        "secret_exposure_evidence": {
            "retrieved_url": _URL,
            "response_status": 200,
            "served_body": served,
        }
    }
    assert _match_firing_marker("secret_leak", {}, info) is None


def test_fail_closed_empty_url():
    info = {
        "secret_exposure_evidence": {
            "retrieved_url": "",
            "response_status": 200,
            "served_body": _SERVED,
        }
    }
    assert _match_firing_marker("secret_leak", {}, info) is None


def test_fail_closed_non_200():
    info = {
        "secret_exposure_evidence": {
            "retrieved_url": _URL,
            "response_status": 404,
            "served_body": _SERVED,
        }
    }
    assert _match_firing_marker("secret_leak", {}, info) is None


def test_fail_closed_missing_served_body():
    info = {
        "secret_exposure_evidence": {
            "retrieved_url": _URL,
            "response_status": 200,
            "served_body": "",
        }
    }
    assert _match_firing_marker("secret_leak", {}, info) is None


def test_fail_closed_missing_evidence_dict():
    assert _match_firing_marker("secret_leak", {}, {}) is None


def test_legacy_ssrf_callback_unchanged():
    # 既存 ssrf_callback（本文指標）への相乗りが無いこと（非回帰）。
    info = {}
    ev = {"response_body": "instance-id metadata 169.254.169.254"}
    assert _match_firing_marker("ssrf", ev, info) == "ssrf_callback"
