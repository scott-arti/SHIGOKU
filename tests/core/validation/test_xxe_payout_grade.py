"""SGK-2026-0486: XXE（XML External Entity・in-band ファイル読み取り）の機械
フロア（payout_grade）発火と fail-closed を検証する。製品非依存（合成データ）。
証拠は「外部実体ペイロード送出」＋「システムファイル署名の反映」で確定。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/home"
_PAYLOAD = (
    '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
    '"file:///etc/passwd">]><items>&x;</items>'
)
_SERVED = '<items>root:x:0:0:root:/root:/bin/ash\ndaemon:x:1:1:daemon:/usr/sbin</items>'


def _finding(**overrides):
    xe = {
        "request_method": "POST",
        "request_url": _URL,
        "param": "xxe",
        "payload": _PAYLOAD,
        "content_type": "application/x-www-form-urlencoded",
        "file_uri": "file:///etc/passwd",
        "response_status": 200,
        "served_body": _SERVED,
    }
    xe.update(overrides.pop("xe", {}))
    base = {
        "vuln_type": "xxe",
        "impact": "外部実体で /etc/passwd を読み取れる。",
        "reproduction_steps": ["外部実体を含む XML を POST する。"],
        "evidence": {
            "request_method": "POST",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _SERVED,
        },
        "additional_info": {"xxe_evidence": xe},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("xxe") == "xxe_file_read"


def test_fires_when_complete():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "xxe_file_read"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_url():
    assert evaluate_payout_grade(_finding(xe={"request_url": ""})).payout_grade is False


def test_fail_closed_status_zero():
    f = _finding(xe={"response_status": 0})
    f["evidence"]["response_status"] = 0
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_payload_without_external_entity():
    # 外部実体宣言の無い payload では発火しない（我々が XXE を送った証明が必要）
    r = evaluate_payout_grade(_finding(xe={"payload": "<items>hello</items>"}))
    assert r.payout_grade is False


def test_fail_closed_no_file_signature_in_body():
    # システムファイル署名が本文に無い（解決されていない）→ 発火しない
    body = "<items>&x;</items>"  # 実体未解決・passwd 署名なし
    f = _finding(xe={"served_body": body})
    f["evidence"]["response_body"] = body
    assert evaluate_payout_grade(f).payout_grade is False


def test_fires_on_pem_private_key_signature():
    # /etc/passwd 以外でも秘密鍵ヘッダ署名で発火する（同 _XXE_FILE_PATTERNS）
    body = "<items>-----BEGIN RSA PRIVATE KEY-----\nMIIE...</items>"
    payload = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM '
        '"file:///home/user/.ssh/id_rsa">]><items>&x;</items>'
    )
    f = _finding(xe={"served_body": body, "payload": payload})
    f["evidence"]["response_body"] = body
    assert evaluate_payout_grade(f).payout_grade is True
