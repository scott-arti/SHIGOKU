"""SGK-2026-0490: JWT RS256→HS256 キー混同の機械フロア（payout_grade）発火と
fail-closed を検証する。製品非依存（合成データ）。確定は alg=none と共有マーカー
jwt_forgery_accepted（jwt_alg=hs256＋key_confusion＋baseline absent＋forged 反映）。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/whoami"
_MARK = "shigoku_jwtforge_abc123"
_FORGED_BODY = f'{{"user":{{"email":"{_MARK}"}}}}'


def _finding(**overrides):
    info = {
        "jwt_alg": "hs256",
        "jwt_key_confusion": True,
        "unauth_baseline_absent": True,
        "forged_identity": _MARK,
        "forged_identity_reflected": True,
        "forged_token": "h.p.s",
        "jwt_forgery_evidence": {"observe_url": _URL, "claim": "data.email",
                                 "forged_status": 200, "forged_served_body": _FORGED_BODY,
                                 "control_served_body": '{"user":{}}',
                                 "wrong_secret_served_body": '{"user":{}}'},
    }
    info.update(overrides.pop("info", {}))
    base = {
        "vuln_type": "jwt_rs256_hs256",
        "impact": "公開鍵を HMAC 秘密に署名した偽造 JWT が受理される（認証バイパス）。",
        "reproduction_steps": ["公開鍵秘密で受理/誤り秘密で拒否/無しで空の3者差分を確認する。"],
        "evidence": {
            "request_method": "GET",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _FORGED_BODY,
        },
        "additional_info": info,
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("jwt_rs256_hs256") == "jwt_forgery_accepted"


def test_shares_marker_with_alg_none():
    assert _MARKER_CATEGORIES.get("jwt_alg_none") == "jwt_forgery_accepted"


def test_fires_when_key_confusion_confirmed():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "jwt_forgery_accepted"


def test_fail_closed_alg_not_hs256():
    assert evaluate_payout_grade(_finding(info={"jwt_alg": "rs256"})).payout_grade is False


def test_fail_closed_key_confusion_false():
    assert evaluate_payout_grade(_finding(info={"jwt_key_confusion": False})).payout_grade is False


def test_fail_closed_baseline_not_absent():
    assert evaluate_payout_grade(_finding(info={"unauth_baseline_absent": False})).payout_grade is False


def test_fail_closed_forged_identity_empty():
    assert evaluate_payout_grade(_finding(info={"forged_identity": ""})).payout_grade is False


def test_fail_closed_not_reflected():
    # 反映フラグ偽 かつ body（evidence+poc）に marker 非出現 → 発火しない。
    f = _finding(info={"forged_identity_reflected": False})
    f["evidence"]["response_body"] = "{}"
    f["additional_info"]["jwt_forgery_evidence"]["forged_served_body"] = "{}"
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_missing_impact():
    f = _finding()
    f.pop("impact")
    f.pop("reproduction_steps")
    assert evaluate_payout_grade(f).payout_grade is False
