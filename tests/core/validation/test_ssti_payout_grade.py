"""SGK-2026-0485: SSTI（サーバサイドテンプレートインジェクション）の機械フロア
（payout_grade）発火と fail-closed を検証する。製品非依存（合成データ）。
証拠は算術積＋一意マーカー（expected）で自然混入・テンプレ捏造不可。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/x?q=%7B%7B7%2A7%7D%7Ddeadbeef"
_EXPECTED = "49deadbeef"  # 算術積 49 ＋ 一意マーカー
_SERVED = f'<p style="font-size:2em;"> https://target.example/x?q={_EXPECTED} </p>'


def _finding(**overrides):
    sse = {
        "parameter": "q",
        "engine": "jinja2",
        "payload": "{{7*7}}deadbeef",
        "expected": _EXPECTED,
        "request_method": "GET",
        "request_url": _URL,
        "response_status": 404,
        "served_body": _SERVED,
    }
    sse.update(overrides.pop("sse", {}))
    base = {
        "vuln_type": "ssti",
        "impact": "テンプレートが評価される（RCE 隣接）。",
        "reproduction_steps": ["算術テンプレートを付けて GET する。"],
        "evidence": {
            "request_method": "GET",
            "request_url": _URL,
            "response_status": 404,
            "response_body": _SERVED,
        },
        "additional_info": {"ssti_evidence": sse},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("ssti") == "template_evaluated"


def test_fires_when_complete():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "template_evaluated"


def test_fires_on_404_status():
    # SSTI は 404 ページで評価されることがある。status>0 なら再現ゲート通過。
    r = evaluate_payout_grade(_finding(sse={"response_status": 404}))
    assert r.payout_grade is True


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_request_url():
    assert evaluate_payout_grade(_finding(sse={"request_url": ""})).payout_grade is False


def test_fail_closed_status_zero():
    f = _finding(sse={"response_status": 0})
    f["evidence"]["response_status"] = 0
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_payload():
    assert evaluate_payout_grade(_finding(sse={"payload": ""})).payout_grade is False


def test_fail_closed_empty_expected():
    assert evaluate_payout_grade(_finding(sse={"expected": ""})).payout_grade is False


def test_fail_closed_expected_absent_from_body():
    # 算術積が本文に無い（＝評価されていない）→ 発火しない
    body = '<p> https://target.example/x?q={{7*7}}deadbeef </p>'  # 未評価
    f = _finding(sse={"served_body": body})
    f["evidence"]["response_body"] = body
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_bare_49_without_marker():
    # マーカー無しの "49" だけが本文にあっても発火しない（自然混入対策）
    body = '<p> price: 49 dollars </p>'
    f = _finding(sse={"served_body": body})
    f["evidence"]["response_body"] = body
    assert evaluate_payout_grade(f).payout_grade is False
