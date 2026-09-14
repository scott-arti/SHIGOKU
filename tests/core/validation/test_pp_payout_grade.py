"""SGK-2026-0497: プロトタイプ汚染の機械フロア（payout_grade）発火と fail-closed を検証。
製品非依存（合成データ）。確定は「汚染後の新オブジェクトにマーカー出現×汚染前は不在」の差分。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_MK = "shigoku_pp_deadbeef01"


def _finding(**over):
    pp = {
        "sink_url": "https://target.example/message",
        "observe_url": "https://target.example/login",
        "pollute_property": "admin",
        "marker": _MK,
        "observe_status": 200,
        "polluted_served_body": f"<h4>Admin: <B>{_MK}</B></h4>",
        "control_served_body": "<h4>Admin: <B></B></h4>",
    }
    pp.update(over.pop("pp", {}))
    base = {
        "vuln_type": "prototype_pollution",
        "impact": "__proto__.admin 汚染で新オブジェクトが admin を継承（privesc）。",
        "reproduction_steps": ["汚染前は空、汚染後に別オブジェクトへマーカー出現の差分を確認。"],
        "evidence": {
            "request_method": "POST", "request_url": "https://target.example/login",
            "response_status": 200, "response_body": f"Admin {_MK}",
        },
        "additional_info": {
            "prototype_pollution_evidence": pp,
            "poc_request": "POST https://target.example/login HTTP/1.1",
            "poc_response": f"HTTP/1.1 200\r\nAdmin {_MK}",
        },
    }
    base.update(over)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("prototype_pollution") == "prototype_pollution_confirmed"


def test_fires_when_differential_holds():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "prototype_pollution_confirmed"


def test_fail_closed_missing_evidence():
    f = _finding()
    f["additional_info"].pop("prototype_pollution_evidence")
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_sink_url():
    assert evaluate_payout_grade(_finding(pp={"sink_url": ""})).payout_grade is False


def test_fail_closed_empty_property():
    assert evaluate_payout_grade(_finding(pp={"pollute_property": ""})).payout_grade is False


def test_fail_closed_marker_not_in_polluted():
    assert evaluate_payout_grade(_finding(pp={"polluted_served_body": "<h4>Admin: <B></B></h4>"})).payout_grade is False


def test_fail_closed_marker_also_in_control():
    assert evaluate_payout_grade(_finding(pp={"control_served_body": f"Admin {_MK}"})).payout_grade is False


def test_fail_closed_observe_non_2xx():
    assert evaluate_payout_grade(_finding(pp={"observe_status": 500})).payout_grade is False


def test_fail_closed_missing_impact():
    f = _finding()
    f.pop("impact")
    f.pop("reproduction_steps")
    assert evaluate_payout_grade(f).payout_grade is False
