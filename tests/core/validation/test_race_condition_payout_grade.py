"""SGK-2026-0489: Race Condition（TOCTOU）の機械フロア（payout_grade）発火と
fail-closed を検証する。製品非依存（合成データ）。確定は「並列でマーカー反映×
逐次で非反映の差分」で行う。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/race"
_MARK = "SHIGOKU_RACE_deadbeef01"
_RACE_BODY = f'<div id="system-message">{_MARK}</div>'
_CTRL_BODY = '<div id="system-message">Default User</div>'


def _finding(**overrides):
    rev = {
        "request_url": _URL,
        "marker": _MARK,
        "race_status": 200,
        "race_served_body": _RACE_BODY,
        "control_status": 200,
        "control_served_body": _CTRL_BODY,
        "concurrency": 8,
        "rounds": 25,
    }
    rev.update(overrides.pop("rev", {}))
    base = {
        "vuln_type": "race_condition",
        "impact": "並列バーストで TOCTOU 窓の注入が実行される（検証バイパス）。",
        "reproduction_steps": ["逐次はマーカー非反映、並列はマーカー反映の差分を確認する。"],
        "evidence": {
            "request_method": "GET",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _RACE_BODY,
        },
        "additional_info": {"race_evidence": rev},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("race_condition") == "race_condition_toctou"


def test_fires_when_differential_holds():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "race_condition_toctou"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_url():
    assert evaluate_payout_grade(_finding(rev={"request_url": ""})).payout_grade is False


def test_fail_closed_empty_marker():
    assert evaluate_payout_grade(_finding(rev={"marker": ""})).payout_grade is False


def test_fail_closed_marker_not_in_race_body():
    # 並列でマーカーが反映されていない → 発火しない。
    r = evaluate_payout_grade(_finding(rev={"race_served_body": "<div>nothing</div>"}))
    assert r.payout_grade is False


def test_fail_closed_marker_also_in_control():
    # 逐次でもマーカーが出る＝TOCTOU 差分でない（単なる注入）→ 発火しない。
    r = evaluate_payout_grade(_finding(rev={"control_served_body": _RACE_BODY}))
    assert r.payout_grade is False


def test_fail_closed_race_non_2xx():
    r = evaluate_payout_grade(_finding(rev={"race_status": 500})).payout_grade
    assert r is False


def test_fail_closed_race_status_bool():
    # bool は int サブクラスだが status として不正 → 発火しない。
    assert evaluate_payout_grade(_finding(rev={"race_status": True})).payout_grade is False


def test_fail_closed_missing_impact():
    f = _finding()
    f.pop("impact")
    f.pop("reproduction_steps")
    assert evaluate_payout_grade(f).payout_grade is False
