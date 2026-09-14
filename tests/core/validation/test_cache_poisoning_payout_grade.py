"""SGK-2026-0492: Web キャッシュポイズニングの機械フロア（payout_grade）発火と
fail-closed を検証する。製品非依存（合成データ）。確定は「一意 marker がクリーンな
victim 応答に出て別鍵の control に出ない差分」で行う。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/?shigoku_cp=abc"
_MARK = "shigoku-cp-deadbeef.evil.example"
_POISONED = f'<script src="//{_MARK}/js/tracking.js"></script>'
_CLEAN = '<script src="//127.0.0.1/js/tracking.js"></script>'


def _finding(**overrides):
    cp = {
        "request_url": _URL,
        "injected_header": "X-Forwarded-Host",
        "marker": _MARK,
        "poison_status": 200,
        "poison_served_body": _POISONED,
        "victim_status": 200,
        "victim_served_body": _POISONED,
        "control_served_body": _CLEAN,
    }
    cp.update(overrides.pop("cp", {}))
    base = {
        "vuln_type": "cache_poisoning",
        "impact": "unkeyed 入力がキャッシュされクリーンな victim に攻撃者コンテンツが配信される。",
        "reproduction_steps": ["毒→victim(クリーン)反映→control 非反映の差分を確認する。"],
        "evidence": {
            "request_method": "GET",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _POISONED,
        },
        "additional_info": {"cache_poisoning_evidence": cp},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("cache_poisoning") == "cache_poisoning_confirmed"


def test_fires_when_victim_poisoned():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "cache_poisoning_confirmed"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_url():
    assert evaluate_payout_grade(_finding(cp={"request_url": ""})).payout_grade is False


def test_fail_closed_empty_header():
    assert evaluate_payout_grade(_finding(cp={"injected_header": ""})).payout_grade is False


def test_fail_closed_empty_marker():
    assert evaluate_payout_grade(_finding(cp={"marker": ""})).payout_grade is False


def test_fail_closed_marker_not_in_victim():
    # victim(クリーン)に marker が出ない＝キャッシュ配信されていない → 発火しない。
    r = evaluate_payout_grade(_finding(cp={"victim_served_body": _CLEAN}))
    assert r.payout_grade is False


def test_fail_closed_marker_also_in_control():
    # 別鍵の control にも marker が出る＝キャッシュ配信の証明にならない → 発火しない。
    r = evaluate_payout_grade(_finding(cp={"control_served_body": _POISONED}))
    assert r.payout_grade is False


def test_fail_closed_victim_non_2xx():
    assert evaluate_payout_grade(_finding(cp={"victim_status": 500})).payout_grade is False


def test_fail_closed_missing_impact():
    f = _finding()
    f.pop("impact")
    f.pop("reproduction_steps")
    assert evaluate_payout_grade(f).payout_grade is False
