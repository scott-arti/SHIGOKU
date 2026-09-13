"""SGK-2026-0487: NoSQL(MongoDB) 演算子注入の機械フロア（payout_grade）発火と
fail-closed を検証する。製品非依存（合成データ）。確定は「演算子成功×無効
リテラル失敗の差分」で行う。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/api/validate-coupon"
_OP_BODY = '{"coupon_code": {"$ne": null}}'
_OP_SERVED = '{"coupon_code":"TRAC075","amount":"75"}'


def _finding(**overrides):
    ne = {
        "request_url": _URL,
        "field": "coupon_code",
        "operator_payload": _OP_BODY,
        "operator_status": 200,
        "operator_served_body": _OP_SERVED,
        "control_value": "shigoku_nosql_deadbeef",
        "control_status": 500,
        "control_served_body": "{}",
    }
    ne.update(overrides.pop("ne", {}))
    base = {
        "vuln_type": "nosql_injection",
        "impact": "演算子で有効レコードが返る（認可バイパス）。",
        "reproduction_steps": ["無効リテラルは失敗、演算子は成功する差分を確認する。"],
        "evidence": {
            "request_method": "POST",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _OP_SERVED,
        },
        "additional_info": {"nosql_evidence": ne},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("nosql_injection") == "nosql_operator_injection"


def test_fires_when_differential_holds():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "nosql_operator_injection"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_url():
    assert evaluate_payout_grade(_finding(ne={"request_url": ""})).payout_grade is False


def test_fail_closed_payload_without_operator():
    # 演算子を含まない payload では発火しない（我々が演算子を送った証明が必要）
    r = evaluate_payout_grade(_finding(ne={"operator_payload": '{"coupon_code": "abc"}'}))
    assert r.payout_grade is False


def test_fail_closed_operator_not_success():
    # 演算子が成功していない（非 2xx）→ 発火しない
    f = _finding(ne={"operator_status": 500})
    f["evidence"]["response_status"] = 500
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_operator_empty_body():
    f = _finding(ne={"operator_served_body": "{}"})
    f["evidence"]["response_body"] = "{}"
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_control_also_succeeds():
    # 負のコントロールも成功する（差分が作れない）→ 発火しない
    r = evaluate_payout_grade(
        _finding(ne={"control_status": 200, "control_served_body": _OP_SERVED})
    )
    assert r.payout_grade is False


def test_fires_with_regex_operator():
    r = evaluate_payout_grade(
        _finding(ne={"operator_payload": '{"coupon_code": {"$regex": ".*"}}'})
    )
    assert r.payout_grade is True
