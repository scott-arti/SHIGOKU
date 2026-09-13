"""SGK-2026-0488: Mass Assignment（特権フィールド昇格）の機械フロア（payout_grade）
発火と fail-closed を検証する。製品非依存（合成データ）。確定は「injection 反映
（攻撃者値）× control 既定値（別の値）の差分」で行う。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/api/Users"
_INJ_SERVED = '{"status":"success","data":{"id":5,"email":"i@target.example","role":"admin"}}'
_CTRL_SERVED = '{"status":"success","data":{"id":4,"email":"c@target.example","role":"customer"}}'


def _finding(**overrides):
    mae = {
        "request_url": _URL,
        "field": "role",
        "injected_value": "admin",
        "injected_payload": '{"email":"i@target.example","role":"admin"}',
        "injected_status": 201,
        "injected_field_value": "admin",
        "injected_served_body": _INJ_SERVED,
        "control_payload": '{"email":"c@target.example"}',
        "control_status": 201,
        "control_field_value": "customer",
        "control_served_body": _CTRL_SERVED,
    }
    mae.update(overrides.pop("mae", {}))
    base = {
        "vuln_type": "mass_assignment",
        "impact": "特権フィールド role を admin で受理させ権限昇格できる。",
        "reproduction_steps": ["role 無しは customer、role:admin 送信で admin になる差分を確認する。"],
        "evidence": {
            "request_method": "POST",
            "request_url": _URL,
            "response_status": 201,
            "response_body": _INJ_SERVED,
        },
        "additional_info": {"mass_assignment_evidence": mae},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    # authz_diff から専用マーカーに分離されていること。
    assert _MARKER_CATEGORIES.get("mass_assignment") == "privileged_field_assigned"


def test_fires_when_differential_holds():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "privileged_field_assigned"


def test_fires_for_boolean_default_false():
    # bool 既定値 False → 攻撃者値 true の昇格も発火する（"false" は非空）。
    r = evaluate_payout_grade(
        _finding(
            mae={
                "field": "verified",
                "injected_value": "true",
                "injected_field_value": "true",
                "control_field_value": "false",
            }
        )
    )
    assert r.payout_grade is True
    assert r.marker == "privileged_field_assigned"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_url():
    assert evaluate_payout_grade(_finding(mae={"request_url": ""})).payout_grade is False


def test_fail_closed_empty_field():
    assert evaluate_payout_grade(_finding(mae={"field": ""})).payout_grade is False


def test_fail_closed_injection_not_reflected():
    # 送った攻撃者値が応答に反映されていない（受理されていない）→ 発火しない。
    r = evaluate_payout_grade(_finding(mae={"injected_field_value": "customer"}))
    assert r.payout_grade is False


def test_fail_closed_echo_control_empty():
    # echo だけ（control でフィールドが応答に現れない＝server-controlled でない）
    # → control_field_value 空で発火しない。
    r = evaluate_payout_grade(_finding(mae={"control_field_value": ""}))
    assert r.payout_grade is False


def test_fail_closed_control_equals_injected():
    # control 既定値が既に攻撃者値と同じ＝昇格になっていない → 発火しない。
    r = evaluate_payout_grade(_finding(mae={"control_field_value": "admin"}))
    assert r.payout_grade is False


def test_fail_closed_injection_non_2xx():
    # injection が成功していない（非 2xx）→ 発火しない。
    r = evaluate_payout_grade(_finding(mae={"injected_status": 400}))
    assert r.payout_grade is False


def test_fail_closed_injected_status_bool():
    # bool は int のサブクラスだが status として不正 → 発火しない。
    r = evaluate_payout_grade(_finding(mae={"injected_status": True}))
    assert r.payout_grade is False


def test_fail_closed_missing_impact():
    # impact/reproduction_steps 欠落は §3 impact ゲートで落ちる。
    f = _finding()
    f.pop("impact")
    f.pop("reproduction_steps")
    assert evaluate_payout_grade(f).payout_grade is False
