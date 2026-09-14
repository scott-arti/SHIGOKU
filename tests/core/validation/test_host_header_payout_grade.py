"""SGK-2026-0491: Host Header Injection（認可バイパス）の機械フロア（payout_grade）
発火と fail-closed を検証する。製品非依存（合成データ）。確定は「注入ホストで制限署名が
出て非バイパスホストで出ない差分」で行う。"""

from src.core.agents.swarm.injection.payout_grade import (
    evaluate_payout_grade,
    _MARKER_CATEGORIES,
)

_URL = "https://target.example/dashboard"
_SIG = "Mr Mark Oney"
_INJ = f"<td>{_SIG}</td><td>1000000</td>"
_CTRL = "Redirecting... you should be redirected to /"


def _finding(**overrides):
    hh = {
        "request_url": _URL,
        "injected_header": "Host",
        "injected_host_value": "localhost",
        "control_host": "shigoku-control.example",
        "restricted_signature": _SIG,
        "injected_status": 200,
        "injected_served_body": _INJ,
        "control_served_body": _CTRL,
    }
    hh.update(overrides.pop("hh", {}))
    base = {
        "vuln_type": "host_header_injection",
        "impact": "Host を localhost に差し替えると制限データが認証なしで漏洩する。",
        "reproduction_steps": ["非バイパスホストで拒否、localhost で制限データが出る差分を確認する。"],
        "evidence": {
            "request_method": "GET",
            "request_url": _URL,
            "response_status": 200,
            "response_body": _INJ,
        },
        "additional_info": {"host_header_evidence": hh},
    }
    base.update(overrides)
    return base


def test_marker_category_registered():
    assert _MARKER_CATEGORIES.get("host_header_injection") == "host_header_auth_bypass"


def test_fires_when_differential_holds():
    r = evaluate_payout_grade(_finding())
    assert r.payout_grade is True
    assert r.marker == "host_header_auth_bypass"


def test_fail_closed_missing_evidence_dict():
    f = _finding()
    f["additional_info"] = {}
    assert evaluate_payout_grade(f).payout_grade is False


def test_fail_closed_empty_url():
    assert evaluate_payout_grade(_finding(hh={"request_url": ""})).payout_grade is False


def test_fail_closed_empty_header():
    assert evaluate_payout_grade(_finding(hh={"injected_header": ""})).payout_grade is False


def test_fail_closed_empty_signature():
    assert evaluate_payout_grade(_finding(hh={"restricted_signature": ""})).payout_grade is False


def test_fail_closed_signature_not_in_injected():
    r = evaluate_payout_grade(_finding(hh={"injected_served_body": "<td>nothing</td>"}))
    assert r.payout_grade is False


def test_fail_closed_signature_also_in_control():
    # 非バイパスでも署名が出る＝アクセス制御されていない → 発火しない。
    r = evaluate_payout_grade(_finding(hh={"control_served_body": _INJ}))
    assert r.payout_grade is False


def test_fail_closed_injection_non_2xx():
    assert evaluate_payout_grade(_finding(hh={"injected_status": 302})).payout_grade is False


def test_fail_closed_missing_impact():
    f = _finding()
    f.pop("impact")
    f.pop("reproduction_steps")
    assert evaluate_payout_grade(f).payout_grade is False
