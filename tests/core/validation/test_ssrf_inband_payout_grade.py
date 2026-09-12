"""SGK-2026-0482: in-band SSRF の確定バー（payout_grade）判定。

製品非依存 fixture のみ。ssrf_inband_evidence が揃ったときだけ ssrf_inband
マーカーが発火し、欠落は fail-closed。既存 ssrf_callback 経路は非回帰。
"""
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade


def _finding(inband=None, body="raw"):
    f = {
        "vuln_type": "ssrf",
        "evidence": {
            "request_method": "POST",
            "request_url": "http://target.example/fetch",
            "response_status": 200,
            "response_body": body,
        },
        "impact": "server-side fetch of internal resource",
        "reproduction_steps": ["send url field", "observe reflected body"],
        "additional_info": {},
    }
    if inband is not None:
        f["additional_info"]["ssrf_inband_evidence"] = inband
    return f


def test_inband_full_evidence_fires():
    r = evaluate_payout_grade(_finding({
        "fetched_url": "http://internal.invalid/",
        "server_reflected_body": "INTERNAL-ONLY-BODY",
        "client_direct_unreachable": True,
    }))
    assert r.payout_grade is True
    assert r.marker == "ssrf_inband"


def test_inband_empty_reflected_body_fails_closed():
    r = evaluate_payout_grade(_finding({
        "fetched_url": "http://internal.invalid/",
        "server_reflected_body": "",
        "client_direct_unreachable": True,
    }))
    assert r.payout_grade is False


def test_inband_client_reachable_fails_closed():
    r = evaluate_payout_grade(_finding({
        "fetched_url": "http://internal.invalid/",
        "server_reflected_body": "BODY",
        "client_direct_unreachable": False,
    }))
    assert r.payout_grade is False


def test_inband_missing_fetched_url_fails_closed():
    r = evaluate_payout_grade(_finding({
        "fetched_url": "",
        "server_reflected_body": "BODY",
        "client_direct_unreachable": True,
    }))
    assert r.payout_grade is False


def test_legacy_ssrf_callback_indicator_unchanged():
    # 既存 OOB/指標エコー経路: ssrf_inband_evidence 無しでも body 指標で発火。
    r = evaluate_payout_grade(_finding(inband=None, body="fetched 169.254.169.254 metadata"))
    assert r.payout_grade is True
    assert r.marker == "ssrf_callback"
