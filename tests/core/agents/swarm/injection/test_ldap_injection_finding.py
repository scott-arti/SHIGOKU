"""SGK-2026-0499: SmartLDAPInjectionHunter が LDAP フィルタのメタ文字による認証バイパスを
差分（リテラル失敗×メタ文字成功）で確定グレードの Finding に変換することを検証する。
製品非依存（合成 form サーバ・target.example）。標的の LDAP は fake（フィルタ意味論を模擬）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.agents.swarm.injection.smart_ldap_injection import SmartLDAPInjectionHunter
from src.core.models.finding import VulnType

_URL = "https://target.example/login"
_SUCCESS = '<p class="ok">You are now admin user!</p>'
_FAIL = "<p>Wrong identity provided.</p>"
# マーカーが先頭切り詰め領域外に来ることを模す長いプレフィックス。
_PREFIX = "<html><head><title>demo</title></head><body>" + ("x" * 1800)


class _FakeLDAPFormClient:
    """`(&(cn=<u>)(sn=<p>))` を模擬: メタ文字 '*' を含むと認証成功ページ、
    リテラルは失敗ページを返す（フィルタ意味論の最小模擬）。"""

    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": dict(data or {})})
        u = str((data or {}).get("username", ""))
        p = str((data or {}).get("password", ""))
        success = self.vulnerable and (u == "*" and p == "*")
        body = _PREFIX + (_SUCCESS if success else _FAIL) + "</body></html>"
        return SimpleNamespace(status=200, body=body, text=body, headers={})


def _run(client, params=None):
    eng = SmartLDAPInjectionHunter()
    eng._client = client
    task = Task(id="t", name="ldap", target=_URL, tags=["ldap_injection"])
    task.params = params or {}
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_differential():
    findings = _run(_FakeLDAPFormClient(vulnerable=True))
    exp = [f for f in findings if f.vuln_type == VulnType.LDAP_INJECTION]
    assert exp, "LDAP injection finding not produced"
    d = exp[0].to_dict()
    ev = d["additional_info"]["ldap_evidence"]
    assert "*" in ev["injection_payload"]
    # マーカー中心スニペットで先頭切り詰めを回避（証拠が snippet に載る）。
    assert ev["success_marker"] in ev["injected_served_body"]
    assert ev["success_marker"] not in ev["control_served_body"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "ldap_injection_confirmed"


def test_poc_shows_both_sides():
    d = _run(_FakeLDAPFormClient(vulnerable=True))[0].to_dict()
    info = d["additional_info"]
    # 両ステップ（control 失敗 / injection 成功）が poc に含まれる（差分の教訓）。
    assert "negative control" in info["poc_request"]
    assert "metacharacter injection" in info["poc_request"]
    assert info["ldap_evidence"]["success_marker"] in info["poc_response"]


def test_no_finding_when_not_vulnerable():
    findings = _run(_FakeLDAPFormClient(vulnerable=False))
    assert [f for f in findings if f.vuln_type == VulnType.LDAP_INJECTION] == []


def test_control_uses_random_literals_without_metachars():
    client = _FakeLDAPFormClient(vulnerable=True)
    _run(client)
    # 最初の2送信は負のコントロール（メタ文字を含まないランダムリテラル）。
    for call in client.calls[:2]:
        assert "*" not in call["data"]["username"]
        assert ")(" not in call["data"]["username"]


def test_provided_marker_is_used_when_given():
    d = _run(_FakeLDAPFormClient(vulnerable=True),
             params={"ldap_success_marker": "You are now admin user!"})[0].to_dict()
    assert d["additional_info"]["ldap_evidence"]["success_marker"] == "You are now admin user!"


def test_payout_grade_fail_closed_when_no_metachar():
    d = _run(_FakeLDAPFormClient(vulnerable=True))[0].to_dict()
    # メタ文字を潰すと発火しない（fail-closed）。
    d["additional_info"]["ldap_evidence"]["injection_payload"] = "username=admin&password=admin"
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False


def test_payout_grade_fail_closed_when_marker_in_control():
    d = _run(_FakeLDAPFormClient(vulnerable=True))[0].to_dict()
    # 成功印がコントロールにも出るなら差分が成立せず → 発火しない。
    ev = d["additional_info"]["ldap_evidence"]
    ev["control_served_body"] = ev["control_served_body"] + ev["success_marker"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False
