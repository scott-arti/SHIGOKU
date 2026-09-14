"""SGK-2026-0499: LDAP インジェクション（認証バイパス）の封印再現（fresh リテラルの
コントロール×確定済みメタ文字ペイロードを再送し、成功印が注入応答に再出現＋コントロールに
非出現）を検証する。製品非依存・実ネット依存なし（sync form fake）。"""

from types import SimpleNamespace

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

_B = "https://target.example"
_SCOPE = ScopeDefinition(program_name="sealed-ldap-test", in_scope_domains=["target.example"])
_MARKER = "You are now admin user!"


class _SyncLDAPServer:
    """checker の sync form パス（_send_post_form）が呼ぶ注入クライアント。
    メタ文字 '*'/'*' で成功印、リテラルで失敗（フィルタ意味論の模擬）。"""

    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable

    def request(self, method, url, data=None, headers=None, **kw):
        u = str((data or {}).get("username", ""))
        p = str((data or {}).get("password", ""))
        ok = self.vulnerable and u == "*" and p == "*"
        body = f"<html>{_MARKER if ok else 'Wrong identity provided.'}</html>"
        return SimpleNamespace(status=200, body=body, headers={})


def _finding():
    return Finding(
        target_url=f"{_B}/login",
        vuln_type=VulnType.LDAP_INJECTION,
        severity=Severity.CRITICAL,
        title="LDAP Injection (auth bypass)",
        description="differential",
        source_agent="SmartLDAPInjectionHunter",
        evidence=Evidence(
            request_method="POST", request_url=f"{_B}/login", request_headers={},
            request_body="username=*&password=*", response_status=200,
            response_body=f"<html>{_MARKER}</html>",
        ),
        additional_info={
            "ldap_evidence": {
                "request_url": f"{_B}/login",
                "injection_payload": "username=*&password=*",
                "success_marker": _MARKER,
                "injected_status": 200,
                "injected_served_body": f"<html>{_MARKER}</html>",
                "control_served_body": "<html>Wrong identity provided.</html>",
            },
            "ldap_replay": {
                "method": "POST", "url": f"{_B}/login",
                "user_param": "username", "pass_param": "password",
                "inj_user": "*", "inj_pass": "*", "success_marker": _MARKER,
            },
            "poc_request": "POST x", "poc_response": "HTTP/1.1 200",
        },
    )


def test_matched_when_metachar_reauthenticates():
    chk = SealedReproductionChecker(
        network_client=_SyncLDAPServer(vulnerable=True), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "matched"
    assert "ldap_injection_confirmed" in out.reason


def test_mismatched_when_not_vulnerable():
    chk = SealedReproductionChecker(
        network_client=_SyncLDAPServer(vulnerable=False), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_no_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=_SCOPE, timeout_seconds=5)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_out_of_scope():
    other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    chk = SealedReproductionChecker(
        network_client=_SyncLDAPServer(vulnerable=True), scope_definition=other, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_replay_has_no_metachar():
    f = _finding().to_dict()
    f["additional_info"]["ldap_replay"]["inj_user"] = "admin"
    f["additional_info"]["ldap_replay"]["inj_pass"] = "admin"
    chk = SealedReproductionChecker(
        network_client=_SyncLDAPServer(vulnerable=True), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(f)
    assert out.status == "not_run"
