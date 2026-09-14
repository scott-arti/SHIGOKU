"""SGK-2026-0497: プロトタイプ汚染の封印再現（pollute→setup→observe を新マーカーで再実行）
を検証。in-band 差分・製品非依存・実ネット依存なし（sync stateful fake）。"""

import json
from types import SimpleNamespace

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

_B = "https://target.example"
_SCOPE = ScopeDefinition(program_name="sealed-pp-test", in_scope_domains=["target.example"])


class _SyncPPServer:
    """checker の sync パス（_send_post_json/_send_post_form）が呼ぶ注入クライアント。"""

    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable
        self.proto = {}

    def request(self, method, url, data=None, headers=None, **kw):
        if url.endswith("/message"):
            body = json.loads(data) if isinstance(data, str) else (data or {})
            proto = body.get("__proto__")
            if self.vulnerable and isinstance(proto, dict):
                self.proto.update(proto)
            return SimpleNamespace(status=302, body="", headers={})
        if url.endswith("/create"):
            return SimpleNamespace(status=200, body="created", headers={})
        if url.endswith("/login"):
            admin = self.proto.get("admin", "")
            return SimpleNamespace(status=200, body=f"<h4>Admin: <B>{admin}</B></h4>", headers={})
        return SimpleNamespace(status=404, body="", headers={})


def _finding():
    return Finding(
        target_url=f"{_B}/message",
        vuln_type=VulnType.PROTOTYPE_POLLUTION,
        severity=Severity.HIGH,
        title="Prototype pollution",
        description="differential",
        source_agent="SmartPrototypePollutionHunter",
        evidence=Evidence(
            request_method="POST", request_url=f"{_B}/login", request_headers={},
            request_body="seed", response_status=200, response_body="Admin seed",
        ),
        additional_info={
            "prototype_pollution_evidence": {
                "sink_url": f"{_B}/message", "observe_url": f"{_B}/login",
                "pollute_property": "admin", "marker": "seedmk", "observe_status": 200,
                "polluted_served_body": "Admin seedmk", "control_served_body": "Admin ",
            },
            "prototype_pollution_replay": {
                "sink": {"method": "POST", "url": f"{_B}/message", "mode": "json",
                         "body": {"__proto__": {"admin": "{marker}"}, "email": "e@e.co", "msg": "x"}},
                "setup": [{"method": "POST", "url": f"{_B}/create", "mode": "form",
                           "body": {"username": "{uniq}", "password": "p"}}],
                "observe": {"method": "POST", "url": f"{_B}/login", "mode": "form",
                            "body": {"username": "{uniq}", "password": "p"}},
                "property": "admin",
            },
            "poc_request": "POST x", "poc_response": "HTTP/1.1 200",
        },
    )


def test_matched_when_repollution_reflects_fresh_marker():
    chk = SealedReproductionChecker(
        network_client=_SyncPPServer(vulnerable=True), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "matched"
    assert "prototype_pollution_confirmed" in out.reason


def test_mismatched_when_not_vulnerable():
    chk = SealedReproductionChecker(
        network_client=_SyncPPServer(vulnerable=False), scope_definition=_SCOPE, timeout_seconds=5,
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
        network_client=_SyncPPServer(vulnerable=True), scope_definition=other, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_replay_incomplete():
    f = _finding().to_dict()
    f["additional_info"]["prototype_pollution_replay"]["property"] = ""
    chk = SealedReproductionChecker(
        network_client=_SyncPPServer(vulnerable=True), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(f)
    assert out.status == "not_run"
