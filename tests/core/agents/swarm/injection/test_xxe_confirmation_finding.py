"""SGK-2026-0486: SmartXXEHunter が in-band XXE を確定グレードの Finding に
変換することを検証する。製品非依存（合成データ・注入クライアント）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_xxe import SmartXXEHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/home"
_PASSWD_BODY = (
    '<html><body><items>root:x:0:0:root:/root:/bin/ash\n'
    'daemon:x:1:1:daemon:/usr/sbin/nologin</items></body></html>'
)


class _Client:
    """外部実体ペイロードに passwd 内容を返す注入クライアント。"""

    def __init__(self, body, status=200, reflect=True):
        self.body = body
        self.status = status
        self.reflect = reflect
        self.calls = []

    async def request(self, method, url, data=None, headers=None, use_proxy=True, **kw):
        self.calls.append({"method": method, "url": url, "data": data})
        body = self.body if self.reflect else "<items>&x;</items>"
        return SimpleNamespace(status=self.status, text=body, body=body, headers={})


def _run(client, params=None):
    eng = SmartXXEHunter()
    eng._client = client
    task = Task(id="t", name="xxe", target=_URL, tags=["xxe"])
    if params:
        task.params = params
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_file_read():
    findings = _run(_Client(_PASSWD_BODY))
    exp = [f for f in findings if f.vuln_type == VulnType.XXE]
    assert exp, "XXE finding not produced"
    d = exp[0].to_dict()
    xe = d["additional_info"]["xxe_evidence"]
    assert "root:x:0:0" in xe["served_body"]
    assert "<!ENTITY" in xe["payload"] and "SYSTEM" in xe["payload"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "xxe_file_read"


def test_replay_descriptor_present():
    f = _run(_Client(_PASSWD_BODY))[0]
    replay = f.to_dict()["additional_info"]["xxe_replay"]
    assert replay["method"] == "POST"
    assert "<!ENTITY" in replay["payload"]
    assert replay["url"]


def test_no_finding_when_no_file_signature():
    # passwd 署名が返らない（解決されない）→ finding を作らない（fail-closed）
    findings = _run(_Client("<items>&x;</items>", reflect=False))
    assert [f for f in findings if f.vuln_type == VulnType.XXE] == []


def test_payload_carries_external_entity():
    f = _run(_Client(_PASSWD_BODY))[0]
    payload = f.to_dict()["additional_info"]["xxe_evidence"]["payload"]
    assert "<!ENTITY" in payload
    assert "file:///etc/passwd" in payload


def test_snippet_is_bounded():
    big = "A" * 5000 + "<items>root:x:0:0:root:/root:/bin/ash</items>" + "B" * 5000
    f = _run(_Client(big))[0]
    served = f.to_dict()["additional_info"]["xxe_evidence"]["served_body"]
    assert "root:x:0:0" in served
    assert len(served) < len(big)
