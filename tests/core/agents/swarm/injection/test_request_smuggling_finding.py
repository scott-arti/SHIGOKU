"""SGK-2026-0503: SmartRequestSmugglingHunter が CL/TE desync のクロスリクエスト汚染を
確定グレードの Finding に変換することを検証する。製品非依存（合成・注入 raw トランスポート＝
front-end が CL・back-end が TE を尊重する CL.TE desync を模擬・実ネット依存なし）。"""

import asyncio

from src.core.agents.swarm.injection.smart_request_smuggling import SmartRequestSmugglingHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_TARGET = "http://target.example:8080/"


class _FakeDesyncTransport:
    """CL.TE desync を模擬する raw トランスポート（共有 upstream の leftover を持ち越す）。

    - TE:chunked 要求（スマグル）: back-end が TE を尊重し ``0\\r\\n\\r\\n`` 以降を leftover に残す。
    - 通常要求: leftover を先頭に連結して reqline を作り、REQLINE=... を反射する（汚染可視化）。
    """

    def __init__(self, vulnerable=True):
        self.leftover = b""
        self.vulnerable = vulnerable

    def send(self, host, port, data, timeout):
        head = data.split(b"\r\n\r\n", 1)[0]
        reqline = head.split(b"\r\n", 1)[0]
        is_chunked = b"transfer-encoding: chunked" in head.lower()
        if is_chunked and self.vulnerable:
            body = data.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in data else b""
            if b"0\r\n\r\n" in body:
                self.leftover = body.split(b"0\r\n\r\n", 1)[1]
            served = reqline
        else:
            served = self.leftover + reqline
            self.leftover = b""
        payload = b"REQLINE=" + served
        return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(payload), payload)


def _run(transport):
    eng = SmartRequestSmugglingHunter()
    eng._raw_send = transport.send
    task = Task(id="t", name="smug", target=_TARGET,
                params={"smuggling_url": _TARGET, "smuggling_variants": ["clte", "tecl"]})
    return asyncio.run(eng.execute(task))


def test_confirms_clte_smuggling_with_token_poisoning():
    findings = _run(_FakeDesyncTransport(vulnerable=True))
    exp = [f for f in findings if f.vuln_type == VulnType.HTTP_REQUEST_SMUGGLING]
    assert exp, "smuggling finding not produced"
    d = exp[0].to_dict()
    se = d["additional_info"]["smuggling_evidence"]
    assert se["variant"] == "clte"
    token = se["token"]
    assert token in se["poisoned_victim_body"]        # 別 victim 応答に混入
    assert token not in se["clean_victim_body"]        # clean には非出現
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "http_request_smuggling_confirmed"


def test_no_finding_when_not_vulnerable():
    findings = _run(_FakeDesyncTransport(vulnerable=False))
    assert [f for f in findings if f.vuln_type == VulnType.HTTP_REQUEST_SMUGGLING] == []


def test_poc_shows_token_and_correlation():
    d = _run(_FakeDesyncTransport(vulnerable=True))[0].to_dict()
    poc = d["additional_info"]["poc_response"]
    token = d["additional_info"]["smuggling_evidence"]["token"]
    assert token in poc
    assert "CORRELATION" in poc


def test_payout_grade_fail_closed_when_token_in_clean():
    d = _run(_FakeDesyncTransport(vulnerable=True))[0].to_dict()
    se = d["additional_info"]["smuggling_evidence"]
    se["clean_victim_body"] = se["clean_victim_body"] + se["token"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False


def test_payout_grade_fail_closed_when_token_absent_from_poisoned():
    d = _run(_FakeDesyncTransport(vulnerable=True))[0].to_dict()
    d["additional_info"]["smuggling_evidence"]["poisoned_victim_body"] = "REQLINE=GET /clean"
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False


def test_payout_grade_fail_closed_bad_variant():
    d = _run(_FakeDesyncTransport(vulnerable=True))[0].to_dict()
    d["additional_info"]["smuggling_evidence"]["variant"] = "xxxx"
    r = evaluate_payout_grade(d)
    assert r.payout_grade is False
