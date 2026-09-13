"""SGK-2026-0485: SmartSSTIHunter が SSTI を確定グレードの Finding に変換し、
生証拠（算術積を含む本文＋実 status＋poc 対＋ssti_evidence/ssti_replay）を
付与することを検証する。製品非依存（合成データ）。"""

import asyncio
import json
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_ssti import SmartSSTIHunter
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/x?q=test"
_EXPECTED = "49deadbeef"
# 反映が本文後方（>2000）にあっても拾えることを確認するための長い前置き。
_LONG_PREFIX = "<html><head>" + ("x" * 3000) + "</head><body>"
_BODY_WITH_PRODUCT = (
    _LONG_PREFIX
    + f'<p style="font-size:2em;"> {_URL}?q={_EXPECTED} </p></body></html>'
)


def _result(proof):
    return {
        "vulnerable": True,
        "param": "q",
        "engine": "jinja2",
        "payload": "{{7*7}}deadbeef",
        "expected": _EXPECTED,
        "method": "GET",
        "confidence": 0.95,
        "evidence": "scanner-raw-evidence",
        "proof": proof,
        "tested_params": ["q"],
        "all_results": [],
    }


def _proof(served_body, status=404):
    return {
        "request_method": "GET",
        "request_url": "https://target.example/x?q=%7B%7B7%2A7%7D%7Ddeadbeef",
        "request_body": "",
        "response_status": status,
        "served_body": served_body,
        "observed": _EXPECTED in served_body,
    }


def test_convert_builds_payout_grade_finding():
    eng = SmartSSTIHunter()
    findings = eng._convert_to_findings(_result(_proof(_BODY_WITH_PRODUCT)), _URL)
    assert findings
    f = findings[0]
    assert f.vuln_type == VulnType.SSTI
    d = f.to_dict()
    sse = d["additional_info"]["ssti_evidence"]
    assert sse["expected"] == _EXPECTED
    assert _EXPECTED in sse["served_body"]
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "template_evaluated"


def test_evidence_snippet_centers_on_deep_reflection():
    # 反映が offset>2000 にあってもスニペットに含まれる（先頭切り詰めの回避）
    eng = SmartSSTIHunter()
    snippet = eng._evidence_snippet(_BODY_WITH_PRODUCT, _EXPECTED)
    assert _EXPECTED in snippet
    assert len(snippet) < len(_BODY_WITH_PRODUCT)


def test_convert_fail_closed_when_product_absent():
    # 算術積が本文に無い（未評価）→ payout_grade は立たない
    eng = SmartSSTIHunter()
    body = _LONG_PREFIX + "<p> not evaluated {{7*7}}deadbeef </p>"
    findings = eng._convert_to_findings(_result(_proof(body)), _URL)
    assert findings  # finding は作るが…
    assert evaluate_payout_grade(findings[0].to_dict()).payout_grade is False


def test_replay_descriptor_present():
    eng = SmartSSTIHunter()
    f = eng._convert_to_findings(_result(_proof(_BODY_WITH_PRODUCT)), _URL)[0]
    replay = f.to_dict()["additional_info"]["ssti_replay"]
    assert replay["method"] == "GET"
    assert replay["expected"] == _EXPECTED
    assert replay["url"]


def test_capture_ssti_via_injected_client():
    eng = SmartSSTIHunter()

    class _Client:
        def __init__(self):
            self.calls = []

        async def request(self, method, url, data=None, headers=None,
                          params=None, use_proxy=True, **kw):
            self.calls.append({"method": method, "url": url, "params": params})
            return SimpleNamespace(
                status=404, text=_BODY_WITH_PRODUCT, body=_BODY_WITH_PRODUCT,
                headers={},
            )

    eng._client = _Client()
    proof = asyncio.run(
        eng._capture_ssti(_URL, "q", "{{7*7}}deadbeef", _EXPECTED, "GET", {})
    )
    assert proof["observed"] is True
    assert proof["response_status"] == 404
    assert _EXPECTED in proof["served_body"]
    # 送信は params 経由（事前エンコード URL の二重エンコード回避）
    assert eng._client.calls[0]["params"] == {"q": "{{7*7}}deadbeef"}


def test_no_finding_when_not_vulnerable():
    eng = SmartSSTIHunter()
    findings = eng._convert_to_findings({"vulnerable": False}, _URL)
    assert findings == []
