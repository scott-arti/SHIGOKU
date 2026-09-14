"""SGK-2026-0493: SmartSubdomainTakeoverHunter が非破壊フィンガープリント検出で
Subdomain Takeover 候補（◯）を Finding 化することを検証する。製品非依存（合成本文＋
プロバイダ表の実サイン＝検出ロジック）。破壊的奪取は行わない＝payout_grade は候補どまり。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_subdomain_takeover import SmartSubdomainTakeoverHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_GH_UNCLAIMED = "<html><body>There isn't a GitHub Pages site here.</body></html>"
_S3_UNCLAIMED = "<Error><Code>NoSuchBucket</Code></Error>"
_CLEAN = "<html><body>Welcome to my site</body></html>"


class _FakeClient:
    def __init__(self, body, status=404):
        self.body = body
        self.status = status

    async def request(self, method, url, use_proxy=True, **kw):
        return SimpleNamespace(status=self.status, body=self.body, text=self.body, headers={})


def _run(client, target, params=None):
    eng = SmartSubdomainTakeoverHunter()
    eng._client = client
    task = Task(id="t", name="to", target=target, tags=["subdomain_takeover"])
    task.params = params or {}
    return asyncio.run(eng.execute(task))


def test_github_pages_candidate_high_confidence():
    findings = _run(_FakeClient(_GH_UNCLAIMED), "https://blog.github.io/")
    exp = [f for f in findings if f.vuln_type == VulnType.SUBDOMAIN_TAKEOVER]
    assert exp, "takeover candidate not produced"
    ev = exp[0].to_dict()["additional_info"]["subdomain_takeover_evidence"]
    assert ev["provider_id"] == "github_pages"
    assert ev["matched_error_token"] == "There isn't a GitHub Pages site here"
    assert ev["cname_provider_match"] is True   # host が github.io に一致
    assert ev["confidence"] == 0.9
    assert ev["grade"] == "candidate"
    assert ev["verification_urls"]              # 手動 claim 用 URL


def test_error_token_only_medium_confidence():
    # host が s3 の fingerprint domain と一致しない → error token のみ＝中確度。
    findings = _run(_FakeClient(_S3_UNCLAIMED), "https://assets.example.com/")
    ev = findings[0].to_dict()["additional_info"]["subdomain_takeover_evidence"]
    assert ev["provider_id"] == "aws_s3"
    assert ev["cname_provider_match"] is False
    assert ev["confidence"] == 0.6


def test_cname_from_params_raises_confidence():
    # recon 由来の cname を渡すと CNAME 委譲一致で高確度になる。
    findings = _run(
        _FakeClient(_S3_UNCLAIMED), "https://assets.example.com/",
        params={"cname": "assets.example.com.s3.amazonaws.com"},
    )
    ev = findings[0].to_dict()["additional_info"]["subdomain_takeover_evidence"]
    assert ev["cname_provider_match"] is True
    assert ev["confidence"] == 0.9


def test_no_finding_when_no_unclaimed_signature():
    findings = _run(_FakeClient(_CLEAN, status=200), "https://blog.github.io/")
    assert [f for f in findings if f.vuln_type == VulnType.SUBDOMAIN_TAKEOVER] == []


def test_candidate_does_not_fire_payout_grade():
    # ○（候補）は payout_grade を発火しない（破壊的奪取なし＝◎未満・fail-closed）。
    d = _run(_FakeClient(_GH_UNCLAIMED), "https://blog.github.io/")[0].to_dict()
    d.setdefault("impact", "takeover candidate")
    d.setdefault("reproduction_steps", ["fingerprint only"])
    assert evaluate_payout_grade(d).payout_grade is False


def test_multiple_subdomains_via_params():
    eng = SmartSubdomainTakeoverHunter()
    eng._client = _FakeClient(_GH_UNCLAIMED)
    task = Task(id="t", name="to", target="", tags=["subdomain_takeover"])
    task.params = {"takeover_subdomains": ["https://a.github.io/", "https://b.github.io/"]}
    findings = asyncio.run(eng.execute(task))
    assert len([f for f in findings if f.vuln_type == VulnType.SUBDOMAIN_TAKEOVER]) == 2
