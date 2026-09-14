"""SGK-2026-0492: SmartCachePoisoningHunter が Web キャッシュポイズニングを差分確認で
確定グレードの Finding に変換することを検証する。製品非依存（合成データ・注入クライアント）。"""

import asyncio
from types import SimpleNamespace

from src.core.agents.swarm.injection.smart_cache_poisoning import SmartCachePoisoningHunter
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade
from src.core.models.finding import VulnType

_URL = "https://target.example/"


def _tracker(host):
    return f"<html><script src='//{host}/js/tracking.js'></script></html>"


class _CacheServer:
    """X-Forwarded-Host を反映しキャッシュ（URL 鍵）する簡易サーバ。"""

    def __init__(self):
        self.cache = {}

    async def request(self, method, url, headers=None, use_proxy=True, **kw):
        xfh = str((headers or {}).get("X-Forwarded-Host") or "")
        if url in self.cache:  # cache hit
            body = self.cache[url]
        elif xfh:  # miss + unkeyed header → reflect + cache
            body = _tracker(xfh)
            self.cache[url] = body
        else:  # miss clean → default + cache
            body = _tracker("127.0.0.1")
            self.cache[url] = body
        return SimpleNamespace(status=200, body=body, text=body, headers={})


class _NoCacheServer:
    """反映するがキャッシュしない → victim(クリーン)に毒が残らない → 確定しない。"""

    async def request(self, method, url, headers=None, use_proxy=True, **kw):
        xfh = str((headers or {}).get("X-Forwarded-Host") or "")
        body = _tracker(xfh) if xfh else _tracker("127.0.0.1")
        return SimpleNamespace(status=200, body=body, text=body, headers={})


class _NoReflectServer:
    """X-Forwarded-Host を反映しない → poison に marker が出ない → スキップ。"""

    async def request(self, method, url, headers=None, use_proxy=True, **kw):
        body = _tracker("127.0.0.1")
        return SimpleNamespace(status=200, body=body, text=body, headers={})


def _run(client):
    eng = SmartCachePoisoningHunter()
    eng._client = client
    task = Task(id="t", name="cp", target=_URL, tags=["cache_poisoning"])
    task.params = {}
    return asyncio.run(eng.execute(task))


def test_builds_payout_grade_finding_on_poisoning():
    findings = _run(_CacheServer())
    exp = [f for f in findings if f.vuln_type == VulnType.CACHE_POISONING]
    assert exp, "cache poisoning finding not produced"
    d = exp[0].to_dict()
    cp = d["additional_info"]["cache_poisoning_evidence"]
    m = cp["marker"]
    assert cp["injected_header"] == "X-Forwarded-Host"
    assert m in cp["poison_served_body"]
    assert m in cp["victim_served_body"]      # クリーン victim に配信
    assert m not in cp["control_served_body"]  # 別鍵には出ない
    r = evaluate_payout_grade(d)
    assert r.payout_grade is True
    assert r.marker == "cache_poisoning_confirmed"


def test_three_step_poc():
    d = _run(_CacheServer())[0].to_dict()
    poc = d["additional_info"]["poc_request"]
    assert "Step 1" in poc and "Step 2" in poc and "Step 3" in poc
    assert d["additional_info"]["cache_poisoning_evidence"]["marker"] in d["additional_info"]["poc_response"]


def test_replay_descriptor_present():
    d = _run(_CacheServer())[0].to_dict()
    replay = d["additional_info"]["cache_poisoning_replay"]
    assert replay["header"] == "X-Forwarded-Host"
    assert replay["base_url"] == _URL


def test_no_finding_when_not_cached():
    findings = _run(_NoCacheServer())
    assert [f for f in findings if f.vuln_type == VulnType.CACHE_POISONING] == []


def test_no_finding_when_not_reflected():
    findings = _run(_NoReflectServer())
    assert [f for f in findings if f.vuln_type == VulnType.CACHE_POISONING] == []
