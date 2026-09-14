"""SGK-2026-0492: Web キャッシュポイズニングの封印再現（poison→victim の2手再現）を検証。
新 marker と新 cache-buster で 毒入り GET→victim GET を送り victim に marker 再出現で matched。
fail-closed（client なし・スコープ外・記述子不正・キャッシュされない）。製品非依存（合成データ）。"""

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-cp-test",
    in_scope_domains=["target.example"],
)
_BASE = "https://target.example/"


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.headers = {}


class FakeCacheNetClient:
    """X-Forwarded-Host を反映し URL 鍵でキャッシュする簡易サーバ（sync）。"""

    def __init__(self, cache_enabled=True):
        self.cache_enabled = cache_enabled
        self.store = {}

    def request(self, method, url, **kwargs):
        xfh = str((kwargs.get("headers") or {}).get("X-Forwarded-Host") or "")
        if self.cache_enabled and url in self.store:
            body = self.store[url]
        elif xfh:
            body = f"<script src='//{xfh}/js'></script>"
            if self.cache_enabled:
                self.store[url] = body
        else:
            body = "<script src='//127.0.0.1/js'></script>"
            if self.cache_enabled:
                self.store[url] = body
        return FakeResponse(200, body)


def _finding():
    return Finding(
        target_url=_BASE,
        vuln_type=VulnType.CACHE_POISONING,
        severity=Severity.HIGH,
        title="Web cache poisoning",
        description="unkeyed input cached and served to victim",
        source_agent="SmartCachePoisoningHunter",
        evidence=Evidence(
            request_method="GET",
            request_url=_BASE + "?shigoku_cp=seed",
            request_headers={},
            request_body="",
            response_status=200,
            response_body="poisoned",
        ),
        additional_info={
            "cache_poisoning_evidence": {
                "request_url": _BASE + "?shigoku_cp=seed", "injected_header": "X-Forwarded-Host",
                "marker": "shigoku-cp-seed.evil.example", "poison_status": 200,
                "poison_served_body": "x", "victim_status": 200, "victim_served_body": "x",
                "control_served_body": "clean",
            },
            "cache_poisoning_replay": {
                "base_url": _BASE,
                "header": "X-Forwarded-Host",
            },
        },
    )


def test_matched_when_victim_poisoned_again():
    client = FakeCacheNetClient(cache_enabled=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "matched"
    assert "cache_poisoning_confirmed" in out.reason


def test_mismatched_when_not_cached():
    client = FakeCacheNetClient(cache_enabled=False)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_no_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_out_of_scope():
    client = FakeCacheNetClient(cache_enabled=True)
    other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    chk = SealedReproductionChecker(network_client=client, scope_definition=other)
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_replay_incomplete():
    f = _finding().to_dict()
    f["additional_info"]["cache_poisoning_replay"]["header"] = ""
    client = FakeCacheNetClient(cache_enabled=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(f)
    assert out.status == "not_run"
