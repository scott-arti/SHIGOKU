"""SGK-2026-0489: Race Condition の封印再現（並列バースト再実行パス）を検証。
新しい一意マーカーを trigger に埋めて並列バーストを再実行し、observe 応答に新マーカーが
再出現すれば matched。fail-closed（client なし・スコープ外・記述子不正・GET 以外）。
製品非依存（合成データ・スレッド安全な注入クライアント）。"""

import re
import threading
from types import SimpleNamespace

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-race-test",
    in_scope_domains=["target.example"],
)
_URL = "https://target.example/race"
_MARKER_RE = re.compile(r"SHIGOKU_RACE_[0-9a-f]+")


class FakeRaceNetClient:
    """trigger URL のマーカーを記憶し、reflect=True なら observe(action=run) 応答へ反映。"""

    def __init__(self, reflect=True):
        self.reflect = reflect
        self.marker = None
        self._lock = threading.Lock()

    def request(self, method, url, **kwargs):
        m = _MARKER_RE.search(url)
        with self._lock:
            if m:
                self.marker = m.group(0)
            mk = self.marker
        if "action=run" in url:  # observe
            if self.reflect and mk:
                body = f'<div id="system-message">{mk}</div>'
            else:
                body = '<div id="system-message">Default User</div>'
        else:
            body = "ok"
        return SimpleNamespace(status=200, body=body, headers={})


def _race_finding(url: str = _URL) -> Finding:
    return Finding(
        target_url=url,
        vuln_type=VulnType.RACE_CONDITION,
        severity=Severity.HIGH,
        title="Race condition (TOCTOU)",
        description="sequential-vs-concurrent differential",
        source_agent="SmartRaceConditionHunter",
        evidence=Evidence(
            request_method="GET",
            request_url=url,
            request_headers={},
            request_body="",
            response_status=200,
            response_body='<div id="system-message">SHIGOKU_RACE_seed01</div>',
        ),
        additional_info={
            "race_evidence": {
                "request_url": url,
                "marker": "SHIGOKU_RACE_seed01",
                "race_status": 200,
                "race_served_body": '<div id="system-message">SHIGOKU_RACE_seed01</div>',
                "control_status": 200,
                "control_served_body": '<div id="system-message">Default User</div>',
            },
            "race_replay": {
                "observe": {"method": "GET", "url": url, "params": {"action": "run"}},
                "trigger": {"method": "GET", "url": url,
                            "params": {"action": "validate", "person": 'x"; echo {marker} #'}},
                "reset": {"method": "GET", "url": url, "params": {"action": "reset"}},
                "concurrency": 3,
                "rounds": 3,
            },
        },
    )


def test_matched_when_marker_reflected_again():
    client = FakeRaceNetClient(reflect=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_race_finding().to_dict())
    assert out.status == "matched"
    assert "race_condition_toctou" in out.reason


def test_mismatched_when_marker_never_reflected():
    client = FakeRaceNetClient(reflect=False)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(_race_finding().to_dict())
    assert out.status == "mismatched"


def test_not_run_when_no_client():
    chk = SealedReproductionChecker(network_client=None, scope_definition=TARGET_SCOPE)
    out = chk.check(_race_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_out_of_scope():
    client = FakeRaceNetClient(reflect=True)
    other = ScopeDefinition(program_name="other", in_scope_domains=["example.org"])
    chk = SealedReproductionChecker(network_client=client, scope_definition=other)
    out = chk.check(_race_finding().to_dict())
    assert out.status == "not_run"


def test_not_run_when_trigger_missing():
    f = _race_finding().to_dict()
    del f["additional_info"]["race_replay"]["trigger"]
    client = FakeRaceNetClient(reflect=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(f)
    assert out.status == "not_run"


def test_not_run_when_method_not_get():
    f = _race_finding().to_dict()
    f["additional_info"]["race_replay"]["trigger"]["method"] = "POST"
    client = FakeRaceNetClient(reflect=True)
    chk = SealedReproductionChecker(network_client=client, scope_definition=TARGET_SCOPE)
    out = chk.check(f)
    assert out.status == "not_run"
