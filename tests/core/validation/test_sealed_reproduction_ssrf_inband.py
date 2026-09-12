"""SGK-2026-0482: in-band SSRF の封印再現（SealedReproductionChecker）。

製品非依存 fixture のみ。トリガ POST(JSON) を対象エンドポイントへ再送し、
応答の reflect_key 値が再び非空なら matched。非反映は mismatched。client
None は not_run（fail-closed）。
"""
import json
from types import SimpleNamespace

from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker
from src.core.security.ethics_guard import ScopeDefinition


class _SyncClient:
    """同期 request（coroutine でない）→ checker は注入クライアントを直接使う。"""

    def __init__(self, reflected="INTERNAL-ONLY-BODY"):
        self._reflected = reflected

    def request(self, method, url, **kw):
        payload = json.dumps({"response_from_api": self._reflected, "status": 200})
        return SimpleNamespace(status=200, body=payload, text=payload, headers={})


def _finding():
    return Finding(
        target_url="http://target.example/fetch",
        vuln_type=VulnType.SSRF,
        severity=Severity.HIGH,
        title="In-band SSRF",
        description="server fetches url and reflects body",
        evidence=Evidence(
            request_method="POST",
            request_url="http://target.example/fetch",
            request_headers={"Authorization": "Bearer t"},
            response_status=200,
            response_body="[In-band SSRF] raw reflected body INTERNAL-ONLY-BODY",
        ),
        impact="server-side fetch of internal resource",
        reproduction_steps=["send url field", "observe reflected body", "confirm differential"],
        tags=["ssrf", "inband"],
        additional_info={
            "ssrf_inband_evidence": {
                "fetched_url": "http://internal.invalid/",
                "server_reflected_body": "INTERNAL-ONLY-BODY",
                "client_direct_unreachable": True,
                "server_status": 200,
            },
            "ssrf_inband_replay": {
                "method": "POST",
                "url": "http://target.example/fetch",
                "body": {"resource_url": "http://internal.invalid/", "other": "x"},
                "content_type": "application/json",
                "url_field": "resource_url",
                "probe_url": "http://internal.invalid/",
                "reflect_key": "response_from_api",
            },
        },
    )


def _checker(client):
    return SealedReproductionChecker(
        network_client=client,
        scope_definition=ScopeDefinition(program_name="x", in_scope_domains=["target.example"]),
    )


def test_matched_when_reflection_reobserved():
    out = _checker(_SyncClient("INTERNAL-ONLY-BODY")).check(_finding())
    assert out.status == "matched"


def test_mismatched_when_reflection_absent():
    out = _checker(_SyncClient("")).check(_finding())
    assert out.status == "mismatched"


def test_not_run_without_client():
    out = _checker(None).check(_finding())
    assert out.status == "not_run"
