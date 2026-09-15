"""SGK-2026-0502: boolean ベース・ブラインド SQLi の封印再現（恒真/恒偽 GET でオラクルを
その場で再校正し、真偽オラクルの二分探索で先頭文字を再抽出して元抽出値と一致）を検証する。
製品非依存・実ネット依存なし（sync fake blind server）。"""

import re
import urllib.parse
from types import SimpleNamespace

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import SealedReproductionChecker

_B = "https://target.example/home"
_SCOPE = ScopeDefinition(program_name="sealed-bsqli-test", in_scope_domains=["target.example"])
_VERSION = "3.25.3"

_TRUE_BODY = (
    "<html>\n<head><title>Article Page</title></head>\n"
    "<body><p>Some article content is shown here for readers.</p></body>\n</html>"
)
_FALSE_BODY = (
    "<html>\n<head><title>Not Found</title></head>\n"
    "<body><p>The requested article does not exist on this server.</p></body>\n</html>"
)


def _eval(cond: str) -> bool:
    cond = cond.strip()
    m = re.fullmatch(r"(\d+)=(\d+)", cond)
    if m:
        return m.group(1) == m.group(2)
    m = re.fullmatch(r"unicode\(substr\(\(SELECT sqlite_version\(\)\),(\d+),1\)\)([>=])(\d+)", cond)
    if m:
        pos, op, num = int(m.group(1)), m.group(2), int(m.group(3))
        if pos < 1 or pos > len(_VERSION):
            return False
        code = ord(_VERSION[pos - 1])
        return code > num if op == ">" else code == num
    return False


class _SyncBlindServer:
    def __init__(self, vulnerable=True):
        self.vulnerable = vulnerable

    def request(self, method, url, **kw):
        value = urllib.parse.unquote(url.rsplit("/", 1)[1])
        m = re.fullmatch(r"1 AND (.+)", value)
        truth = _eval(m.group(1)) if m else True
        if not self.vulnerable:
            body = _TRUE_BODY  # 真偽で変わらない
        else:
            body = _TRUE_BODY if truth else _FALSE_BODY
        return SimpleNamespace(status=200, body=body, headers={})


def _finding():
    return Finding(
        target_url=_B,
        vuln_type=VulnType.BLIND_SQLI,
        severity=Severity.CRITICAL,
        title="Boolean-based blind SQLi",
        description="oracle + extraction",
        source_agent="SmartBlindSQLiHunter",
        evidence=Evidence(
            request_method="GET", request_url=_B, request_headers={},
            request_body="", response_status=200, response_body=_TRUE_BODY,
        ),
        additional_info={
            "blind_sqli_evidence": {
                "request_url": _B,
                "true_condition": "1=1",
                "false_condition": "1=2",
                "oracle_true_class": "true",
                "oracle_false_class": "false",
                "true_sig": "<title>Article Page</title>",
                "false_sig": "<title>Not Found</title>",
                "extracted_field": "sqlite_version()",
                "extracted_value": _VERSION,
            },
            "blind_sqli_replay": {
                "mode": "path", "base_url": _B, "base_value": "1", "quote": "",
                "param": "id", "extracted_field": "sqlite_version()",
            },
            "poc_request": "GET x", "poc_response": "oracle",
        },
    )


def test_matched_when_oracle_and_extraction_reproduce():
    chk = SealedReproductionChecker(
        network_client=_SyncBlindServer(vulnerable=True), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "matched"
    assert "blind_sqli_confirmed" in out.reason


def test_mismatched_when_oracle_indistinguishable():
    chk = SealedReproductionChecker(
        network_client=_SyncBlindServer(vulnerable=False), scope_definition=_SCOPE, timeout_seconds=5,
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
        network_client=_SyncBlindServer(vulnerable=True), scope_definition=other, timeout_seconds=5,
    )
    out = chk.check(_finding().to_dict())
    assert out.status == "not_run"


def test_mismatched_when_extracted_char_differs():
    f = _finding().to_dict()
    # 元抽出値の先頭を別文字にすると、再抽出（実データ由来 '3'）と一致せず mismatched。
    f["additional_info"]["blind_sqli_evidence"]["extracted_value"] = "9.9.9"
    chk = SealedReproductionChecker(
        network_client=_SyncBlindServer(vulnerable=True), scope_definition=_SCOPE, timeout_seconds=5,
    )
    out = chk.check(f)
    assert out.status == "mismatched"
