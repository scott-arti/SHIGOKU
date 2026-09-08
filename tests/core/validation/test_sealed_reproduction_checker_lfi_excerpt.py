"""
SGK-2026-0474 — SealedReproductionChecker file_content_leak excerpt 再出現テスト

PRODUCT-INDEPENDENT fixtures のみ（target.example・一般ファイル名）。実ネット
ワーク不使用（FakeNetworkClient）。

カバー:
(a) 元 Finding の file_marker_excerpt が封印 GET 再送本文に再出現 → matched
(b) 再出現しない → mismatched
(c) 空/短すぎ/空白のみ excerpt → excerpt 経路では matched にしない
    （_LFI_PATTERNS 経路のみ・fail-closed）
(d) 既存 _LFI_PATTERNS 一致（/etc/passwd 系）→ matched（非回帰）
(e) 他種別（sql_error / reflected_payload）の照合は不変、client None → not_run
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-lfi-excerpt-test",
    in_scope_domains=["target.example"],
)

URL = "https://target.example/private/report.bak%2500.md"
PASSWD_URL = "https://target.example/private/report.bak"

# 漏洩本文（JSON 風・複数行・_LFI_PATTERNS に非一致）。
LEAK_BODY = (
    "{\n"
    '  "quarterly_report": "2026-Q1",\n'
    '  "total_amount": 1250000,\n'
    '  "internal_note": "unaudited draft for board review",\n'
    '  "entries": [\n'
    '    {"region": "emea", "amount": 340000}\n'
    "  ]\n"
    "}\n"
)
# 本文中の安定した specific 断片（単一行・24 文字以上）。
EXCERPT = '"internal_note": "unaudited draft for board review"'

OTHER_BODY = (
    "{\n"
    '  "quarterly_report": "2026-Q2",\n'
    '  "total_amount": 700000,\n'
    '  "entries": [{"region": "apac", "amount": 700000}]\n'
    "}\n"
)

SQL_BODY = "SQL syntax error near '1' at line 1"


class FakeResponse:
    def __init__(self, status: int = 200, body: "str | bytes" = ""):
        self.status = status
        self.body = body


class FakeNetworkClient:
    def __init__(self, response: "FakeResponse | None" = None):
        self.response = response if response is not None else FakeResponse(200, "")
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        return self.response


def make_lfi_finding(
    *,
    url: str = URL,
    response_body: str = LEAK_BODY,
    excerpt: str = EXCERPT,
    method: str = "GET",
) -> Finding:
    return Finding(
        vuln_type=VulnType.LFI,
        severity=Severity.HIGH,
        title="Path-based file disclosure in report download",
        description="Generic path-based LFI finding for sealed reproduction tests.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method=method,
            request_url=url,
            response_status=200,
            response_body=response_body,
        ),
        reproduction_steps=["GET the bypass URL", "Observe the leaked content"],
        impact="Unauthorized access to server files.",
        additional_info={
            "parameter": None,
            "tested_params": [],
            "payload": "/private/report.bak%2500.md",
            "file_marker_excerpt": excerpt,
            "target_file": "/private/report.bak",
        },
    )


def make_sqli_finding() -> Finding:
    return Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.HIGH,
        title="SQL injection in item lookup",
        description="Generic SQLi finding for sealed reproduction tests.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/item?id=1",
            response_status=200,
            response_body=SQL_BODY,
        ),
        reproduction_steps=["Send the probe request"],
        impact="Database error disclosure.",
        additional_info={},
    )


def make_xss_finding() -> Finding:
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected payload in search response",
        description="Generic reflected-XSS style finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/search?q=probe",
            response_status=200,
            response_body="no reflection here",
        ),
        reproduction_steps=["Send the probe request"],
        impact="Session hijack via reflected payload execution.",
        additional_info={},
    )


class TestLfiExcerptReappearance:
    def test_excerpt_reappears_matched(self):
        """(a) excerpt が再送本文に再出現（_LFI_PATTERNS 非一致でも）→ matched."""
        client = FakeNetworkClient(FakeResponse(200, LEAK_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_lfi_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:file_content_leak"

    def test_excerpt_whitespace_variant_reappears_matched(self):
        """(a') 改行/インデント差異があっても正規化照合で再出現 → matched."""
        spaced_body = "{\n  \"quarterly_report\": \"2026-Q1\",\n" + (
            '  "internal_note":   "unaudited   draft for board review",\n'
            '  "total_amount": 1250000\n}\n'
        )
        client = FakeNetworkClient(FakeResponse(200, spaced_body))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_lfi_finding(excerpt=EXCERPT))
        assert outcome.status == "matched"

    def test_excerpt_absent_mismatched(self):
        """(b) 再送本文に excerpt が再出現しない → mismatched（唯一の mismatch 経路）."""
        client = FakeNetworkClient(FakeResponse(200, OTHER_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_lfi_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_short_excerpt_never_matches_via_excerpt(self):
        """(c) 短すぎ excerpt（24 文字未満）は excerpt 経路で matched にしない.
        パターン非一致なら mismatched（fail-closed）。"""
        short_excerpt = "abcdefghijklmnopqrstuvwxy"[:16]
        body = LEAK_BODY + f"<!-- {short_excerpt} -->\n"
        client = FakeNetworkClient(FakeResponse(200, body))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_lfi_finding(excerpt=short_excerpt))
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_empty_and_whitespace_excerpt_never_match_via_excerpt(self):
        """(c') 空/空白のみ excerpt → excerpt 経路では matched にしない."""
        for bad in ("", "   \t  "):
            client = FakeNetworkClient(FakeResponse(200, LEAK_BODY))
            checker = SealedReproductionChecker(
                network_client=client, scope_definition=TARGET_SCOPE
            )
            outcome = checker.check(make_lfi_finding(excerpt=bad))
            assert outcome.status == "mismatched"
            assert outcome.reason == "reproduction_marker_mismatch"

    def test_lfi_pattern_match_regression(self):
        """(d) 既存 _LFI_PATTERNS 一致（excerpt 不使用）→ matched（非回帰）."""
        passwd_body = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
        client = FakeNetworkClient(FakeResponse(200, passwd_body))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(
            make_lfi_finding(url=PASSWD_URL, response_body=passwd_body, excerpt="")
        )
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:file_content_leak"

    def test_lfi_client_none_not_run(self):
        """client None → not_run（送信不能・fail-closed・mismatch にしない）."""
        checker = SealedReproductionChecker(
            network_client=None, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_lfi_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"

    def test_sql_error_category_regression(self):
        """(e) sql_error の照合は不変（matched / reason 同一）."""
        client = FakeNetworkClient(FakeResponse(200, SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"

    def test_reflected_payload_category_regression(self):
        """(e') reflected_payload の照合は不変（非発火 → mismatched）."""
        client = FakeNetworkClient(FakeResponse(200, "clean page without reflection"))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_xss_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"
