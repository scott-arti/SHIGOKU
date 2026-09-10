"""
SGK-2026-0480 — SealedReproductionChecker file_upload（任意ファイル設置＋
Web 取得）再現照合単体テスト。

PRODUCT-INDEPENDENT fixtures のみ（target.example・汎用良性マーカー）。
- (a) retrieval_url GET で一意マーカー再出現 → matched
- (b) 応答あり・非出現 → mismatched（唯一の mismatch 経路）
- (c) network_client None → not_run（fail-closed）
- (d) retrieval_url / retrieval_marker / file_upload_evidence 欠落 → not_run
- (e) 他マーカー（sqli）・GET-only ガードは非回帰
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation.sealed_reproduction_checker import (
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-file-upload-test",
    in_scope_domains=["target.example"],
)

UPLOAD_URL = "https://target.example/upload"
RETRIEVAL_URL = "https://target.example/uploads/probe_a1b2c3d4e5f60718.txt"
MARKER = "SHIGOKU_PROBE_a1b2c3d4e5f60718"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class FakeResponse:
    def __init__(self, status: int = 200, body: "str | bytes" = ""):
        self.status = status
        self.body = body


class FakeNetworkClient:
    """Synchronous transport fake: records calls, returns a configurable
    response or raises a configurable error (mirrors NetworkResponse shape)."""

    def __init__(self, response: "FakeResponse | None" = None, error: "Exception | None" = None):
        self.response = response if response is not None else FakeResponse(200, "")
        self.error = error
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if self.error is not None:
            raise self.error
        return self.response


class FakeMasker:
    """[PII:VALUE:xxx] -> original value restoration (thin 0439 stand-in)."""

    def __init__(self, mapping: dict):
        self._mapping = dict(mapping)

    def unmask(self, text: str) -> str:
        for token, value in self._mapping.items():
            text = text.replace(token, value)
        return text


def _file_upload_evidence(**overrides) -> dict:
    evidence = {
        "upload_allowed": True,
        "retrieved": True,
        "retrieval_url": RETRIEVAL_URL,
        "retrieval_status": 200,
        "execution_observed": False,
        "safe_canary": True,
        "mime_type": "image/jpeg",
        "technique": "Safe Canary Upload Probe",
        "retrieval_marker": MARKER,
    }
    evidence.update(overrides)
    return evidence


def make_upload_finding(
    *,
    response_body: str = "",
    additional_info_extra: "dict | None" = None,
    file_upload_evidence: "dict | None" = None,
) -> Finding:
    info: dict = {}
    if file_upload_evidence is not None:
        info["file_upload_evidence"] = file_upload_evidence
    if additional_info_extra:
        info.update(additional_info_extra)
    return Finding(
        vuln_type=VulnType.FILE_UPLOAD,
        severity=Severity.HIGH,
        title="Unrestricted file upload with web retrieval",
        description="Generic benign non-executable upload finding.",
        target_url=UPLOAD_URL,
        evidence=Evidence(
            request_method="POST",
            request_url=UPLOAD_URL,
            request_headers={"Cookie": "session=abc123"},
            response_status=200,
            response_body=response_body or "Status: 200\nUpload accepted",
        ),
        reproduction_steps=[
            "Upload a benign file carrying a unique marker.",
            "GET the retrieval URL and observe the same marker.",
        ],
        impact="認証境界内で任意の非実行ファイルをサーバへ設置し Web から取得可能。",
        additional_info=info,
    )


def make_sqli_finding(*, method: str = "GET", body: str = "") -> Finding:
    return Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.HIGH,
        title="SQL injection in item lookup",
        description="Generic SQLi finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method=method,
            request_url="https://target.example/item?id=1",
            response_status=200,
            response_body=body or "SQL syntax error near '1'",
        ),
        reproduction_steps=["Send the probe request"],
        impact="Database error disclosure.",
    )


def default_checker(**kwargs) -> SealedReproductionChecker:
    kwargs.setdefault("network_client", FakeNetworkClient())
    kwargs.setdefault("scope_definition", TARGET_SCOPE)
    return SealedReproductionChecker(**kwargs)


# ---------------------------------------------------------------------------
# uploaded_file_retrieved replay
# ---------------------------------------------------------------------------


class TestFileUploadRetrievalReplay:
    def test_marker_reappears_matched(self) -> None:
        """(a) retrieval_url GET で一意マーカー再出現 → matched。"""
        client = FakeNetworkClient(FakeResponse(200, f"file content {MARKER} end"))
        checker = default_checker(network_client=client)
        outcome = checker.check(make_upload_finding(file_upload_evidence=_file_upload_evidence()))
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:uploaded_file_retrieved"
        assert client.calls[0]["method"] == "GET"
        assert client.calls[0]["url"] == RETRIEVAL_URL
        kwargs = client.calls[0]["kwargs"]
        assert kwargs["use_cache"] is False
        assert kwargs["retries"] == 0
        assert kwargs["auto_waf_bypass"] is False
        assert kwargs["allow_redirects"] is False
        assert kwargs["use_proxy"] is True

    def test_marker_absent_mismatched(self) -> None:
        """(b) 応答あり・マーカー非出現 → mismatched（唯一の mismatch 経路）。"""
        client = FakeNetworkClient(FakeResponse(200, "<html>not found</html>"))
        checker = default_checker(network_client=client)
        outcome = checker.check(make_upload_finding(file_upload_evidence=_file_upload_evidence()))
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_network_client_none_not_run(self) -> None:
        """(c) client None → not_run（fail-closed・mismatch にしない）。"""
        checker = default_checker(network_client=None)
        outcome = checker.check(make_upload_finding(file_upload_evidence=_file_upload_evidence()))
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"

    def test_retrieval_url_missing_not_run(self) -> None:
        """(d) retrieval_url 欠落 → not_run（記述子なし・送信しない）。"""
        client = FakeNetworkClient(FakeResponse(200, MARKER))
        checker = default_checker(network_client=client)
        outcome = checker.check(
            make_upload_finding(
                file_upload_evidence=_file_upload_evidence(retrieval_url="")
            )
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_retrieval_marker_missing_not_run(self) -> None:
        """(d) retrieval_marker 欠落 → not_run（記述子なし・送信しない）。"""
        client = FakeNetworkClient(FakeResponse(200, MARKER))
        checker = default_checker(network_client=client)
        outcome = checker.check(
            make_upload_finding(
                file_upload_evidence=_file_upload_evidence(retrieval_marker="")
            )
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_file_upload_evidence_missing_not_run(self) -> None:
        """(d) file_upload_evidence そのものが無い → not_run（送信しない）。"""
        client = FakeNetworkClient(FakeResponse(200, MARKER))
        checker = default_checker(network_client=client)
        outcome = checker.check(make_upload_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_retrieved_false_no_marker_not_run(self) -> None:
        """非取得（retrieved=False・marker 無し）の finding は matched にしない。"""
        client = FakeNetworkClient(FakeResponse(200, MARKER))
        checker = default_checker(network_client=client)
        outcome = checker.check(
            make_upload_finding(
                file_upload_evidence=_file_upload_evidence(
                    retrieved=False, retrieval_marker=""
                )
            )
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_transport_exception_not_run(self) -> None:
        client = FakeNetworkClient(error=RuntimeError("connection refused"))
        checker = default_checker(network_client=client)
        outcome = checker.check(make_upload_finding(file_upload_evidence=_file_upload_evidence()))
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_out_of_scope_retrieval_url_not_run(self) -> None:
        """retrieval_url が封印スコープ外 → not_run（送信しない）。"""
        client = FakeNetworkClient(FakeResponse(200, MARKER))
        checker = default_checker(network_client=client)
        outcome = checker.check(
            make_upload_finding(
                file_upload_evidence=_file_upload_evidence(
                    retrieval_url="https://out-of-scope.example/uploads/x.txt"
                )
            )
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []

    def test_masked_retrieval_url_restored_and_sent(self) -> None:
        """マスク済 retrieval_url は 0439 token_map で復元して GET する。"""
        masked_url = "https://target.example/uploads/[PII:VALUE:abc12345]"
        masker = FakeMasker({"[PII:VALUE:abc12345]": "probe_a1b2c3d4e5f60718.txt"})
        client = FakeNetworkClient(FakeResponse(200, f"stored {MARKER}"))
        checker = SealedReproductionChecker(
            network_client=client,
            scope_definition=TARGET_SCOPE,
            masker=masker,
        )
        outcome = checker.check(
            make_upload_finding(
                file_upload_evidence=_file_upload_evidence(retrieval_url=masked_url)
            )
        )
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:uploaded_file_retrieved"
        assert client.calls[0]["url"] == RETRIEVAL_URL


# ---------------------------------------------------------------------------
# Non-regression: other markers + GET-only guards
# ---------------------------------------------------------------------------


class TestOtherMarkersNonRegression:
    def test_sqli_get_still_matched(self) -> None:
        """(e) 他マーカー（sqli GET）は従来どおり matched。"""
        client = FakeNetworkClient(
            FakeResponse(200, "SQL syntax error near '1' at line 1")
        )
        checker = default_checker(network_client=client)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"

    def test_sqli_post_still_get_only_not_run(self) -> None:
        """(e) POST 等価 finding は従来どおり GET-only fingerprint で not_run。"""
        client = FakeNetworkClient(FakeResponse(200, "SQL syntax error near '1'"))
        checker = default_checker(network_client=client)
        outcome = checker.check(make_sqli_finding(method="POST"))
        assert outcome.status == "not_run"
        assert outcome.reason == "request_fingerprint_mismatch"
        assert client.calls == []
