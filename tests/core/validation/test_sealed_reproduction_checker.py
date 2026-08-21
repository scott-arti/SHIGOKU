"""
SealedReproductionChecker Tests - SGK-2026-0445 appendix §B/C

PRODUCT-INDEPENDENT fixtures only: generic targets (https://target.example/),
no product identifiers, no real network (FakeNetworkClient).

Covers:
- GET-only: POST-equivalent finding -> not_run (fingerprint mismatch);
  read-only-probe rejection (non-http URL) -> not_run.
- state-changing exclusion (action_semantics=form_submit) -> not_run.
- scope fail-closed (scope_definition=None) -> not_run.
- fingerprint mismatch -> not_run.
- network_client=None -> not_run.
- budget: max_replays exhausted -> not_run; PoCJudgeBudget exceeded ->
  JudgeBudgetExhausted (FakeJudge).
- marker matched / response present but not fired -> mismatched /
  exception -> not_run (transport_error).
- masked URL unresolvable -> not_run; masked URL restored by FakeMasker ->
  the restored URL is actually sent.
"""
import pytest

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ScopeDefinition
from src.core.validation import sealed_reproduction_checker as checker_module
from src.core.validation.sealed_reproduction_checker import (
    BudgetedPoCJudge,
    JudgeBudgetExhausted,
    PoCJudgeBudget,
    SealedReproductionChecker,
)

TARGET_SCOPE = ScopeDefinition(
    program_name="sealed-repro-test",
    in_scope_domains=["target.example"],
)

_SQL_BODY = "SQL syntax error near '1' at line 1"
_XSS_BODY = '<html><script>alert(1)</script></html>'

_URL = "https://target.example/item?id=1"


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


def make_sqli_finding(
    *,
    url: str = _URL,
    method: str = "GET",
    response_body: str = _SQL_BODY,
    additional_info: "dict | None" = None,
) -> Finding:
    return Finding(
        vuln_type=VulnType.SQLI,
        severity=Severity.HIGH,
        title="SQL injection in item lookup",
        description="Generic SQLi finding for sealed reproduction tests.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method=method,
            request_url=url,
            response_status=200,
            response_body=response_body,
        ),
        reproduction_steps=["Send the probe request", "Observe the SQL error"],
        impact="Database error disclosure.",
        additional_info=additional_info or {},
    )


def make_xss_finding(
    *, url: str = "https://target.example/search?q=probe", response_body: str = _XSS_BODY
) -> Finding:
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected payload in search response",
        description="Generic reflected-XSS style finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url=url,
            response_status=200,
            response_body=response_body,
        ),
        reproduction_steps=["Send the probe request", "Observe the reflected payload"],
        impact="Session hijack via reflected payload execution.",
    )


def make_idor_finding() -> Finding:
    return Finding(
        vuln_type=VulnType.IDOR,
        severity=Severity.HIGH,
        title="IDOR on record fetch",
        description="Generic IDOR finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/records/42",
            response_status=200,
            response_body='{"owner": "alice", "id": 42}',
        ),
        reproduction_steps=["Fetch record 42 without auth"],
        impact="Cross-account record access.",
        additional_info={
            "authz_differential": {
                "scenario": "unauth vs auth",
                "signals": ["auth_success", "unauth_success"],
            }
        },
    )


def make_other_finding() -> Finding:
    """Unknown category: no firing-marker vocabulary exists."""
    return Finding(
        vuln_type=VulnType.OTHER,
        severity=Severity.LOW,
        title="Miscellaneous observation",
        description="Generic uncategorized finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url="https://target.example/status",
            response_status=200,
            response_body="all systems nominal",
        ),
        reproduction_steps=["Fetch the status page"],
        impact="Informational.",
    )


def default_checker(**kwargs) -> SealedReproductionChecker:
    """Checker with a working sync transport + sealed scope by default."""
    kwargs.setdefault("network_client", FakeNetworkClient(FakeResponse(200, _SQL_BODY)))
    kwargs.setdefault("scope_definition", TARGET_SCOPE)
    return SealedReproductionChecker(**kwargs)


# ---------------------------------------------------------------------------
# GET-only / probe / state-change / scope / fingerprint guards
# ---------------------------------------------------------------------------

class TestGETOnlyAndGuards:
    def test_post_equivalent_finding_not_run(self):
        """POST-equivalent finding: GET replay fingerprint cannot match."""
        checker = default_checker()
        outcome = checker.check(make_sqli_finding(method="POST"))
        assert outcome.status == "not_run"
        assert outcome.reason == "request_fingerprint_mismatch"

    def test_read_only_probe_rejected_for_non_http_url(self):
        """assert_read_only_probe rejection -> not_run (no send)."""
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding(url="ftp://target.example/item?id=1"))
        assert outcome.status == "not_run"
        assert outcome.reason == "read_only_probe_rejected"
        assert client.calls == []

    def test_missing_request_url_not_run(self):
        outcome = default_checker().check(make_sqli_finding(url=""))
        assert outcome.status == "not_run"
        assert outcome.reason == "read_only_probe_rejected"

    def test_state_changing_semantics_excluded(self):
        """action_semantics=form_submit on a GET -> state_changing_excluded."""
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(
            make_sqli_finding(additional_info={"action_semantics": "form_submit"})
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "state_changing_excluded"
        assert client.calls == []

    def test_scope_definition_none_fails_closed(self):
        """scope_definition=None -> scope_revalidation_blocked (no send)."""
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(network_client=client, scope_definition=None)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []

    def test_out_of_scope_url_fails_closed(self):
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding(url="https://out-of-scope.example/item?id=1"))
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert client.calls == []

    def test_network_client_none_not_run(self):
        """network_client=None -> reproduction_disabled_no_client."""
        checker = SealedReproductionChecker(scope_definition=TARGET_SCOPE)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_disabled_no_client"


# ---------------------------------------------------------------------------
# Transport / marker comparison
# ---------------------------------------------------------------------------

class TestTransportAndMarkers:
    def test_marker_matched(self):
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"
        assert client.calls[0]["method"] == "GET"
        assert client.calls[0]["url"] == _URL
        kwargs = client.calls[0]["kwargs"]
        assert kwargs["use_cache"] is False
        assert kwargs["retries"] == 0
        assert kwargs["auto_waf_bypass"] is False
        assert kwargs["allow_redirects"] is False
        assert kwargs["use_proxy"] is True

    def test_response_present_but_marker_not_fired_mismatched(self):
        """唯一の mismatched 経路: 応答あり・同一カテゴリのマーカー非検出."""
        client = FakeNetworkClient(FakeResponse(200, "OK"))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_transport_exception_not_run(self):
        client = FakeNetworkClient(error=RuntimeError("connection refused"))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_empty_response_body_not_run(self):
        """応答が空 → not_run（mismatch にしない・fail-closed）."""
        client = FakeNetworkClient(FakeResponse(200, ""))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_status_zero_not_run(self):
        client = FakeNetworkClient(FakeResponse(0, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_client_without_request_method_not_run(self):
        """client に request が無い → 送信不能（transport_error・fail-closed）."""

        class BrokenClient:
            pass

        checker = SealedReproductionChecker(
            network_client=BrokenClient(), scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_bytes_response_body_normalized(self):
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY.encode("utf-8")))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"

    def test_authz_diff_not_observable_in_replay(self):
        """authz_diff は単一 GET 再送では再検証不能 → not_run（決して mismatched にしない）."""
        client = FakeNetworkClient(FakeResponse(200, '{"owner": "alice", "id": 42}'))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_idor_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_marker_not_observable_in_replay"
        assert client.calls == []

    def test_unknown_category_not_run(self):
        client = FakeNetworkClient(FakeResponse(200, "all systems nominal"))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_other_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_unknown_category"
        assert client.calls == []

    def test_async_client_uses_sync_requests_fallback(self, monkeypatch):
        """AsyncNetworkClient は同期 Protocol から await 不可 → 既存同期
        requests パターンで送信（run_until_complete 不使用）."""
        captured = {}

        class FakeAsyncClient:
            async def request(self, *args, **kwargs):
                raise AssertionError("async request must not be awaited")

        class FakeRequestsResponse:
            status_code = 200
            text = _SQL_BODY

        def fake_get(url, **kwargs):
            captured["url"] = url
            captured["kwargs"] = kwargs
            return FakeRequestsResponse()

        monkeypatch.setattr(checker_module.requests, "get", fake_get)
        checker = SealedReproductionChecker(
            network_client=FakeAsyncClient(), scope_definition=TARGET_SCOPE
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert captured["url"] == _URL
        assert captured["kwargs"]["allow_redirects"] is False
        assert captured["kwargs"]["timeout"] == 15


# ---------------------------------------------------------------------------
# Masked URL handling (0439)
# ---------------------------------------------------------------------------

class TestMaskedUrl:
    MASKED_URL = "https://target.example/search?q=[PII:VALUE:abc12345]"
    RESTORED_URL = "https://target.example/search?q=probe"

    def test_masked_url_without_masker_not_run(self):
        checker = SealedReproductionChecker(
            network_client=FakeNetworkClient(FakeResponse(200, _XSS_BODY)),
            scope_definition=TARGET_SCOPE,
            masker=None,
        )
        outcome = checker.check(make_xss_finding(url=self.MASKED_URL))
        assert outcome.status == "not_run"
        assert outcome.reason == "masked_url_unresolvable"

    def test_masked_url_masker_cannot_resolve_not_run(self):
        masker = FakeMasker({})  # token unknown -> stays masked
        checker = SealedReproductionChecker(
            network_client=FakeNetworkClient(FakeResponse(200, _XSS_BODY)),
            scope_definition=TARGET_SCOPE,
            masker=masker,
        )
        outcome = checker.check(make_xss_finding(url=self.MASKED_URL))
        assert outcome.status == "not_run"
        assert outcome.reason == "masked_url_unresolvable"

    def test_masked_url_restored_by_masker_is_sent(self):
        masker = FakeMasker({"[PII:VALUE:abc12345]": "probe"})
        client = FakeNetworkClient(FakeResponse(200, _XSS_BODY))
        checker = SealedReproductionChecker(
            network_client=client, scope_definition=TARGET_SCOPE, masker=masker
        )
        outcome = checker.check(make_xss_finding(url=self.MASKED_URL))
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:reflected_payload"
        assert client.calls[0]["url"] == self.RESTORED_URL


# ---------------------------------------------------------------------------
# Budgets
# ---------------------------------------------------------------------------

class TestBudgets:
    def test_replay_count_budget_exhausted(self):
        """max_replays 消費後の check → not_run（budget_exhausted）."""
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client,
            scope_definition=TARGET_SCOPE,
            max_replays=1,
        )
        first = checker.check(make_sqli_finding())
        assert first.status == "matched"
        second = checker.check(make_sqli_finding())
        assert second.status == "not_run"
        assert second.reason == "reproduction_budget_exhausted"
        assert len(client.calls) == 1

    def test_replay_time_budget_exhausted(self, monkeypatch):
        # started_at is recorded at construction; the check reads monotonic
        # again later — simulate a large elapsed with a 2-value sequence.
        values = iter([0.0, 100.0])
        monkeypatch.setattr(checker_module.time, "monotonic", lambda: next(values))
        checker = default_checker(time_budget_seconds=1.0)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_budget_exhausted"

    def test_extended_time_budget_allows_replay_after_slow_judge(self, monkeypatch):
        """SGK-2026-0452 (承認D・2026-08-16): checker 生成から check まで
        100 秒経過（＝遅い judge／judge 再試行の実行時間を再現）しても、
        拡大 time_budget_seconds=600 なら replay が budget 内で走り
        matched に到達する（judge 時間が replay budget を食わない）。"""
        values = iter([0.0, 100.0])
        monkeypatch.setattr(checker_module.time, "monotonic", lambda: next(values))
        checker = default_checker(time_budget_seconds=600)
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"

    def test_default_time_budget_still_exhausted_after_slow_judge(self, monkeypatch):
        """既定 time_budget_seconds=60 では 100 秒経過で not_run（回帰なし・
        既定の fail-closed 挙動を固定）。"""
        values = iter([0.0, 100.0])
        monkeypatch.setattr(checker_module.time, "monotonic", lambda: next(values))
        checker = default_checker()  # 既定 60s
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_budget_exhausted"

    def test_poc_judge_budget_exhausted_raises(self):
        budget = PoCJudgeBudget(max_calls=1)
        calls = {"n": 0}

        class FakeJudge:
            def judge(self, finding):
                calls["n"] += 1
                return "judged"

        wrapped = BudgetedPoCJudge(FakeJudge(), budget)
        assert wrapped.judge(None) == "judged"
        with pytest.raises(JudgeBudgetExhausted):
            wrapped.judge(None)
        assert calls["n"] == 1

    def test_poc_judge_budget_time_exhausted(self, monkeypatch):
        monkeypatch.setattr(checker_module.time, "monotonic", lambda: 0.0)
        budget = PoCJudgeBudget(max_calls=10, max_seconds=1.0)
        monkeypatch.setattr(checker_module.time, "monotonic", lambda: 100.0)
        assert budget.acquire() is False


# ---------------------------------------------------------------------------
# SGK-2026-0455: DOM-variant browser re-execution path (T1 / T2)
# ---------------------------------------------------------------------------


class FakeBrowserValidator:
    """Sync browser-validator stub (``validate_xss_sync`` interface).

    ``available`` controls ``is_available`` (fail-closed gate); ``error``
    makes the load raise (transport-error mapping); otherwise ``result`` is
    the dialog-observed outcome of the browser re-execution.
    """

    def __init__(
        self,
        *,
        available: bool = True,
        result: bool = False,
        error: "Exception | None" = None,
    ):
        self.is_available = available
        self.result = result
        self.error = error
        self.calls: list = []

    def validate_xss_sync(self, url: str, timeout: float = 10.0):
        self.calls.append({"url": url, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return self.result


_DOM_TEST_URL = "https://target.example/#/results?q=%3Cimg%20src=x%20onerror=alert(1)%3E"
_DOM_PAYLOAD = "<img src=x onerror=alert(1)>"


def make_dom_xss_finding(
    *,
    test_url: str = _DOM_TEST_URL,
    request_url: str = "https://target.example/#/search?q=probe",
    dialog_observed: bool = True,
    variant: str = "dom",
    response_body: str = "",
    additional_info: "dict | None" = None,
) -> Finding:
    """DOM-variant XSS finding carrying ``browser_execution`` evidence."""
    info = {
        "browser_execution": {
            "dialog_observed": dialog_observed,
            "executor": "playwright",
            "event": "dom_runtime_execution",
            "variant": variant,
            "parameter": "q",
            "payload": _DOM_PAYLOAD,
            "test_url": test_url,
        }
    }
    if additional_info:
        info.update(additional_info)
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="DOM XSS in search results",
        description="Generic DOM-variant XSS style finding.",
        target_url="https://target.example/",
        evidence=Evidence(
            request_method="GET",
            request_url=request_url,
            response_status=200,
            response_body=response_body,
        ),
        reproduction_steps=["Open the URL in a browser", "Observe the alert"],
        impact="DOM-based execution in the victim's browser.",
        additional_info=info,
    )


class TestDomBrowserPath:
    def _checker(self, *, validator=None, **kwargs) -> SealedReproductionChecker:
        kwargs.setdefault("browser_validator", validator)
        kwargs.setdefault("scope_definition", TARGET_SCOPE)
        return SealedReproductionChecker(**kwargs)

    def test_dom_variant_dialog_reobserved_matched(self):
        """T1: 確定時ブラウザ再実行で dialog 再観測 → matched."""
        validator = FakeBrowserValidator(result=True)
        checker = self._checker(validator=validator)
        outcome = checker.check(make_dom_xss_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_browser_dialog_observed"
        assert validator.calls == [{"url": _DOM_TEST_URL, "timeout": 15.0}]

    def test_dom_variant_no_dialog_mismatched(self):
        """T1: 応答したが dialog 非発火 → mismatched（唯一の DOM mismatch 経路）."""
        validator = FakeBrowserValidator(result=False)
        checker = self._checker(validator=validator)
        outcome = checker.check(make_dom_xss_finding())
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_dom_variant_browser_unavailable_not_run(self):
        """T1: ブラウザ不能 → not_run（fail-closed。mismatch にしない）."""
        validator = FakeBrowserValidator(available=False)
        checker = self._checker(validator=validator)
        outcome = checker.check(make_dom_xss_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_browser_unavailable"
        assert validator.calls == []

    def test_dom_variant_transport_error_not_run(self):
        """T1: 送信/観測例外 → not_run（fail-closed・transport_error）."""
        validator = FakeBrowserValidator(error=RuntimeError("browser crashed"))
        checker = self._checker(validator=validator)
        outcome = checker.check(make_dom_xss_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "reproduction_transport_error"

    def test_dom_variant_out_of_scope_not_run(self):
        """scope 再検証: 封印スコープ外の test_url → not_run（send なし）."""
        validator = FakeBrowserValidator(result=True)
        checker = self._checker(validator=validator)
        outcome = checker.check(
            make_dom_xss_finding(test_url="https://out-of-scope.example/#/search?q=x")
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert validator.calls == []

    def test_dom_variant_scope_definition_none_fails_closed(self):
        validator = FakeBrowserValidator(result=True)
        checker = SealedReproductionChecker(
            browser_validator=validator, scope_definition=None
        )
        outcome = checker.check(make_dom_xss_finding())
        assert outcome.status == "not_run"
        assert outcome.reason == "scope_revalidation_blocked"
        assert validator.calls == []

    def test_dom_variant_state_changing_excluded(self):
        """GET ロードのみ: 状態変更セマンティクスは排除（send なし）."""
        validator = FakeBrowserValidator(result=True)
        checker = self._checker(validator=validator)
        outcome = checker.check(
            make_dom_xss_finding(additional_info={"action_semantics": "form_submit"})
        )
        assert outcome.status == "not_run"
        assert outcome.reason == "state_changing_excluded"
        assert validator.calls == []

    def test_dom_variant_budget_consumed_by_browser_attempt(self):
        """run 全体予算: ブラウザ試行後は _replays_used が消費される."""
        validator = FakeBrowserValidator(result=True)
        checker = self._checker(validator=validator, max_replays=1)
        first = checker.check(make_dom_xss_finding())
        assert first.status == "matched"
        second = checker.check(make_dom_xss_finding())
        assert second.status == "not_run"
        assert second.reason == "reproduction_budget_exhausted"

    def test_reflected_finding_without_browser_evidence_keeps_http_path(self):
        """T1 回帰: ブラウザ証拠の無い反射型 finding は既存 HTTP 再送経路."""
        validator = FakeBrowserValidator(result=True)
        client = FakeNetworkClient(FakeResponse(200, _SQL_BODY))
        checker = SealedReproductionChecker(
            network_client=client,
            scope_definition=TARGET_SCOPE,
            browser_validator=validator,
        )
        outcome = checker.check(make_sqli_finding())
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:sql_error"
        assert validator.calls == []  # ブラウザ経路は使われない

    def test_non_dom_variant_with_browser_execution_uses_http_path(self):
        """variant!=dom（例: reflected）は既存 HTTP 再送経路."""
        validator = FakeBrowserValidator(result=True)
        client = FakeNetworkClient(FakeResponse(200, _XSS_BODY))
        checker = SealedReproductionChecker(
            network_client=client,
            scope_definition=TARGET_SCOPE,
            browser_validator=validator,
        )
        outcome = checker.check(make_dom_xss_finding(variant="reflected"))
        assert outcome.status == "matched"
        assert outcome.reason == "reproduction_marker_matched:reflected_payload"
        assert validator.calls == []

    def test_dom_candidate_without_prior_dialog_and_no_fire_never_matches(self):
        """T2 (偽陽性回帰): ブラウザ実行証拠の無い DOM 候補は、確定時再実行でも
        dialog 非発火なら matched にならない → confirmed 到達不可."""
        validator = FakeBrowserValidator(result=False)
        checker = self._checker(validator=validator)
        outcome = checker.check(make_dom_xss_finding(dialog_observed=False))
        assert outcome.status == "mismatched"
        assert outcome.reason == "reproduction_marker_mismatch"

    def test_dom_finding_without_browser_execution_never_matches(self):
        """T2 (偽陽性回帰): browser_execution を全く持たない DOM 風 finding は
        HTTP 再送経路に落ち、body に発火マーカーが無ければ matched にならない."""
        validator = FakeBrowserValidator(result=True)
        client = FakeNetworkClient(FakeResponse(200, "OK"))
        checker = SealedReproductionChecker(
            network_client=client,
            scope_definition=TARGET_SCOPE,
            browser_validator=validator,
        )
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="DOM-ish candidate without browser evidence",
            description="d",
            target_url="https://target.example/",
            evidence=Evidence(
                request_method="GET",
                request_url=_DOM_TEST_URL,
                response_status=200,
                response_body="OK",
            ),
            reproduction_steps=["Open the URL"],
            impact="Hypothetical DOM execution.",
            additional_info={},
        )
        outcome = checker.check(finding)
        assert outcome.status != "matched"  # mismatched/not_run — never matched
        assert validator.calls == []
