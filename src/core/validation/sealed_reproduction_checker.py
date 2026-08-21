"""
Sealed-environment reproduction back-check checker — SGK-2026-0445 appendix §B/C.

``ReproductionChecker`` Protocol implementation (T3): re-sends the PoC as ONE
sealed GET and confirms that the SAME firing-marker category fired again.

Guard column (all existing assets reused, nothing modified):

- send eligibility: ``assert_read_only_probe("GET", url)`` + 
  ``evaluate_readonly_request`` (state-changing semantics / GraphQL mutation
  rejected) — payout_grade.py:495-511 / vdp_readonly_guard.py:111-204
- scope: ``revalidate_scope_for_request`` (None scope definition fails closed)
  — vdp_scope_validator.py:52-110
- request identity: ``build_request_fingerprint`` equality (no send on
  mismatch) — vdp_follow_up_executor.py:201-224
- transport: ``network_client=None`` -> not_run; otherwise ONE GET with
  use_cache=False, retries=0, auto_waf_bypass=False, allow_redirects=False,
  explicit timeout (executor ``_send_read_request`` contract :1090-1155).
- marker comparison: the replay response body is evaluated against the
  existing payout-grade marker vocabulary (``_MARKER_CATEGORIES`` and the
  per-category patterns in payout_grade.py — imported, never duplicated, no
  new markers). Same-category firing -> matched; response present but no
  same-category firing -> mismatched; no response / timeout / error ->
  not_run (never mismatched).
- mask: 0439 token_map restore when available; an unresolvable masked URL ->
  not_run (fail-closed, no send).
- budget: one replay per finding; run-wide replay cap (default 5) + time
  budget (default 60 s), measured with ``time.monotonic()``.

SYNC/ASYNC CONTRACT: the ``ReproductionChecker`` Protocol is SYNCHRONOUS
(finding_validator.py:287-288; ``evaluate`` calls ``checker.check(finding)``
synchronously at finding_validator.py:222). ``check`` is therefore
synchronous. When the injected client's ``request`` is a coroutine function
(the real AsyncNetworkClient), the send falls back to the existing
synchronous ``requests`` pattern (exploit_verifier.py:176) — 
``run_until_complete`` / ``asyncio.run`` are NOT used (forbidden).

Also implements the poc_judge run budget (§C): ``PoCJudgeBudget`` /
``BudgetedPoCJudge`` / ``JudgeBudgetExhausted`` (fail-closed; the Lane B
wiring catches the exception and maps it to ai_judge=None -> needs_more).
"""
from __future__ import annotations

import inspect
import re
import time
from typing import Any, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import requests

from src.core.agents.swarm.injection.payout_grade import (
    _CMD_INDICATORS,
    _LFI_PATTERNS,
    _MARKER_CATEGORIES,
    _SQL_ERROR_PATTERNS,
    _SSRF_INDICATORS,
    _SSRF_METADATA_PATTERNS,
    _XSS_MARKERS,
    assert_read_only_probe,
    evaluate_payout_grade,
    finding_payload,
)
from src.core.domain.scope.vdp_scope_validator import revalidate_scope_for_request
from src.core.engine.vdp_follow_up_executor import build_request_fingerprint
from src.core.engine.vdp_readonly_guard import evaluate_readonly_request
from src.core.security.pii_masker import PIIMasker
from src.core.validation.finding_validator import ReproductionOutcome
from src.tools.browser.playwright_validator import PlaywrightValidator

# PII token format is owned by PIIMasker (0439 token_map); reuse its pattern
# so the residual-check syntax can never drift from the masker.
_PII_TOKEN_RE = PIIMasker.TOKEN_PATTERN

# Firing-marker vocabulary tokens that are observable in a single replay
# response body (subset of the payout-grade marker tokens).
_BODY_OBSERVABLE_MARKERS = frozenset({
    "sql_error",
    "reflected_payload",
    "file_content_leak",
    "command_execution",
    "ssrf_callback",
})
# authz_diff is intentionally NOT body-observable: its proof lives in
# additional_info.authz_differential and requires two accounts.
_NON_BODY_MARKERS = frozenset({"authz_diff"})

# Stable fail-closed reason codes.
_REASON_BUDGET_EXHAUSTED = "reproduction_budget_exhausted"
_REASON_MASKED_URL_UNRESOLVABLE = "masked_url_unresolvable"
_REASON_READ_ONLY_PROBE_REJECTED = "read_only_probe_rejected"
_REASON_STATE_CHANGING_EXCLUDED = "state_changing_excluded"
_REASON_SCOPE_REVALIDATION_BLOCKED = "scope_revalidation_blocked"
_REASON_REQUEST_FINGERPRINT_MISMATCH = "request_fingerprint_mismatch"
_REASON_TRANSPORT_ERROR = "reproduction_transport_error"
_REASON_DISABLED_NO_CLIENT = "reproduction_disabled_no_client"
_REASON_MARKER_MISMATCH = "reproduction_marker_mismatch"
_REASON_MARKER_NOT_OBSERVABLE = "reproduction_marker_not_observable_in_replay"
_REASON_UNKNOWN_CATEGORY = "reproduction_unknown_category"
_REASON_BROWSER_UNAVAILABLE = "reproduction_browser_unavailable"
_REASON_BROWSER_DIALOG_OBSERVED = "reproduction_browser_dialog_observed"


def _sync_http_get(url: str, *, timeout_seconds: float) -> Tuple[str, int]:
    """Synchronous GET fallback (existing pattern: exploit_verifier.py:176).

    Used when the injected client's ``request`` is a coroutine function
    (AsyncNetworkClient) and the synchronous Protocol cannot await it.
    Redirects are never followed; explicit timeout; env proxies apply by
    default (same as the existing requests pattern). Transport failures
    raise — the caller maps them to not_run.
    """
    response = requests.get(
        url, timeout=int(timeout_seconds), allow_redirects=False, verify=False
    )
    return response.text, int(response.status_code or 0)


def _extract_response(resp: Any) -> Tuple[str, int]:
    """Project a NetworkResponse-like object to ``(body, status)``.

    ``body`` is normalized to str (bytes decoded with replacement);
    a missing status is projected as 0 (transport failure semantics).
    """
    status = int(getattr(resp, "status", 0) or 0)
    body = getattr(resp, "body", "") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return str(body), status


def _detect_marker_in_response(category: str, body: str) -> Optional[str]:
    """Same-category firing-marker detection on a replay response body.

    Reuses the payout-grade vocabulary EXACTLY (the pattern tuples are
    imported from payout_grade.py — no new markers, no duplication). The
    body-only subset mirrors payout_grade's ``_match_firing_marker`` body
    checks; additional_info-only signals (reflection_observed etc.) are not
    available on a replay response and are never re-used here.

    Returns the fired marker token, or None when the category is known but
    nothing fired (fail-closed).
    """
    body_lower = body.lower()

    if category == "sql_error":
        if any(re.search(p, body, re.IGNORECASE) for p in _SQL_ERROR_PATTERNS):
            return "sql_error"
        return None

    if category == "reflected_payload":
        if any(marker in body_lower for marker in _XSS_MARKERS):
            return "reflected_payload"
        return None

    if category == "file_content_leak":
        if any(
            re.search(p, body, re.IGNORECASE | re.MULTILINE) for p in _LFI_PATTERNS
        ):
            return "file_content_leak"
        return None

    if category == "command_execution":
        if any(marker in body_lower for marker in _CMD_INDICATORS):
            return "command_execution"
        return None

    if category == "ssrf_callback":
        if any(marker in body_lower for marker in _SSRF_INDICATORS):
            return "ssrf_callback"
        if any(re.search(p, body, re.IGNORECASE) for p in _SSRF_METADATA_PATTERNS):
            return "ssrf_callback"
        return None

    return None  # authz_diff / unknown: not observable in a single response


def _param_names_from_url(url: str) -> Tuple[str, ...]:
    """Query param NAMES only (values are never part of any fingerprint)."""
    parsed = urlsplit(url)
    return tuple(sorted(key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)))


class SealedReproductionChecker:
    """封印環境で PoC を GET 再送し、同一発火マーカーを確認する ReproductionChecker。

    - GET のみ・封印ローカル（scope 再検証必須）・state-changing 除外・
      fingerprint 一致必須。
    - タイムアウト/エラー/スコープ外/状態変更/復元不能 → not_run
      （mismatch にしない・fail-closed）。
    - mismatched は「応答あり・同一カテゴリの発火マーカー非検出」のみ。
    - 再送は1 finding あたり1回。run 全体の再送回数上限と時間予算を保持。
    """

    def __init__(
        self,
        *,
        network_client=None,           # AsyncNetworkClient 互換。None なら送信不可（not_run）
        scope_definition=None,         # 封印スコープ。None なら fail-closed（not_run）
        masker=None,                   # PIIMasker 互換（unmask 用・0439）。None かつマスク済 URL は復元不能 → not_run
        max_replays: int = 5,          # run 全体の再送回数上限
        time_budget_seconds: float = 60.0,  # run 全体の再送時間予算
        timeout_seconds: float = 15.0,      # 1 送信のタイムアウト
        browser_validator=None,             # PlaywrightValidator 互換。None なら遅延生成
    ) -> None:
        self._network_client = network_client
        self._scope_definition = scope_definition
        self._masker = masker
        self._max_replays = max(0, int(max_replays))
        self._time_budget_seconds = max(0.0, float(time_budget_seconds))
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self._browser_validator_arg = browser_validator
        self._browser_validator_instance = None
        self._replays_used = 0
        self._started_at = time.monotonic()

    # ------------------------------------------------------------------
    # Public contract
    # ------------------------------------------------------------------

    def check(self, finding: Any) -> ReproductionOutcome:
        """Replay the finding's PoC as ONE sealed GET (fail-closed)."""
        # 1) run-wide budget (replay count / elapsed time)
        if self._replays_used >= self._max_replays:
            return ReproductionOutcome("not_run", _REASON_BUDGET_EXHAUSTED)
        if time.monotonic() - self._started_at >= self._time_budget_seconds:
            return ReproductionOutcome("not_run", _REASON_BUDGET_EXHAUSTED)

        # SGK-2026-0455: DOM-variant browser re-execution path. The sealed
        # HTTP GET replay below cannot carry #fragment payloads (fragments
        # never reach the server), so a DOM-variant finding is re-verified
        # by re-loading the PoC URL in a real browser and re-observing the
        # alert() dialog. The reflected HTTP path stays byte-identical for
        # every other finding.
        payload = finding_payload(finding)
        _info = payload.get("additional_info")
        if not isinstance(_info, dict):
            _info = {}
        _browser_execution = _info.get("browser_execution")
        if (
            isinstance(_browser_execution, dict)
            and str(_browser_execution.get("variant") or "").strip().lower() == "dom"
            and str(_browser_execution.get("test_url") or "").strip()
        ):
            return self._check_dom_via_browser(_browser_execution, _info)

        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        url = str(evidence.get("request_url") or "").strip()
        if not url:
            return ReproductionOutcome("not_run", _REASON_READ_ONLY_PROBE_REJECTED)

        # 2) masked URL resolution (0439 token_map restore). An
        #    unresolvable masked URL never reaches the network.
        resolved_url = self._resolve_url(url)
        if resolved_url is None:
            return ReproductionOutcome("not_run", _REASON_MASKED_URL_UNRESOLVABLE)

        # 3) GET-only probe (the sealed re-send is always a GET).
        if not assert_read_only_probe("GET", resolved_url):
            return ReproductionOutcome("not_run", _REASON_READ_ONLY_PROBE_REJECTED)

        # 4) read-only guard: state-changing semantics on a GET are excluded.
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            info = {}
        headers = evidence.get("request_headers")
        if not isinstance(headers, dict):
            headers = {}
        content_type = str(
            headers.get("Content-Type") or headers.get("content-type") or ""
        )
        readonly = evaluate_readonly_request(
            "GET",
            action_semantics=str(info.get("action_semantics") or ""),
            graphql_operation="",
            body=None,  # GET replay carries no body
            url=resolved_url,
            content_type=content_type,
        )
        if not readonly.allowed:
            return ReproductionOutcome("not_run", _REASON_STATE_CHANGING_EXCLUDED)

        # 5) scope revalidation against the SEALED scope snapshot.
        scope_result = revalidate_scope_for_request(
            resolved_url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)

        # 6) request identity: the replay fingerprint must equal the
        #    original request's fingerprint (method/url/param_names).
        param_names = _param_names_from_url(resolved_url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""),
            resolved_url,
            param_names,
        )
        replay_fp = build_request_fingerprint("GET", resolved_url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)

        # Record the expected firing-marker category from the ORIGINAL
        # finding (payout-grade marker, or evidence-internal marker, or the
        # category mapping as last resort).
        expected_marker = self._expected_marker(payload, evidence)
        if expected_marker is None:
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if expected_marker in _NON_BODY_MARKERS:
            # authz_diff cannot be re-verified by one sealed GET (its proof
            # needs two accounts) — never refute speculatively, fail closed.
            return ReproductionOutcome("not_run", _REASON_MARKER_NOT_OBSERVABLE)

        # 7) sealed send (ONE GET; hidden communication disabled).
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        try:
            body, status = self._send_get(resolved_url)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            body, status = None, 0
        # 9) budget consumed for the replay attempt (send attempted).
        self._replays_used += 1

        # 8) firing-marker comparison on the replay response.
        if body is None or status <= 0 or not body:
            # 応答なし/空/異常 → not_run（mismatch にしない・fail-closed）
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        fired = _detect_marker_in_response(expected_marker, body)
        if fired is not None:
            return ReproductionOutcome(
                "matched", f"reproduction_marker_matched:{fired}"
            )
        # 応答あり・同一カテゴリの発火マーカー非検出 → mismatched（唯一の mismatch 経路）
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _browser_validator(self) -> Any:
        """Lazily constructed browser validator (injected stub wins).
        Construction is cheap (availability check only); the browser is
        launched at most once per finding by validate_xss_sync."""
        if self._browser_validator_instance is None:
            self._browser_validator_instance = (
                self._browser_validator_arg
                if self._browser_validator_arg is not None
                else PlaywrightValidator()
            )
        return self._browser_validator_instance

    def _check_dom_via_browser(
        self, browser_execution: dict, info: dict
    ) -> ReproductionOutcome:
        """DOM-variant sealed reproduction: ONE real-browser re-load of the
        PoC test_url with re-observation of the alert() dialog (fail-closed).

        GET-load only (no form fill / no click / no state change); scope is
        revalidated against the SEALED target-only snapshot; browser
        unavailability and transport errors are not_run, never mismatched.
        """
        test_url = str(browser_execution.get("test_url") or "").strip()
        # 1) masked URL resolution (0439 token_map restore) — same guard
        #    as the HTTP path; an unresolvable URL never reaches the browser.
        resolved_url = self._resolve_url(test_url)
        if resolved_url is None:
            return ReproductionOutcome("not_run", _REASON_MASKED_URL_UNRESOLVABLE)
        # 2) GET-only probe (the browser load is a GET).
        if not assert_read_only_probe("GET", resolved_url):
            return ReproductionOutcome("not_run", _REASON_READ_ONLY_PROBE_REJECTED)
        # 3) read-only guard: state-changing semantics on a GET are excluded.
        readonly = evaluate_readonly_request(
            "GET",
            action_semantics=str(info.get("action_semantics") or ""),
            graphql_operation="",
            body=None,
            url=resolved_url,
            content_type="",
        )
        if not readonly.allowed:
            return ReproductionOutcome("not_run", _REASON_STATE_CHANGING_EXCLUDED)
        # 4) scope revalidation against the SEALED scope snapshot.
        scope_result = revalidate_scope_for_request(
            resolved_url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        # 5) browser availability (fail-closed — unavailable is not_run).
        validator = self._browser_validator()
        if not validator.is_available:
            return ReproductionOutcome("not_run", _REASON_BROWSER_UNAVAILABLE)
        # 6) ONE browser re-load: dialog re-observed -> matched; responded
        #    but no dialog -> mismatched; exception/timeout -> not_run.
        try:
            fired = bool(validator.validate_xss_sync(resolved_url, timeout=self._timeout_seconds))
        except Exception:  # noqa: BLE001 — browser boundary, fail closed
            fired = None
        self._replays_used += 1  # browser-load attempt consumed the budget slot
        if fired is None:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if fired:
            return ReproductionOutcome("matched", _REASON_BROWSER_DIALOG_OBSERVED)
        # Browser responded but no dialog fired -> the ONLY DOM mismatch path.
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _resolve_url(self, url: str) -> Optional[str]:
        """Restore 0439 tokens via the masker; None when unresolvable."""
        if not _PII_TOKEN_RE.search(url):
            return url
        if self._masker is None:
            return None
        try:
            resolved = self._masker.unmask(url)
        except Exception:  # noqa: BLE001 — masker boundary, fail closed
            return None
        if _PII_TOKEN_RE.search(str(resolved or "")):
            return None
        return str(resolved)

    def _expected_marker(self, payload: dict, evidence: dict) -> Optional[str]:
        """Expected firing-marker token of the ORIGINAL finding.

        Priority: evaluate_payout_grade's fired marker → evidence-internal
        marker (only when it is a known vocabulary token) → the category
        mapping. None = unknown category (fail-closed).
        """
        floor = evaluate_payout_grade(payload)
        marker = getattr(floor, "marker", None)
        if marker:
            return marker
        evidence_marker = evidence.get("marker")
        if evidence_marker in _BODY_OBSERVABLE_MARKERS or evidence_marker in _NON_BODY_MARKERS:
            return evidence_marker
        vuln_type = str(payload.get("vuln_type") or "").strip().lower()
        return _MARKER_CATEGORIES.get(vuln_type)

    def _send_get(self, url: str) -> Tuple[str, int]:
        """Send ONE sealed GET through the injected client.

        A synchronously-callable client ``request`` is used directly with
        the executor send contract kwargs. An async client (coroutine
        function) cannot be awaited from the synchronous Protocol
        (run_until_complete/asyncio.run forbidden) — the existing
        synchronous requests pattern is used instead.
        """
        request = getattr(self._network_client, "request", None)
        if request is None:
            raise RuntimeError("network client has no request()")
        if inspect.iscoroutinefunction(request):
            return _sync_http_get(url, timeout_seconds=self._timeout_seconds)
        resp = request(
            "GET",
            url,
            use_cache=False,
            retries=0,
            auto_waf_bypass=False,
            allow_redirects=False,
            timeout=int(self._timeout_seconds),
            use_proxy=True,
        )
        return _extract_response(resp)


class PoCJudgeBudget:
    """poc_judge 実起動の run スコープ予算（fail-closed）。"""

    def __init__(self, max_calls: int = 10, max_seconds: float = 600.0) -> None:
        self._max_calls = max(0, int(max_calls))
        self._max_seconds = max(0.0, float(max_seconds))
        self._used_calls = 0
        self._started_at = time.monotonic()

    def acquire(self) -> bool:
        """回数/時間の両方が残っていれば消費して True。"""
        if self._used_calls >= self._max_calls:
            return False
        if time.monotonic() - self._started_at >= self._max_seconds:
            return False
        self._used_calls += 1
        return True


class JudgeBudgetExhausted(Exception):
    """予算超過。配線側（Lane B）が catch して ai_judge=None 扱いに写像する。"""


class BudgetedPoCJudge:
    """PoCJudge を予算付きでラップ。予算超過時 JudgeBudgetExhausted を raise
    （fail-closed・確認しない）。"""

    def __init__(self, judge, budget: PoCJudgeBudget) -> None:
        self._judge = judge
        self._budget = budget

    def judge(self, finding):
        if not self._budget.acquire():
            raise JudgeBudgetExhausted(
                "poc_judge budget exhausted (run-wide judge call/time budget)"
            )
        return self._judge.judge(finding)
