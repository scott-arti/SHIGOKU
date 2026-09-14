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
- marker comparison: the replay response is evaluated against the
  existing payout-grade marker vocabulary (``_MARKER_CATEGORIES`` and the
  per-category patterns in payout_grade.py — imported, never duplicated, no
  new markers). Body markers are detected on the replay response body;
  ``external_redirect`` (open_redirect) is header-observable and is instead
  re-confirmed from the Location header of a 3xx replay response;
  ``cors_credentialed_reflection`` (cors) is header-observable AND needs an
  Origin-attached replay — it is re-confirmed from the
  Access-Control-Allow-Origin/Access-Control-Allow-Credentials headers of a
  dedicated Origin-carrying sealed GET (``_check_cors_replay``);
  ``jwt_forgery_accepted`` (jwt_alg_none, SGK-2026-0476) is observable in
  ONE replay GET carrying the original forged token — it is re-confirmed by
  re-observing the forged identity in the replay body of a dedicated
  forged-token GET (``_check_jwt_forgery_replay``);
  ``command_execution`` (SGK-2026-0478) from a POST form injection is
  observable in ONE replay of the ORIGINAL form POST — findings carrying a
  validated ``command_replay`` descriptor (read-only allowlisted command
  only, ``_check_command_execution_replay``) are re-sent with the original
  method + ``body_params``; the GET-only relaxation is limited to this
  non-destructive POST replay, and descriptors that are missing or carry a
  non-allowlisted command fall back to the unchanged GET body-marker path.
  ``uploaded_file_retrieved`` (SGK-2026-0480, file_upload) is observable by
  re-reading the stored file — the finding's original evidence method is the
  upload POST, so the sealed replay is ONE pure GET to the recorded
  ``file_upload_evidence.retrieval_url`` re-observing the recorded
  ``retrieval_marker`` (``_check_file_upload_retrieval``; GET-only relaxation
  is NOT needed — the re-read itself is a GET). Same
  category firing -> matched; response present but no same-category firing
  -> mismatched; no response / timeout / error -> not_run (never mismatched).
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
import json
import re
import time
from typing import Any, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import requests

from src.core.agents.swarm.injection.payout_grade import (
    _CMD_INDICATORS,
    _LFI_PATTERNS,
    _MARKER_CATEGORIES,
    _REDIRECT_STATUSES,
    _SECRET_EXPOSURE_PATTERNS,
    _SQL_ERROR_PATTERNS,
    _SSRF_INDICATORS,
    _SSRF_METADATA_PATTERNS,
    _XSS_MARKERS,
    _XXE_ENTITY_PATTERN,
    _XXE_FILE_PATTERNS,
    _NOSQL_OPERATOR_PATTERN,
    _nosql_body_has_data,
    _acao_reflects_test_origin,
    _external_redirect_observed,
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
    # SGK-2026-0480: uploaded_file_retrieved (file_upload) は retrieval_url
    # への単一 GET 再読の応答本文で観測できる（専用 _check_file_upload_retrieval）。
    "uploaded_file_retrieved",
    # SGK-2026-0483: secret_exposed (secret_leak) は取得元URL（evidence.request_url）
    # への単一 GET 再読の応答本文に資格情報代入パターンが再出現すれば観測できる
    # （汎用 GET 経路 + _detect_marker_in_response の secret_exposed 分岐）。
    "secret_exposed",
})
# authz_diff is intentionally NOT body-observable: its proof lives in
# additional_info.authz_differential and requires two accounts.
_NON_BODY_MARKERS = frozenset({"authz_diff"})
# external_redirect is observable in ONE replay GET, but via the Location
# HEADER of a 3xx response (an open-redirect replay response often has an
# empty body) — never a body marker and never treated as non-observable.
# cors_credentialed_reflection (SGK-2026-0475) is likewise observable in
# ONE replay GET via the ACAO/ACAC headers — but the replay must carry the
# original test_origin as an Origin header (dedicated _check_cors_replay).
_HEADER_OBSERVABLE_MARKERS = frozenset({
    "external_redirect",
    "cors_credentialed_reflection",
})

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

# SGK-2026-0474: file_content_leak の excerpt 再出現照合に使う最小長
# （正規化後）。これ未満/空/空白のみの抜粋は excerpt 一致に使わない
# （fail-closed・従来の _LFI_PATTERNS 経路のみに落ちる）。
_MIN_EXCERPT_MATCH_LENGTH = 24

# SGK-2026-0478: command_execution の封印 POST 再送で許容する読み取り専用
# コマンドの許可リスト。smart_cmd_ssrf.py の READONLY_COMMAND_ALLOWLIST と
# 同一値（validation 層は swarm エンジンを import しないため local 定義）。
# 許可外コマンドの記述子は POST 再送しない（fail-closed・GET フォールバック）。
_READONLY_COMMANDS: frozenset = frozenset({
    "id", "whoami", "uname", "pwd", "hostname", "groups",
})

# SGK-2026-0478: command_execution POST 再送で扱う form body の Content-Type
# （smart_cmd_ssrf が command_replay に記録する値と同一）。
_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"


def _collapse_whitespace(text: str) -> str:
    """連続空白を単一スペースに潰す（excerpt 再出現の安定照合用）。"""
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _sync_http_get(url: str, *, timeout_seconds: float) -> Tuple[str, int, str]:
    """Synchronous GET fallback (existing pattern: exploit_verifier.py:176).

    Used when the injected client's ``request`` is a coroutine function
    (AsyncNetworkClient) and the synchronous Protocol cannot await it.
    Redirects are never followed; explicit timeout; env proxies apply by
    default (same as the existing requests pattern). Transport failures
    raise — the caller maps them to not_run. Returns ``(body, status,
    location)``; ``location`` is the Location header value or "" when the
    response carries none (header case is handled by requests' case
    insensitive mapping).
    """
    response = requests.get(
        url, timeout=int(timeout_seconds), allow_redirects=False, verify=False
    )
    location = ""
    headers = getattr(response, "headers", None) or {}
    get = getattr(headers, "get", None)
    if callable(get):
        location = str(get("Location") or get("location") or "")
    return response.text, int(response.status_code or 0), location


def _extract_cors_headers(resp: Any) -> Tuple[str, str]:
    """Project ACAO/ACAC header values from a NetworkResponse-like object
    (case-insensitive). Returns ``("", "")`` when headers are unreadable."""
    acao = ""
    acac = ""
    headers = getattr(resp, "headers", None)
    if headers is not None:
        get = getattr(headers, "get", None)
        if callable(get):
            acao = str(
                get("Access-Control-Allow-Origin")
                or get("access-control-allow-origin")
                or ""
            )
            acac = str(
                get("Access-Control-Allow-Credentials")
                or get("access-control-allow-credentials")
                or ""
            )
    return acao, acac


def _sync_http_get_with_origin(
    url: str, *, headers: dict, timeout_seconds: float
) -> Tuple[int, str, str]:
    """Synchronous Origin-carrying GET fallback (CORS replay; same pattern
    as ``_sync_http_get`` — requests fallback for async injected clients).
    Returns ``(status, acao, acac)``."""
    response = requests.get(
        url,
        headers=headers,
        timeout=int(timeout_seconds),
        allow_redirects=False,
        verify=False,
    )
    acao, acac = _extract_cors_headers(response)
    return int(response.status_code or 0), acao, acac


def _sync_http_get_with_headers(
    url: str, *, headers: dict, timeout_seconds: float
) -> Tuple[int, str]:
    """Synchronous header-carrying GET fallback (JWT replay; same pattern as
    ``_sync_http_get_with_origin`` — requests fallback for async injected
    clients). Returns ``(status, body)``."""
    response = requests.get(
        url,
        headers=headers,
        timeout=int(timeout_seconds),
        allow_redirects=False,
        verify=False,
    )
    return int(response.status_code or 0), response.text


def _sync_http_post_form(
    url: str, *, data: dict, headers: dict, timeout_seconds: float
) -> Tuple[int, str]:
    """Synchronous form-POST fallback (command_execution replay; same
    requests fallback pattern as ``_sync_http_get_with_headers`` — used when
    the injected client's ``request`` is a coroutine function). Redirects are
    never followed. Returns ``(status, body)``."""
    response = requests.post(
        url,
        data=data,
        headers=headers,
        timeout=int(timeout_seconds),
        allow_redirects=False,
        verify=False,
    )
    return int(response.status_code or 0), response.text


def _sync_http_post_json(
    url: str, *, data: str, headers: dict, timeout_seconds: float
) -> Tuple[int, str]:
    """Synchronous JSON-POST fallback (in-band SSRF replay; same requests
    fallback pattern as ``_sync_http_post_form`` — used when the injected
    client's ``request`` is a coroutine function). Redirects are never
    followed. ``data`` is a pre-serialized JSON string. Returns
    ``(status, body)``."""
    response = requests.post(
        url,
        data=data,
        headers=headers,
        timeout=int(timeout_seconds),
        allow_redirects=False,
        verify=False,
    )
    return int(response.status_code or 0), response.text


def _extract_response(resp: Any) -> Tuple[str, int, str]:
    """Project a NetworkResponse-like object to ``(body, status, location)``.

    ``body`` is normalized to str (bytes decoded with replacement);
    a missing status is projected as 0 (transport failure semantics);
    ``location`` is the Location header value or "" when the response has no
    (or no readable) headers.
    """
    status = int(getattr(resp, "status", 0) or 0)
    body = getattr(resp, "body", "") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    location = ""
    headers = getattr(resp, "headers", None)
    if headers is not None:
        get = getattr(headers, "get", None)
        if callable(get):
            location = str(get("Location") or get("location") or "")
    return str(body), status, location


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

    if category == "secret_exposed":
        # SGK-2026-0483: 再取得した応答本文に資格情報代入パターンが再出現すれば
        # 同一カテゴリ発火。ライブ再取得本文はここで照合するだけで永続しない
        # （値は残さない・照合はキー側パターン）。
        if any(p.search(body) for p in _SECRET_EXPOSURE_PATTERNS):
            return "secret_exposed"
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

        # SGK-2026-0455/0457: DOM/stored-variant browser re-execution path.
        # The sealed HTTP GET replay below cannot carry #fragment payloads
        # (fragments never reach the server), nor can it re-render a stored
        # payload (the save is a POST; a plain GET replay re-sends the probe
        # request, not the saved page). DOM and stored findings are therefore
        # re-verified by re-loading their PoC/revisit URL in a real browser
        # and re-observing the alert() dialog. The reflected HTTP path stays
        # byte-identical for every other finding.
        payload = finding_payload(finding)
        _info = payload.get("additional_info")
        if not isinstance(_info, dict):
            _info = {}
        _browser_execution = _info.get("browser_execution")
        if (
            isinstance(_browser_execution, dict)
            and str(_browser_execution.get("variant") or "").strip().lower()
            in {"dom", "stored"}
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

        # 2.5) SGK-2026-0478: command_execution 専用の POST 再現パス。
        #      additional_info.command_replay（読み取り専用コマンド限定の
        #      フォーム再送記述子）を持つ finding は GET-only ガードより
        #      前に分岐する — POST フォームへの注入は GET 再送では再現
        #      できないため。記述子なし/許可外コマンド/command_execution
        #      以外は、下記 3) 以降の従来 GET-only 経路へ byte-identical
        #      にフォールバックする（非回帰）。GET-only ガードの緩和は
        #      この非破壊コマンド POST 再送に限る。
        cmd_replay = self._command_replay_descriptor(payload)
        if (
            cmd_replay is not None
            and self._expected_marker(payload, evidence) == "command_execution"
        ):
            return self._check_command_execution_replay(payload, resolved_url, cmd_replay)

        # 2.7) SGK-2026-0480: file_upload 専用の再現パス。アップロード POST の
        #      再送ではなく、additional_info.file_upload_evidence.retrieval_url
        #      への純 GET 再読（記録済み retrieval_marker の再出現確認）で
        #      再現する。evidence.request_method は POST（アップロード）のため
        #      従来の GET-only/fingerprint ガード（evidence.request_url 前提）
        #      より前に分岐する。GET-only ガードの緩和は不要（再送は GET のみ）。
        if self._expected_marker(payload, evidence) == "uploaded_file_retrieved":
            return self._check_file_upload_retrieval(payload, _info)

        # 2.8) SGK-2026-0482: in-band SSRF 専用再現パス。トリガとなる元 POST(JSON)
        #      を封印スコープ内の対象エンドポイントへ再送し、応答に取得本文が
        #      in-band 反映される（reflect_key 値が再び非空）ことを再観測する。
        #      probe_url（内部/スコープ外ホスト）へはクライアントから直接送信
        #      しない（差分は元 finding の payout-grade 証拠として確定済み）。
        #      トリガ先のみ接触するため GET-only ガードより前に分岐する。
        if self._expected_marker(payload, evidence) == "ssrf_inband":
            return self._check_inband_ssrf_replay(payload, _info)

        # 2.9) SGK-2026-0484: GraphQL 認可欠陥 専用再現パス。トリガとなる
        #      GraphQL クエリ(JSON POST)を封印スコープ内の endpoint へ 1 回
        #      再送し、応答 JSON に期待する機微フィールドキーが再出現する
        #      ことを再観測する。GraphQL は JSON POST（body に query を持つ）
        #      のため GET 再送では再現できず、GET-only ガードより前に分岐する。
        #      記述子なし/graphql_sensitive_exposed 以外は従来経路へ非回帰
        #      フォールバック。
        if self._expected_marker(payload, evidence) == "graphql_sensitive_exposed":
            return self._check_graphql_exposure_replay(payload, _info)

        # 2.10) SGK-2026-0485: SSTI 専用再現パス。確定済み算術テンプレート
        #       ペイロードを封印スコープ内へ 1 回だけ再送し、応答本文に期待積
        #       expected（"49<marker>" 等・一意マーカー付きで捏造不可）が再出現
        #       することを再観測する。GET はテンプレート評価＝読み取りのみ。
        #       payload が query にあるため専用パスで扱う。
        if self._expected_marker(payload, evidence) == "template_evaluated":
            return self._check_ssti_replay(payload, _info)

        # 2.11) SGK-2026-0486: XXE 専用再現パス。確定済みの外部実体ペイロード
        #       （form パラメータ or 生 XML ボディ）を封印スコープ内へ 1 回だけ
        #       再送し、応答本文にシステムファイルの署名が再出現することを
        #       再観測する。XXE ファイル読み取りは非破壊（読み取りのみ）。
        if self._expected_marker(payload, evidence) == "xxe_file_read":
            return self._check_xxe_replay(payload, _info)

        # 2.12) SGK-2026-0487: NoSQL 演算子注入 専用再現パス。確定済みの演算子
        #       ペイロード（JSON body）を封印スコープ内へ 1 回だけ再送し、演算子が
        #       再び成功（2xx＋データ）することを再観測する。演算子成功×リテラル
        #       失敗の差分は元 finding で確定済み。JSON POST のため専用パスで扱う。
        if self._expected_marker(payload, evidence) == "nosql_operator_injection":
            return self._check_nosql_replay(payload, _info)

        # 2.13) SGK-2026-0488: Mass Assignment 専用再現パス。確定済みの injection
        #       ボディ（未使用の fresh 値を予約済み・JSON body）を封印スコープ内へ
        #       1 回だけ再送し、応答の同名フィールドが再び攻撃者値になることを
        #       再観測する。injection 反映×control 既定値の差分は元 finding で確定済み。
        #       JSON POST のため専用パスで扱う（登録＝追加系で非破壊）。
        if self._expected_marker(payload, evidence) == "privileged_field_assigned":
            return self._check_mass_assignment_replay(payload, _info)

        # 2.14) SGK-2026-0489: Race Condition（TOCTOU）専用再現パス。新しい一意
        #       マーカーを trigger に埋め、封印スコープ内で並列バーストを1シーケンス
        #       再実行し、observe 応答に新マーカーが再出現することを再観測する。race は
        #       単発再送では再現できないため burst 再現が正当（GET 限定・上限クランプ）。
        if self._expected_marker(payload, evidence) == "race_condition_toctou":
            return self._check_race_replay(payload, _info)

        # 2.15) SGK-2026-0491: Host Header Injection 専用再現パス。注入ヘッダ付き
        #       GET を封印スコープ内へ 1 回再送し、制限署名が 2xx 応答に再出現
        #       することを再観測する（GET＋任意ヘッダ送信）。
        if self._expected_marker(payload, evidence) == "host_header_auth_bypass":
            return self._check_host_header_replay(payload, _info)

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
        if expected_marker == "cors_credentialed_reflection":
            # SGK-2026-0475: cors はヘッダ観測型かつ Origin 付き再送が必須
            # → 専用再現パス（_send_get 本文経路は他種別のまま不変）。
            return self._check_cors_replay(payload, resolved_url)
        if expected_marker == "jwt_forgery_accepted":
            # SGK-2026-0476: jwt 偽造受理は forged_token を Authorization/
            # Cookie に付けた封印 GET 再送で forged_identity の再出現を
            # 観測する専用再現パス（_send_get 本文経路は他種別のまま不変）。
            return self._check_jwt_forgery_replay(payload, resolved_url)

        # 7) sealed send (ONE GET; hidden communication disabled).
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        try:
            body, status, location = self._send_get(resolved_url)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            body, status, location = None, 0, ""
        # 9) budget consumed for the replay attempt (send attempted).
        self._replays_used += 1

        # 8) firing-marker comparison on the replay response.
        if body is None or status <= 0:
            # 応答なし/異常 → not_run（mismatch にしない・fail-closed）
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if expected_marker == "external_redirect":
            # ヘッダ経由マーカー（open_redirect）: 3xx の Location ヘッダで
            # 照合する。リダイレクト応答はボディが空でも観測可能。
            return self._check_external_redirect_replay(payload, status, location)
        if not body:
            # 応答が空 → not_run（mismatch にしない・fail-closed）
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        fired = _detect_marker_in_response(expected_marker, body)
        if fired is None and expected_marker == "file_content_leak":
            # SGK-2026-0474: _LFI_PATTERNS 非一致でも、元 Finding の
            # file_marker_excerpt（パス方式で取得した機密本文の抜粋）が
            # 再送本文に再出現すれば同一カテゴリ発火として matched にする。
            # 空/短すぎ抜粋は excerpt 経路では matched にしない（fail-closed）。
            fired = self._match_file_marker_excerpt(payload, body)
        if fired is not None:
            return ReproductionOutcome(
                "matched", f"reproduction_marker_matched:{fired}"
            )
        # 応答あり・同一カテゴリの発火マーカー非検出 → mismatched（唯一の mismatch 経路）
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _match_file_marker_excerpt(self, payload: dict, body: str) -> Optional[str]:
        """SGK-2026-0474: 元 Finding の file_marker_excerpt 再出現照合。

        - payload（= finding payload）の additional_info.file_marker_excerpt
          を取得する。
        - 空/空白のみ/正規化後に _MIN_EXCERPT_MATCH_LENGTH 未満 → None
          （excerpt 経路では matched にしない・fail-closed）。
        - ガード通過時のみ、再送本文（空白正規化）への再出現で
          "file_content_leak" を返す。本文経路のみ（_NON_BODY_MARKERS /
          _HEADER_OBSERVABLE_MARKERS には入れない）。
        """
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            info = {}
        excerpt = str(info.get("file_marker_excerpt") or "")
        if not excerpt.strip():
            return None
        normalized_excerpt = _collapse_whitespace(excerpt)
        if len(normalized_excerpt) < _MIN_EXCERPT_MATCH_LENGTH:
            return None
        if normalized_excerpt in _collapse_whitespace(body):
            return "file_content_leak"
        return None

    def _check_external_redirect_replay(
        self, payload: dict, status: int, location: str
    ) -> ReproductionOutcome:
        """external_redirect (open_redirect) の再現照合: 再送応答の 3xx と
        Location ヘッダで、元 Finding の攻撃者ホスト再出現 + 外部（対象
        自身のホストでない）を確認する（fail-closed・payout_grade と同一
        意味論を共有ヘルパーで利用）。

        - 3xx かつ攻撃者ホスト再出現（外部）→ matched
        - 応答あり・非再出現 → mismatched（唯一の mismatch 経路）
        """
        if status not in _REDIRECT_STATUSES:
            return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        self_url = str(evidence.get("request_url") or "").strip()
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            info = {}
        if _external_redirect_observed(
            info=info, location=location, self_url=self_url
        ):
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:external_redirect"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_cors_replay(
        self, payload: dict, url: str
    ) -> ReproductionOutcome:
        """cors_credentialed_reflection (CORS) の再現照合 (SGK-2026-0475)。

        元 Finding の additional_info.test_origin を Origin ヘッダに付けた
        封印 GET を対象 URL へ再送し（元 evidence.request_headers の
        Origin 以外のヘッダ＝認証情報があれば併せて付与）、再送応答の
        ACAO が test_origin にホスト一致で反映 かつ ACAC が真なら matched。

        - matched: 反映＋ACAC true（reproduction_marker_matched:...）
        - mismatched: 応答あり・非反映/ACAC 非真（唯一の mismatch 経路）
        - not_run: client None / 送信不能 / 例外（fail-closed 不変）
        """
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            info = {}
        test_origin = str(info.get("test_origin") or "").strip()
        if not test_origin:
            # 再送に必要な Origin が無い → 送信しない（fail-closed）
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        headers: dict = {"Origin": test_origin}
        request_headers = evidence.get("request_headers")
        if isinstance(request_headers, dict):
            for key, value in request_headers.items():
                if str(key).lower() != "origin":
                    headers[str(key)] = str(value)
        try:
            status, acao, acac = self._send_get_cors(url, headers=headers)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1  # 再送試行は予算を消費
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1  # 再送試行は予算を消費
        if status <= 0:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self_url = str(evidence.get("request_url") or "")
        if (
            _acao_reflects_test_origin(
                acao=acao, test_origin=test_origin, self_url=self_url
            )
            and acac.lower() == "true"
        ):
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:cors_credentialed_reflection"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _send_get_cors(self, url: str, *, headers: dict) -> Tuple[int, str, str]:
        """Send ONE sealed Origin-carrying GET through the injected client
        (same sync/async branching as ``_send_get``; ``_send_get`` itself
        stays untouched for the other body-marker paths). Returns
        ``(status, acao, acac)``."""
        request = getattr(self._network_client, "request", None)
        if request is None:
            raise RuntimeError("network client has no request()")
        if inspect.iscoroutinefunction(request):
            return _sync_http_get_with_origin(
                url, headers=headers, timeout_seconds=self._timeout_seconds
            )
        resp = request(
            "GET",
            url,
            headers=headers,
            use_cache=False,
            retries=0,
            auto_waf_bypass=False,
            allow_redirects=False,
            timeout=int(self._timeout_seconds),
            use_proxy=True,
        )
        acao, acac = _extract_cors_headers(resp)
        status = int(getattr(resp, "status", 0) or 0)
        return status, acao, acac

    def _check_jwt_forgery_replay(
        self, payload: dict, url: str
    ) -> ReproductionOutcome:
        """jwt_forgery_accepted (JWT alg=none 偽造受理) の再現照合 (SGK-2026-0476)。

        元 Finding の additional_info.forged_token を ``Authorization: Bearer``
        と ``Cookie: token=`` に付けた封印 GET を対象 URL（＝元
        evidence.request_url・forged 送信先 auth_endpoint）へ再送し、再送応答
        本文に forged_identity（エンジン fabricate 値）が再出現すれば matched。

        - matched: forged_identity 再出現（reproduction_marker_matched:...）
        - mismatched: 応答あり・非再出現（唯一の mismatch 経路）
        - not_run: client None / forged_token・forged_identity 欠落 / 送信不能
          （fail-closed 不変）
        """
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            info = {}
        forged_token = str(info.get("forged_token") or "").strip()
        forged_identity = str(info.get("forged_identity") or "").strip()
        if not forged_token or not forged_identity:
            # 再送に必要な偽造トークン/identity が無い → 送信しない（fail-closed）
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        headers: dict = {
            "Authorization": f"Bearer {forged_token}",
            "Cookie": f"token={forged_token}",
        }
        try:
            status, body = self._send_get_jwt(url, headers=headers)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1  # 再送試行は予算を消費
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1  # 再送試行は予算を消費
        if status <= 0:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if forged_identity in body:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:jwt_forgery_accepted"
            )
        # 応答あり・forged_identity 非再出現 → mismatched（唯一の mismatch 経路）
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _send_get_jwt(self, url: str, *, headers: dict) -> Tuple[int, str]:
        """Send ONE sealed forged-token GET through the injected client (same
        sync/async branching as ``_send_get``/``_send_get_cors``; the existing
        body-marker send paths stay untouched). Returns ``(status, body)``."""
        request = getattr(self._network_client, "request", None)
        if request is None:
            raise RuntimeError("network client has no request()")
        if inspect.iscoroutinefunction(request):
            return _sync_http_get_with_headers(
                url, headers=headers, timeout_seconds=self._timeout_seconds
            )
        resp = request(
            "GET",
            url,
            headers=headers,
            use_cache=False,
            retries=0,
            auto_waf_bypass=False,
            allow_redirects=False,
            timeout=int(self._timeout_seconds),
            use_proxy=True,
        )
        body = getattr(resp, "body", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        status = int(getattr(resp, "status", 0) or 0)
        return status, str(body)

    def _check_file_upload_retrieval(
        self, payload: dict, info: dict
    ) -> ReproductionOutcome:
        """uploaded_file_retrieved (file_upload) の再現照合 (SGK-2026-0480)。

        アップロードは POST（書き込み）であり封印再送の対象ではないため、
        元 Finding の additional_info.file_upload_evidence.retrieval_url へ
        **純 GET 再読**し、記録済み retrieval_marker（実行毎の一意マーカー）
        が再送応答本文に再出現すれば matched。

        - matched: retrieval_marker 再出現（reproduction_marker_matched:...）
        - mismatched: 応答あり・非再出現（唯一の mismatch 経路）
        - not_run: client None / retrieval_url・retrieval_marker 欠落 /
          masked URL 復元不能 / GET-only 拒否 / scope 再検証不可 / 送信不能・
          例外 / 空応答（fail-closed・mismatch にしない）
        """
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        upload_evidence = info.get("file_upload_evidence")
        if not isinstance(upload_evidence, dict):
            # 再現に必要な記述子が無い → 送信しない（fail-closed）
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        retrieval_url = str(upload_evidence.get("retrieval_url") or "").strip()
        retrieval_marker = str(upload_evidence.get("retrieval_marker") or "").strip()
        if not retrieval_url or not retrieval_marker:
            # 再現に必要な記述子が無い → 送信しない（fail-closed）
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        # masked URL 復元（0439 token_map restore）— 復元不能なら送信しない。
        resolved_url = self._resolve_url(retrieval_url)
        if resolved_url is None:
            return ReproductionOutcome("not_run", _REASON_MASKED_URL_UNRESOLVABLE)
        # GET-only probe（再読は常に GET）。
        if not assert_read_only_probe("GET", resolved_url):
            return ReproductionOutcome("not_run", _REASON_READ_ONLY_PROBE_REJECTED)
        # read-only guard: state-changing semantics on a GET are excluded
        # （既存 dom/cors 経路と同じガードを踏襲）。
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
        # scope revalidation against the SEALED scope snapshot.
        scope_result = revalidate_scope_for_request(
            resolved_url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        try:
            body, status, _location = self._send_get(resolved_url)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1  # 再送試行は予算を消費
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1  # 再送試行は予算を消費
        if status <= 0 or not body:
            # 応答なし/異常/空 → not_run（mismatch にしない・fail-closed）
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if retrieval_marker in body:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:uploaded_file_retrieved"
            )
        # 応答あり・マーカー非再出現 → mismatched（唯一の mismatch 経路）
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _command_replay_descriptor(self, payload: dict) -> Optional[dict]:
        """additional_info.command_replay の検証済みコピー（無効なら None）。

        - readonly_command が読み取り専用許可リスト（id/whoami/uname/pwd/
          hostname/groups）に含まれること。
        - method が GET 系でないこと（GET 系 in-band は従来の GET 再送で
          再現できるため、この専用パスは使わない）。
        - body_params が非空 dict、url/content_type が非空文字列、
          content_type が form-urlencoded であること。

        検証を満たさない記述子は None → check() は従来の GET-only 経路へ
        フォールバックする（fail-closed・POST 再送しない）。
        """
        info = payload.get("additional_info")
        if not isinstance(info, dict):
            return None
        replay = info.get("command_replay")
        if not isinstance(replay, dict):
            return None
        readonly_command = str(replay.get("readonly_command") or "").strip()
        if readonly_command not in _READONLY_COMMANDS:
            return None
        method = str(replay.get("method") or "").strip().upper()
        if method in {"", "GET", "HEAD", "OPTIONS"}:
            return None
        body_params = replay.get("body_params")
        if not isinstance(body_params, dict) or not body_params:
            return None
        url = str(replay.get("url") or "").strip()
        content_type = str(replay.get("content_type") or "").strip()
        if not url or content_type != _FORM_CONTENT_TYPE:
            return None
        return {
            "method": method,
            "url": url,
            "body_params": {str(key): value for key, value in body_params.items()},
            "readonly_command": readonly_command,
            "content_type": content_type,
        }

    def _check_command_execution_replay(
        self, payload: dict, url: str, replay: dict
    ) -> ReproductionOutcome:
        """command_execution の専用再現パス（SGK-2026-0478・POST フォーム）。

        元 Finding の command_replay 記述子（読み取り専用コマンド限定）に
        従い、元 method（POST 等）＋ body_params（注入を含むフォーム値
        一式）で同一フォームを再送し、再送応答本文に _CMD_INDICATORS
        （uid= 等）が再出現すれば matched。

        - matched: 本文指標再出現（reproduction_marker_matched:command_execution）
        - mismatched: 応答あり・非再出現（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          空応答 / 送信不能・例外（fail-closed 不変）
        """
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        # 封印スコープは専用パスでも再検証する（GET-only ガードより前に
        # 分岐するため、ここで封印 fail-closed を維持する）。
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        # request identity: 再送 method は元 finding の evidence.request_method
        # と一致しなければ送信しない（従来 GET 経路の fingerprint 契約と同義）。
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""),
            url,
            param_names,
        )
        replay_fp = build_request_fingerprint(replay["method"], url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        # 認証ヘッダ/Cookie は元 evidence.request_headers を再利用
        # （_check_cors_replay と同一契約）。長さ/転送系ヘッダは再送に
        # 不要なため含めない。
        headers: dict = {}
        request_headers = evidence.get("request_headers")
        if isinstance(request_headers, dict):
            for key, value in request_headers.items():
                if str(key).lower() not in {
                    "content-length",
                    "transfer-encoding",
                    "host",
                    "connection",
                }:
                    headers[str(key)] = str(value)
        headers.setdefault("Content-Type", replay["content_type"])
        try:
            status, body = self._send_post_form(
                replay["method"],
                url,
                data=replay["body_params"],
                headers=headers,
            )
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1  # 再送試行は予算を消費
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1  # 再送試行は予算を消費
        if status <= 0:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if not body:
            # 空応答は判定不能（mismatch にしない・fail-closed）
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        fired = _detect_marker_in_response("command_execution", body)
        if fired is not None:
            return ReproductionOutcome(
                "matched", f"reproduction_marker_matched:{fired}"
            )
        # 応答あり・同一カテゴリの発火マーカー非検出 → mismatched（唯一の
        # mismatch 経路）
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _send_post_form(
        self, method: str, url: str, *, data: dict, headers: dict
    ) -> Tuple[int, str]:
        """Send ONE sealed form POST through the injected client (same
        sync/async branching as ``_send_get_cors``/``_send_get_jwt``; the
        existing body-marker send paths stay untouched). Returns
        ``(status, body)``."""
        request = getattr(self._network_client, "request", None)
        if request is None:
            raise RuntimeError("network client has no request()")
        if inspect.iscoroutinefunction(request):
            return _sync_http_post_form(
                url, data=data, headers=headers, timeout_seconds=self._timeout_seconds
            )
        resp = request(
            method,
            url,
            data=data,
            headers=headers,
            use_cache=False,
            retries=0,
            auto_waf_bypass=False,
            allow_redirects=False,
            timeout=int(self._timeout_seconds),
            use_proxy=True,
        )
        body = getattr(resp, "body", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        status = int(getattr(resp, "status", 0) or 0)
        return status, str(body)

    def _check_inband_ssrf_replay(
        self, payload: dict, info: dict
    ) -> ReproductionOutcome:
        """in-band SSRF の専用再現パス（SGK-2026-0482・POST(JSON) 再送）。

        元 Finding の ssrf_inband_replay 記述子に従い、トリガとなる元 POST を
        同一 body（URL 値フィールドに probe_url を含む）で再送し、応答に取得
        本文が in-band 反映される（reflect_key 値が再び非空）なら matched。

        - matched: reflect_key 値の再出現（reproduction_marker_matched:ssrf_inband）
        - mismatched: 応答あり・反映非再出現（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          記述子不正 / 空応答・送信不能（fail-closed 不変）
        """
        replay = info.get("ssrf_inband_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        method = str(replay.get("method") or "").strip().upper()
        url = str(replay.get("url") or "").strip()
        body = replay.get("body")
        reflect_key = str(replay.get("reflect_key") or "").strip()
        if method in {"", "GET", "HEAD", "OPTIONS"} or not url or not isinstance(body, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        # 封印スコープはトリガ先（in-scope endpoint）で再検証する。
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""), url, param_names
        )
        replay_fp = build_request_fingerprint(method, url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        headers: dict = {}
        request_headers = evidence.get("request_headers")
        if isinstance(request_headers, dict):
            for key, value in request_headers.items():
                if str(key).lower() not in {
                    "content-length", "transfer-encoding", "host", "connection",
                }:
                    headers[str(key)] = str(value)
        headers.setdefault("Content-Type", "application/json")
        try:
            status, resp_body = self._send_post_json(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0 or not resp_body:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        reflected = ""
        if reflect_key:
            try:
                parsed = json.loads(resp_body)
                value = parsed.get(reflect_key) if isinstance(parsed, dict) else None
                if value is not None:
                    reflected = value if isinstance(value, str) else json.dumps(value)
            except (ValueError, TypeError):
                reflected = ""
        else:
            reflected = resp_body
        if reflected.strip():
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:ssrf_inband"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_graphql_exposure_replay(
        self, payload: dict, info: dict
    ) -> ReproductionOutcome:
        """GraphQL 認可欠陥の専用再現パス（SGK-2026-0484・POST(JSON) 再送）。

        元 Finding の graphql_bola_replay 記述子に従い、トリガとなる GraphQL
        クエリ(JSON POST・body に query を持つ)を封印スコープ内の endpoint へ
        1 回再送し、応答 JSON に期待する機微フィールドキー(reflect_fields)が
        再出現すれば matched。ライブ再取得本文は照合のみで非永続。

        - matched: reflect_fields のいずれかのキーが応答に再出現
          （reproduction_marker_matched:graphql_sensitive_exposed）
        - mismatched: 応答あり・機微フィールド非再出現（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          記述子不正 / 空応答・送信不能（fail-closed 不変）
        """
        replay = info.get("graphql_bola_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        method = str(replay.get("method") or "").strip().upper()
        url = str(replay.get("url") or "").strip()
        body = replay.get("body")
        reflect_fields = replay.get("reflect_fields")
        if (
            method in {"", "GET", "HEAD", "OPTIONS"}
            or not url
            or not isinstance(body, dict)
            or not isinstance(reflect_fields, (list, tuple))
            or not reflect_fields
        ):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        # 封印スコープはトリガ先（in-scope endpoint）で再検証する。
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""), url, param_names
        )
        replay_fp = build_request_fingerprint(method, url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        headers: dict = {}
        request_headers = evidence.get("request_headers")
        if isinstance(request_headers, dict):
            for key, value in request_headers.items():
                if str(key).lower() not in {
                    "content-length", "transfer-encoding", "host", "connection",
                }:
                    headers[str(key)] = str(value)
        headers.setdefault("Content-Type", "application/json")
        try:
            status, resp_body = self._send_post_json(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0 or not resp_body:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        # 応答 JSON に機微フィールドキーが再出現するかを照合する。まず JSON
        # として解析しキーの実在を確認（構造ベース）。解析不能時は生本文への
        # 文字列包含にフォールバック（fail-closed 側は変えない）。
        observed = self._graphql_fields_present(resp_body, reflect_fields)
        if observed:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:graphql_sensitive_exposed"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_ssti_replay(self, payload: dict, info: dict) -> ReproductionOutcome:
        """SSTI の専用再現パス（SGK-2026-0485）。

        元 Finding の ssti_replay 記述子に従い、確定済み算術テンプレート
        ペイロードを封印スコープ内へ 1 回だけ再送し、応答本文に期待積
        expected（"49<marker>" 等）が再出現すれば matched。GET はテンプレート
        評価＝読み取りのみ（状態変更なし）。POST は非破壊フォーム再送に限る。

        - matched: expected の再出現（reproduction_marker_matched:template_evaluated）
        - mismatched: 応答あり・expected 非再出現（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          記述子不正 / 空応答・送信不能（fail-closed 不変）
        """
        replay = info.get("ssti_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        method = str(replay.get("method") or "").strip().upper()
        url = str(replay.get("url") or "").strip()
        expected = str(replay.get("expected") or "").strip()
        replay_param = str(replay.get("param") or "").strip()
        replay_payload = str(replay.get("payload") or "")
        if not url or not expected or method not in {"GET", "POST"}:
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if method == "POST" and not replay_param:
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        resolved_url = self._resolve_url(url)
        if resolved_url is None:
            return ReproductionOutcome("not_run", _REASON_MASKED_URL_UNRESOLVABLE)
        scope_result = revalidate_scope_for_request(
            resolved_url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(resolved_url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""), resolved_url, param_names
        )
        replay_fp = build_request_fingerprint(method, resolved_url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        try:
            if method == "GET":
                resp_body, status, _loc = self._send_get(resolved_url)
            else:
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                status, resp_body = self._send_post_form(
                    "POST", resolved_url,
                    data={replay_param: replay_payload}, headers=headers,
                )
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0 or not resp_body:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if expected in resp_body:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:template_evaluated"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_nosql_replay(self, payload: dict, info: dict) -> ReproductionOutcome:
        """NoSQL 演算子注入の専用再現パス（SGK-2026-0487）。

        元 Finding の nosql_replay 記述子に従い、確定済みの演算子ペイロード
        （JSON body）を封印スコープ内へ 1 回だけ再送し、演算子が再び成功
        （2xx＋実データ）することを再観測する。演算子成功×無効リテラル失敗の
        差分は元 finding で確定済み（payout_grade が両者を検証）。認証付き
        エンドポイントの再送は evidence.request_headers（実 auth）を用いる。

        - matched: 演算子が再び成功（reproduction_marker_matched:nosql_operator_injection）
        - mismatched: 応答あり・演算子が成功しない（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          記述子不正（演算子なし含む）/ 空応答・送信不能（fail-closed）
        """
        replay = info.get("nosql_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        method = str(replay.get("method") or "").strip().upper()
        url = str(replay.get("url") or "").strip()
        body = replay.get("body")
        if (
            method != "POST"
            or not url
            or not isinstance(body, dict)
            or not _NOSQL_OPERATOR_PATTERN.search(json.dumps(body))
        ):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""), url, param_names
        )
        replay_fp = build_request_fingerprint(method, url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        headers: dict = {}
        request_headers = evidence.get("request_headers")
        if isinstance(request_headers, dict):
            for key, value in request_headers.items():
                if str(key).lower() not in {
                    "content-length", "transfer-encoding", "host", "connection",
                }:
                    headers[str(key)] = str(value)
        headers.setdefault("Content-Type", "application/json")
        try:
            status, resp_body = self._send_post_json(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if _nosql_body_has_data(status, resp_body):
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:nosql_operator_injection"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_mass_assignment_replay(self, payload: dict, info: dict) -> ReproductionOutcome:
        """Mass Assignment の専用再現パス（SGK-2026-0488）。

        元 Finding の mass_assignment_replay 記述子に従い、確定済みの injection
        ボディ（未使用の fresh 値を予約済み・JSON body）を封印スコープ内へ 1 回だけ
        再送し、応答の同名フィールドが再び攻撃者値（expected_value）になることを
        再観測する。injection 反映×control 既定値の差分は元 finding で確定済み
        （payout_grade が両者を検証）。authed 対象は evidence.request_headers を用いる。

        - matched: 応答の field が再び expected_value
          （reproduction_marker_matched:privileged_field_assigned）
        - mismatched: 応答あり・field が expected_value にならない（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          記述子不正 / 非2xx・空応答・送信不能（fail-closed）
        """
        replay = info.get("mass_assignment_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        method = str(replay.get("method") or "").strip().upper()
        url = str(replay.get("url") or "").strip()
        body = replay.get("body")
        field = str(replay.get("field") or "").strip()
        expected_value = str(replay.get("expected_value") or "").strip()
        if (
            method != "POST"
            or not url
            or not isinstance(body, dict)
            or not field
            or not expected_value
        ):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""), url, param_names
        )
        replay_fp = build_request_fingerprint(method, url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        headers: dict = {}
        request_headers = evidence.get("request_headers")
        if isinstance(request_headers, dict):
            for key, value in request_headers.items():
                if str(key).lower() not in {
                    "content-length", "transfer-encoding", "host", "connection",
                }:
                    headers[str(key)] = str(value)
        headers.setdefault("Content-Type", "application/json")
        try:
            status, resp_body = self._send_post_json(method, url, body=body, headers=headers)
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if not (200 <= status < 300):
            return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)
        # フィールド読取・正規化はエンジンと同一ロジックを再利用（確定時と一貫）。
        from src.core.agents.swarm.injection.smart_mass_assignment import (
            _read_field as _ma_read_field,
            _norm as _ma_norm,
        )
        present, value = _ma_read_field(resp_body, field)
        if present and _ma_norm(value) == expected_value:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:privileged_field_assigned"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_race_replay(self, payload: dict, info: dict) -> ReproductionOutcome:
        """Race Condition（TOCTOU）の専用再現パス（SGK-2026-0489）。

        race_replay 記述子に従い、**新しい一意マーカー**を trigger に埋め、封印スコープ内で
        並列バーストを1シーケンス再実行し、observe 応答に新マーカーが再出現することを
        再観測する。race は単発再送では再現できないため burst 再現が正当（並列は
        ThreadPoolExecutor・concurrency/rounds は上限クランプ・trigger/observe/reset の
        各 URL をスコープ再検証・GET 限定）。

        - matched: 新マーカーが observe 応答（2xx）に出現
        - mismatched: バースト完了・新マーカーが出ない（唯一の mismatch 経路）
        - not_run: client None / スコープ外 / 記述子不正 / GET 以外 / 送信不能（fail-closed）
        """
        import uuid as _uuid
        import concurrent.futures as _cf
        from urllib.parse import urlencode as _urlencode, urlunsplit as _urlunsplit

        replay = info.get("race_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        observe = replay.get("observe")
        trigger = replay.get("trigger")
        reset = replay.get("reset")
        if not (isinstance(observe, dict) and isinstance(trigger, dict)):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        obs_url = str(observe.get("url") or "").strip()
        trg_url = str(trigger.get("url") or "").strip()
        obs_method = str(observe.get("method") or "GET").strip().upper()
        trg_method = str(trigger.get("method") or "GET").strip().upper()
        if not obs_url or not trg_url or obs_method != "GET" or trg_method != "GET":
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        reset_url = ""
        if isinstance(reset, dict):
            reset_url = str(reset.get("url") or "").strip()
        for u in [obs_url, trg_url] + ([reset_url] if reset_url else []):
            if not revalidate_scope_for_request(
                u, scope_definition=self._scope_definition
            ).allowed:
                return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        concurrency = max(1, min(12, int(replay.get("concurrency") or 8)))
        rounds = max(1, min(40, int(replay.get("rounds") or 10)))
        marker = "SHIGOKU_RACE_" + _uuid.uuid4().hex[:12]

        def _full(base_url: str, params: Any) -> str:
            subst = {
                k: (v.replace("{marker}", marker) if isinstance(v, str) else v)
                for k, v in (params if isinstance(params, dict) else {}).items()
            }
            parts = urlsplit(base_url)
            q = dict(parse_qsl(parts.query, keep_blank_values=True))
            q.update({k: str(v) for k, v in subst.items()})
            return _urlunsplit(
                (parts.scheme, parts.netloc, parts.path, _urlencode(q), parts.fragment)
            )

        trg_full = _full(trg_url, trigger.get("params"))
        obs_full = _full(obs_url, observe.get("params"))
        reset_full = _full(reset_url, reset.get("params")) if reset_url else None

        hit = False
        try:
            for _ in range(rounds):
                if reset_full:
                    try:
                        self._send_get(reset_full)
                    except Exception:  # noqa: BLE001 — transport boundary, tolerate
                        pass
                    self._replays_used += 1
                with _cf.ThreadPoolExecutor(max_workers=concurrency * 2) as ex:
                    obs_futs = []
                    all_futs = []
                    for _ in range(concurrency):
                        all_futs.append(ex.submit(self._send_get, trg_full))
                        f = ex.submit(self._send_get, obs_full)
                        obs_futs.append(f)
                        all_futs.append(f)
                    _cf.wait(all_futs, timeout=self._timeout_seconds)
                self._replays_used += concurrency * 2
                for f in obs_futs:
                    if not f.done():
                        continue
                    try:
                        body, status, _loc = f.result()
                    except Exception:  # noqa: BLE001 — per-request failure, skip
                        continue
                    if marker in str(body) and 200 <= int(status) < 300:
                        hit = True
                        break
                if hit:
                    break
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)

        if hit:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:race_condition_toctou"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_host_header_replay(self, payload: dict, info: dict) -> ReproductionOutcome:
        """Host Header Injection（認可バイパス）の専用再現パス（SGK-2026-0491）。

        host_header_replay 記述子（url/header/value/signature）に従い、注入ヘッダを付けた
        封印 GET を対象 URL へ 1 回再送し、制限署名が 2xx 応答に再出現すれば matched。
        GET＋任意ヘッダ送信は既存の汎用ヘッダ GET 経路（_send_get_jwt）を流用する
        （jwt 固有処理は無く、任意 headers をそのまま送るだけ）。

        - matched: 制限署名が 2xx 応答に再出現
        - mismatched: 応答あり・署名非再出現（唯一の mismatch 経路）
        - not_run: client None / スコープ外 / 記述子不正 / 送信不能（fail-closed）
        """
        replay = info.get("host_header_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        url = str(replay.get("url") or "").strip()
        header = str(replay.get("header") or "").strip()
        value = str(replay.get("value") or "").strip()
        signature = str(replay.get("signature") or "").strip()
        if not url or not header or not value or not signature:
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        scope_result = revalidate_scope_for_request(
            url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        try:
            status, body = self._send_get_jwt(url, headers={header: value})
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if signature in str(body) and 200 <= int(status) < 300:
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:host_header_auth_bypass"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    def _check_xxe_replay(self, payload: dict, info: dict) -> ReproductionOutcome:
        """XXE の専用再現パス（SGK-2026-0486）。

        元 Finding の xxe_replay 記述子に従い、確定済みの外部実体ペイロードを
        封印スコープ内へ 1 回だけ再送（form パラメータ or 生 XML ボディ）し、
        応答本文にシステムファイルの署名（_XXE_FILE_PATTERNS）が再出現すれば
        matched。ファイル読み取りは非破壊（読み取りのみ）。ライブ再取得本文は
        照合のみで非永続。

        - matched: ファイル署名の再出現（reproduction_marker_matched:xxe_file_read）
        - mismatched: 応答あり・署名非再出現（唯一の mismatch 経路）
        - not_run: client None / スコープ再検証不可 / fingerprint 不一致 /
          記述子不正（外部実体なし含む）/ 空応答・送信不能（fail-closed）
        """
        replay = info.get("xxe_replay")
        if not isinstance(replay, dict):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        method = str(replay.get("method") or "").strip().upper()
        url = str(replay.get("url") or "").strip()
        payload_xml = str(replay.get("payload") or "")
        param = replay.get("param")
        content_type = str(replay.get("content_type") or "application/xml")
        # 外部実体を含まないペイロードは再送しない（fail-closed）。
        if method != "POST" or not url or not _XXE_ENTITY_PATTERN.search(payload_xml):
            return ReproductionOutcome("not_run", _REASON_UNKNOWN_CATEGORY)
        if self._network_client is None:
            return ReproductionOutcome("not_run", _REASON_DISABLED_NO_CLIENT)
        resolved_url = self._resolve_url(url)
        if resolved_url is None:
            return ReproductionOutcome("not_run", _REASON_MASKED_URL_UNRESOLVABLE)
        scope_result = revalidate_scope_for_request(
            resolved_url, scope_definition=self._scope_definition
        )
        if not scope_result.allowed:
            return ReproductionOutcome("not_run", _REASON_SCOPE_REVALIDATION_BLOCKED)
        evidence = payload.get("evidence")
        if not isinstance(evidence, dict):
            evidence = {}
        param_names = _param_names_from_url(resolved_url)
        original_fp = build_request_fingerprint(
            str(evidence.get("request_method") or ""), resolved_url, param_names
        )
        replay_fp = build_request_fingerprint(method, resolved_url, param_names)
        if original_fp != replay_fp:
            return ReproductionOutcome("not_run", _REASON_REQUEST_FINGERPRINT_MISMATCH)
        headers = {"Content-Type": content_type}
        data: Any = {str(param): payload_xml} if param else payload_xml
        try:
            status, resp_body = self._send_post_form(
                "POST", resolved_url, data=data, headers=headers,
            )
        except Exception:  # noqa: BLE001 — transport boundary, fail closed
            self._replays_used += 1
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        self._replays_used += 1
        if status <= 0 or not resp_body:
            return ReproductionOutcome("not_run", _REASON_TRANSPORT_ERROR)
        if any(p.search(resp_body) for p in _XXE_FILE_PATTERNS):
            return ReproductionOutcome(
                "matched", "reproduction_marker_matched:xxe_file_read"
            )
        return ReproductionOutcome("mismatched", _REASON_MARKER_MISMATCH)

    @staticmethod
    def _graphql_fields_present(resp_body: str, reflect_fields: Any) -> bool:
        """True iff any reflect_field key appears in the GraphQL JSON response
        (structural key check; falls back to substring on parse failure)."""
        fields = [str(f) for f in reflect_fields if str(f)]
        if not fields:
            return False

        def _walk(node: Any) -> bool:
            if isinstance(node, dict):
                for key, value in node.items():
                    if key in fields:
                        return True
                    if _walk(value):
                        return True
            elif isinstance(node, list):
                for item in node:
                    if _walk(item):
                        return True
            return False

        try:
            parsed = json.loads(resp_body)
            if _walk(parsed):
                return True
        except (ValueError, TypeError):
            pass
        return any(f in resp_body for f in fields)

    def _send_post_json(
        self, method: str, url: str, *, body: dict, headers: dict
    ) -> Tuple[int, str]:
        """Send ONE sealed JSON POST through the injected client (same
        sync/async branching as ``_send_post_form``). Returns ``(status, body)``."""
        request = getattr(self._network_client, "request", None)
        if request is None:
            raise RuntimeError("network client has no request()")
        payload_text = json.dumps(body)
        if inspect.iscoroutinefunction(request):
            return _sync_http_post_json(
                url, data=payload_text, headers=headers,
                timeout_seconds=self._timeout_seconds,
            )
        resp = request(
            method, url, data=payload_text, headers=headers,
            use_cache=False, retries=0, auto_waf_bypass=False,
            allow_redirects=False, timeout=int(self._timeout_seconds), use_proxy=True,
        )
        resp_body = getattr(resp, "body", "") or getattr(resp, "text", "") or ""
        if isinstance(resp_body, bytes):
            resp_body = resp_body.decode("utf-8", errors="replace")
        status = int(getattr(resp, "status", 0) or 0)
        return status, str(resp_body)

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
        """DOM/stored-variant sealed reproduction: ONE real-browser re-load
        of the PoC/revisit test_url with re-observation of the alert()
        dialog (fail-closed).

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
        if (
            evidence_marker in _BODY_OBSERVABLE_MARKERS
            or evidence_marker in _NON_BODY_MARKERS
            or evidence_marker in _HEADER_OBSERVABLE_MARKERS
        ):
            return evidence_marker
        vuln_type = str(payload.get("vuln_type") or "").strip().lower()
        return _MARKER_CATEGORIES.get(vuln_type)

    def _send_get(self, url: str) -> Tuple[str, int, str]:
        """Send ONE sealed GET through the injected client.

        A synchronously-callable client ``request`` is used directly with
        the executor send contract kwargs. An async client (coroutine
        function) cannot be awaited from the synchronous Protocol
        (run_until_complete/asyncio.run forbidden) — the existing
        synchronous requests pattern is used instead. Returns
        ``(body, status, location)``.
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
