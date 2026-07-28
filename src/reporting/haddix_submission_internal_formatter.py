"""
HaddixSubmissionInternalFormatter: submission/internal split formatter.

Implements SGK-2026-0345 P0 — split a Haddix-style vulnerability report into:

1. ``# 提出用レポート / Submission Report`` — the Bug Bounty submission copy scope.
   Contains only confirmed findings rendered in Japanese.

2. ``# 内部評価（私用） / Internal Review Notes`` — internal QA/ops material
   (execution notes, scenario coverage, family gate, initial release gate,
   submission readiness diagnostics, non-submission candidates, third-party
   review memo).

3. ``# Report`` — an English-only copy scope for external submission.

The formatter subclasses :class:`HaddixFormatter` to reuse the canonical
finding splitting, evidence template, severity emoji, and reason-code helpers
without duplicating that business logic. Only the section layout and per-finding
language rendering are added here.

Machine-readable compatibility is preserved so existing tooling keeps working:

* ``**Generated:**`` / ``**Source Session:**`` header lines are still emitted
  (consistency checker regex match).
* ``Coverage: X/Y (Z%), Missing: ...`` scenario-coverage line stays in the
  internal section (consistency checker regex match, searched anywhere).
* ``Gate: PASS|FAIL, Coverage: ...`` family-gate line stays in the internal
  section (initial-release gate regex match).
* ``Confirmed: X / Candidate: Y`` and the PoC / reason-code counters stay in
  the Submission Readiness Diagnostics section (initial-release gate regex
  match).

This formatter is the canonical ``haddix`` report renderer. The
``haddix-submission-internal`` CLI format remains as a backwards-compatible
alias for callers that already selected the split renderer explicitly.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from zoneinfo import ZoneInfo
except Exception:  # pragma: no cover - fallback only
    ZoneInfo = None

from src.reporting.haddix_evidence_quality import (
    HaddixEvidenceQualityValidator,
    EvidenceVerdict,
    redact_raw_request,
    redact_raw_response,
)
from src.reporting.haddix_formatter import (
    HaddixFinding,
    HaddixFormatter,
    MODULE_TIME_BUDGETS,
    SLOW_PROBE_THRESHOLD_SECONDS,
    PROBE_STATE_EXECUTED,
    PROBE_STATE_INSTRUMENTATION_MISSING,
    PROBE_STATE_NOT_APPLICABLE,
    PROBE_STATE_NOT_DISCOVERED,
    PROBE_STATE_SKIPPED,
    build_finding_memo_map,
)


_THIRD_PARTY_REVIEW_ROWS = [
    ("R-01", "内部QAレポートとしては良いがBug Bounty提出用には弱い",
     "提出用セクションを first-class output とし、内部QA指標は後半へ隔離"),
    ("R-02", "PoC raw request に攻撃ペイロードが入っていない",
     "Evidence quality validator で payload presence を shadow 検査"),
    ("R-03", "HTTP/1.1 0 は実HTTPレスポンスではない",
     "synthetic detector note を提出用から除外し内部評価で明示"),
    ("R-04", "Blind SQLi は単発 SLEEP(3) だけでは弱い",
     "baseline/sleep/逆条件の timing evidence を validator で評価"),
    ("R-05", "Reflected XSS は反射だけでなくブラウザ実行証拠が必要",
     "browser execution evidence を validator で評価"),
    ("R-06", "Stored XSS は保存後再表示/別セッション実行 evidence が必要",
     "stored validator で posting/revisit step を評価"),
    ("R-07", "SQLi はレスポンス差分・SQLエラー・抽出結果が不足",
     "boolean/error/union/data-diff evidence を分類して評価"),
    ("R-08", "LFI は payload が実URLに出ていない",
     "request URL/query の traversal payload presence を評価"),
    ("R-09", "API unauth access は 200->200 だけでは High/confirmed が弱い",
     "unauth/auth differential と機密フィールド確認を評価"),
    ("R-10", "CSRF は tokenless と成立確認が別物",
     "forged request と before/after state を評価"),
    ("R-11", "CSRF remediation が CORS 寄りでズレている",
     "CSRF 用 remediation (token/SameSite/re-auth/origin) を使用"),
    ("R-12", "Command Injection/DOM XSS/Open Redirect/Weak Session IDs の取りこぼし",
     "本タスクでは実装せず P2 backlog として内部評価に記録"),
    ("R-13", "Severity が過大評価",
     "提出用 severity normalization は P1/P2 で別途導入"),
    ("R-14", "Coverage Gate や Baseline Diff が提出本文で前面に出すぎ",
     "本フォーマッタで内部評価側へ分離済み"),
]

_FORBIDDEN_REPRO_STEP_STRINGS = [
    "再構成してください",
    "TODO",
    "TBD",
    "manual verification required",
]


class HaddixSubmissionInternalFormatter(HaddixFormatter):
    """Submission/Internal split Haddix-style report formatter.

    Reuses :class:`HaddixFormatter` helpers for finding splitting, evidence
    template rendering, severity emoji, blind-correlation / authZ differential
    summaries, reason-code inference, and scenario/family/gate rendering.

    The submission scope contains only confirmed findings. The internal scope
    keeps all execution notes, coverage, gate, candidates, and diagnostics.
    """

    # ------------------------------------------------------------------
    # P2-2: Vulnerability class templates
    # ------------------------------------------------------------------

    _CLASS_TEMPLATES: dict = {
        "xss": {
            "expected_result_ja": "ユーザ入力がHTMLコンテキストに応じてエスケープされ、スクリプト実行に至らないこと。",
            "expected_result_en": "User input is encoded for its HTML context and script execution does not occur.",
            "remediation_ja": "ユーザー入力をコンテキストに応じてエスケープし、CSPを適用する。フレームワークの自動エスケープ機能を利用する。",
            "remediation_en": "Apply context-aware output encoding. Enforce strict Content-Security-Policy. Prefer framework-provided auto-escaping.",
            "negative_test_ja": "同一ペイロード `{payload}` を送信し、ブラウザ上でスクリプトが実行されないことを確認する。",
            "negative_test_en": "Send the same payload `{payload}` and confirm script execution does not occur in the browser.",
            "regression_test_ja": "正常なユーザー入力が引き続き正しく表示されることを確認する。",
            "regression_test_en": "Confirm legitimate user input continues to display correctly.",
        },
        "sqli": {
            "expected_result_ja": "パラメータ化クエリにより、入力値がSQL構文として解釈されないこと。",
            "expected_result_en": "Parameterized queries prevent input from being interpreted as SQL syntax.",
            "remediation_ja": "プレースホルダ付きクエリ（Prepared Statement）へ統一し、動的SQL連結を廃止する。",
            "remediation_en": "Use parameterized queries for all database access. Never concatenate user input into SQL.",
            "negative_test_ja": "同一ペイロード `{payload}` を送信し、SQLエラーやレスポンス遅延が発生しないことを確認する。",
            "negative_test_en": "Send the same payload `{payload}` and confirm no SQL errors or response delays occur.",
            "regression_test_ja": "正常なクエリパラメータでDB操作が正しく動作することを確認する。",
            "regression_test_en": "Confirm database operations with normal parameters continue to work correctly.",
        },
        "csrf": {
            "expected_result_ja": "状態変更リクエストに有効なCSRFトークンと正しいSameSite Cookieが必須となること。",
            "expected_result_en": "State-changing requests require a valid CSRF token and correct SameSite cookie.",
            "remediation_ja": "全状態変更リクエストにCSRFトークン検証とSameSite Cookie設定を適用する。Origin/Referer検証も併用する。CORS設定に依存しない。",
            "remediation_en": "Require anti-CSRF tokens on all state-changing requests, set SameSite=Strict|Lax, validate Origin/Referer. Do not rely on CORS alone.",
            "negative_test_ja": "CSRFトークンなしで状態変更リクエストを送信し、拒否される（403/Invalid Token）ことを確認する。",
            "negative_test_en": "Send a state-changing request without a CSRF token and confirm it is rejected (403/Invalid Token).",
            "regression_test_ja": "正当なCSRFトークンを含むリクエストが引き続き成功することを確認する。",
            "regression_test_en": "Confirm requests with valid CSRF tokens continue to succeed.",
        },
        "broken_access_control": {
            "expected_result_ja": "認証・認可チェックにより、権限外のリソースへのアクセスが拒否されること。",
            "expected_result_en": "Authentication and authorization checks deny access to resources outside the user's privilege scope.",
            "remediation_ja": "すべてのAPIエンドポイントで認証・認可チェックを実施する。オブジェクトレベルのアクセス制御を実装する。",
            "remediation_en": "Enforce authentication and authorization on every API endpoint. Implement object-level access control.",
            "negative_test_ja": "未認証または低権限セッションで同一リクエストを送信し、401/403が返ることを確認する。",
            "negative_test_en": "Send the same request in an unauthenticated or low-privilege session and confirm 401/403 is returned.",
            "regression_test_ja": "正当な権限で同一エンドポイントを実行し、正しく動作することを確認する。",
            "regression_test_en": "Execute the same endpoint with legitimate privileges and confirm it works correctly.",
        },
        "lfi": {
            "expected_result_ja": "パス区切り文字を含む入力が拒否またはサニタイズされ、ファイルシステムパスが解決されないこと。",
            "expected_result_en": "Inputs containing path separators are rejected or sanitized and filesystem paths are not resolved.",
            "remediation_ja": "パス区切り文字を拒否/サニタイズする。ファイルパスを許可リストに対して正規化し、意図したリソースのみを提供する。",
            "remediation_en": "Reject or sanitize path separators. Resolve file paths against an explicit allow-list and serve only intended resources.",
            "negative_test_ja": "同一ペイロード `{payload}` を送信し、ファイル内容が返らず、エラーまたは空レスポンスになることを確認する。",
            "negative_test_en": "Send the same payload `{payload}` and confirm file contents are not returned (error or empty response).",
            "regression_test_ja": "許可されたファイルパスで正しくファイルが提供されることを確認する。",
            "regression_test_en": "Confirm allowed file paths continue to serve files correctly.",
        },
        "command_injection": {
            "expected_result_ja": "OSコマンドに渡される入力値が適切にサニタイズされ、シェルメタ文字が解釈されないこと。",
            "expected_result_en": "Inputs passed to OS commands are properly sanitized and shell metacharacters are not interpreted.",
            "remediation_ja": "OSコマンド実行を避け、APIやライブラリを使用する。やむを得ない場合は入力の厳格な許可リスト検証と`exec`系ではなく`execve`系を使用する。",
            "remediation_en": "Avoid OS command execution; use APIs/libraries instead. If unavoidable, use strict allow-list input validation and execve-style (not exec-style) calls.",
            "negative_test_ja": "同一ペイロード `{payload}` を送信し、コマンド実行結果が返らないことを確認する。",
            "negative_test_en": "Send the same payload `{payload}` and confirm no command execution output is returned.",
            "regression_test_ja": "許可された入力値で正規の機能が動作することを確認する。",
            "regression_test_en": "Confirm legitimate inputs continue to work correctly.",
        },
        "open_redirect": {
            "expected_result_ja": "リダイレクト先が厳格な許可リストで検証され、外部URLへのリダイレクトが拒否されること。",
            "expected_result_en": "Redirect targets are validated against a strict allow-list and external URL redirects are rejected.",
            "remediation_ja": "リダイレクト先を許可リストで検証する。相対URLのみ許可し、絶対URL・外部URLを拒否する。",
            "remediation_en": "Validate redirect targets against an explicit allow-list. Allow only relative URLs; reject absolute and external URLs.",
            "negative_test_ja": "外部URL `{payload}` をリダイレクトパラメータに指定し、リダイレクトされない（エラー/相対パスに留まる）ことを確認する。",
            "negative_test_en": "Specify external URL `{payload}` in the redirect parameter and confirm no redirect occurs (error or stays on relative path).",
            "regression_test_ja": "許可されたリダイレクト先で正しくリダイレクトされることを確認する。",
            "regression_test_en": "Confirm allowed redirect targets continue to work correctly.",
        },
        "cors": {
            "expected_result_ja": "信頼されていないOriginに対してAccess-Control-Allow-Originヘッダを返さず、許可済みOriginのみ明示的に許可すること。",
            "expected_result_en": "Access-Control-Allow-Origin must not be returned for untrusted origins. Only explicitly allowed origins should receive the header.",
            "remediation_ja": "ACAOにワイルドカード(*)や任意Origin反射を使用せず、許可Originを明示的ホワイトリストで管理する。ACAC:trueの場合は特に厳格に制御する。",
            "remediation_en": "Maintain an explicit allow-list of trusted origins. Do not use wildcard (*) or echo untrusted origins in ACAO. When ACAC is true, this control must be especially strict.",
            "negative_test_ja": "許可リスト外のOriginでクロスオリジンリクエストを送信し、ACAOヘッダが返らないことを確認する。",
            "negative_test_en": "Send a cross-origin request with a non-allowlisted origin and confirm no ACAO header is returned.",
            "regression_test_ja": "許可リスト内のOriginでクロスオリジンリクエストを送信し、ACAOヘッダが正しく返ることを確認する。",
            "regression_test_en": "Send a cross-origin request with an allowlisted origin and confirm the correct ACAO header is returned.",
        },
        "ssrf": {
            "expected_result_ja": "許可リスト外のホストや内部アドレスへのサーバー側リクエストが拒否されること。",
            "expected_result_en": "Server-side requests to hosts outside the allow-list (including internal addresses) are rejected.",
            "remediation_ja": "URL入力を許可リスト方式で検証し、スキーム・ホスト・ポートを制限する。内部アドレスとクラウドメタデータエンドポイントを遮断する。",
            "remediation_en": "Enforce an outbound allow-list, block internal IP ranges and cloud metadata endpoints. Revalidate redirect targets with the same policy.",
            "negative_test_ja": "内部アドレス `{payload}` をURLパラメータに指定し、リクエストが拒否されることを確認する。",
            "negative_test_en": "Specify internal address `{payload}` in the URL parameter and confirm the request is rejected.",
            "regression_test_ja": "許可された外部URLへのリクエストが正しく動作することを確認する。",
            "regression_test_en": "Confirm requests to allowed external URLs continue to work correctly.",
        },
    }

    @classmethod
    def _get_template(cls, vuln_type: str) -> dict:
        """Get the class template dict for a vulnerability type.

        Uses substring matching so ``"cors_misconfiguration"`` maps to ``"cors"``.
        Returns an empty dict when no template matches.
        """
        vtype = str(vuln_type or "").strip().lower()
        for key in cls._CLASS_TEMPLATES:
            if key in vtype:
                return cls._CLASS_TEMPLATES[key]
        return {}

    def _format_template_field(
        self, vuln_type: str, field: str,
        lang: str = "ja", payload: str = "",
    ) -> str:
        """Get a template field value with ``{payload}`` substitution."""
        template = self._get_template(vuln_type)
        key = f"{field}_{lang}"
        value = template.get(key, "")
        if "{payload}" in value and payload:
            value = value.replace("{payload}", payload)
        return value

    # ------------------------------------------------------------------
    # P1-3: Reproduction steps validation and auto-generation
    # ------------------------------------------------------------------

    @staticmethod
    def _is_forbidden_step_text(text: str) -> bool:
        """Return True if *text* matches or contains any forbidden string.

        Empty strings and pure whitespace are also treated as forbidden.
        """
        text_clean = text.strip()
        if not text_clean:
            return True
        text_lower = text_clean.lower()
        for forbidden in _FORBIDDEN_REPRO_STEP_STRINGS:
            if forbidden.lower() in text_lower:
                return True
        return False

    @staticmethod
    def _validate_repro_steps(steps: List[str]) -> List[str]:
        """Return *steps* unchanged if all pass validation; return an empty
        list (fail-closed) if any step contains a forbidden string or is empty."""
        for step in steps:
            if HaddixSubmissionInternalFormatter._is_forbidden_step_text(step):
                return []
        return steps

    def _has_placeholder_steps(self, steps: List[str]) -> bool:
        """Return True if any step contains forbidden/placeholder text."""
        for step in steps:
            if self._is_forbidden_step_text(step):
                return True
        return False

    @staticmethod
    def _extract_param_from_finding(finding: HaddixFinding) -> str:
        """Extract a likely attack parameter name from the finding."""
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        tested_params = info.get("tested_params", [])
        if tested_params and isinstance(tested_params, list) and tested_params:
            return str(tested_params[0])
        url = str(finding.target_url or "")
        if "?" in url:
            query = url.split("?")[1]
            if "=" in query:
                return query.split("=")[0].split("&")[0]
        return "param"

    @staticmethod
    def _primary_payload(finding: HaddixFinding) -> str:
        """Return the first payload from the finding, or a placeholder."""
        if finding.payloads_used:
            return str(finding.payloads_used[0])
        return "(payload not recorded)"

    def _auto_generate_repro_steps(
        self, finding: HaddixFinding, lang: str = "ja",
    ) -> List[str]:
        """Generate reproduction steps for *finding* based on its vulnerability
        class when no explicit steps exist.

        *lang* controls the output language: ``"ja"`` (default) or ``"en"``.
        When the vulnerability class is unrecognised, a generic fallback
        template is returned.
        """
        target_url = self._normalize_url_string(finding.target_url)
        param = self._extract_param_from_finding(finding)
        payload = self._primary_payload(finding)
        vtype = str(finding.vuln_type or "").lower()

        if lang == "en":
            return self._auto_generate_repro_steps_en(
                vtype, target_url, param, payload, finding,
            )
        return self._auto_generate_repro_steps_ja(
            vtype, target_url, param, payload, finding,
        )

    # ---- Japanese templates ------------------------------------------------

    def _auto_generate_repro_steps_ja(
        self,
        vtype: str,
        target_url: str,
        param: str,
        payload: str,
        finding: HaddixFinding,
    ) -> List[str]:
        if "xss" in vtype or "reflected_xss" in vtype:
            return [
                f"認証済みセッションで `{target_url}` にアクセスする。",
                f"パラメータ `{param}` にペイロード `{payload}` を送信する。",
                "レスポンスHTML内でペイロードがJavaScriptとして実行されることをブラウザ上で確認する。",
            ]
        if "sqli" in vtype or "sql" in vtype:
            return [
                f"認証済みセッションで `{target_url}` にアクセスする。",
                f"パラメータ `{param}` にペイロード `{payload}` を送信する。",
                "レスポンスの遅延（timing）またはレスポンス内容の変化を確認する。",
            ]
        if "csrf" in vtype:
            return [
                "被害者のセッションCookieを取得した状態で、以下のHTMLをブラウザで開く。",
                "Forged request HTMLにおいて、状態変更リクエストが自動送信されることを確認する。",
                "対象アカウントの状態（メールアドレス等）が攻撃者の指定した値に変更されたことを確認する。",
            ]
        if "broken_access_control" in vtype or "idor" in vtype:
            return [
                f"未認証または低権限セッションで `{target_url}` にアクセスする。",
                f"パラメータ `{param}` を変更し、他ユーザーのリソースIDを指定する。",
                "レスポンスに他ユーザーの機密情報（メールアドレス、APIキー等）が含まれることを確認する。",
            ]
        if "lfi" in vtype or "path_traversal" in vtype:
            return [
                f"認証済みセッションで `{target_url}` にアクセスする。",
                f"パラメータ `{param}` にパストラバーサルペイロード `{payload}` を送信する。",
                "レスポンスに対象ファイルの内容（例: `root:x:0:0:`）が含まれることを確認する。",
            ]
        if "command_injection" in vtype or "rce" in vtype:
            return [
                f"認証済みセッションで `{target_url}` にアクセスする。",
                f"パラメータ `{param}` にコマンド注入ペイロード `{payload}` を送信する。",
                "レスポンスにコマンド実行結果が含まれること、またはレスポンス遅延を確認する。",
            ]
        if "cors" in vtype:
            return [
                f"信頼されていないOrigin（例: `https://attacker.example.com`）を含むクロスオリジンリクエストを `{target_url}` に送信する。",
                "レスポンスヘッダー `Access-Control-Allow-Origin` に送信したOriginが反射されていることを確認する。",
                "（認証情報付きの場合）`Access-Control-Allow-Credentials: true` が返されていることを確認する。",
            ]
        if "open_redirect" in vtype:
            return [
                f"`{target_url}` のリダイレクトパラメータ `{param}` に外部URL `{payload}` を指定する。",
                "`Location` ヘッダーに外部URLが設定されていること、またはブラウザが外部URLへ遷移することを確認する。",
            ]
        # generic fallback
        return [
            f"`{target_url}` にアクセスする。",
            f"パラメータ `{param}` にペイロード `{payload}` を送信する。",
            "レスポンスに脆弱性を示す証拠が含まれることを確認する。",
        ]

    # ---- English templates -------------------------------------------------

    def _auto_generate_repro_steps_en(
        self,
        vtype: str,
        target_url: str,
        param: str,
        payload: str,
        finding: HaddixFinding,
    ) -> List[str]:
        if "xss" in vtype or "reflected_xss" in vtype:
            return [
                f"Access `{target_url}` in an authenticated session.",
                f"Send payload `{payload}` via parameter `{param}`.",
                "Confirm in the browser that the payload is executed as JavaScript in the response HTML.",
            ]
        if "sqli" in vtype or "sql" in vtype:
            return [
                f"Access `{target_url}` in an authenticated session.",
                f"Send payload `{payload}` via parameter `{param}`.",
                "Check for response delay (timing) or change in response content.",
            ]
        if "csrf" in vtype:
            return [
                "Open the following HTML in a browser while holding the victim session cookie.",
                "Confirm that the forged request HTML automatically sends the state-changing request.",
                "Confirm that the target account state (email address, etc.) has been changed to the attacker-specified value.",
            ]
        if "broken_access_control" in vtype or "idor" in vtype:
            return [
                f"Access `{target_url}` with an unauthenticated or low-privilege session.",
                f"Modify parameter `{param}` to specify another user's resource ID.",
                "Confirm that the response contains another user's sensitive information (email, API key, etc.).",
            ]
        if "lfi" in vtype or "path_traversal" in vtype:
            return [
                f"Access `{target_url}` in an authenticated session.",
                f"Send path traversal payload `{payload}` via parameter `{param}`.",
                "Confirm that the response contains file contents (e.g. `root:x:0:0:`).",
            ]
        if "command_injection" in vtype or "rce" in vtype:
            return [
                f"Access `{target_url}` in an authenticated session.",
                f"Send command injection payload `{payload}` via parameter `{param}`.",
                "Confirm that the response contains command execution results or a response delay.",
            ]
        if "cors" in vtype:
            return [
                f"Send a cross-origin request to `{target_url}` with an untrusted Origin header (e.g. `https://attacker.example.com`).",
                "Confirm that the `Access-Control-Allow-Origin` response header reflects the sent Origin.",
                "(When credentials are involved) Confirm that `Access-Control-Allow-Credentials: true` is returned.",
            ]
        if "open_redirect" in vtype:
            return [
                f"Specify an external URL `{payload}` via the redirect parameter `{param}` at `{target_url}`.",
                "Confirm that the `Location` header is set to the external URL, or the browser navigates to the external URL.",
            ]
        # generic fallback
        return [
            f"Access `{target_url}`.",
            f"Send payload `{payload}` via parameter `{param}`.",
            "Confirm that the response contains evidence of the vulnerability.",
        ]

    # ------------------------------------------------------------------
    # Top-level entry point
    # ------------------------------------------------------------------

    def format_markdown(self) -> str:
        lines: List[str] = []
        lines.extend(self._format_submission_section())
        lines.extend(self._format_internal_section())
        if lines and lines[-1] != "":
            lines.append("")
        lines.extend(self._format_english_submission_section())
        return "\n".join(lines)

    def _report_generated_at(self) -> datetime:
        generated_at = getattr(self, "_cached_report_generated_at", None)
        if generated_at is None:
            generated_at = self._now_jst()
            self._cached_report_generated_at = generated_at
        return generated_at

    # ------------------------------------------------------------------
    # Enforcement-mode evidence quality split (SGK-2026-0347 P1)
    # ------------------------------------------------------------------

    def _get_enforced_split(
        self,
    ) -> tuple[List[HaddixFinding], List[HaddixFinding], List[EvidenceVerdict]]:
        """Return (enforced_confirmed, enforced_candidates, verdicts) using the
        enforcement-mode evidence quality validator. Results are cached on the
        instance so both submission and internal sections consume the same
        classification."""
        cached = getattr(self, "_cached_enforced_split", None)
        if cached is not None:
            return cached
        sorted_findings = self._sorted_findings()
        confirmed, candidates = self._split_findings_by_confirmation(sorted_findings)
        result = self._enforced_split(
            confirmed_findings=confirmed,
            candidate_findings=candidates,
        )
        self._cached_enforced_split = result
        return result

    def _enforced_split(
        self,
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> tuple[List[HaddixFinding], List[HaddixFinding], List[EvidenceVerdict]]:
        """Run the evidence quality validator in enforcement mode and return
        the reclassified (enforced_confirmed, enforced_candidates, verdicts)
        tuple. Findings that fail evidence quality requirements are demoted
        from confirmed to candidate in enforce mode.

        SGK-2026-0348: CSRF findings stored as misconfiguration in raw sessions
        are normalized to ``vuln_type="csrf"`` before the validator runs so that
        CSRF-specific proof requirements (state_change) are applied.
        """
        # --- CSRF normalization (SGK-2026-0348) ---
        for finding in confirmed_findings:
            self._normalize_submission_quality_finding(finding)
        for finding in candidate_findings:
            self._normalize_submission_quality_finding(finding)

        validator = HaddixEvidenceQualityValidator(mode="enforce")
        all_findings: List[HaddixFinding] = []
        statuses: List[str] = []
        all_findings.extend(confirmed_findings)
        statuses.extend(["confirmed"] * len(confirmed_findings))
        all_findings.extend(candidate_findings)
        statuses.extend(["candidate"] * len(candidate_findings))
        if not all_findings:
            return [], [], []
        verdicts = validator.evaluate_findings(findings=all_findings, current_statuses=statuses)

        enforced_confirmed: List[HaddixFinding] = []
        enforced_candidates: List[HaddixFinding] = []
        for idx, verdict in enumerate(verdicts):
            if verdict.effective_status == "confirmed":
                enforced_confirmed.append(all_findings[idx])
            else:
                enforced_candidates.append(all_findings[idx])
                # --- Propagate evidence-quality reason codes (SGK-2026-0348) ---
                finding = all_findings[idx]
                info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
                finding.additional_info = info
                if verdict.reason_codes:
                    info["evidence_quality_reason_codes"] = list(verdict.reason_codes)
                    # Also set as primary reason_codes so _ensure_unconfirmed_reason_codes
                    # picks them up when rendering the candidate display.
                    if not info.get("reason_codes"):
                        info["reason_codes"] = list(verdict.reason_codes)

        enforced_candidates = self._deduplicate_candidate_findings(enforced_candidates)
        return enforced_confirmed, enforced_candidates, verdicts

    # ------------------------------------------------------------------
    # Report-time CSRF finding type normalization (SGK-2026-0348 P0)
    # ------------------------------------------------------------------

    _AMBIGUOUS_VULN_TYPES: set[str] = {"misconfiguration", "other", "unknown", ""}

    _CSRF_TITLE_TOKENS: list[str] = [
        "csrf",
        "cross site request forgery",
        "tokenless stateful form",
    ]

    _CSRF_URL_PATH_TOKENS: list[str] = ["csrf"]

    _CSRF_SUMMARY_TOKENS: list[str] = [
        "anti-csrf token",
        "anti-csrf",
        "csrf token",
        "forged_request_succeeded",
        "active_verify",
    ]

    _CSRF_ADDITIONAL_INFO_KEYS: set[str] = {
        "csrf_state_change",
        "forged_request_succeeded",
        "active_verify",
    }

    @classmethod
    def _normalize_submission_quality_finding(
        cls, finding: HaddixFinding,
    ) -> HaddixFinding:
        """Apply report-time vuln_type normalization for CSRF findings.

        When a finding's ``vuln_type`` is ambiguous (misconfiguration / other /
        unknown) but the title, URL, summary, or additional_info contain strong
        CSRF signals, the in-memory ``vuln_type`` is set to ``"csrf"`` so that
        downstream evidence-quality validation and remediation templates treat
        it correctly.

        Returns the same finding object (mutated in-place) for chaining.
        """
        vuln_type = str(finding.vuln_type or "").strip().lower()
        if vuln_type not in cls._AMBIGUOUS_VULN_TYPES:
            return finding

        # --- title signal ---
        title_lower = str(finding.title or "").lower()
        has_title_signal = any(
            token in title_lower for token in cls._CSRF_TITLE_TOKENS
        )

        # --- URL path signal ---
        url_lower = str(finding.target_url or "").lower()
        has_url_signal = any(
            f"/{token}/" in url_lower or f"/{token}?" in url_lower or url_lower.endswith(f"/{token}")
            for token in cls._CSRF_URL_PATH_TOKENS
        )

        # --- summary signal ---
        summary_lower = str(finding.summary or "").lower()
        has_summary_signal = any(
            token in summary_lower for token in cls._CSRF_SUMMARY_TOKENS
        )

        # --- additional_info signal ---
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        has_info_signal = any(
            key in info and info[key]
            for key in cls._CSRF_ADDITIONAL_INFO_KEYS
        )

        if not (has_title_signal or has_url_signal or has_summary_signal or has_info_signal):
            return finding

        # At least one CSRF signal found → normalize
        signals: list[str] = []
        if has_title_signal:
            signals.append("title")
        if has_url_signal:
            signals.append("url")
        if has_summary_signal:
            signals.append("summary")
        if has_info_signal:
            signals.append("additional_info")

        original_type = finding.vuln_type
        finding.vuln_type = "csrf"
        finding.additional_info = info  # ensure dict
        finding.additional_info["normalized_vuln_type_from"] = original_type
        finding.additional_info["normalization_reason"] = (
            f"vuln_type={original_type} recategorized to csrf based on "
            f"signals: {', '.join(signals)}"
        )
        return finding

    # ------------------------------------------------------------------
    # Shadow-mode evidence quality verdict (P1)
    # ------------------------------------------------------------------

    def _build_shadow_verdicts(
        self,
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> List[EvidenceVerdict]:
        """Run the evidence quality validator over the existing split and
        return per-finding shadow verdicts. Does not mutate the split.
        """
        validator = HaddixEvidenceQualityValidator()
        findings: List[HaddixFinding] = []
        statuses: List[str] = []
        findings.extend(confirmed_findings)
        statuses.extend(["confirmed"] * len(confirmed_findings))
        findings.extend(candidate_findings)
        statuses.extend(["candidate"] * len(candidate_findings))
        if not findings:
            return []
        return validator.evaluate_findings(findings=findings, current_statuses=statuses)

    # ------------------------------------------------------------------
    # Submission section
    # ------------------------------------------------------------------

    def _format_submission_section(self) -> List[str]:
        lines: List[str] = []
        enforced_confirmed, _enforced_candidates, _verdicts = self._get_enforced_split()

        generated_now = self._report_generated_at()
        lines.append("# 提出用レポート / Submission Report")
        lines.append("")
        lines.append(f"**Target:** {self._target}")
        if self._program_name:
            lines.append(f"**Program:** {self._program_name}")
        lines.append(f"**Generated:** {generated_now.strftime('%Y-%m-%d %H:%M:%S')} JST")
        if self._source_session:
            lines.append(f"**Source Session:** {self._source_session}")
        lines.append("**Tool:** SHIGOKU - Sovereign VAPT Engine")
        lines.append("")

        lines.append("## コピー範囲 / Copy Scope")
        lines.append("")
        lines.append(
            "この見出しから下位の **内部評価（私用） / Internal Review Notes** セクションの直前までが提出用です。"
        )
        lines.append("")

        lines.extend(self._format_japanese_summary(enforced_confirmed))

        lines.append("## Findings")
        lines.append("")
        if enforced_confirmed:
            for index, finding in enumerate(enforced_confirmed, 1):
                lines.extend(self._format_submission_finding_japanese(index, finding))
                lines.append("")
        else:
            lines.append("本スキャンでは提出用の確定脆弱性は検出されませんでした。")
            lines.append("")

        return lines

    def _format_english_submission_section(self) -> List[str]:
        lines: List[str] = []
        enforced_confirmed, _enforced_candidates, _verdicts = self._get_enforced_split()

        generated_now = self._report_generated_at()
        lines.append("# Report")
        lines.append("")
        lines.append(f"**Target:** {self._target}")
        if self._program_name:
            lines.append(f"**Program:** {self._program_name}")
        lines.append(f"**Generated:** {generated_now.strftime('%Y-%m-%d %H:%M:%S')} JST")
        if self._source_session:
            lines.append(f"**Source Session:** {self._source_session}")
        lines.append("**Tool:** SHIGOKU - Sovereign VAPT Engine")
        lines.append("")
        lines.append("Copy only this section for an English-only external submission.")
        lines.append("")

        lines.extend(self._format_english_summary(enforced_confirmed))

        lines.append("## Findings")
        lines.append("")
        if enforced_confirmed:
            for index, finding in enumerate(enforced_confirmed, 1):
                lines.extend(self._format_submission_finding_english(index, finding))
                lines.append("")
        else:
            lines.append("No confirmed findings in this run.")
            lines.append("")

        return lines

    def _format_japanese_summary(self, confirmed_findings: List[HaddixFinding]) -> List[str]:
        lines: List[str] = []
        lines.append("## 日本語サマリー")
        lines.append("")
        if not confirmed_findings:
            lines.append("本スキャンでは提出用の確定脆弱性は検出されませんでした。")
            lines.append("")
            return lines

        severity_counts: Dict[str, int] = {}
        for finding in confirmed_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        lines.append(f"本レポートは {len(confirmed_findings)} 件の提出用脆弱性を含みます。")
        parts: List[str] = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                emoji = self._severity_emoji(sev)
                parts.append(f"{emoji} {sev.upper()}: {count}件")
        if parts:
            lines.append("深刻度内訳: " + ", ".join(parts))
        lines.append("")
        return lines

    def _format_english_summary(self, confirmed_findings: List[HaddixFinding]) -> List[str]:
        lines: List[str] = []
        lines.append("## English Summary")
        lines.append("")
        if not confirmed_findings:
            lines.append("No submission-ready confirmed vulnerabilities were detected in this run.")
            lines.append("")
            return lines

        severity_counts: Dict[str, int] = {}
        for finding in confirmed_findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        lines.append(
            f"This report contains {len(confirmed_findings)} submission-ready "
            f"confirmed vulnerability finding(s)."
        )
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                emoji = self._severity_emoji(sev)
                lines.append(f"| {emoji} {sev.upper()} | {count} |")
        lines.append("")
        return lines

    def _format_submission_finding_japanese(self, index: int, finding: HaddixFinding) -> List[str]:
        """Render a confirmed finding for the Japanese submission section."""
        lines: List[str] = []
        severity = self._normalize_submission_severity(finding)
        emoji = self._severity_emoji(severity)
        severity_label = str(severity or "").upper()
        target_url = self._normalize_url_string(finding.target_url)
        impact_text = self._safe_text(finding.impact) or self._target_specific_impact(finding)
        remediation_jp = self._remediation(finding)
        verification_steps = self._verification_steps(finding)

        lines.append(f"### {index}. {emoji} [{severity_label}] {finding.title}")
        lines.append("")
        lines.append(f"- 影響: {impact_text}")
        lines.append(f"- 影響を受けるエンドポイント: `{target_url}`")
        lines.append("- 再現手順:")
        repro_steps = self._safe_step_list(finding)
        if not repro_steps:
            auto_steps = self._auto_generate_repro_steps(finding, lang="ja")
            valid_steps = self._validate_repro_steps(auto_steps)
            if valid_steps:
                for step in valid_steps:
                    lines.append(f"  - {step}")
            else:
                lines.append("  - (再現手順を自動生成できませんでした。Candidateとして手動確認が必要です。)")
        elif self._has_placeholder_steps(repro_steps):
            # User-provided steps contain forbidden/placeholder text → fail-closed
            lines.append("  - (再現手順を自動生成できませんでした。Candidateとして手動確認が必要です。)")
        else:
            for step in repro_steps:
                lines.append(f"  - {step}")
        lines.append("- PoCリクエスト:")
        if finding.poc_request:
            lines.append("  ```http")
            for request_line in redact_raw_request(str(finding.poc_request)).splitlines():
                lines.append(f"  {request_line}")
            lines.append("  ```")
        else:
            lines.append("  - (raw HTTP request artifact なし)")
        lines.append("- 証拠:")
        lines.extend(self._format_japanese_evidence_bullets(finding))
        lines.append(f"- 期待される結果: {self._expected_result_text(finding)}")
        lines.append(f"- 実際の結果: {self._actual_result_text(finding)}")
        lines.append(f"- 修正案: {remediation_jp}")
        lines.append("- 修正後の確認:")
        if verification_steps:
            for step in verification_steps:
                lines.append(f"  - {step}")
        else:
            lines.append("  - 修正後に同一ペイロードで再実行し、脆弱挙動が再現しないことを確認する。")
        lines.append("")

        lines.append("---")
        return lines

    def _format_submission_finding_english(self, index: int, finding: HaddixFinding) -> List[str]:
        """Render a confirmed finding for the English submission section."""
        lines: List[str] = []
        severity = self._normalize_submission_severity(finding)
        emoji = self._severity_emoji(severity)
        severity_label = str(severity or "").upper()
        target_url = self._normalize_url_string(finding.target_url)
        remediation_en = self._english_remediation_text(finding)
        verification_steps = self._verification_steps(finding)

        lines.append(f"### {index}. {emoji} [{severity_label}] {finding.title}")
        lines.append("")
        lines.append(f"- Impact: {self._safe_text(finding.impact) or self._english_target_impact(finding)}")
        lines.append(f"- Affected endpoint: `{target_url}`")
        lines.append("- Steps to reproduce:")
        repro_steps_en = self._safe_step_list(finding)
        if not repro_steps_en:
            auto_steps_en = self._auto_generate_repro_steps(finding, lang="en")
            valid_steps_en = self._validate_repro_steps(auto_steps_en)
            if valid_steps_en:
                for step in valid_steps_en:
                    lines.append(f"  - {step}")
            else:
                lines.append("  - (Could not auto-generate reproduction steps. Manual verification required as a candidate.)")
        elif self._has_placeholder_steps(repro_steps_en):
            lines.append("  - (Could not auto-generate reproduction steps. Manual verification required as a candidate.)")
        else:
            for step in repro_steps_en:
                lines.append(f"  - {step}")
        lines.append("- PoC request:")
        if finding.poc_request:
            lines.append("  ```http")
            for request_line in redact_raw_request(str(finding.poc_request)).splitlines():
                lines.append(f"  {request_line}")
            lines.append("  ```")
        else:
            lines.append("  - (No raw HTTP request artifact available.)")
        lines.append("- Evidence:")
        lines.extend(self._format_english_evidence_bullets(finding))
        lines.append(f"- Expected result: {self._english_expected_result(finding)}")
        lines.append(f"- Actual result: {self._english_actual_result(finding)}")
        lines.append(f"- Remediation: {remediation_en}")
        lines.append("- Verification after fix:")
        if verification_steps:
            for step in verification_steps:
                lines.append(f"  - {step}")
        else:
            lines.append("  - Re-run the same payload after the fix and confirm the vulnerable behaviour no longer reproduces.")
        lines.append("")

        lines.append("---")
        return lines

    # ------------------------------------------------------------------
    # Internal section
    # ------------------------------------------------------------------

    def _format_internal_section(self) -> List[str]:
        lines: List[str] = []
        enforced_confirmed, enforced_candidates, _verdicts = self._get_enforced_split()

        lines.append("# 内部評価（私用） / Internal Review Notes")
        lines.append("")
        lines.append(
            "本セクションは内部QA/運用評価用であり、提出用 copy scope には含めない。"
        )
        lines.append("")

        lines.extend(self._format_internal_execution_notes())
        lines.extend(self._format_internal_scenario_coverage())
        lines.extend(self._format_internal_family_gate())
        lines.extend(self._format_internal_initial_release_gate())
        lines.extend(self._format_internal_submission_readiness_diagnostics(
            confirmed_findings=enforced_confirmed,
            candidate_findings=enforced_candidates,
        ))
        lines.extend(self._format_internal_evidence_quality_shadow_verdict(
            confirmed_findings=enforced_confirmed,
            candidate_findings=enforced_candidates,
        ))
        lines.extend(self._format_internal_candidates(enforced_candidates))
        lines.extend(self._format_third_party_review_memo())

        return lines

    def _format_internal_execution_notes(self) -> List[str]:
        if not self._execution_notes:
            return []
        lines: List[str] = ["## 実行ログ / Execution Notes", ""]
        lines.append(
            "| URL | Type | Status | Duration(s) | Retry | Tested Params | Probe Sent | Probe Skip Reason | Blind Evidence |"
        )
        lines.append(
            "|-----|------|--------|-------------|-------|---------------|------------|-------------------|----------------|"
        )
        timeout_count = 0
        completed_count = 0
        error_count = 0
        retry_total = 0
        slow_completed_count = 0
        for note in self._execution_notes:
            url = self._normalize_url_string(str(note.get("url", "")))
            vuln_type = str(note.get("vuln_type", ""))
            status = str(note.get("status", ""))
            status_lower = status.lower()
            if status_lower == "timeout":
                timeout_count += 1
            elif status_lower in {"completed", "cache_hit"}:
                completed_count += 1
            elif status_lower == "error":
                error_count += 1
            duration = note.get("duration_seconds")
            duration_val = float(duration) if duration is not None else 0.0
            duration_str = f"{duration}" if duration is not None else "-"
            # Slow probe warning: long-running completed tasks
            if status_lower in {"completed", "cache_hit"} and duration_val >= SLOW_PROBE_THRESHOLD_SECONDS:
                slow_completed_count += 1
            retry_count = int(note.get("retry_count", 0) or 0)
            retry_total += retry_count
            tested_params = note.get("tested_params", [])
            probe_sent = note.get("probe_sent")
            probe_state = str(note.get("probe_state", "") or "").strip()
            if probe_state == PROBE_STATE_NOT_APPLICABLE:
                tested_params_str = "N/A"
            elif not tested_params:
                tested_params_str = "none discovered"
            else:
                tested_params_str = ", ".join(str(p) for p in tested_params)
            if probe_sent is True:
                probe_sent_str = "yes"
            elif probe_state == PROBE_STATE_NOT_APPLICABLE:
                probe_sent_str = "N/A"
            elif probe_state == PROBE_STATE_SKIPPED:
                probe_sent_str = "no (skipped)"
            elif probe_state == PROBE_STATE_NOT_DISCOVERED:
                probe_sent_str = "no (no params)"
            elif probe_state == PROBE_STATE_INSTRUMENTATION_MISSING:
                probe_sent_str = "no (no instr.)"
            elif probe_sent is False:
                probe_sent_str = "no"
            else:
                probe_sent_str = "unknown"
            probe_skipped_reason = str(note.get("probe_skipped_reason", "") or "").strip()
            probe_skip_reason_code = str(note.get("probe_skip_reason_code", "") or "").strip()
            if probe_sent is True or probe_state == PROBE_STATE_NOT_APPLICABLE:
                probe_skipped_reason_str = "-"
            elif probe_skip_reason_code:
                probe_skipped_reason_str = probe_skip_reason_code
            elif probe_skipped_reason:
                probe_skipped_reason_str = probe_skipped_reason
            else:
                probe_skipped_reason_str = "unspecified"
            blind_correlation = note.get("blind_correlation", {})
            blind_summary = self._format_blind_summary(blind_correlation)
            lines.append(
                f"| `{url}` | {vuln_type} | {status} | {duration_str} | {retry_count} | "
                f"{tested_params_str} | {probe_sent_str} | {probe_skipped_reason_str} | {blind_summary} |"
            )
        lines.append("")
        total_notes = len(self._execution_notes)
        timeout_rate = (timeout_count / total_notes * 100.0) if total_notes else 0.0
        avg_retry = (retry_total / total_notes) if total_notes else 0.0
        lines.append(
            f"KPI: total={total_notes}, completed={completed_count}, timeout={timeout_count}, "
            f"error={error_count}, timeout_rate={timeout_rate:.1f}%, avg_retry={avg_retry:.2f}"
        )
        if slow_completed_count > 0:
            lines.append(
                f"Slow Probe Warning: {slow_completed_count} completed task(s) >= "
                f"{SLOW_PROBE_THRESHOLD_SECONDS:.0f}s duration. "
                "Investigate lightweight probes or timeout tuning for stability."
            )
        lines.append("")
        return lines

    def _format_internal_scenario_coverage(self) -> List[str]:
        if not self._scenario_coverage:
            return []
        # Delegate the body to the upstream renderer, then demote the heading
        # to a clear internal-only marker.
        rendered = self._render_upstream_scenario_coverage_body()
        if not rendered:
            return []
        lines: List[str] = ["## Scenario Coverage", ""]
        lines.extend(rendered)
        return lines

    def _format_internal_family_gate(self) -> List[str]:
        if not self._vulnerability_family_coverage:
            return []
        rendered = self._render_upstream_family_gate_body()
        if not rendered:
            return []
        lines: List[str] = ["## Vulnerability Family Coverage Gate", ""]
        lines.extend(rendered)
        return lines

    def _format_internal_initial_release_gate(self) -> List[str]:
        if not self._initial_release_gate:
            return []
        rendered = self._render_upstream_initial_release_gate_body()
        if not rendered:
            return []
        lines: List[str] = ["## Initial Release Gate", ""]
        lines.extend(rendered)
        return lines

    @staticmethod
    def _compute_submission_readiness_score(
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
        confirmed_poc_missing: int,
        candidate_reason_missing: int,
    ) -> float:
        """Compute a Bug Bounty submission readiness score (0-100).

        Based on three factors:
        - Evidence completeness (confirmed PoC presence): 40 points max
        - Reason-code coverage (candidates have explicit gaps): 30 points max
        - Confirmed-to-candidate ratio: 30 points max

        This is separate from the internal release gate (internal_gate_passed).
        """
        total_findings = len(confirmed_findings) + len(candidate_findings)
        if total_findings == 0:
            return 0.0

        # Evidence completeness: penalise confirmed findings with missing PoC
        poc_score = 40.0
        if confirmed_findings:
            poc_missing_ratio = confirmed_poc_missing / len(confirmed_findings)
            poc_score = max(0.0, 40.0 * (1.0 - poc_missing_ratio))

        # Reason-code coverage: penalise candidates without explicit reason
        reason_score = 30.0
        if candidate_findings:
            reason_missing_ratio = candidate_reason_missing / len(candidate_findings)
            reason_score = max(0.0, 30.0 * (1.0 - reason_missing_ratio))

        # Confirmed-to-candidate ratio: reward higher confirmed ratios
        ratio_score = 30.0
        if total_findings > 0:
            confirmed_ratio = len(confirmed_findings) / total_findings
            ratio_score = 30.0 * confirmed_ratio

        return round(poc_score + reason_score + ratio_score, 1)

    def _format_internal_submission_readiness_diagnostics(
        self,
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> List[str]:
        lines: List[str] = ["## Submission Readiness Diagnostics", ""]

        # Machine-readable line consumed by initial_release_gate.py
        lines.append(f"Confirmed: {len(confirmed_findings)} / Candidate: {len(candidate_findings)}")
        lines.append("")
        lines.append(f"Submission-ready findings: {len(confirmed_findings)}")
        lines.append(f"Hold-back candidates: {len(candidate_findings)}")
        if candidate_findings:
            lines.append(
                "Candidate items are separated into a non-submission appendix until manual verification is complete."
            )
        else:
            lines.append("All listed findings are submission-ready under the current report policy.")
        lines.append("")

        confirmed_poc_missing = 0
        for finding in confirmed_findings:
            has_request = bool(str(finding.poc_request or "").strip())
            has_response = bool(str(finding.poc_response or "").strip())
            if not (has_request and has_response):
                confirmed_poc_missing += 1

        candidate_reason_missing = 0
        if candidate_findings:
            reason_breakdown: Dict[str, int] = {}
            with_reason = 0
            for finding in candidate_findings:
                reason_codes = self._ensure_unconfirmed_reason_codes(
                    finding,
                    demoted_for_missing_poc=not (
                        bool(str(finding.poc_request or "").strip())
                        and bool(str(finding.poc_response or "").strip())
                    ),
                )
                if reason_codes:
                    with_reason += 1
                    for code in dict.fromkeys(reason_codes):
                        reason_breakdown[code] = reason_breakdown.get(code, 0) + 1
            missing_reason = len(candidate_findings) - with_reason
            candidate_reason_missing = missing_reason
            reason_breakdown_text = (
                ", ".join(f"{code}:{count}" for code, count in sorted(reason_breakdown.items()))
                if reason_breakdown
                else "-"
            )
            lines.append(
                f"Candidate Reason-Code Coverage: {with_reason}/{len(candidate_findings)} (missing={missing_reason})"
            )
            lines.append(f"Candidate Reason-Code Breakdown: {reason_breakdown_text}")
            lines.append("")
        # Machine-readable lines consumed by initial_release_gate.py
        lines.append(f"Confirmed PoC Missing: {confirmed_poc_missing}")
        lines.append(f"Candidate Reason-Code Missing: {candidate_reason_missing}")
        lines.append("")

        # Submission readiness score (SGK-2026-0347 P1)
        readiness_score = self._compute_submission_readiness_score(
            confirmed_findings=confirmed_findings,
            candidate_findings=candidate_findings,
            confirmed_poc_missing=confirmed_poc_missing,
            candidate_reason_missing=candidate_reason_missing,
        )
        lines.append("### Submission Readiness Score")
        lines.append("")
        lines.append(
            f"Submisson Readiness: {readiness_score:.0f}/100 "
            f"({'✅ Ready' if readiness_score >= 70 else '⚠ Needs Improvement' if readiness_score >= 40 else '❌ Not Ready'})"
        )
        lines.append(
            "This metric evaluates Bug Bounty submission quality based on evidence completeness, "
            "reason-code coverage, and confirmed-to-candidate ratio. It is separate from the "
            "internal release gate."
        )
        lines.append("")

        findings_class_summary = self._build_findings_class_summary(
            confirmed_findings=confirmed_findings,
            candidate_findings=candidate_findings,
        )
        class_rows = findings_class_summary.get("rows", [])
        if isinstance(class_rows, list) and class_rows:
            lines.append("### Findings by Vulnerability Class")
            lines.append("")
            lines.append("| Vulnerability Class | Confirmed | Candidate | Total |")
            lines.append("|---------------------|-----------|-----------|-------|")
            for row in class_rows:
                if not isinstance(row, dict):
                    continue
                vuln_class = str(row.get("vuln_class", "") or "").strip()
                if not vuln_class:
                    continue
                confirmed_count = int(row.get("confirmed", 0) or 0)
                candidate_count = int(row.get("candidate", 0) or 0)
                total_count = int(row.get("total", confirmed_count + candidate_count) or 0)
                lines.append(
                    f"| {vuln_class} | {confirmed_count} | {candidate_count} | {total_count} |"
                )
            lines.append("")

        detection_class_summary = self._build_detection_class_summary(
            confirmed_findings=confirmed_findings,
            candidate_findings=candidate_findings,
        )
        detection_rows = detection_class_summary.get("rows", [])
        if isinstance(detection_rows, list) and detection_rows:
            lines.append("### Findings by Detection Class")
            lines.append("")
            lines.append("| Detection Class | Confirmed | Candidate | Total | Scenario Backfill |")
            lines.append("|-----------------|-----------|-----------|-------|-------------------|")
            for row in detection_rows:
                if not isinstance(row, dict):
                    continue
                detection_class = str(row.get("detection_class", "") or "").strip()
                if not detection_class:
                    continue
                confirmed_count = int(row.get("confirmed", 0) or 0)
                candidate_count = int(row.get("candidate", 0) or 0)
                total_count = int(row.get("total", confirmed_count + candidate_count) or 0)
                scenario_backfill = int(row.get("scenario_backfill", 0) or 0)
                lines.append(
                    f"| {detection_class} | {confirmed_count} | {candidate_count} | {total_count} | {scenario_backfill} |"
                )
            lines.append("")

        if self._initial_release_gate:
            baseline_block = self._render_upstream_baseline_diff_body()
            if baseline_block:
                lines.extend(baseline_block)

        return lines

    def _format_internal_evidence_quality_shadow_verdict(
        self,
        *,
        confirmed_findings: List[HaddixFinding],
        candidate_findings: List[HaddixFinding],
    ) -> List[str]:
        """Render the P1 evidence-quality shadow verdict section.

        Plan section 8.5 requires the validator to run in shadow mode: it
        produces a diff vs the existing confirmed/candidate split without
        enforcing its verdict. Enforcement is a later switch gated on the
        acceptance criteria.
        """
        verdicts = self._build_shadow_verdicts(
            confirmed_findings=confirmed_findings,
            candidate_findings=candidate_findings,
        )
        lines: List[str] = ["## Evidence Quality Shadow Verdict (P1)", ""]
        if not verdicts:
            lines.append("No findings to evaluate.")
            lines.append("")
            return lines

        validator = HaddixEvidenceQualityValidator()
        summary = validator.summarize_diff(verdicts)
        lines.append(
            f"Shadow diff: total={summary['total']}, "
            f"would_demote={summary['would_demote']}, "
            f"would_promote={summary['would_promote']}, "
            f"match={summary['match']}. "
            "Enforcement is disabled in shadow mode; existing confirmed/candidate split is unchanged."
        )
        lines.append("")
        lines.append(
            "| # | Finding | Vuln Type | Current | Shadow | Δ | Payload in Request | Response Kind | Reason Codes |"
        )
        lines.append(
            "|---|---------|-----------|---------|--------|---|-------------------|---------------|--------------|"
        )
        for index, verdict in enumerate(verdicts, 1):
            delta = "-"
            if verdict.would_demote:
                delta = "demote"
            elif verdict.would_promote:
                delta = "promote"
            title = str(verdict.finding_id or "").replace("|", "\\|")
            if len(title) > 60:
                title = title[:57] + "..."
            reason_text = ", ".join(verdict.reason_codes) if verdict.reason_codes else "-"
            lines.append(
                f"| {index} | {title} | {verdict.vuln_type} | "
                f"{verdict.current_status} | {verdict.shadow_status} | {delta} | "
                f"{'yes' if verdict.payload_in_request else 'no'} | "
                f"{verdict.response_kind} | {reason_text} |"
            )
        lines.append("")
        lines.append(
            "Reason codes follow the plan section 7.2 matrix. "
            "Switching from shadow to enforcement is a separate, gated change."
        )
        lines.append("")
        return lines

    def _format_internal_candidates(self, candidate_findings: List[HaddixFinding]) -> List[str]:
        lines: List[str] = ["## 候補・保留項目 / Non-Submission Candidates", ""]
        if not candidate_findings:
            lines.append("No non-submission candidates in this run.")
            lines.append("")
            return lines

        lines.append(
            "Candidate findings are not part of the submission copy scope. "
            "Each candidate carries a standard reason code that explains the gap."
        )
        lines.append("")
        lines.append("| # | Severity | Type | Title | Reason Codes |")
        lines.append("|---|----------|------|-------|--------------|")
        for index, finding in enumerate(candidate_findings, 1):
            reason_codes = self._ensure_unconfirmed_reason_codes(
                finding,
                demoted_for_missing_poc=not (
                    bool(str(finding.poc_request or "").strip())
                    and bool(str(finding.poc_response or "").strip())
                ),
            )
            emoji = self._severity_emoji(finding.severity)
            reason_text = ", ".join(reason_codes) if reason_codes else "-"
            title = str(finding.title or "").replace("|", "\\|")
            lines.append(
                f"| {index} | {emoji} {str(finding.severity or '').upper()} | "
                f"{finding.vuln_type} | {title} | {reason_text} |"
            )
        lines.append("")
        lines.append("### Finding ID -> 内部メモ (Finding Memo Map)")
        lines.append("")
        lines.append("| Finding ID | 内部メモ |")
        lines.append("|------------|----------|")
        for index, finding in enumerate(candidate_findings, 1):
            reason_codes = self._ensure_unconfirmed_reason_codes(
                finding,
                demoted_for_missing_poc=not (
                    bool(str(finding.poc_request or "").strip())
                    and bool(str(finding.poc_response or "").strip())
                ),
            )
            memo_parts: List[str] = []
            if reason_codes:
                memo_parts.append("reason_codes=" + ",".join(reason_codes))
            summary = self._safe_text(finding.summary)
            if summary:
                memo_parts.append(summary)
            if not memo_parts:
                memo_parts.append("manual verification required")
            memo_text = "; ".join(memo_parts).replace("|", "\\|")
            lines.append(f"| C{index} | {memo_text} |")
        lines.append("")
        lines.append("### Candidate Detail")
        lines.append("")
        for index, finding in enumerate(candidate_findings, 1):
            lines.extend(self._format_candidate_detail(index, finding))
            lines.append("")
        return lines

    def _format_candidate_detail(self, index: int, finding: HaddixFinding) -> List[str]:
        emoji = self._severity_emoji(finding.severity)
        lines: List[str] = [
            f"#### C{index}. {emoji} [{str(finding.severity or '').upper()}] {finding.title}",
            "",
            f"- Type: {finding.vuln_type}",
            f"- Endpoint: `{self._normalize_url_string(finding.target_url)}`",
        ]
        info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        merged_duplicate_count = info.get("merged_duplicate_count")
        try:
            merged_duplicate_count_int = int(merged_duplicate_count or 0)
        except Exception:
            merged_duplicate_count_int = 0
        if merged_duplicate_count_int > 1:
            lines.append(f"- Merged duplicate raw candidates: {merged_duplicate_count_int}")
        reason_codes = self._ensure_unconfirmed_reason_codes(
            finding,
            demoted_for_missing_poc=not (
                bool(str(finding.poc_request or "").strip())
                and bool(str(finding.poc_response or "").strip())
            ),
        )
        lines.append(f"- Reason Codes: {', '.join(reason_codes) if reason_codes else '-'}")
        if finding.summary:
            lines.append(f"- Summary: {self._safe_text(finding.summary)}")
        if finding.poc_request:
            lines.append("")
            lines.append("```http")
            lines.append(finding.poc_request)
            lines.append("```")
        if finding.poc_response:
            lines.append("")
            lines.append("```http")
            lines.append(finding.poc_response)
            lines.append("```")
        return lines

    def _format_third_party_review_memo(self) -> List[str]:
        lines: List[str] = ["## 第三者指摘対応メモ", ""]
        lines.append(
            "計画書 (SGK-2026-0345) の第三者指摘トレース表に基づく、本レポートの対応状況。"
        )
        lines.append("")
        lines.append("| ID | 指摘 | 実装対応 |")
        lines.append("|----|------|----------|")
        for row in _THIRD_PARTY_REVIEW_ROWS:
            lines.append(f"| {row[0]} | {row[1]} | {row[2]} |")
        lines.append("")
        lines.append(
            "Detection 拡張 (Command Injection / DOM XSS / Open Redirect / Weak Session IDs) "
            "は本タスクのスコープ外 (P2) とし、別タスクで追跡する。"
        )
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Upstream body reuse helpers
    # ------------------------------------------------------------------

    def _render_upstream_scenario_coverage_body(self) -> List[str]:
        """Render the scenario-coverage body (without the heading) by invoking
        the upstream renderer and trimming the heading lines it emits."""
        if not self._scenario_coverage:
            return []
        rendered = self._upstream_format_section_body(
            marker="## 🧪 Scenario Coverage (SCN01-12)",
        )
        return rendered

    def _render_upstream_family_gate_body(self) -> List[str]:
        if not self._vulnerability_family_coverage:
            return []
        return self._upstream_format_section_body(
            marker="## 🧱 Vulnerability Family Coverage Gate",
        )

    def _render_upstream_initial_release_gate_body(self) -> List[str]:
        if not self._initial_release_gate:
            return []
        return self._upstream_format_section_body(marker="## 🚦 Initial Release Gate")

    def _render_upstream_baseline_diff_body(self) -> List[str]:
        """Extract just the Baseline Diff block from the upstream gate section."""
        if not self._initial_release_gate:
            return []
        rendered = self._upstream_format_section_body(marker="## 🚦 Initial Release Gate")
        baseline_lines: List[str] = []
        emitting = False
        for line in rendered:
            if "Baseline Diff:" in line:
                emitting = True
                baseline_lines.append(line)
                continue
            if emitting:
                if line.strip() == "":
                    baseline_lines.append(line)
                    break
                baseline_lines.append(line)
        return baseline_lines

    def _upstream_format_section_body(self, *, marker: str) -> List[str]:
        """Render the upstream ``format_markdown`` body for the section that
        starts with ``marker`` and return its lines (without the heading)."""
        try:
            full_md = super().format_markdown()
        except Exception:
            return []
        lines = full_md.splitlines()
        out: List[str] = []
        in_section = False
        for line in lines:
            if not in_section:
                if line.startswith(marker):
                    in_section = True
                continue
            # Stop at the next H2 heading
            if line.startswith("## "):
                break
            out.append(line)
        # Trim a single trailing blank if present
        while out and out[-1] == "":
            out.pop()
        if out:
            out.append("")
        return out

    # ------------------------------------------------------------------
    # Per-finding helpers (bilingual)
    # ------------------------------------------------------------------

    def _format_japanese_evidence_bullets(self, finding: HaddixFinding) -> List[str]:
        bullets: List[str] = []
        if finding.payloads_used:
            bullets.append("  - 使用ペイロード:")
            for payload in finding.payloads_used:
                bullets.append(f"    - `{payload}`")
        if finding.poc_response and not self._is_synthetic_response(finding):
            bullets.append("  - Response evidence:")
            bullets.append("  ```http")
            for response_line in redact_raw_response(str(finding.poc_response)).splitlines():
                bullets.append(f"  {response_line}")
            bullets.append("  ```")
        elif finding.poc_response and self._is_synthetic_response(finding):
            bullets.append("  - Response evidence: (synthetic detector note を提出用から除外。詳細は内部評価の Shadow Verdict を参照)")
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        # XSS: render context + browser execution evidence (SGK-2026-0347)
        render_ctx = self._render_context_text(finding, lang="ja")
        if render_ctx:
            bullets.append(f"  - 出力コンテキスト: {render_ctx}")
        browser_note = self._browser_execution_note(additional_info, lang="ja")
        if browser_note:
            bullets.append(f"  - ブラウザ実行証拠: {browser_note}")
        blind_note = self._blind_evidence_note(additional_info)
        if blind_note:
            bullets.append(f"  - Blind evidence: {blind_note}")
        authz_note = self._authz_differential_note(additional_info)
        if authz_note:
            bullets.append(f"  - AuthZ differential: {authz_note}")
        poc_html = str(additional_info.get("poc_html", "") or "").strip()
        if poc_html:
            bullets.append("  - PoC HTML (Browser Execution):")
            bullets.append("  ```html")
            for html_line in poc_html.splitlines():
                bullets.append(f"  {html_line}")
            bullets.append("  ```")
        if not bullets:
            bullets.append("  - (evidence artifact なし)")
        return bullets

    def _format_english_evidence_bullets(self, finding: HaddixFinding) -> List[str]:
        bullets: List[str] = []
        if finding.payloads_used:
            bullets.append("  - Payloads used:")
            for payload in finding.payloads_used:
                bullets.append(f"    - `{payload}`")
        if finding.poc_response and not self._is_synthetic_response(finding):
            bullets.append("  - Response evidence:")
            bullets.append("  ```http")
            for response_line in redact_raw_response(str(finding.poc_response)).splitlines():
                bullets.append(f"  {response_line}")
            bullets.append("  ```")
        elif finding.poc_response and self._is_synthetic_response(finding):
            bullets.append("  - Response evidence: (synthetic detector note excluded from the submission scope; see the Shadow Verdict section in the internal review notes)")
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        # XSS: render context + browser execution evidence (SGK-2026-0347)
        render_ctx = self._render_context_text(finding, lang="en")
        if render_ctx:
            bullets.append(f"  - Render Context: {render_ctx}")
        browser_note = self._browser_execution_note(additional_info, lang="en")
        if browser_note:
            bullets.append(f"  - Browser Execution: {browser_note}")
        blind_note = self._blind_evidence_note(additional_info)
        if blind_note:
            bullets.append(f"  - Blind evidence: {blind_note}")
        authz_note = self._authz_differential_note(additional_info)
        if authz_note:
            bullets.append(f"  - AuthZ differential: {authz_note}")
        poc_html_en = str(additional_info.get("poc_html", "") or "").strip()
        if poc_html_en:
            bullets.append("  - PoC HTML (Browser Execution):")
            bullets.append("  ```html")
            for html_line in poc_html_en.splitlines():
                bullets.append(f"  {html_line}")
            bullets.append("  ```")
        if not bullets:
            bullets.append("  - (No evidence artifact available.)")
        return bullets

    @staticmethod
    def _render_context_text(finding: HaddixFinding, *, lang: str = "en") -> str:
        """Extract the XSS render context from additional_info.

        Plan section 4.5 requires render_context for XSS findings to clarify
        where the payload appears in the DOM."""
        vtype = str(finding.vuln_type or "").lower()
        if "xss" not in vtype:
            return ""
        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        ctx = str(additional_info.get("render_context", "") or "").strip()
        if not ctx:
            return ""
        # Translate known context values
        ctx_labels = {
            "html_body": "HTML body (Element content)",
            "attribute": "HTML attribute value",
            "js_string": "JavaScript string literal",
            "html_comment": "HTML comment",
            "css_context": "CSS context",
            "url_attribute": "URL attribute (href/src)",
        }
        ja_labels = {
            "html_body": "HTML body（要素内容）",
            "attribute": "HTML属性値",
            "js_string": "JavaScript文字列リテラル",
            "html_comment": "HTMLコメント",
            "css_context": "CSSコンテキスト",
            "url_attribute": "URL属性（href/src）",
        }
        if lang == "ja":
            return ja_labels.get(ctx, ctx)
        return ctx_labels.get(ctx, ctx)

    @staticmethod
    def _normalize_submission_severity(finding: HaddixFinding) -> str:
        """Normalize severity for Bug Bounty submission (SGK-2026-0347 P1).

        AuthZ/API findings must not carry 'high' severity unless:
        - There is an expected denied behavior (401/403) that was bypassed, OR
        - Sensitive fields (email, token, PII, balance, credentials) are exposed, OR
        - A privilege escalation path is demonstrated.
        """
        severity = str(finding.severity or "").strip().lower()
        if severity != "high":
            return severity
        vtype = str(finding.vuln_type or "").lower()
        authz_types = {
            "broken_access_control", "idor", "bola", "unauthenticated_api_access",
            "authorization_bypass", "api_unauth_access", "mass_assignment",
        }
        if vtype not in authz_types and "access_control" not in vtype:
            return severity

        additional_info = finding.additional_info if isinstance(finding.additional_info, dict) else {}
        # Check for sensitive signal evidence
        differential = additional_info.get("authz_differential", {}) if isinstance(additional_info.get("authz_differential"), dict) else {}
        signals = differential.get("signals", [])
        if isinstance(signals, list):
            sensitive_tokens = {
                "email_exposed", "api_key_exposed", "token_exposed", "secret_exposed",
                "balance_exposed", "pii_exposed", "credential_exposed",
            }
            has_sensitive_signal = any(
                str(s).lower() in sensitive_tokens
                for s in signals
            )
            if has_sensitive_signal:
                return "high"

        # Check for expected denied behavior
        expected_denied = str(additional_info.get("expected_denied_behavior", "") or "").strip()
        if expected_denied:
            return "high"

        # Check response body for sensitive fields
        body = str(finding.poc_response or "").lower()
        sensitive_body_tokens = ("email", "balance", "api_key", "apikey", "token", "secret", "password", "ssn", "credit_card")
        if any(t in body for t in sensitive_body_tokens):
            return "high"

        return "medium"

    @staticmethod
    def _browser_execution_note(additional_info: dict, *, lang: str = "en") -> str:
        """Format browser execution evidence from additional_info."""
        browser_exec = additional_info.get("browser_execution", {}) if additional_info else {}
        if not isinstance(browser_exec, dict):
            return ""
        dialog_observed = bool(browser_exec.get("dialog_observed", False))
        dom_mutation = bool(browser_exec.get("dom_mutation_observed", False))
        executor = str(browser_exec.get("executor", "") or "").strip()
        if not dialog_observed and not dom_mutation:
            return ""
        parts = []
        if dialog_observed:
            dialog_text = str(browser_exec.get("dialog_text", "") or "").strip()
            if lang == "ja":
                parts.append(f"ダイアログ表示: \"{dialog_text}\"" if dialog_text else "ダイアログ表示を確認")
            else:
                parts.append(f"Dialog observed: \"{dialog_text}\"" if dialog_text else "Dialog observed")
        if dom_mutation:
            parts.append("DOM mutation あり" if lang == "ja" else "DOM mutation detected")
        if executor:
            parts.append(f"Executor: {executor}")
        return ", ".join(parts)

    def _is_synthetic_response(self, finding: HaddixFinding) -> bool:
        """Return True if the captured response evidence must not appear in
        the submission copy scope.

        Per SGK-2026-0345 acceptance criteria, ``HTTP/1.1 0`` (and any
        response text whose status line is ``HTTP/<ver> 0``) is a synthetic
        detector note and is excluded from submission evidence regardless of
        whether the finding also carries browser-execution evidence. The
        Shadow Verdict section in the internal scope records the
        classification.
        """
        raw_response = str(finding.poc_response or "")
        if not raw_response.strip():
            return False
        return bool(HaddixEvidenceQualityValidator._HTTP_ZERO_STATUS_RE.search(raw_response))

    def _safe_text(self, value: Any) -> str:
        text = str(value or "").strip()
        return text.replace("\n", " ")

    def _safe_step_list(self, finding: HaddixFinding) -> List[str]:
        steps = list(finding.steps_to_reproduce or [])
        normalized: List[str] = []
        for step in steps:
            token = str(step or "").strip().replace("\n", " ")
            if token and token not in normalized:
                normalized.append(token)
        return normalized

    def _verification_steps(self, finding: HaddixFinding) -> List[str]:
        # SGK-2026-0357 regression fix: 提出用レポートでは再現手順は上部の
        # 「再現手順」セクションに表示済み。ベース実装は steps_to_reproduce を
        # 検証セクションに inline 展開するが、提出用では攻撃手順が検証に漏れ出し
        # 「再現しないことの確認」と矛盾する。再現手順を除外しつつ、標準の修正後
        # 確認 bullets は必ず含める。
        base_steps = super()._verification_steps(finding)
        repro = {str(s).strip() for s in (finding.steps_to_reproduce or [])}
        filtered = [s for s in base_steps if str(s).strip() not in repro]

        # P2-2: add template-based negative test and regression test
        payload = self._primary_payload(finding)
        negative_test = self._format_template_field(finding.vuln_type, "negative_test", "ja", payload)
        regression_test = self._format_template_field(finding.vuln_type, "regression_test", "ja", payload)

        if negative_test and negative_test not in filtered:
            filtered.append(negative_test)
        if regression_test and regression_test not in filtered:
            filtered.append(regression_test)

        standard = [
            "修正前に成立したPoCリクエストを同条件で再送する。",
            "修正後レスポンスで脆弱挙動（反射・実行・注入）が再現しないことを確認する。",
            "正常系リクエストが影響を受けず動作することを回帰確認する。",
        ]
        for s in standard:
            if s not in filtered:
                filtered.append(s)
        return filtered

    def _expected_result_text(self, finding: HaddixFinding) -> str:
        # P2-2: prefer vulnerability-class template
        payload = self._primary_payload(finding)
        templated = self._format_template_field(finding.vuln_type, "expected_result", "ja", payload)
        if templated:
            return templated
        # fall back to existing logic for un-templated types
        vtype = str(finding.vuln_type or "").lower()
        if "xss" in vtype:
            return "ユーザ入力がHTMLコンテキストに応じてエスケープされ、スクリプト実行に至らないこと。"
        if "sqli" in vtype or "sql" in vtype:
            return "パラメータ化クエリにより、入力値がSQL構文として解釈されないこと。"
        if "csrf" in vtype:
            return "状態変更リクエストに有効なCSRFトークンと正しいSameSite Cookieが必須となること。"
        if "lfi" in vtype:
            return "パス区切り文字を含む入力が拒否またはサニタイズされ、ファイルシステムパスが解決されないこと。"
        if "ssrf" in vtype:
            return "許可リスト外のホストや内部アドレスへのリクエストが拒否されること。"
        if "cors" in vtype or "misconfiguration" in vtype:
            return "信頼されていないOriginに対してAccess-Control-Allow-Originヘッダを返さないこと。"
        return "入力値検証・出力エンコード・認可チェックにより、当該脆弱経路が再現しないこと。"

    def _actual_result_text(self, finding: HaddixFinding) -> str:
        summary = self._safe_text(finding.summary)
        if summary:
            return summary
        return "検出された evidence に基づき、脆弱挙動が再現した。"

    def _english_expected_result(self, finding: HaddixFinding) -> str:
        # P2-2: prefer vulnerability-class template
        payload = self._primary_payload(finding)
        templated = self._format_template_field(finding.vuln_type, "expected_result", "en", payload)
        if templated:
            return templated
        # fall back to existing logic for un-templated types
        vtype = str(finding.vuln_type or "").lower()
        if "xss" in vtype:
            return "User input is encoded for its HTML context and script execution does not occur."
        if "sqli" in vtype or "sql" in vtype:
            return "Parameterized queries prevent the input from being interpreted as SQL syntax."
        if "csrf" in vtype:
            return "State-changing requests require a valid CSRF token and a correct SameSite cookie."
        if "lfi" in vtype:
            return "Inputs containing path separators are rejected or sanitized and filesystem paths are not resolved."
        if "ssrf" in vtype:
            return "Requests to hosts outside the allow-list (including internal addresses) are rejected."
        if "cors" in vtype or "misconfiguration" in vtype:
            return "Access-Control-Allow-Origin must not be returned for untrusted origins."
        return "Input validation, output encoding, and authorization checks prevent the vulnerable path from reproducing."

    def _english_actual_result(self, finding: HaddixFinding) -> str:
        summary = self._safe_text(finding.summary)
        if summary:
            return summary
        return "Based on the captured evidence, the vulnerable behaviour reproduced."

    def _english_target_impact(self, finding: HaddixFinding) -> str:
        vtype = str(finding.vuln_type or "").lower()
        if "xss" in vtype:
            return "Attacker-controlled JavaScript can execute in a victim session, enabling session theft and DOM manipulation."
        if "sqli" in vtype or "sql" in vtype:
            return "Attacker can read or tamper with database contents through the vulnerable query path."
        if "csrf" in vtype:
            return "Attacker can forge a state-changing request that the application accepts on behalf of an authenticated victim."
        if "lfi" in vtype:
            return "Attacker can read arbitrary files from the server filesystem via path traversal."
        if "ssrf" in vtype:
            return "Attacker can reach internal services or metadata endpoints through the server-side request path."
        return "The vulnerable endpoint exposes a target-specific security impact that must be validated for direct business exposure."

    def _remediation(self, finding: HaddixFinding) -> str:
        # P2-2: prefer vulnerability-class template
        templated = self._format_template_field(finding.vuln_type, "remediation", "ja")
        if templated:
            return templated
        # fall back to parent logic for un-templated types
        return super()._remediation(finding)

    def _english_remediation_text(self, finding: HaddixFinding) -> str:
        # P2-2: prefer vulnerability-class template
        templated = self._format_template_field(finding.vuln_type, "remediation", "en")
        if templated:
            return templated
        # fall back to existing logic for un-templated types
        vtype = str(finding.vuln_type or "").lower()
        if "xss" in vtype:
            return (
                "Apply context-aware output encoding for all user-supplied content. "
                "Enforce a strict Content-Security-Policy and prefer framework-provided auto-escaping."
            )
        if "sqli" in vtype or "sql" in vtype:
            return (
                "Use parameterized queries (prepared statements) for every database access path. "
                "Never concatenate user input into SQL."
            )
        if "csrf" in vtype:
            return (
                "Require anti-CSRF tokens on every state-changing request, set SameSite=Strict|Lax on session cookies, "
                "and validate Origin/Referer headers. Do not rely on CORS alone."
            )
        if "lfi" in vtype:
            return (
                "Reject or sanitize path separators in user input. Resolve file paths against an explicit allow-list "
                "and serve only intended resources."
            )
        if "ssrf" in vtype:
            return (
                "Enforce an outbound allow-list, block internal IP ranges and cloud metadata endpoints, "
                "and revalidate redirect targets with the same policy."
            )
        if "cors" in vtype or "misconfiguration" in vtype:
            return (
                "Do not use a wildcard (*) or echo untrusted origins in the "
                "Access-Control-Allow-Origin header. Maintain an explicit allow-list "
                "of trusted origins. When Access-Control-Allow-Credentials is true, "
                "this control must be especially strict."
            )
        return (
            "Apply the principle of least privilege. Validate and sanitize all user inputs at the boundary, "
            "and follow OWASP guidance for the identified vulnerability class."
        )


# ---------------------------------------------------------------------------
# Convenience function (mirrors generate_haddix_report signature)
# ---------------------------------------------------------------------------

def generate_haddix_submission_internal_report(
    findings: List[Dict[str, Any]],
    target: str,
    output_path: Path,
    program_name: str = "",
    execution_notes: Optional[List[Dict[str, Any]]] = None,
    scenario_coverage: Optional[Dict[str, Any]] = None,
    vulnerability_family_coverage: Optional[Dict[str, Any]] = None,
    initial_release_gate: Optional[Dict[str, Any]] = None,
    source_session: str = "",
) -> None:
    """Generate a submission/internal split Haddix report from findings.

    Mirrors :func:`generate_haddix_report` so callers can switch formatters
    with a single import change.
    """
    formatter = HaddixSubmissionInternalFormatter()
    formatter.set_target(target, program_name)
    formatter.set_source_session(source_session)
    formatter.set_execution_notes(execution_notes or [])
    formatter.set_scenario_coverage(scenario_coverage or {})
    formatter.set_vulnerability_family_coverage(vulnerability_family_coverage or {})
    formatter.set_initial_release_gate(initial_release_gate or {})

    for raw_finding in findings:
        formatter.add_finding_from_dict(raw_finding)

    formatter.save_markdown(output_path)


def generate_separated_report_files(
    findings: List[Dict[str, Any]],
    target: str,
    output_dir: Path,
    program_name: str = "",
    execution_notes: Optional[List[Dict[str, Any]]] = None,
    scenario_coverage: Optional[Dict[str, Any]] = None,
    vulnerability_family_coverage: Optional[Dict[str, Any]] = None,
    initial_release_gate: Optional[Dict[str, Any]] = None,
    source_session: str = "",
) -> Dict[str, Path]:
    """Generate three separated output files:

    - *_submission.md: Submission-ready confirmed findings only (no internal QA)
    - *_internal.md: Internal QA, coverage, gate, candidate details
    - *_internal.json: Machine-readable data (execution, evidence, reason codes, gate results)

    Returns: {"submission": Path, "internal_md": Path, "internal_json": Path}
    """
    import json
    from datetime import datetime

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    formatter = HaddixSubmissionInternalFormatter()
    formatter.set_target(target, program_name)
    formatter.set_source_session(source_session)
    formatter.set_execution_notes(execution_notes or [])
    formatter.set_scenario_coverage(scenario_coverage or {})
    formatter.set_vulnerability_family_coverage(vulnerability_family_coverage or {})
    formatter.set_initial_release_gate(initial_release_gate or {})

    for raw_finding in findings:
        formatter.add_finding_from_dict(raw_finding)

    enforced_confirmed, enforced_candidates, _verdicts = formatter._get_enforced_split()
    all_findings: List[HaddixFinding] = list(enforced_confirmed) + list(enforced_candidates)

    # Generate a timestamp-based stem for filenames
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"haddix_{ts}"

    # ---- Submission file (confirmed only, no internal content) ----
    submission_lines: List[str] = []
    generated_now = formatter._report_generated_at()

    submission_lines.append("# 提出用レポート / Submission Report")
    submission_lines.append("")
    submission_lines.append(f"**Target:** {formatter._target}")
    if program_name:
        submission_lines.append(f"**Program:** {program_name}")
    submission_lines.append(f"**Generated:** {generated_now.strftime('%Y-%m-%d %H:%M:%S')} JST")
    if source_session:
        submission_lines.append(f"**Source Session:** {source_session}")
    submission_lines.append("**Tool:** SHIGOKU - Sovereign VAPT Engine")
    submission_lines.append("")
    submission_lines.append("## コピー範囲 / Copy Scope")
    submission_lines.append("")
    submission_lines.append(
        "この見出しから下位までが提出用です。内部評価情報（シナリオカバレッジ、"
        "ゲート判定、Shadow Verdict、候補詳細、第三者指摘対応など）は一切含まれていません。"
    )
    submission_lines.append("")

    # Japanese summary
    severity_counts: Dict[str, int] = {}
    for finding in enforced_confirmed:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

    submission_lines.append("## 日本語サマリー")
    submission_lines.append("")
    if not enforced_confirmed:
        submission_lines.append("本スキャンでは提出用の確定脆弱性は検出されませんでした。")
        submission_lines.append("")
    else:
        submission_lines.append(f"本レポートは {len(enforced_confirmed)} 件の提出用脆弱性を含みます。")
        parts: List[str] = []
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                emoji = formatter._severity_emoji(sev)
                parts.append(f"{emoji} {sev.upper()}: {count}件")
        if parts:
            submission_lines.append("深刻度内訳: " + ", ".join(parts))
        submission_lines.append("")

    # Findings
    submission_lines.append("## Findings")
    submission_lines.append("")
    if enforced_confirmed:
        for index, finding in enumerate(enforced_confirmed, 1):
            submission_lines.extend(formatter._format_submission_finding_japanese(index, finding))
            submission_lines.append("")
    else:
        submission_lines.append("本スキャンでは提出用の確定脆弱性は検出されませんでした。")
        submission_lines.append("")

    submission_path = output_dir / f"{stem}_submission.md"
    submission_path.write_text("\n".join(submission_lines), encoding="utf-8")

    # ---- Internal file (full split report, serves as internal.md) ----
    full_md = formatter.format_markdown()
    # Extract the internal section (everything after "# 内部評価（私用） / Internal Review Notes")
    internal_lines: List[str] = []
    header_added = False
    for line in full_md.splitlines():
        if "# 内部評価（私用） / Internal Review Notes" in line:
            header_added = True
            internal_lines.append(line)
            continue
        if header_added:
            internal_lines.append(line)

    internal_md_path = output_dir / f"{stem}_internal.md"
    internal_md_path.write_text("\n".join(internal_lines), encoding="utf-8")

    # ---- Internal JSON (machine-readable data) ----
    memo_maps = [build_finding_memo_map(f) for f in all_findings]
    internal_json_data: Dict[str, Any] = {
        "meta": {
            "target": target,
            "program_name": program_name,
            "generated_at": generated_now.isoformat(),
            "source_session": source_session,
            "tool": "SHIGOKU",
        },
        "findings": {
            "confirmed_count": len(enforced_confirmed),
            "candidate_count": len(enforced_candidates),
            "items": [f.to_dict() for f in all_findings],
        },
        "finding_memo_maps": memo_maps,
        "execution_notes": execution_notes or [],
        "scenario_coverage": scenario_coverage or {},
        "vulnerability_family_coverage": vulnerability_family_coverage or {},
        "initial_release_gate": initial_release_gate or {},
        "evidence_ids": [
            {
                "finding_id": mm.get("finding_id", ""),
                "timing_evidence_id": mm.get("timing_evidence_id"),
                "browser_trace_id": mm.get("browser_trace_id"),
            }
            for mm in memo_maps
        ],
    }
    internal_json_path = output_dir / f"{stem}_internal.json"
    internal_json_path.write_text(json.dumps(internal_json_data, indent=2, ensure_ascii=False), encoding="utf-8")

    return {
        "submission": submission_path,
        "internal_md": internal_md_path,
        "internal_json": internal_json_path,
    }
