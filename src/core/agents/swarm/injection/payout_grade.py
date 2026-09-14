"""
SGK-2026-0441 Lane A — payout-grade PoC gate (deterministic, fail-closed).

The validation loop is modernized so candidates confirm ONLY with a
"payout-grade PoC": a reproducible request/response pair plus a firing
marker plus an impact statement. This module is the shared contract
between Lane A (manager gate / specialist stop wiring) and Lane B
(time-budget + poc_judge role):

- ``PayoutGradeResult``: deterministic verdict payload.
- ``evaluate_payout_grade(finding: dict)``: the ONLY public evaluation
  entry. Raise-only, deterministic, NO LLM calls, NEVER raises on
  malformed input (fail-closed -> ``payout_grade=False`` with a reason
  code: ``missing_evidence`` / ``not_reproducible`` /
  ``no_firing_marker`` / ``unknown_category`` / ``missing_impact``).
- ``payout_grade_stage(finding_id, result)``: returns ``"F4"`` when the
  result is payout-grade else ``None`` — used by the funnel emitters in
  ``manager.py`` (this module never emits funnel events itself).
- ``finding_payload(finding)``: guarded projection of a Finding-like
  object to the dict shape ``evaluate_payout_grade`` consumes.
- ``has_explicit_refute_signal(finding)``: fail-closed refute-signal
  detector used by the Phase-2 merge (candidates are NEVER marked
  refuted speculatively).
- ``assert_read_only_probe(method, url)``: Phase-2 verification probes
  are GET-only (approved design). The re-send loop itself is wired by
  Lane B; the guard is implemented here and unit-tested so Lane B calls
  it at the send boundary (the existing specialist send path stays
  untouched).

Marker helpers mirror the existing per-specialist deterministic helpers
so the payout-grade marker vocabulary stays in sync with the detectors:

- sql_error          -> smart_sqli ``sql_errors`` (smart_sqli.py:1097-1107),
                        ``_classify_sql_error`` patterns
                        (smart_sqli.py:1261-1355) and the ExploitVerifier
                        SQL-error regexes (exploit_verifier.py:207-215)
- reflected_payload  -> smart_xss ``suspicious_markers``
                        (smart_xss.py:202-212) + ``diff=="reflected"``
                        analog (finding-level ``reflection_observed``)
- file_content_leak  -> smart_lfi ``lfi_patterns`` (smart_lfi.py:524-534)
                        + ``additional_info.file_marker_excerpt``
- command_execution  -> smart_cmd_ssrf ``cmd_indicators``
                        (smart_cmd_ssrf.py:1186-1195) +
                        ``additional_info.command_execution_evidence``
- ssrf_callback      -> smart_cmd_ssrf ``ssrf_indicators``
                        (smart_cmd_ssrf.py:1196) + OOB/DNS blind
                        correlation confirmations
- authz_diff         -> ``additional_info.authz_differential`` proving
                        unauthenticated success vs authenticated success
                        (manager.py api probes)
- privileged_field_assigned -> smart_mass_assignment
                        ``additional_info.mass_assignment_evidence``: an
                        injected privileged field is persisted with the
                        attacker value (injected_field_value==injected_value)
                        while a control request without it yields a different
                        server default (control_field_value)
- race_condition_toctou -> smart_race_condition
                        ``additional_info.race_evidence``: a unique marker is
                        reflected under a concurrent burst (race_served_body)
                        but absent under sequential requests
                        (control_served_body), proving execution in the
                        check-then-act (TOCTOU) window
- host_header_auth_bypass -> smart_host_header
                        ``additional_info.host_header_evidence``: injecting a
                        Host-family header exposes restricted content
                        (restricted_signature in injected_served_body) that a
                        non-bypass host does not (absent in
                        control_served_body)
- cache_poisoning_confirmed -> smart_cache_poisoning
                        ``additional_info.cache_poisoning_evidence``: an
                        attacker marker injected via an unkeyed header is
                        served to a CLEAN victim request (marker in
                        victim_served_body) while a different cache key is not
                        poisoned (absent in control_served_body)
- oob_interaction_received -> generic OOB (smart_blind_xxe etc.):
                        ``additional_info.oob_evidence``: a unique token we
                        placed inside the payload was delivered to our own OOB
                        receiver by the target (token in payload AND in the
                        received interaction.path). vuln_type-agnostic — works
                        for blind XXE / SSRF / SQLi / deserialization
- open_redirect      -> ``external_redirect`` (OpenRedirectSpecialist
                        open_redirect.py): the observed Location header of a
                        3xx response points at the injected attacker-managed
                        host (``additional_info.injected_host``) that is
                        external to the target itself
- cors               -> ``cors_credentialed_reflection`` (SmartCORSHunter
                        smart_cors.py / CORSTester cors_tester.py): the
                        observed Access-Control-Allow-Origin header reflects
                        the sent attacker test_origin (hostname match) with
                        Access-Control-Allow-Credentials: true AND a
                        credentialed cross-origin response body excerpt was
                        captured (``additional_info.credentialed_body_excerpt``).
                        `*` / null / no-reflection / no-credentials /
                        public-data CORS never fires (fail-closed)
- jwt_alg_none       -> ``jwt_forgery_accepted`` (AuthNinja
                        auth/auth_ninja.py): the server accepted an UNSIGNED
                        alg=none forgery carrying an engine-fabricated
                        identity — proved by a differential (the forged
                        identity is absent in the unauth baseline response
                        and reflected in the forged-token response).
                        Signed/already-accepted / no-differential never
                        fires (fail-closed)
- jwt_rs256_hs256     -> ``jwt_forgery_accepted`` (smart_jwt_forgery):
                        RS256->HS256 key confusion — an HS256 token signed
                        with the server's RSA public key as the HMAC secret
                        is accepted (jwt_alg=hs256 + jwt_key_confusion +
                        unauth_baseline_absent + forged_identity reflected).
                        Shares the marker with jwt_alg_none (same acceptance
                        semantics, different forgery technique); a wrong-secret
                        token must be rejected (fail-closed)
- file_upload         -> ``uploaded_file_retrieved`` (FileUploadSpecialist
                        file_upload.py / FileUploadTester
                        file_upload_tester.py): a benign non-executable file
                        carrying a per-run unique marker was stored and the
                        marker was re-observed from its retrieval URL
                        (``additional_info.file_upload_evidence`` must be
                        complete: upload_allowed true AND retrieved true AND
                        retrieval_marker non-empty AND retrieval_url
                        non-empty). Missing-any-piece never fires
                        (fail-closed)

Nothing here lowers any existing evidence threshold: the gate is purely
additive and every missing piece fails the candidate closed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Marker vocabulary (mirrors the specialist helpers cited above)
# ---------------------------------------------------------------------------

# smart_sqli.py:1097-1107 (sql_errors) + :1261-1355 (_classify_sql_error) +
# exploit_verifier.py:207-215 (error_patterns).
_SQL_ERROR_PATTERNS: tuple = (
    r"SQL syntax",
    r"mysql_fetch",
    r"ORA-\d+",
    r"PostgreSQL",
    r"SQLite",
    r"ODBC",
    r"JDBC",
    r"unclosed quotation mark",
    r"syntax error",
    r"mariadb",
    r"mysqli?_sql_exception",
    r"you have an error in your sql syntax",
    r"unexpected token",
    r"unexpected end of statement",
    r"parse error",
    r"invalid syntax",
    r"near.*syntax error",
    r"missing.*in expression",
    r"missing.*at or near",
    r"table.*doesn'?t exist",
    r"no such table",
    r"no such column",
    r"unknown column",
    r"invalid object name",
    r"SQLSTATE",
    r"access denied",
    r"permission denied",
)

# smart_xss.py:202-212 (suspicious_markers).
_XSS_MARKERS: tuple = (
    "<script",
    "&lt;script",
    "onerror",
    "onload",
    "javascript:",
    "alert(",
    "<img",
    "<svg",
)

# smart_lfi.py:524-534 (lfi_patterns).
_LFI_PATTERNS: tuple = (
    r"root:[^\n]*:0:0:",
    r"daemon:[^\n]*:[0-9]+:[0-9]+:",
    r"bin:[^\n]*:1:1:",
    r"www-data:[^\n]*:[0-9]+:[0-9]+:",
    r"\[extensions\]",
    r"\[fonts\]",
    r"\[boot loader\]",
    r"\[mci extensions\]",
    r"PD9waH[A-Za-z0-9+/=]{8,}",
)

# smart_cmd_ssrf.py:1186-1195 (cmd_indicators).
_CMD_INDICATORS: tuple = (
    "uid=",
    "gid=",
    "groups=",
    "root:",
    "daemon:",
    "www-data:",
    "www-data",
    "/bin/bash",
)

# smart_cmd_ssrf.py:1196 (ssrf_indicators).
_SSRF_INDICATORS: tuple = (
    "aws",
    "metadata",
    "169.254",
    "localhost",
    "127.0.0.1",
)

# Cloud-metadata response patterns (exploit_verifier.py:248-254,
# ``_verify_ssrf`` metadata_patterns).
_SSRF_METADATA_PATTERNS: tuple = (
    r"ami-[a-z0-9]+",
    r"instance-id",
    r"iam/security-credentials",
    r"metadata\.google",
    r"computeMetadata",
)

# SGK-2026-0483: credential-bearing assignment patterns for enumerated
# secret exposure (secret/manager.py SecretExposure). These match the KEY
# side of an env/config assignment (``NAME=...`` / ``NAME: ...``) or a PEM
# private-key header, so detection survives value redaction — the served
# credential VALUE is never required (and must never be persisted); the
# presence of a credential-bearing assignment in a publicly served file IS
# the exposure. Anchored per-line (MULTILINE) to avoid matching prose.
_SECRET_EXPOSURE_PATTERNS: tuple = (
    re.compile(
        r"(?im)^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_.]*"
        r"(?:PASSWORD|PASSWD|SECRET|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|TOKEN|CREDENTIAL)"
        r"[A-Za-z0-9_.]*[ \t]*[=:]"
    ),
    re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
)

# SGK-2026-0486: XXE ファイル読み取りの署名。外部実体で /etc/passwd を解決
# できたことの高信頼指標（アプリ応答に自然混入しにくい）。エンジンが読み取る
# システムファイルの特徴的内容で照合する。
_XXE_FILE_PATTERNS: tuple = (
    re.compile(r"root:.*?:0:0:"),                       # /etc/passwd
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
)
# XXE ペイロードが外部実体を含むことの検証（発火には payload 側の外部実体
# 宣言も必須）。
_XXE_ENTITY_PATTERN = re.compile(r"(?is)<!ENTITY\s+\S+\s+SYSTEM\s")

# SGK-2026-0487: NoSQL(MongoDB) 演算子注入。payload に演算子が含まれることの検証。
_NOSQL_OPERATOR_PATTERN = re.compile(r"\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|exists)\b")
# SGK-2026-0499: LDAP フィルタのメタ文字（ワイルドカード * / フィルタ閉じ→再オープン )( /
# 論理 OR (| / 論理 AND (&）。リテラル値には現れず、入力が LDAP フィルタとして解釈される
# ことを示す最小シグネチャ（単なる `=` や `(` 単体は誤検知を避けるため対象外）。
_LDAP_METACHAR_PATTERN = re.compile(r"\*|\)\(|\(\||\(&")


def _nosql_body_has_data(status: Any, body: str) -> bool:
    """2xx かつ本文が非空の実データ（空 dict/list/null/エラーでない）か。
    NoSQL 差分確定の「成功」判定に用いる（payout_grade と再現チェッカーで共有）。"""
    if not (isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300):
        return False
    text = str(body or "").strip()
    if text in ("", "{}", "[]", "null", "false"):
        return False
    try:
        import json as _json
        parsed = _json.loads(text)
    except (ValueError, TypeError):
        return bool(text)
    if isinstance(parsed, dict):
        return len(parsed) > 0
    if isinstance(parsed, list):
        return len(parsed) > 0
    return parsed not in (None, "", 0, False)

# Authz differential signals that prove unauthenticated success against an
# authenticated baseline (manager.py api probes, api_probe_analysis.py).
_AUTHZ_PROOF_SIGNALS: frozenset = frozenset(
    {"auth_success", "unauth_success", "status_improved_with_auth"}
)

# VDP-style impact markers (vdp_evidence_validator.py:64-74,
# ``_REQUIREMENT_MARKERS`` values): explicit structured proof tokens. Their
# presence in additional_info satisfies the impact/reproducibility condition
# for VDP findings that do not carry free-text impact/reproduction_steps.
_VDP_IMPACT_MARKERS: tuple = (
    "authz_impact_proven",
    "semantic_diff_observed",
    "second_account_compared",
    "request_fingerprint_matched",
    "state_change_verified",
    "state_change_readback_observed",
    "ssrf_proof_established",
    "unique_oob_callback_received",
    "timing_difference_observed",
)

# Explicit refute signals (never speculative; candidates stay candidates
# unless one of these is present).
_REFUTE_SIGNAL_KEYS: tuple = (
    "falsification",
    "falsified",
    "refuted",
    "false_positive",
)

# vuln_type -> expected marker vocabulary (known categories).
_MARKER_CATEGORIES: Dict[str, str] = {
    "sqli": "sql_error",
    "xss": "reflected_payload",
    "lfi": "file_content_leak",
    "cmd_ssrf": "command_execution",
    "os_command_injection": "command_execution",
    "rce": "command_execution",
    "ssrf": "ssrf_callback",
    "open_redirect": "external_redirect",
    "api": "authz_diff",
    "broken_access_control": "authz_diff",
    "idor": "authz_diff",
    # SGK-2026-0488: mass assignment は authz_diff（IDOR/BAC の認証有無差分）と
    # 意味論が異なる（特権フィールドの一括代入受理）。専用マーカーに分離。
    "mass_assignment": "privileged_field_assigned",
    # SGK-2026-0475: both spellings occur in the codebase
    # (VulnType.CORS_MISCONFIGURATION.value == "cors_misconfiguration";
    # manager.py:1713 also matches "cors").
    "cors": "cors_credentialed_reflection",
    "cors_misconfiguration": "cors_credentialed_reflection",
    # SGK-2026-0476: JWT alg=none 無署名偽造の受理。
    # (VulnType.JWT_ALG_NONE.value == VulnType.JWT_NONE_ALG.value ==
    # "jwt_alg_none")
    "jwt_alg_none": "jwt_forgery_accepted",
    # SGK-2026-0490: JWT RS256→HS256 キー混同（公開鍵を HMAC 秘密に HS256 署名した
    # 偽造トークンの受理）。確定意味論は alg=none と同型（偽造手法が違うだけ）のため
    # 同一マーカー jwt_forgery_accepted を共有＝封印再現（_check_jwt_forgery_replay）も
    # forged_token 再送で手法非依存に流用される。
    "jwt_rs256_hs256": "jwt_forgery_accepted",
    # SGK-2026-0480: unrestricted file upload（良性・非実行ファイルの設置＋
    # Web 取得）。発火は file_upload_evidence の完備（upload_allowed 真＋
    # retrieved 真＋retrieval_marker 非空＋retrieval_url 非空）でのみ。
    "file_upload": "uploaded_file_retrieved",
    # SGK-2026-0483: enumerated secret exposure（公開URLで資格情報を含む
    # ファイルが配信される）。発火は secret_exposure_evidence の完備
    # （retrieved_url 非空＋response_status=200＋served_body に資格情報
    # 代入パターン一致）でのみ。
    "secret_leak": "secret_exposed",
    # SGK-2026-0484: GraphQL broken authorization（認証なしの GraphQL クエリ
    # が認可ゲート付きの機微データ＝資格情報等を返す）。発火は
    # graphql_exposure_evidence の完備（endpoint 非空＋response_status=200＋
    # served_body 非空＋matched_fields 非空＋query 非空、かつ served_body に
    # matched_fields のいずれかのキーが実在）でのみ。値は redact 済みでも
    # キー側フィールド名で照合。
    "graphql_authz_exposure": "graphql_sensitive_exposed",
    # SGK-2026-0485: SSTI（サーバサイドテンプレートインジェクション）。発火は
    # ssti_evidence の完備（request_url 非空＋response_status>0＋payload 非空＋
    # 期待積 expected 非空、かつ served_body に expected が実在）でのみ。
    # expected は算術積＋一意マーカー（例 "49<hex>"）のため自然混入・
    # テンプレ捏造不可。1 つでも欠ければ None（fail-closed）。
    "ssti": "template_evaluated",
    # SGK-2026-0486: XXE（XML External Entity・in-band ファイル読み取り）。発火は
    # xxe_evidence の完備（request_url 非空＋response_status>0＋payload に外部実体
    # 宣言（<!ENTITY ... SYSTEM）＋served_body にシステムファイル署名一致）でのみ。
    # 我々が外部実体を送った事実＋読めないはずのファイル内容の反映が実害の証拠。
    "xxe": "xxe_file_read",
    # SGK-2026-0487: NoSQL(MongoDB) 演算子注入。発火は nosql_evidence の完備
    # （request_url 非空＋operator_payload に演算子＋operator が成功(2xx+データ)＋
    # control（無効リテラル）が失敗）でのみ。演算子成功×リテラル失敗の差分が
    # 「フィールドがクエリ演算子として解釈された」決定的証拠。
    "nosql_injection": "nosql_operator_injection",
    # SGK-2026-0489: Race Condition（TOCTOU）。発火は race_evidence の完備
    # （request_url 非空＋marker 非空＋並列バースト成功(2xx)＋marker が
    # race_served_body に実在＋marker が control_served_body に非実在）でのみ。
    # 並列で出て逐次で出ない差分が「TOCTOU 窓で実行された」決定的証拠。
    "race_condition": "race_condition_toctou",
    # SGK-2026-0491: Host Header Injection（認証/認可バイパス）。発火は
    # host_header_evidence の完備（request_url 非空＋injected_header 非空＋
    # injected_host_value 非空＋restricted_signature 非空＋injection 2xx＋
    # 署名が injected_served_body に実在＋control_served_body に非実在）でのみ。
    # 注入ホストで制限署名が出て非バイパスホストで出ない差分が「Host ヘッダを
    # 認可に信頼している」決定的証拠。
    "host_header_injection": "host_header_auth_bypass",
    # SGK-2026-0496: Insecure Deserialization。in-band 確認は未実装だが、OOB(帯域外)
    # 確認（デシリアライズ時のコールバック）で汎用マーカー oob_interaction_received を
    # 発火させるため vuln_type を既知カテゴリに登録する（in-band 専用ブランチは無し＝
    # OOB 経路が唯一の発火。将来 in-band ガジェット確認を足す場合はブランチ追加）。
    "deserialization": "oob_interaction_received",
    # SGK-2026-0497: Prototype Pollution（Node.js）。発火は prototype_pollution_evidence の
    # 完備（sink_url／observe_url／pollute_property／marker 非空＋observe 2xx＋marker が
    # polluted_served_body に実在＋control_served_body に非実在）でのみ。汚染後に新オブジェクトへ
    # マーカーが現れて汚染前は現れない差分が Object.prototype 汚染の決定的証拠。
    "prototype_pollution": "prototype_pollution_confirmed",
    # SGK-2026-0492: Web キャッシュポイズニング。発火は cache_poisoning_evidence の
    # 完備（request_url 非空＋injected_header 非空＋marker 非空＋victim 2xx＋marker が
    # victim_served_body（クリーン応答）に実在＋marker が control_served_body に非実在）
    # でのみ。クリーンな victim に攻撃者 marker が出ることがキャッシュ配信の決定的証拠。
    "cache_poisoning": "cache_poisoning_confirmed",
    # SGK-2026-0499: LDAP インジェクション（認証/フィルタバイパス）。発火は
    # ldap_evidence の完備（request_url 非空＋injection_payload に LDAP メタ文字
    # （* や )( や (| や (&）＋success_marker 非空＋injection 成功(2xx)＋success_marker が
    # injected_served_body に実在＋success_marker が control_served_body（メタ文字無しの
    # リテラル資格情報）に非実在）でのみ。リテラルは失敗しメタ文字で成功する差分が
    # 「入力が LDAP フィルタとして解釈された」決定的証拠。
    "ldap_injection": "ldap_injection_confirmed",
}

# ---------------------------------------------------------------------------
# open_redirect (OpenRedirectSpecialist): external Location redirect marker.
#
# The specialist injects a unique per-run attacker-managed host
# (shigoku-verify-<uuid>.evil.com) and records it as
# ``additional_info.injected_host``. The marker fires ONLY when the observed
# Location header of a 3xx response points at that external host; every
# ambiguity (no 3xx, internal/relative Location, missing attacker host,
# self-redirect to the target's own host) fails closed to None.
# ---------------------------------------------------------------------------

_REDIRECT_STATUSES: frozenset = frozenset({301, 302, 303, 307, 308})


def _redirect_host(value: Any) -> str:
    """Lowercased netloc of a URL-ish string ("" when absent).

    Relative locations behave correctly: ``//attacker.example/`` yields the
    host (external), ``/internal/path`` yields "" (no host, i.e. internal).
    Host-less values that are not URLs also yield "" so nothing can fire on
    ambiguous input (fail-closed).
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        parsed = urlparse(text)
    except ValueError:
        return ""
    return parsed.netloc.lower()


def _external_attacker_host(info: Dict[str, Any]) -> str:
    """The attacker-managed host the specialist injected (lowercased).

    Priority: ``additional_info.injected_host`` -> the host of
    ``additional_info.redirect_to`` -> the host of ``additional_info.payload``.
    Empty when nothing resolves to a host (fail-closed).
    """
    injected = str(info.get("injected_host") or "").strip()
    if injected:
        # injected_host はホスト名（例 shigoku-verify-<uuid>.evil.com）が正形。
        # URL 形で入っていた場合のみ netloc を取り、それ以外はそのまま使う。
        return _redirect_host(injected) or injected.lower()
    for key in ("redirect_to", "payload"):
        host = _redirect_host(info.get(key))
        if host:
            return host
    return ""


def _external_redirect_observed(
    *, info: Dict[str, Any], location: str, self_url: str
) -> bool:
    """True ONLY when ``location`` points at the injected attacker host AND
    that host is external to ``self_url``'s own host (fail-closed: any one
    missing piece -> False)."""
    attacker_host = _external_attacker_host(info)
    if not attacker_host:
        return False
    location_host = _redirect_host(location)
    if not location_host or location_host != attacker_host:
        return False
    self_host = _redirect_host(self_url)
    if self_host and location_host == self_host:
        # 対象自身のホストへの自己リダイレクトは外部ではない
        return False
    return True


# ---------------------------------------------------------------------------
# cors (SmartCORSHunter / CORSTester): credentialed origin reflection marker.
#
# The tester sends an attacker-controlled test_origin and records the
# observed Access-Control-Allow-Origin / Access-Control-Allow-Credentials
# values plus (for origin reflection WITH credentials) an excerpt of the
# credentialed cross-origin response body. The firing marker requires ALL
# of: (1) acao reflects the test_origin by hostname (never `*`, `null`,
# empty, or the target's own origin), (2) acac == true (case-insensitive),
# (3) a non-empty ``credentialed_body_excerpt`` proving sensitive
# cross-origin content was actually read. Anything else fails closed to
# None — wildcard/null/unauthenticated CORS stays below the confirmation
# bar (public-data CORS is a known safe hold, never promoted).
# ---------------------------------------------------------------------------


def _origin_host(value: Any) -> str:
    """Lowercased urlparse ``hostname`` of an origin/URL-ish string ("" when
    absent or unparseable).

    Host-only comparison: scheme and port never matter (``*`` / ``null`` /
    bare tokens have no hostname and yield "")."""
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        return (urlparse(text).hostname or "").lower()
    except ValueError:
        return ""


def _acao_reflects_test_origin(
    *, acao: str, test_origin: str, self_url: str
) -> bool:
    """True ONLY when ``acao`` reflects ``test_origin`` by hostname AND the
    reflected host is not the target's own host (fail-closed: `*`, `null`,
    empty, self-origin, or any missing piece -> False)."""
    acao_host = _origin_host(acao)
    test_host = _origin_host(test_origin)
    if not acao_host or not test_host or acao_host != test_host:
        return False
    self_host = _origin_host(self_url)
    if self_host and test_host == self_host:
        # 対象自身のオリジンへの「反映」は攻撃者オリジンではない
        return False
    return True


def _evidence_header(headers: Any, name: str) -> str:
    """Case-insensitive single-header lookup on an evidence headers dict.

    Auxiliary source only — canonical marker values live in
    additional_info; the evidence headers are consulted only when the
    additional_info value is missing/empty."""
    if not isinstance(headers, dict):
        return ""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value or "")
    return ""


# Read-only methods allowed for Phase-2 verification probes (GET-only
# design; HEAD/OPTIONS are accepted as read-only companions).
_READ_ONLY_METHODS: frozenset = frozenset({"GET", "HEAD", "OPTIONS"})

_REASON_PAYOUT_GRADE_SATISFIED = "payout_grade_satisfied"
_REASON_MISSING_EVIDENCE = "missing_evidence"
_REASON_NOT_REPRODUCIBLE = "not_reproducible"
_REASON_NO_FIRING_MARKER = "no_firing_marker"
_REASON_UNKNOWN_CATEGORY = "unknown_category"
_REASON_MISSING_IMPACT = "missing_impact"

_METHOD_TOKEN_RE = re.compile(r"^\s*(?:GET|POST|HEAD|OPTIONS|PUT|DELETE|PATCH|TRACE|CONNECT)\s+\S+", re.IGNORECASE)
_STATUS_LINE_RE = re.compile(r"^\s*HTTP/\d(?:\.\d)?\s+\d{3}")


@dataclass
class PayoutGradeResult:
    """Deterministic payout-grade verdict for one candidate finding.

    ``payout_grade`` True only when ALL evidence conditions hold;
    ``reason`` is a stable code (``payout_grade_satisfied`` on success);
    ``evidence_refs`` lists the field names that satisfied the
    reproducibility condition; ``marker`` is the matched firing marker
    vocabulary token (or None when no marker matched).
    """

    payout_grade: bool
    reason: str
    evidence_refs: list
    marker: Optional[str]


def finding_payload(finding: Any) -> dict:
    """Guarded projection of a Finding-like object to the dict shape that
    ``evaluate_payout_grade`` consumes (fail-closed: malformed input -> {}).

    Finding objects are converted via ``to_dict()`` (the canonical
    serialization); plain dicts pass through unchanged.
    """
    if isinstance(finding, dict):
        return finding
    try:
        if hasattr(finding, "to_dict") and callable(finding.to_dict):
            payload = finding.to_dict()
            if isinstance(payload, dict):
                return payload
    except Exception:  # noqa: BLE001 — boundary guard, fail closed
        pass
    return {}


def _poc_request_complete(poc_request: str) -> bool:
    """A PoC request is complete when it starts with a method + target
    (the format the specialist ``_build_poc_request`` helpers produce)."""
    return bool(_METHOD_TOKEN_RE.match(str(poc_request or "")))


def _poc_response_complete(poc_response: str) -> bool:
    """A PoC response is complete when it starts with an HTTP status line
    (the format the specialist ``_build_poc_response`` helpers produce)."""
    return bool(_STATUS_LINE_RE.match(str(poc_response or "")))


def _response_status_ok(status: Any) -> bool:
    """Fail-closed status check: a real captured HTTP status (> 0)."""
    return isinstance(status, int) and not isinstance(status, bool) and status > 0


def _response_text(*, evidence_body: str, poc_response: str) -> str:
    """The deterministic marker search text: response body + PoC response."""
    return "\n".join(
        text for text in (str(evidence_body or ""), str(poc_response or "")) if text
    )


def _match_firing_marker(
    vuln_type: str, evidence: Dict[str, Any], info: Dict[str, Any]
) -> Optional[str]:
    """Category-specific deterministic firing-marker match.

    Returns the marker vocabulary token, or None when the category is
    known but nothing fired (fail-closed).
    """
    body = _response_text(
        evidence_body=evidence.get("response_body", ""),
        poc_response=info.get("poc_response", ""),
    )
    body_lower = body.lower()

    # SGK-2026-0494: OOB（帯域外）確認は vuln_type 横断の汎用経路。ブラインド脆弱性
    # （XXE/SSRF/SQLi 等）で in-band に何も返らなくても、「我々が生成した一意 token を
    # ペイロードに埋めて送り、標的が我々の受信器へその token でコールバックした」事実
    # （additional_info.oob_evidence）が揃えば発火する。要件（すべて必須）:
    #  (1) token 非空、(2) token が payload に実在（＝我々が送った外部実体/URL に埋めた）、
    #  (3) interaction_received 真、(4) 受信した interaction.path に token が実在
    #     （＝標的からのコールバックが我々の一意 token を運んできた）。
    # 乱数 token のため偶然混入・捏造不可。1 つでも欠ければ通常の in-band 経路へ
    # フォールバック（fail-closed・既存マーカーは不変）。
    oob = info.get("oob_evidence")
    if isinstance(oob, dict):
        oob_token = str(oob.get("token") or "").strip()
        oob_payload = str(oob.get("payload") or "")
        oob_received = bool(oob.get("interaction_received"))
        oob_interaction = oob.get("interaction")
        oob_path = str(oob_interaction.get("path") or "") if isinstance(oob_interaction, dict) else ""
        if (
            oob_token
            and oob_token in oob_payload
            and oob_received
            and oob_token in oob_path
        ):
            return "oob_interaction_received"

    if vuln_type == "sqli":
        if any(re.search(p, body, re.IGNORECASE) for p in _SQL_ERROR_PATTERNS):
            return "sql_error"
        return None

    if vuln_type == "xss":
        if any(marker in body_lower for marker in _XSS_MARKERS):
            return "reflected_payload"
        # finding-level analog of the specialist's diff == "reflected"
        # (smart_xss.py:199-200): reflection_observed is only ever set
        # together with vulnerable + a captured reflection.
        if bool(info.get("reflection_observed")):
            return "reflected_payload"
        # SGK-2026-0477: 実ブラウザ発火は本文反映より強い発火証拠。DOM XSS は
        # ペイロードが URL フラグメント由来で HTTP 本文に出ないため、本文マーカー/
        # reflection_observed が無くても、additional_info.browser_execution の
        # dialog_observed=true（実際に alert/script が実行された）で発火と確定する。
        # dialog 非観測（DOM mutation のみ等）の弱い証拠では発火しない（fail-closed）。
        browser_execution = info.get("browser_execution")
        if isinstance(browser_execution, dict) and bool(
            browser_execution.get("dialog_observed")
        ):
            return "reflected_payload"
        return None

    if vuln_type == "lfi":
        if any(re.search(p, body, re.IGNORECASE | re.MULTILINE) for p in _LFI_PATTERNS):
            return "file_content_leak"
        if str(info.get("file_marker_excerpt") or "").strip():
            return "file_content_leak"
        return None

    if vuln_type in {"cmd_ssrf", "os_command_injection", "rce"}:
        if any(marker in body_lower for marker in _CMD_INDICATORS):
            return "command_execution"
        if info.get("command_execution_evidence"):
            return "command_execution"
        return None

    if vuln_type == "ssrf":
        # SGK-2026-0482: in-band SSRF. The server fetched an attacker-chosen
        # URL and reflected its response body, where that URL is NOT directly
        # reachable by the client (server-side network vantage differential).
        # All three structured signals must be present (fail-closed); this is
        # additive and independent of the OOB/metadata ssrf_callback paths.
        inband = info.get("ssrf_inband_evidence")
        if isinstance(inband, dict):
            if (
                str(inband.get("fetched_url") or "").strip()
                and str(inband.get("server_reflected_body") or "").strip()
                and inband.get("client_direct_unreachable") is True
            ):
                return "ssrf_inband"
        if any(marker in body_lower for marker in _SSRF_INDICATORS):
            return "ssrf_callback"
        if any(re.search(p, body, re.IGNORECASE) for p in _SSRF_METADATA_PATTERNS):
            return "ssrf_callback"
        blind = info.get("blind_correlation")
        if isinstance(blind, dict):
            oob = blind.get("oob")
            dns = blind.get("dns")
            if not isinstance(oob, dict):
                oob = {}
            if not isinstance(dns, dict):
                dns = {}
            if oob.get("confirmed") or dns.get("confirmed"):
                return "ssrf_callback"
        return None

    if vuln_type in {"api", "broken_access_control", "idor"}:
        differential = info.get("authz_differential")
        if isinstance(differential, dict) and str(differential.get("scenario") or "").strip():
            signals = differential.get("signals")
            if isinstance(signals, list) and (
                ("auth_success" in signals and "unauth_success" in signals)
                or "status_improved_with_auth" in signals
            ):
                return "authz_diff"
        return None

    if vuln_type == "mass_assignment":
        # 発火は「特権フィールド昇格の本物のみ」(SGK-2026-0488):
        # additional_info.mass_assignment_evidence が、
        #  (1) request_url 非空、
        #  (2) field 非空、
        #  (3) injected_value 非空、
        #  (4) injection が成功（injected_status が 2xx）、
        #  (5) 応答に反映された値 injected_field_value が injected_value と一致
        #      （＝送った特権フィールドがサーバに受理された）、
        #  (6) control（当該フィールド無し）の反映値 control_field_value が
        #      非空でかつ injected_value と異なる（＝サーバが既定値を入れる
        #      server-controlled フィールドを client が上書きした差分）、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        # control_field_value が空＝echo だけの応答（フィールドを送らないと応答に
        # 現れない）は発火しない。
        mae = info.get("mass_assignment_evidence")
        if isinstance(mae, dict):
            request_url = str(mae.get("request_url") or "").strip()
            field = str(mae.get("field") or "").strip()
            injected_value = str(mae.get("injected_value") or "").strip()
            injected_status = mae.get("injected_status")
            injected_field_value = str(mae.get("injected_field_value") or "").strip()
            control_field_value = str(mae.get("control_field_value") or "").strip()
            status_2xx = (
                isinstance(injected_status, int)
                and not isinstance(injected_status, bool)
                and 200 <= injected_status < 300
            )
            if (
                request_url
                and field
                and injected_value
                and status_2xx
                and injected_field_value == injected_value
                and control_field_value
                and control_field_value != injected_value
            ):
                return "privileged_field_assigned"
        return None

    if vuln_type == "race_condition":
        # 発火は「TOCTOU レースの本物のみ」(SGK-2026-0489):
        # additional_info.race_evidence が、
        #  (1) request_url 非空、
        #  (2) marker 非空、
        #  (3) 並列バーストが成功（race_status が 2xx）、
        #  (4) marker が race_served_body に実在（並列で反映された）、
        #  (5) marker が control_served_body に非実在（逐次では出ない）、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        # 並列で出て逐次で出ない差分が「TOCTOU 窓で実行された」決定的証拠。
        # marker は乱数トークンのため偶然混入・捏造不可。
        rev = info.get("race_evidence")
        if isinstance(rev, dict):
            request_url = str(rev.get("request_url") or "").strip()
            marker = str(rev.get("marker") or "").strip()
            race_status = rev.get("race_status")
            race_body = str(rev.get("race_served_body") or "")
            control_body = str(rev.get("control_served_body") or "")
            status_2xx = (
                isinstance(race_status, int)
                and not isinstance(race_status, bool)
                and 200 <= race_status < 300
            )
            if (
                request_url
                and marker
                and status_2xx
                and marker in race_body
                and marker not in control_body
            ):
                return "race_condition_toctou"
        return None

    if vuln_type == "prototype_pollution":
        # 発火は「プロトタイプ汚染の本物のみ」(SGK-2026-0497):
        # additional_info.prototype_pollution_evidence が、
        #  (1) sink_url 非空、(2) observe_url 非空、(3) pollute_property 非空、
        #  (4) marker 非空、(5) observe が成功（observe_status 2xx）、
        #  (6) marker が polluted_served_body（汚染後の新オブジェクト応答）に実在、
        #  (7) marker が control_served_body（汚染前）に非実在、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        pp = info.get("prototype_pollution_evidence")
        if isinstance(pp, dict):
            sink_url = str(pp.get("sink_url") or "").strip()
            observe_url = str(pp.get("observe_url") or "").strip()
            prop = str(pp.get("pollute_property") or "").strip()
            marker = str(pp.get("marker") or "").strip()
            polluted_body = str(pp.get("polluted_served_body") or "")
            control_body = str(pp.get("control_served_body") or "")
            status = pp.get("observe_status")
            status_2xx = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and 200 <= status < 300
            )
            if (
                sink_url
                and observe_url
                and prop
                and marker
                and status_2xx
                and marker in polluted_body
                and marker not in control_body
            ):
                return "prototype_pollution_confirmed"
        return None

    if vuln_type == "ldap_injection":
        # 発火は「LDAP インジェクション（認証/フィルタバイパス）の本物のみ」(SGK-2026-0499):
        # additional_info.ldap_evidence が、
        #  (1) request_url 非空、
        #  (2) injection_payload に LDAP メタ文字（* / )( / (| / (&）、
        #  (3) success_marker 非空、
        #  (4) injection が成功（injected_status 2xx）、
        #  (5) success_marker が injected_served_body に実在（メタ文字で成功した）、
        #  (6) success_marker が control_served_body（メタ文字無しリテラル）に非実在、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        # リテラルは失敗しメタ文字で成功する差分が「入力が LDAP フィルタとして
        # 解釈された」決定的証拠（＝正当な資格情報なしの認証バイパス）。
        le = info.get("ldap_evidence")
        if isinstance(le, dict):
            request_url = str(le.get("request_url") or "").strip()
            payload = str(le.get("injection_payload") or "")
            success_marker = str(le.get("success_marker") or "").strip()
            inj_body = str(le.get("injected_served_body") or "")
            ctrl_body = str(le.get("control_served_body") or "")
            status = le.get("injected_status")
            status_2xx = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and 200 <= status < 300
            )
            if (
                request_url
                and _LDAP_METACHAR_PATTERN.search(payload)
                and success_marker
                and status_2xx
                and success_marker in inj_body
                and success_marker not in ctrl_body
            ):
                return "ldap_injection_confirmed"
        return None

    if vuln_type == "host_header_injection":
        # 発火は「Host ヘッダ注入による認可バイパスの本物のみ」(SGK-2026-0491):
        # additional_info.host_header_evidence が、
        #  (1) request_url 非空、
        #  (2) injected_header 非空、
        #  (3) injected_host_value 非空、
        #  (4) restricted_signature 非空、
        #  (5) injection が成功（injected_status 2xx）、
        #  (6) 署名が injected_served_body に実在（バイパスで制限コンテンツが出た）、
        #  (7) 署名が control_served_body に非実在（非バイパスでは出ない差分）、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        hh = info.get("host_header_evidence")
        if isinstance(hh, dict):
            request_url = str(hh.get("request_url") or "").strip()
            header = str(hh.get("injected_header") or "").strip()
            host_value = str(hh.get("injected_host_value") or "").strip()
            signature = str(hh.get("restricted_signature") or "").strip()
            inj_body = str(hh.get("injected_served_body") or "")
            ctrl_body = str(hh.get("control_served_body") or "")
            status = hh.get("injected_status")
            status_2xx = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and 200 <= status < 300
            )
            if (
                request_url
                and header
                and host_value
                and signature
                and status_2xx
                and signature in inj_body
                and signature not in ctrl_body
            ):
                return "host_header_auth_bypass"
        return None

    if vuln_type == "cache_poisoning":
        # 発火は「Web キャッシュポイズニングの本物のみ」(SGK-2026-0492):
        # additional_info.cache_poisoning_evidence が、
        #  (1) request_url 非空、
        #  (2) injected_header 非空（unkeyed 入力）、
        #  (3) marker 非空（一意の攻撃者ホスト）、
        #  (4) victim が成功（victim_status 2xx）、
        #  (5) marker が victim_served_body（クリーン応答）に実在＝キャッシュ配信、
        #  (6) marker が control_served_body（別鍵）に非実在、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        # クリーンな victim に攻撃者 marker が出ることがキャッシュ配信の決定的証拠。
        cp = info.get("cache_poisoning_evidence")
        if isinstance(cp, dict):
            request_url = str(cp.get("request_url") or "").strip()
            header = str(cp.get("injected_header") or "").strip()
            marker = str(cp.get("marker") or "").strip()
            victim_body = str(cp.get("victim_served_body") or "")
            control_body = str(cp.get("control_served_body") or "")
            v_status = cp.get("victim_status")
            status_2xx = (
                isinstance(v_status, int)
                and not isinstance(v_status, bool)
                and 200 <= v_status < 300
            )
            if (
                request_url
                and header
                and marker
                and status_2xx
                and marker in victim_body
                and marker not in control_body
            ):
                return "cache_poisoning_confirmed"
        return None

    if vuln_type == "open_redirect":
        # 発火は「本物のみ」: 3xx かつ Location が注入した攻撃者管理ホストを
        # 指し、かつ外部（対象自身のホストでない）。1 つでも欠ければ None。
        status = evidence.get("response_status")
        if not (
            isinstance(status, int)
            and not isinstance(status, bool)
            and status in _REDIRECT_STATUSES
        ):
            return None
        headers = evidence.get("response_headers")
        if not isinstance(headers, dict):
            headers = {}
        location = str(
            headers.get("Location")
            or headers.get("location")
            or info.get("redirect_to")
            or ""
        )
        if not location:
            return None
        self_url = str(evidence.get("request_url") or "").strip()
        if _external_redirect_observed(info=info, location=location, self_url=self_url):
            return "external_redirect"
        return None

    if vuln_type in {"cors", "cors_misconfiguration"}:
        # 発火は「認証付きオリジン反映の本物のみ」(SGK-2026-0475):
        # acao がテストオリジンにホスト一致で反映（`*`/null/空/対象自身の
        # オリジンは不可）＋ acac==true ＋ 認証付き越境応答本文の抜粋
        # （credentialed_body_excerpt）非空。1 つでも欠ければ None
        # （fail-closed・public-data CORS を確定に上げない）。
        headers_ev = evidence.get("response_headers")
        acao = str(
            info.get("acao")
            or _evidence_header(headers_ev, "Access-Control-Allow-Origin")
            or ""
        ).strip()
        acac = str(
            info.get("acac")
            or _evidence_header(headers_ev, "Access-Control-Allow-Credentials")
            or ""
        ).strip()
        excerpt = str(info.get("credentialed_body_excerpt") or "").strip()
        test_origin = str(info.get("test_origin") or "").strip()
        if not excerpt or acac.lower() != "true" or not test_origin:
            return None
        self_url = str(evidence.get("request_url") or "").strip()
        if _acao_reflects_test_origin(
            acao=acao, test_origin=test_origin, self_url=self_url
        ):
            return "cors_credentialed_reflection"
        return None

    if vuln_type == "jwt_alg_none":
        # 発火は「無署名偽造トークンの受理の本物のみ」(SGK-2026-0476):
        # (1) jwt_alg が "none"（無署名/未検証。RS256/HS256 等の署名検証
        #     済みトークンでは発火しない）、
        # (2) unauth_baseline_absent が真（トークン無しでは fabricate
        #     identity が非出現＝盗んだ有効セッションの再生ではなく無署名
        #     偽造の受理である差分証明）、
        # (3) forged_identity が非空 かつ 応答に反映（additional_info の
        #     forged_identity_reflected フラグ、または evidence.response_body /
        #     poc_response への forged_identity 文字列出現）。
        # 1 つでも欠ければ None（fail-closed・既存マーカーには相乗りしない）。
        if str(info.get("jwt_alg") or "").strip().lower() != "none":
            return None
        if not bool(info.get("unauth_baseline_absent")):
            return None
        forged_identity = str(info.get("forged_identity") or "").strip()
        if not forged_identity:
            return None
        if not (bool(info.get("forged_identity_reflected")) or forged_identity in body):
            return None
        return "jwt_forgery_accepted"

    if vuln_type == "jwt_rs256_hs256":
        # 発火は「RS256→HS256 キー混同の受理の本物のみ」(SGK-2026-0490):
        # (1) jwt_alg が "hs256"（攻撃者は公開鍵を HMAC 秘密に HS256 署名）、
        # (2) jwt_key_confusion 真（公開鍵を HMAC 秘密として検証している＝
        #     誤り秘密は拒否される差分をエンジンが確認した証拠）、
        # (3) unauth_baseline_absent 真（トークン無しでは forged_identity が
        #     非出現＝盗んだセッション再生でなく偽造の受理である差分証明）、
        # (4) forged_identity 非空 かつ 応答に反映。
        # 1 つでも欠ければ None（fail-closed）。alg=none 分岐とは独立・共有
        # マーカー jwt_forgery_accepted を返す（偽造手法が違うだけ）。
        if str(info.get("jwt_alg") or "").strip().lower() != "hs256":
            return None
        if not bool(info.get("jwt_key_confusion")):
            return None
        if not bool(info.get("unauth_baseline_absent")):
            return None
        forged_identity = str(info.get("forged_identity") or "").strip()
        if not forged_identity:
            return None
        if not (bool(info.get("forged_identity_reflected")) or forged_identity in body):
            return None
        return "jwt_forgery_accepted"

    if vuln_type == "secret_leak":
        # 発火は「列挙系シークレット露出の本物のみ」(SGK-2026-0483):
        # additional_info.secret_exposure_evidence が、
        #  (1) retrieved_url 非空（in-scope で配信された取得元URL）、
        #  (2) response_status == 200（実際に配信された）、
        #  (3) served_body 非空 かつ 資格情報代入パターン一致
        #      （_SECRET_EXPOSURE_PATTERNS。値は redact 済みでもキー側で一致）
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed・
        # 資格情報を含まない公開ファイルは確定に上げない）。served_body の
        # 秘密値は呼び出し側で redact 済み（値は不要・照合はキー側）。
        sec = info.get("secret_exposure_evidence")
        if isinstance(sec, dict):
            retrieved_url = str(sec.get("retrieved_url") or "").strip()
            status = sec.get("response_status")
            served_body = str(sec.get("served_body") or "")
            status_ok = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and status == 200
            )
            if (
                retrieved_url
                and status_ok
                and served_body
                and any(p.search(served_body) for p in _SECRET_EXPOSURE_PATTERNS)
            ):
                return "secret_exposed"
        return None

    if vuln_type == "graphql_authz_exposure":
        # 発火は「GraphQL 認可欠陥の本物のみ」(SGK-2026-0484):
        # additional_info.graphql_exposure_evidence が、
        #  (1) endpoint 非空（in-scope の GraphQL エンドポイント）、
        #  (2) response_status == 200（実際に応答が返った）、
        #  (3) served_body 非空（値 redact 済みの実応答 JSON）、
        #  (4) matched_fields 非空（応答に実在した機微スカラーフィールド名）、
        #  (5) query 非空（認証なしで実行した実クエリ）、
        # かつ served_body に matched_fields のいずれかのキーが実在する
        # ときのみ。1 つでも欠ければ None（fail-closed・認証なしで機微データが
        # 返る本物のみ確定に上げる）。served_body の機微値は呼び出し側で
        # redact 済み（値は不要・照合はキー側フィールド名）。
        gql = info.get("graphql_exposure_evidence")
        if isinstance(gql, dict):
            endpoint = str(gql.get("endpoint") or "").strip()
            status = gql.get("response_status")
            served_body = str(gql.get("served_body") or "")
            query = str(gql.get("query") or "").strip()
            matched_fields = gql.get("matched_fields")
            status_ok = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and status == 200
            )
            if (
                endpoint
                and status_ok
                and served_body
                and query
                and isinstance(matched_fields, (list, tuple))
                and matched_fields
                and any(
                    str(f) and str(f) in served_body for f in matched_fields
                )
            ):
                return "graphql_sensitive_exposed"
        return None

    if vuln_type == "ssti":
        # 発火は「テンプレート評価の本物のみ」(SGK-2026-0485):
        # additional_info.ssti_evidence が、
        #  (1) request_url 非空、
        #  (2) response_status > 0（実際に応答が返った）、
        #  (3) payload 非空（送出した算術テンプレートペイロード）、
        #  (4) expected 非空（算術積＋一意マーカー。例 "49<hex>"）、
        # かつ served_body に expected が実在するときのみ。1 つでも欠ければ
        # None（fail-closed）。expected はマーカー付きで自然混入・捏造不可
        # のため、算術積の再出現が評価の決定的証拠になる。
        sst = info.get("ssti_evidence")
        if isinstance(sst, dict):
            request_url = str(sst.get("request_url") or "").strip()
            status = sst.get("response_status")
            payload = str(sst.get("payload") or "").strip()
            expected = str(sst.get("expected") or "").strip()
            served_body = str(sst.get("served_body") or "")
            status_ok = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and status > 0
            )
            if (
                request_url
                and status_ok
                and payload
                and expected
                and expected in served_body
            ):
                return "template_evaluated"
        return None

    if vuln_type == "xxe":
        # 発火は「in-band XXE ファイル読み取りの本物のみ」(SGK-2026-0486):
        # additional_info.xxe_evidence が、
        #  (1) request_url 非空、
        #  (2) response_status > 0、
        #  (3) payload に外部実体宣言（<!ENTITY ... SYSTEM）が存在、
        #  (4) served_body にシステムファイルの署名（_XXE_FILE_PATTERNS）が一致、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        # 我々が外部実体を送った事実＋本来読めないファイル内容の反映が実害の証拠。
        xxe = info.get("xxe_evidence")
        if isinstance(xxe, dict):
            request_url = str(xxe.get("request_url") or "").strip()
            status = xxe.get("response_status")
            payload = str(xxe.get("payload") or "")
            served_body = str(xxe.get("served_body") or "")
            status_ok = (
                isinstance(status, int)
                and not isinstance(status, bool)
                and status > 0
            )
            if (
                request_url
                and status_ok
                and _XXE_ENTITY_PATTERN.search(payload)
                and any(p.search(served_body) for p in _XXE_FILE_PATTERNS)
            ):
                return "xxe_file_read"
        return None

    if vuln_type == "nosql_injection":
        # 発火は「NoSQL 演算子注入の本物のみ」(SGK-2026-0487):
        # additional_info.nosql_evidence が、
        #  (1) request_url 非空、
        #  (2) operator_payload に MongoDB 演算子が存在、
        #  (3) 演算子が成功（operator_status 2xx＋operator_served_body に実データ）、
        #  (4) 負のコントロール（無効リテラル）が失敗（control が 2xx+データでない）、
        # のすべてを満たすときのみ。1 つでも欠ければ None（fail-closed）。
        # 演算子成功×リテラル失敗の差分が「クエリ演算子として解釈された」証拠。
        nsq = info.get("nosql_evidence")
        if isinstance(nsq, dict):
            request_url = str(nsq.get("request_url") or "").strip()
            operator_payload = str(nsq.get("operator_payload") or "")
            op_ok = _nosql_body_has_data(
                nsq.get("operator_status"), str(nsq.get("operator_served_body") or "")
            )
            ctrl_ok = _nosql_body_has_data(
                nsq.get("control_status"), str(nsq.get("control_served_body") or "")
            )
            if (
                request_url
                and _NOSQL_OPERATOR_PATTERN.search(operator_payload)
                and op_ok
                and not ctrl_ok
            ):
                return "nosql_operator_injection"
        return None

    if vuln_type == "file_upload":
        # 発火は「設置＋Web 取得の本物のみ」(SGK-2026-0480): アップロードした
        # 一意マーカー入り良性ファイルが Web から取得できた証跡
        # file_upload_evidence が、upload_allowed 真 かつ retrieved 真 かつ
        # retrieval_marker 非空(str) かつ retrieval_url 非空(str) のときのみ。
        # 1 つでも欠落すれば None（fail-closed・取得不可は確定に上げない）。
        upload_evidence = info.get("file_upload_evidence")
        if not isinstance(upload_evidence, dict):
            return None
        if upload_evidence.get("upload_allowed") is not True:
            return None
        if upload_evidence.get("retrieved") is not True:
            return None
        retrieval_marker = str(upload_evidence.get("retrieval_marker") or "").strip()
        retrieval_url = str(upload_evidence.get("retrieval_url") or "").strip()
        if not retrieval_marker or not retrieval_url:
            return None
        return "uploaded_file_retrieved"

    return None  # unknown category


def _has_vdp_impact_markers(info: Dict[str, Any]) -> bool:
    """VDP-style structured impact/repro markers (fail-closed: unknown
    markers are ignored)."""
    for key in _VDP_IMPACT_MARKERS:
        if bool(info.get(key)):
            return True
    return False


def evaluate_payout_grade(finding: dict) -> PayoutGradeResult:
    """The ONLY public payout-grade evaluation entry (SGK-2026-0441).

    Fail-closed: any missing evidence, missing impact, unknown category,
    or non-matching marker -> ``payout_grade=False`` with a stable reason
    code. Deterministic, raise-only, NO LLM calls. Accepts the dict shape
    produced by ``Finding.to_dict()`` (use ``finding_payload()`` to
    project Finding-like objects).
    """
    if not isinstance(finding, dict):
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_MISSING_EVIDENCE,
            evidence_refs=[],
            marker=None,
        )

    vuln_type = str(finding.get("vuln_type") or "").strip().lower()
    evidence = finding.get("evidence")
    info = finding.get("additional_info")
    if not isinstance(evidence, dict):
        evidence = {}
    if not isinstance(info, dict):
        info = {}

    # 1) Reproducibility — structured Evidence-style fields OR complete
    #    additional_info PoC pair.
    ev_method = str(evidence.get("request_method") or "").strip()
    ev_url = str(evidence.get("request_url") or "").strip()
    ev_status_ok = _response_status_ok(evidence.get("response_status"))
    ev_body = str(evidence.get("response_body") or "")
    refs: List[str] = []
    if ev_method and ev_url and ev_status_ok and ev_body:
        refs = [
            "evidence.request_method",
            "evidence.request_url",
            "evidence.response_status",
            "evidence.response_body",
        ]
    else:
        poc_request = str(info.get("poc_request") or "")
        poc_response = str(info.get("poc_response") or "")
        if _poc_request_complete(poc_request) and _poc_response_complete(poc_response):
            refs = ["additional_info.poc_request", "additional_info.poc_response"]
        else:
            partial_refs: List[str] = []
            if ev_method:
                partial_refs.append("evidence.request_method")
            if ev_url:
                partial_refs.append("evidence.request_url")
            if ev_status_ok:
                partial_refs.append("evidence.response_status")
            if ev_body:
                partial_refs.append("evidence.response_body")
            if poc_request or poc_response:
                return PayoutGradeResult(
                    payout_grade=False,
                    reason=_REASON_NOT_REPRODUCIBLE,
                    evidence_refs=partial_refs,
                    marker=None,
                )
            return PayoutGradeResult(
                payout_grade=False,
                reason=_REASON_MISSING_EVIDENCE,
                evidence_refs=partial_refs,
                marker=None,
            )

    # 2) Firing marker (category-specific, deterministic).
    expected_marker = _MARKER_CATEGORIES.get(vuln_type)
    if expected_marker is None:
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_UNKNOWN_CATEGORY,
            evidence_refs=refs,
            marker=None,
        )
    marker = _match_firing_marker(vuln_type, evidence, info)
    if marker is None:
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_NO_FIRING_MARKER,
            evidence_refs=refs,
            marker=None,
        )

    # 3) Impact: non-empty impact + non-empty reproduction steps (or
    #    VDP-style structured markers).
    impact = str(finding.get("impact") or "").strip()
    steps = finding.get("reproduction_steps")
    if not isinstance(steps, list):
        steps = [steps] if isinstance(steps, str) and steps.strip() else []
    steps_ok = bool(steps) and all(str(step).strip() for step in steps)
    if not (impact and steps_ok) and not _has_vdp_impact_markers(info):
        return PayoutGradeResult(
            payout_grade=False,
            reason=_REASON_MISSING_IMPACT,
            evidence_refs=refs,
            marker=marker,
        )

    return PayoutGradeResult(
        payout_grade=True,
        reason=_REASON_PAYOUT_GRADE_SATISFIED,
        evidence_refs=refs,
        marker=marker,
    )


def payout_grade_stage(finding_id: str, result: PayoutGradeResult) -> Optional[str]:
    """Stage token for funnel emitters: ``"F4"`` when the result is
    payout-grade, else ``None``. Pure value return — this module never
    emits funnel events (the emitters live in ``manager.py``)."""
    if getattr(result, "payout_grade", False):
        return "F4"
    return None


def has_explicit_refute_signal(finding: Any) -> bool:
    """Fail-closed refute-signal detector (Phase-2 merge).

    True ONLY when the finding carries an explicit refutation marker
    (falsification/refuted keys, or a delivery payload explicitly
    marked undelivered). Absence of evidence is NEVER a refutation.
    """
    payload = finding_payload(finding)
    info = payload.get("additional_info")
    if not isinstance(info, dict):
        return False
    if any(bool(info.get(key)) for key in _REFUTE_SIGNAL_KEYS):
        return True
    delivery = info.get("payload_delivery")
    if isinstance(delivery, dict) and delivery.get("delivered") is False:
        return True
    return False


def assert_read_only_probe(method: str, url: str) -> bool:
    """Phase-2 verification probes are GET-only (approved design).

    Returns True only for GET/HEAD/OPTIONS against a well-formed
    http(s) URL; anything else -> False (fail-closed: callers must NOT
    send the probe when False). The Phase-2 payout-grade re-send loop is
    wired by Lane B — this guard is the send boundary check it calls
    (the existing specialist send path stays untouched).
    """
    m = str(method or "").strip().upper()
    if m not in _READ_ONLY_METHODS:
        return False
    try:
        parsed = urlparse(str(url or ""))
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:  # noqa: BLE001 — boundary guard, fail closed
        return False
