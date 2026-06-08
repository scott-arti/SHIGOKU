"""
Stored XSS Detector - Phase X-2
X2-2〜X2-4: フォーム検出・マーカー注入・表示画面巡回・Playwright発火確認

設計方針:
- 「保存→表示」フロー追跡による Stored XSS 検出
- HITL 統合: 本番データ保存前・高リスクフォームは人間承認
- Safety-first: shigoku_probe_ プレフィックスで安全なマーカーを使用
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from uuid import uuid4

from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class FormRiskLevel(str, Enum):
    """フォームリスクレベル"""
    LOW = "low"        # 読み取り系
    MEDIUM = "medium"  # 作成・更新系
    HIGH = "high"      # 削除・管理系


@dataclass
class ParsedForm:
    """解析済みHTMLフォーム"""
    action: str
    method: str  # GET / POST
    params: Dict[str, str]  # name -> default value
    risk_level: FormRiskLevel = FormRiskLevel.MEDIUM
    
    def is_safe_to_auto_submit(self) -> bool:
        """HITLなしで自動送信可能かどうか"""
        return self.risk_level == FormRiskLevel.LOW


@dataclass
class MarkerReflection:
    """マーカー反射確認結果"""
    found: bool
    url: str
    context: str = ""         # HTML context: tag_attr / script / text
    raw_snippet: str = ""     # 反射周辺のHTMLスニペット


@dataclass
class StoredXSSFinding:
    """Stored XSS 検出結果"""
    entry_point: str           # 保存フォームのaction URL
    display_point: str         # 反射・発火した表示画面URL
    parameter: str             # 注入パラメータ名
    payload: str               # 使用したXSSペイロード
    marker: str                # 事前確認に使ったマーカー
    confidence: float          # 0.0-1.0
    context: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    hitl_required: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": "stored_xss",
            "entry_point": self.entry_point,
            "display_point": self.display_point,
            "parameter": self.parameter,
            "payload": self.payload,
            "marker": self.marker,
            "confidence": self.confidence,
            "context": self.context,
            "evidence": self.evidence,
        }


@dataclass
class HITLRequest:
    """人間承認要求"""
    reason: str
    form_action: str
    risk_level: FormRiskLevel
    data_to_submit: Dict[str, str]
    approved: bool = False
    ticket_id: str = ""
    status: str = "PENDING"
    channel: str = ""
    error_code: str = ""
    timestamp: str = ""


class HITLRequestStore:
    """XCTO-4: HITL承認要求の永続化ストア（最小実装）"""

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._rows: List[Dict[str, Any]] = []

    def save(self, req: HITLRequest) -> None:
        self._rows.append(
            {
                "ticket_id": req.ticket_id,
                "form_action": req.form_action,
                "risk_level": req.risk_level.value,
                "status": req.status,
                "timestamp": req.timestamp,
            }
        )

    def list_pending(self) -> List[Dict[str, Any]]:
        return [r for r in self._rows if r.get("status") == "PENDING"]


# ---------------------------------------------------------------------------
# HITL Gate
# ---------------------------------------------------------------------------

class HITLGate:
    """
    Human-in-the-Loop 承認ゲート

    HITL範囲定義:
      AI自動実行:      マーカー注入（低リスクフォーム）、マーカー反射確認、発火確認
      HITL必須承認:    本番データ保存前（中・高リスク）、スコープ外検出時
    """

    def __init__(
        self,
        auto_approve_low_risk: bool = True,
        approval_callback: Optional[Any] = None,
        request_store: Optional[HITLRequestStore] = None,
        notification_channel: Optional[Any] = None,
        notification_retry: int = 0,
        notification_backoff_seconds: Optional[List[float]] = None,
    ):
        self.auto_approve_low_risk = auto_approve_low_risk
        self.approval_callback = approval_callback
        self.request_store = request_store
        self.notification_channel = notification_channel
        self.notification_retry = max(0, int(notification_retry))
        self.notification_backoff_seconds = notification_backoff_seconds or []
        self._pending: List[HITLRequest] = []
        self._metrics: Dict[str, float] = {
            "total_requests": 0.0,
            "notification_attempts": 0.0,
            "notification_successes": 0.0,
            "approved_count": 0.0,
            "expired_count": 0.0,
            "fail_closed_count": 0.0,
            "approval_latency_total_seconds": 0.0,
        }

    async def request_approval(
        self,
        form: ParsedForm,
        data: Dict[str, str],
        reason: str,
    ) -> bool:
        """
        承認を要求。

        Returns:
            True  = 承認（実行可）
            False = 拒否（スキップ）
        """
        if self.auto_approve_low_risk and form.is_safe_to_auto_submit():
            logger.debug("[HITL] Auto-approved (low-risk): %s", form.action)
            return True

        self._metrics["total_requests"] += 1
        now = datetime.now(timezone.utc).isoformat()
        req = HITLRequest(
            reason=reason,
            form_action=form.action,
            risk_level=form.risk_level,
            data_to_submit=data,
            ticket_id=f"hitl-{uuid4().hex}",
            status="PENDING",
            timestamp=now,
        )

        # 外部承認コールバック（最優先）
        if self.approval_callback is not None:
            try:
                approved = await self.approval_callback(req)
                req.approved = bool(approved)
                req.status = "APPROVED" if req.approved else "REJECTED"
                if req.approved:
                    self._metrics["approved_count"] += 1
                    return True
                self._pending.append(req)
                if self.request_store is not None:
                    self.request_store.save(req)
                return False
            except Exception:
                req.error_code = "approval_callback_error"
                req.status = "REJECTED"
                self._metrics["fail_closed_count"] += 1
                self._pending.append(req)
                if self.request_store is not None:
                    self.request_store.save(req)
                return False

        # 通知チャネル経由（fail-closed）
        if self.notification_channel is not None:
            attempts = self.notification_retry + 1
            last_error = ""
            for attempt in range(attempts):
                self._metrics["notification_attempts"] += 1
                try:
                    ticket_id = await self.notification_channel.send(req)
                    req.channel = self.notification_channel.__class__.__name__
                    if ticket_id:
                        req.ticket_id = str(ticket_id)
                    self._metrics["notification_successes"] += 1
                    break
                except Exception as e:
                    last_error = str(e)
                    if attempt < attempts - 1:
                        delay = (
                            self.notification_backoff_seconds[attempt]
                            if attempt < len(self.notification_backoff_seconds)
                            else 0.0
                        )
                        if delay > 0:
                            await asyncio.sleep(delay)
                    else:
                        req.error_code = "notification_failed"
                        req.channel = self.notification_channel.__class__.__name__
                        req.status = "PENDING"
                        self._metrics["fail_closed_count"] += 1
                        self._pending.append(req)
                        if self.request_store is not None:
                            self.request_store.save(req)
                        logger.warning(
                            "[HITL] Notification failed for %s: %s",
                            form.action,
                            last_error,
                        )
                        return False

        self._pending.append(req)
        if self.request_store is not None:
            self.request_store.save(req)

        # 実際の HITL 実装では WebSocket / CLI プロンプト等で通知するが、
        # 現フェーズでは pending リストに積んで「承認待ち」とする。
        logger.warning(
            "[HITL] Approval required for %s (risk=%s): %s",
            form.action, form.risk_level.value, reason,
        )
        # NOTE: 将来的には await notification_channel.wait_for_approval(req)
        return False  # デフォルト: 本番保存は自動実行しない

    def get_pending_requests(self) -> List[HITLRequest]:
        return list(self._pending)

    def transition_request(self, ticket_id: str, from_status: str, to_status: str) -> bool:
        """XCTO-4: 単方向状態遷移（CAS的チェック）"""
        allowed = {
            "PENDING": {"APPROVED", "REJECTED", "EXPIRED"},
            "APPROVED": set(),
            "REJECTED": set(),
            "EXPIRED": set(),
        }
        for req in self._pending:
            if req.ticket_id != ticket_id:
                continue
            if req.status != from_status:
                return False
            if to_status not in allowed.get(from_status, set()):
                return False
            req.status = to_status
            if to_status == "APPROVED":
                req.approved = True
                self._metrics["approved_count"] += 1
            if to_status == "EXPIRED":
                self._metrics["expired_count"] += 1
            return True
        return False

    def get_metrics(self) -> Dict[str, float]:
        """XCTO-4 KPI出力"""
        total_requests = self._metrics["total_requests"]
        notification_attempts = self._metrics["notification_attempts"]
        delivery_rate = (
            self._metrics["notification_successes"] / notification_attempts
            if notification_attempts > 0 else 0.0
        )
        approval_rate = (
            self._metrics["approved_count"] / total_requests
            if total_requests > 0 else 0.0
        )
        expiration_rate = (
            self._metrics["expired_count"] / total_requests
            if total_requests > 0 else 0.0
        )
        fail_closed_rate = (
            self._metrics["fail_closed_count"] / total_requests
            if total_requests > 0 else 0.0
        )
        avg_approval_latency = (
            self._metrics["approval_latency_total_seconds"] / self._metrics["approved_count"]
            if self._metrics["approved_count"] > 0 else 0.0
        )
        return {
            "notification_delivery_rate": delivery_rate,
            "approval_rate": approval_rate,
            "avg_approval_latency_seconds": avg_approval_latency,
            "expiration_rate": expiration_rate,
            "fail_closed_rate": fail_closed_rate,
        }


# ---------------------------------------------------------------------------
# Form Detector (X2-2 helper)
# ---------------------------------------------------------------------------

class FormDetector:
    """HTMLフォームの検出・リスク分類"""

    # 削除・管理系フォームのキーワード（高リスク）
    _HIGH_RISK_KEYWORDS = frozenset(
        ["delete", "remove", "destroy", "admin", "reset", "purge"]
    )
    # 更新・作成系（中リスク）
    _MEDIUM_RISK_KEYWORDS = frozenset(
        ["create", "update", "edit", "post", "submit", "save", "add"]
    )

    def classify_risk(self, form_action: str, method: str) -> FormRiskLevel:
        """フォームのリスクレベルを分類"""
        path_lower = urlparse(form_action).path.lower()
        
        if any(kw in path_lower for kw in self._HIGH_RISK_KEYWORDS):
            return FormRiskLevel.HIGH
        if method.upper() == "POST" or any(
            kw in path_lower for kw in self._MEDIUM_RISK_KEYWORDS
        ):
            return FormRiskLevel.MEDIUM
        return FormRiskLevel.LOW

    async def detect_forms(
        self, url: str, headers: Optional[Dict[str, str]] = None
    ) -> List[ParsedForm]:
        """URLからHTMLフォームを検出・解析"""
        from src.core.infra.network_client import AsyncNetworkClient

        forms: List[ParsedForm] = []
        try:
            client = AsyncNetworkClient()
            resp = await client.request("GET", url, headers=headers or {})
            body = (
                resp.get("body", "") if isinstance(resp, dict)
                else getattr(resp, "text", "")
            )
            await client.close()
        except Exception as e:
            logger.warning("[StoredXSS] Form fetch failed for %s: %s", url, e)
            return forms

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body, "html.parser")

            for form_tag in soup.find_all("form"):
                raw_action = form_tag.get("action", url)
                action = urljoin(url, raw_action)
                method = form_tag.get("method", "GET").upper()

                params: Dict[str, str] = {}
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        params[name] = inp.get("value", "")

                risk = self.classify_risk(action, method)
                forms.append(ParsedForm(
                    action=action,
                    method=method,
                    params=params,
                    risk_level=risk,
                ))

        except ImportError:
            logger.warning("[StoredXSS] BeautifulSoup not available")
        except Exception as e:
            logger.warning("[StoredXSS] Form parse error: %s", e)

        return forms


# ---------------------------------------------------------------------------
# Display URL Resolver (X2-3 helper)
# ---------------------------------------------------------------------------

class DisplayURLResolver:
    """
    表示画面URL推定エンジン

    戦略:
    1. パスパターン推測 (/create → /list, /index)
    2. レスポンスのリダイレクト追跡
    3. レスポンスボディ内リンク解析
    """

    _DISPLAY_SUFFIX_MAP: Dict[str, List[str]] = {
        "/create": ["/list", "/index", "/", "../"],
        "/add":    ["/list", "/index", "/"],
        "/post":   ["/", "/feed", "/list"],
        "/new":    ["/list", "/index", "/"],
        "/submit": ["/", "/result", "/list"],
    }

    @staticmethod
    def is_in_scope(url: str, origin_url: str) -> bool:
        """
        url が origin_url と同一オリジン（scheme + netloc）かを確認。

        form.action が相対パスの場合は urljoin で絶対化してから渡すこと。
        スコープ外URLへのアクセスは Bug Bounty 即失格リスクのため必須チェック。
        """
        o = urlparse(origin_url)
        t = urlparse(url)
        return (
            bool(o.netloc)              # origin が絶対URLであること
            and o.scheme == t.scheme
            and o.netloc == t.netloc
        )

    def resolve(self, form: ParsedForm, page_url: str = "") -> List[str]:
        """
        フォームアクションから表示画面URLを推測。

        Args:
            form: 解析済みフォーム
            page_url: フォームが存在するページのURL（相対 action の絶対化に使用）
        """
        # form.action が相対パスの場合は page_url で絶対化
        absolute_action = urljoin(page_url, form.action) if page_url else form.action
        path = urlparse(absolute_action).path.rstrip("/")
        base = f"{urlparse(absolute_action).scheme}://{urlparse(absolute_action).netloc}"
        
        candidates: List[str] = []

        # 1. パターンマッチで推測
        for suffix, display_paths in self._DISPLAY_SUFFIX_MAP.items():
            if path.endswith(suffix):
                for dp in display_paths:
                    parent = path[: -len(suffix)]
                    candidates.append(urljoin(base, parent + dp))

        # 2. 末尾のパスセグメントを除いた URL も候補に
        parent_path = "/".join(path.split("/")[:-1]) or "/"
        candidates.append(urljoin(base, parent_path))

        # 3. ルートも常に候補
        candidates.append(base + "/")

        # 4. スコープ外（別オリジン）を除去
        in_scope = [
            u for u in dict.fromkeys(candidates)
            if self.is_in_scope(u, absolute_action)
        ]
        return in_scope

    @staticmethod
    def extract_from_response_headers(
        headers: Dict[str, str],
        base_url: str,
    ) -> List[str]:
        """
        Location / X-Resource-Id レスポンスヘッダーから表示画面URLを取得。

        RESTful API (POST /api/v1/messages -> GET /api/v1/messages/{id}) のような
        パターンマップで特定できないケースに対応する。

        Args:
            headers: レスポンスヘッダー (lowercase key)
            base_url: フォームアクションの絶対URL

        Returns:
            候補URLリスト
        """
        candidates: List[str] = []

        if "location" in headers:
            # urljoin は Location が絶対URLの場合それを優先するため、
            # スコープ外（別オリジン）になり得る。ここでチェックして除外する。
            candidate = urljoin(base_url, headers["location"])
            if DisplayURLResolver.is_in_scope(candidate, base_url):
                candidates.append(candidate)

        if "x-resource-id" in headers:
            resource_id = headers["x-resource-id"]
            parsed = urlparse(base_url)
            parent = "/".join(parsed.path.rstrip("/").split("/")[:-1]) or "/"
            candidate = urljoin(
                f"{parsed.scheme}://{parsed.netloc}",
                f"{parent}/{resource_id}",
            )
            if DisplayURLResolver.is_in_scope(candidate, base_url):
                candidates.append(candidate)

        return candidates

    async def extract_from_response_links(
        self,
        response_body: str,
        base_url: str,
    ) -> List[str]:
        """レスポンスボディ内の全リンクを抽出"""
        links: List[str] = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(response_body, "html.parser")
            for tag in soup.find_all("a", href=True):
                href = urljoin(base_url, tag["href"])
                links.append(href)
        except Exception:
            pass
        return links


# ---------------------------------------------------------------------------
# Reflection Context Analyzer
# ---------------------------------------------------------------------------

_CONTEXT_PATTERNS = [
    ("script_block",   re.compile(r"<script[^>]*>[^<]*{marker}[^<]*</script>", re.I)),
    ("tag_attribute",  re.compile(r'<[^>]+(?:href|src|action|data-[^=]*)=["\']?[^"\']*{marker}', re.I)),
    ("html_text",      re.compile(r"{marker}", re.I)),
]


def _classify_reflection_context(html: str, marker: str) -> str:
    """マーカーが反射しているHTML文脈を分類"""
    for context_name, pattern in _CONTEXT_PATTERNS:
        compiled = re.compile(pattern.pattern.replace("{marker}", re.escape(marker)), re.I)
        if compiled.search(html):
            return context_name
    return "unknown"


def _extract_snippet(html: str, marker: str, window: int = 100) -> str:
    """マーカー周辺のHTMLスニペットを抽出"""
    idx = html.lower().find(marker.lower())
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end = min(len(html), idx + len(marker) + window)
    return html[start:end]


# ---------------------------------------------------------------------------
# Payload Generator
# ---------------------------------------------------------------------------

class XSSPayloadGenerator:
    """コンテキスト対応XSSペイロード生成"""

    _PAYLOADS: Dict[str, List[str]] = {
        "html_text": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ],
        "tag_attribute": [
            '"><script>alert(1)</script>',
            "' onmouseover=alert(1) x='",
            '" autofocus onfocus=alert(1) "',
        ],
        "script_block": [
            "';alert(1)//",
            '";alert(1)//',
            "`${alert(1)}`",
        ],
        "unknown": [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
        ],
    }

    def generate(self, context: str) -> List[str]:
        """文脈に応じたペイロードリストを返却"""
        return self._PAYLOADS.get(context, self._PAYLOADS["unknown"])


# ---------------------------------------------------------------------------
# StoredXSSDetector (main class)
# ---------------------------------------------------------------------------

class StoredXSSDetector:
    """
    Stored XSS 検出エンジン (X2-2 〜 X2-4)

    検出フロー:
        1. フォーム検出（FormDetector）
        2. HITL承認 → 安全なマーカー注入
        3. 表示画面URL特定（DisplayURLResolver）
        4. マーカー反射確認
        5. HITL承認 → XSSペイロード注入
        6. 表示画面でPlaywright発火確認（オプション）
    """

    def __init__(
        self,
        hitl_gate: Optional[HITLGate] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        use_playwright: bool = False,
        allowed_domains: Optional[List[str]] = None,
    ):
        self.hitl = hitl_gate or HITLGate(auto_approve_low_risk=True)
        self.auth_headers = auth_headers or {}
        self.use_playwright = use_playwright
        # Bug Bounty スコープ設定: None の場合は origin と同一 netloc のみ許可
        # サブドメインを含む場合は例: ["example.com", "api.example.com"] を渡す
        self.allowed_domains: Optional[List[str]] = allowed_domains

        self._form_detector = FormDetector()
        self._url_resolver = DisplayURLResolver()
        self._payload_gen = XSSPayloadGenerator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(self, target_url: str) -> List[StoredXSSFinding]:
        """
        ターゲットURLの全フォームに対してStored XSS検出を実行

        Args:
            target_url: スキャン対象URL

        Returns:
            List[StoredXSSFinding]: 検出されたStored XSS脆弱性
        """
        logger.info("[StoredXSS] Starting scan: %s", target_url)
        findings: List[StoredXSSFinding] = []

        forms = await self._form_detector.detect_forms(target_url, self.auth_headers)
        logger.info("[StoredXSS] Detected %d form(s)", len(forms))

        for form in forms:
            form_findings = await self._scan_form(form)
            findings.extend(form_findings)

        logger.info("[StoredXSS] Scan complete. %d finding(s) found", len(findings))
        return findings

    # ------------------------------------------------------------------
    # Core detection logic
    # ------------------------------------------------------------------

    async def _scan_form(self, form: ParsedForm) -> List[StoredXSSFinding]:
        """1フォームに対するStored XSS検出"""
        findings: List[StoredXSSFinding] = []

        # Skip forms with no injectable params
        injectable = self._get_injectable_params(form)
        if not injectable:
            return findings

        # --- Step 1: Marker injection ---
        marker = self._generate_marker()
        marker_data = {**form.params, **{p: marker for p in injectable}}

        approved = await self.hitl.request_approval(
            form, marker_data,
            reason="Marker injection for Stored XSS probe"
        )
        if not approved:
            logger.info("[StoredXSS] HITL: marker injection skipped for %s", form.action)
            return findings

        submit_result = await self._submit_form(form, marker_data)
        if len(submit_result) == 2:
            submit_ok, response_body = submit_result
            resp_headers: Dict[str, str] = {}
        else:
            submit_ok, response_body, resp_headers = submit_result
        if not submit_ok:
            return findings

        # --- Step 2: Identify display URLs ---
        display_urls = [
            u for u in self._url_resolver.resolve(form, page_url=form.action)
            if self._is_url_allowed(u, form.action)
        ]
        # Location / X-Resource-Id ヘッダーから表示画面候補を追加
        header_urls = DisplayURLResolver.extract_from_response_headers(
            resp_headers, form.action
        )
        header_urls = [
            u for u in header_urls
            if self._is_url_allowed(u, form.action)
        ]
        # レスポンスボディ内リンクからも候補を追加
        extra_links = await self._url_resolver.extract_from_response_links(
            response_body, form.action
        )
        extra_links = [
            u for u in extra_links
            if self._is_url_allowed(u, form.action)
        ]
        display_urls = list(dict.fromkeys(display_urls + header_urls + extra_links))

        # --- Step 3: Check marker reflection ---
        reflections = await self._check_reflections(marker, display_urls)
        if not reflections:
            logger.debug("[StoredXSS] Marker not reflected on any display URL")
            return findings

        # --- Step 4: XSS payload injection per reflection ---
        for reflection in reflections:
            context = reflection.context
            payloads = self._payload_gen.generate(context)

            for payload in payloads[:2]:  # Limit to 2 payloads per context
                payload_data = {**form.params, **{p: payload for p in injectable}}

                approved = await self.hitl.request_approval(
                    form, payload_data,
                    reason=f"XSS payload injection (context={context})"
                )
                if not approved:
                    continue

                payload_submit_result = await self._submit_form(form, payload_data)
                if len(payload_submit_result) == 2:
                    submit_ok, _ = payload_submit_result
                else:
                    submit_ok, _, _hdrs = payload_submit_result
                if not submit_ok:
                    continue

                await asyncio.sleep(1)  # Allow storage propagation

                # --- Step 5: Verify execution ---
                executed, evidence = await self._verify_execution(
                    reflection.url, payload
                )

                if executed:
                    findings.append(StoredXSSFinding(
                        entry_point=form.action,
                        display_point=reflection.url,
                        parameter=injectable[0],
                        payload=payload,
                        marker=marker,
                        confidence=0.90,
                        context=context,
                        evidence=evidence,
                    ))
                    logger.warning(
                        "[StoredXSS] CONFIRMED: %s → %s [%s]",
                        form.action, reflection.url, context,
                    )
                    break  # One confirmed finding per form is enough

        return findings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_url_allowed(self, url: str, origin_url: str) -> bool:
        """
        url がスキャン許可スコープ内かを確認。

        - ``allowed_domains`` が設定されている場合: url の netloc がリスト内に含まれること
        - ``allowed_domains`` が None の場合: origin_url と同一 netloc (is_in_scope) であること

        Bug Bounty でサブドメインが複数スコープに含まれる場合は
        ``StoredXSSDetector(allowed_domains=["example.com", "api.example.com"])``
        のように渡すことで柔軟に対応できる。
        """
        if self.allowed_domains is not None:
            netloc = urlparse(url).netloc
            return netloc in self.allowed_domains
        return DisplayURLResolver.is_in_scope(url, origin_url)

    def _generate_marker(self) -> str:
        """安全なプローブマーカー生成（shigoku_probe_ プレフィックス）"""
        token = secrets.token_hex(8)
        return f"shigoku_probe_{token}"

    def _get_injectable_params(self, form: ParsedForm) -> List[str]:
        """注入対象パラメータを返却（hidden/submit系を除外）"""
        exclude_types_keywords = {"_token", "csrf", "submit", "action", "_method"}
        return [
            name for name in form.params
            if not any(kw in name.lower() for kw in exclude_types_keywords)
        ]

    async def _submit_form(
        self, form: ParsedForm, data: Dict[str, str]
    ) -> Tuple[bool, str, Dict[str, str]]:
        """
        フォームを送信してレスポンスを返却。

        Returns:
            (success, body, response_headers)
            response_headers は lowercase キー正規化済み。
        """
        try:
            client = AsyncNetworkClient()
            method = form.method.upper()

            if method == "POST":
                resp = await client.request(
                    "POST", form.action,
                    headers=self.auth_headers,
                    data=data,
                )
            else:
                from urllib.parse import urlencode
                url_with_params = f"{form.action}?{urlencode(data)}"
                resp = await client.request(
                    "GET", url_with_params,
                    headers=self.auth_headers,
                )

            await client.close()
            body = (
                resp.get("body", "") if isinstance(resp, dict)
                else getattr(resp, "text", "")
            )
            raw_headers: Dict[str, str] = (
                resp.get("headers", {}) if isinstance(resp, dict)
                else dict(getattr(resp, "headers", {}))
            )
            resp_headers = {k.lower(): v for k, v in raw_headers.items()}
            return True, body, resp_headers

        except Exception as e:
            logger.warning("[StoredXSS] Form submit failed: %s", e)
            return False, "", {}

    async def _check_reflections(
        self, marker: str, display_urls: List[str]
    ) -> List[MarkerReflection]:
        """複数の表示画面URLでマーカー反射を確認"""
        reflections: List[MarkerReflection] = []
        
        async def _check_one(url: str) -> Optional[MarkerReflection]:
            try:
                client = AsyncNetworkClient()
                resp = await client.request("GET", url, headers=self.auth_headers)
                await client.close()
                body = (
                    resp.get("body", "") if isinstance(resp, dict)
                    else getattr(resp, "text", "")
                )
                if marker.lower() in body.lower():
                    context = _classify_reflection_context(body, marker)
                    snippet = _extract_snippet(body, marker)
                    return MarkerReflection(
                        found=True, url=url,
                        context=context, raw_snippet=snippet
                    )
            except Exception as e:
                logger.debug("[StoredXSS] Reflection check failed for %s: %s", url, e)
            return None

        results = await asyncio.gather(*[_check_one(u) for u in display_urls])
        reflections = [r for r in results if r is not None]
        return reflections

    async def _verify_execution(
        self, display_url: str, payload: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        XSSペイロード発火確認

        X2-4: Playwright利用可能な場合はブラウザで確認。
        フォールバック: HTMLにペイロードが未エスケープで反射していれば confirmed。
        """
        if self.use_playwright:
            return await self._verify_with_playwright(display_url, payload)
        return await self._verify_with_static_check(display_url, payload)

    async def _verify_with_static_check(
        self, url: str, payload: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """静的確認: ペイロードが未エスケープで反射しているか"""
        try:
            client = AsyncNetworkClient()
            resp = await client.request("GET", url, headers=self.auth_headers)
            await client.close()
            body = (
                resp.get("body", "") if isinstance(resp, dict)
                else getattr(resp, "text", "")
            )
            # ペイロードの核心部分（<script> or onerror= 等）が未エスケープで存在するか
            key = payload.replace('"', "").replace("'", "")[:20]
            if key.lower() in body.lower():
                snippet = _extract_snippet(body, key)
                return True, {
                    "method": "static_reflection_check",
                    "url": url,
                    "snippet": snippet,
                }
        except Exception as e:
            logger.debug("[StoredXSS] Static verify failed: %s", e)

        return False, {}

    async def _verify_with_playwright(
        self, url: str, payload: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """Playwright でダイアログ発火を確認"""
        try:
            from playwright.async_api import async_playwright

            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                page = await browser.new_page()

                dialog_fired = asyncio.Event()
                dialog_message: Optional[str] = None

                async def handle_dialog(dialog):
                    nonlocal dialog_message
                    dialog_message = dialog.message
                    dialog_fired.set()
                    await dialog.dismiss()

                page.on("dialog", handle_dialog)
                await page.goto(url, wait_until="networkidle", timeout=10000)

                try:
                    await asyncio.wait_for(dialog_fired.wait(), timeout=3.0)
                    executed = True
                except asyncio.TimeoutError:
                    executed = False

                await browser.close()

            return executed, {
                "method": "playwright_dialog",
                "url": url,
                "dialog_message": dialog_message,
            }

        except ImportError:
            logger.debug("[StoredXSS] Playwright not installed, falling back to static check")
            return await self._verify_with_static_check(url, payload)
        except Exception as e:
            logger.warning("[StoredXSS] Playwright verify error: %s", e)
            return False, {}
