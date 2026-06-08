"""
ProxyLogAnalyzer: Caido/Burpプロキシログ解析

手動調査（プロキシ経由ブラウジング）で収集したHTTPログを解析し、
攻撃価値のあるリクエストを抽出。適切なエージェントを推奨する。

機能:
1. ノイズ除去: 静的アセット、無関係ドメインを除外
2. 匂い検知: IDOR候補、隠しパラメータ、認証異常を検出
3. 攻撃プラン生成: 推奨エージェントと優先度を提案
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs


class SmellType(Enum):
    """検出する「匂い」の種類"""
    IDOR_CANDIDATE = "idor_candidate"          # ID/UUIDパラメータ
    HIDDEN_PARAM = "hidden_param"              # 隠しパラメータ
    AUTH_ANOMALY = "auth_anomaly"              # 認証異常
    JWT_DETECTED = "jwt_detected"              # JWT検出
    OAUTH_FLOW = "oauth_flow"                  # OAuthフロー
    MFA_FLOW = "mfa_flow"                      # MFAフロー
    SENSITIVE_DATA = "sensitive_data"          # 機密データ露出
    API_VERSIONING = "api_versioning"          # バージョン付きAPI
    ADMIN_ENDPOINT = "admin_endpoint"          # 管理者エンドポイント
    PAYMENT_ENDPOINT = "payment_endpoint"      # 決済/支払いエンドポイント
    STATE_MACHINE_SMELL = "state_machine_smell" # 順序依存性/状態遷移の異常


@dataclass
class HttpEntry:
    """パース済みHTTPエントリ"""
    method: str
    url: str
    host: str
    path: str
    query_params: dict
    request_headers: dict
    request_body: str
    status_code: int
    response_headers: dict
    response_body: str
    timestamp: Optional[datetime] = None
    
    def get_header(self, name: str, default: str = "") -> str:
        """ヘッダーを大文字小文字無視で取得"""
        for k, v in self.request_headers.items():
            if k.lower() == name.lower():
                return v
        return default


@dataclass
class FindingCandidate:
    """脆弱性仮説（攻撃前の候補）"""
    smell_type: SmellType
    target_url: str
    method: str
    evidence: str              # 検出の根拠
    parameters: dict = field(default_factory=dict)  # 関連パラメータ
    confidence: float = 0.5    # 0.0-1.0
    
    def __post_init__(self):
        import hashlib
        content = f"{self.smell_type.value}:{self.target_url}:{self.method}"
        self.id = hashlib.md5(content.encode()).hexdigest()[:8]


@dataclass
class AttackPlan:
    """推奨される攻撃プラン"""
    target_url: str
    method: str
    candidate: FindingCandidate
    recommended_agent: str     # "jwt_inspector", "oauth_dancer", etc.
    priority: int              # 1-5 (5が最高)
    rationale: str             # なぜこの攻撃を推奨するか
    attack_params: dict = field(default_factory=dict)  # エージェントに渡すパラメータ
    
    def to_dict(self) -> dict:
        return {
            "id": self.candidate.id,
            "target_url": self.target_url,
            "method": self.method,
            "smell_type": self.candidate.smell_type.value,
            "recommended_agent": self.recommended_agent,
            "priority": self.priority,
            "rationale": self.rationale,
        }


class ProxyLogAnalyzer:
    """
    プロキシログ解析クラス
    
    Caido/BurpからエクスポートされたJSONログを解析し、
    攻撃価値のあるリクエストを抽出する。
    """
    
    # ノイズ除去: 静的アセット拡張子
    STATIC_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".mp3", ".webm", ".pdf", ".zip",
    }
    
    # ノイズ除去: 無関係ドメイン
    NOISE_DOMAINS = {
        "google-analytics.com", "googletagmanager.com", "doubleclick.net",
        "facebook.com", "facebook.net", "twitter.com",
        "fonts.googleapis.com", "fonts.gstatic.com",
        "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
        "sentry.io", "newrelic.com", "datadoghq.com",
    }
    
    # ノイズ除去: 無関係パス
    NOISE_PATHS = {
        "/favicon.ico", "/robots.txt", "/sitemap.xml",
        "/.well-known/", "/wp-includes/", "/wp-content/",
    }
    
    # IDOR検出パターン
    IDOR_PATTERNS = [
        r"[?&](user_?id|account_?id|profile_?id|customer_?id)=(\d+)",
        r"[?&](id|uid|pid)=(\d+)",
        r"/users?/(\d+)",
        r"/accounts?/(\d+)",
        r"/profiles?/(\d+)",
        r"[?&][a-z_]*uuid=([a-f0-9-]{36})",
        r"/([a-f0-9-]{36})/",
    ]
    
    # 隠しパラメータパターン
    HIDDEN_PARAM_PATTERNS = [
        r"[?&](admin|is_?admin|role|user_?role)=(false|0|user|guest)",
        r"[?&](debug|test|dev|internal)=(false|0|off)",
        r"[?&](verified|enabled|active|approved)=(true|1|yes)",
        r'"(admin|role|is_admin|permissions?)"\s*:\s*"?(false|user|guest|0)"?',
    ]
    
    # 認証関連ヘッダー
    AUTH_HEADERS = ["authorization", "x-auth-token", "x-api-key", "x-access-token"]
    
    # SmellType → 推奨エージェント マッピング
    AGENT_MAPPING = {
        SmellType.IDOR_CANDIDATE: ("bizlogic_hunter", 4, "IDOR vulnerability potential - test with different user IDs"),
        SmellType.HIDDEN_PARAM: ("bizlogic_hunter", 4, "Hidden parameter manipulation may bypass access control"),
        SmellType.AUTH_ANOMALY: ("auth_ninja", 3, "Authentication implementation may have flaws"),
        SmellType.JWT_DETECTED: ("jwt_inspector", 5, "JWT token detected - test for algorithm confusion"),
        SmellType.OAUTH_FLOW: ("oauth_dancer", 4, "OAuth flow detected - test for redirect_uri bypass"),
        SmellType.MFA_FLOW: ("mfa_bypasser", 5, "MFA flow detected - test for bypass vulnerabilities"),
        SmellType.ADMIN_ENDPOINT: ("bizlogic_hunter", 5, "Admin endpoint - high-value target"),
        SmellType.API_VERSIONING: ("bizlogic_hunter", 2, "Older API version may have vulnerabilities"),
        SmellType.PAYMENT_ENDPOINT: ("bizlogic_hunter", 5, "Payment endpoint - manual verification required"),
        SmellType.STATE_MACHINE_SMELL: ("bizlogic_hunter", 4, "Potential state machine bypass - check for sequence enforcement"),
    }
    
    def __init__(self, scope_domains: Optional[list[str]] = None):
        """
        Args:
            scope_domains: スコープ内ドメインのリスト（Noneなら全て対象）
        """
        self.scope_domains = scope_domains or []
        self._entries: list[HttpEntry] = []
        self._candidates: list[FindingCandidate] = []
    
    def load_json(self, file_path: str) -> int:
        """
        JSONログファイルを読み込み
        
        Args:
            file_path: JSONファイルのパス
        
        Returns:
            読み込んだエントリ数
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        # HAR形式かどうかを判定
        if isinstance(data, dict) and "log" in data:
            return self._parse_har(data)
        elif isinstance(data, list):
            return self._parse_caido_json(data)
        else:
            raise ValueError("Unsupported JSON format")
    
    def _parse_har(self, data: dict) -> int:
        """HAR形式をパース"""
        entries = data.get("log", {}).get("entries", [])
        count = 0
        
        for entry in entries:
            request = entry.get("request", {})
            response = entry.get("response", {})
            
            url = request.get("url", "")
            parsed = urlparse(url)
            
            # リクエストヘッダーを辞書に
            req_headers = {}
            for h in request.get("headers", []):
                req_headers[h.get("name", "")] = h.get("value", "")
            
            # レスポンスヘッダーを辞書に
            resp_headers = {}
            for h in response.get("headers", []):
                resp_headers[h.get("name", "")] = h.get("value", "")
            
            # POSTデータ
            post_data = ""
            if request.get("postData"):
                post_data = request["postData"].get("text", "")
            
            # レスポンスボディ
            resp_body = ""
            if response.get("content"):
                resp_body = response["content"].get("text", "")
            
            http_entry = HttpEntry(
                method=request.get("method", "GET"),
                url=url,
                host=parsed.netloc,
                path=parsed.path,
                query_params=parse_qs(parsed.query),
                request_headers=req_headers,
                request_body=post_data,
                status_code=response.get("status", 0),
                response_headers=resp_headers,
                response_body=resp_body,
            )
            
            self._entries.append(http_entry)
            count += 1
        
        return count
    
    def _parse_caido_json(self, data: list) -> int:
        """Caido JSON形式をパース"""
        count = 0
        
        for entry in data:
            # Caidoの一般的なJSON構造に対応
            request = entry.get("request", entry)
            response = entry.get("response", {})
            
            url = request.get("url", "")
            if not url and "host" in request:
                scheme = "https" if request.get("tls", True) else "http"
                url = f"{scheme}://{request['host']}{request.get('path', '/')}"
            
            parsed = urlparse(url)
            
            # ヘッダー処理
            req_headers = request.get("headers", {})
            if isinstance(req_headers, list):
                req_headers = {h.get("name", ""): h.get("value", "") for h in req_headers}
            
            resp_headers = response.get("headers", {})
            if isinstance(resp_headers, list):
                resp_headers = {h.get("name", ""): h.get("value", "") for h in resp_headers}
            
            http_entry = HttpEntry(
                method=request.get("method", "GET"),
                url=url,
                host=parsed.netloc or request.get("host", ""),
                path=parsed.path or request.get("path", "/"),
                query_params=parse_qs(parsed.query),
                request_headers=req_headers,
                request_body=request.get("body", ""),
                status_code=response.get("statusCode", response.get("status", 0)),
                response_headers=resp_headers,
                response_body=response.get("body", ""),
            )
            
            self._entries.append(http_entry)
            count += 1
        
        return count
    
    def filter_noise(self) -> int:
        """
        ノイズを除去
        
        Returns:
            除去後のエントリ数
        """
        filtered = []
        
        for entry in self._entries:
            # 静的アセット除外
            path_lower = entry.path.lower()
            if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
                continue
            
            # ノイズドメイン除外
            host_lower = entry.host.lower()
            if any(noise in host_lower for noise in self.NOISE_DOMAINS):
                continue
            
            # ノイズパス除外
            if any(noise in path_lower for noise in self.NOISE_PATHS):
                continue
            
            # スコープチェック（設定されている場合）
            if self.scope_domains:
                in_scope = any(
                    scope in host_lower or host_lower.endswith(f".{scope}")
                    for scope in self.scope_domains
                )
                if not in_scope:
                    continue
            
            filtered.append(entry)
        
        self._entries = filtered
        return len(filtered)
    
    def detect_smells(self) -> list[FindingCandidate]:
        """
        「匂い」を検知
        
        Returns:
            FindingCandidateのリスト
        """
        self._candidates = []
        
        for entry in self._entries:
            # 1. IDOR候補検出
            self._detect_idor(entry)
            
            # 2. 隠しパラメータ検出
            self._detect_hidden_params(entry)
            
            # 3. 認証異常検出
            self._detect_auth_anomaly(entry)
            
            # 4. JWT検出
            self._detect_jwt(entry)
            
            # 5. OAuth/MFA検出
            self._detect_auth_flows(entry)
            
            # 6. 管理者エンドポイント検出
            self._detect_admin_endpoint(entry)
            
            # 7. 決済エンドポイント検出
            self._detect_payment_endpoint(entry)
        
        return self._candidates
    
    def _detect_idor(self, entry: HttpEntry) -> None:
        """IDOR候補を検出"""
        full_url = entry.url + entry.request_body
        
        for pattern in self.IDOR_PATTERNS:
            matches = re.findall(pattern, full_url, re.IGNORECASE)
            if matches:
                self._candidates.append(FindingCandidate(
                    smell_type=SmellType.IDOR_CANDIDATE,
                    target_url=entry.url,
                    method=entry.method,
                    evidence=f"ID parameter detected: {matches[0]}",
                    parameters={"matches": matches},
                    confidence=0.7,
                ))
                break
    
    def _detect_hidden_params(self, entry: HttpEntry) -> None:
        """隠しパラメータを検出"""
        search_text = entry.url + entry.request_body
        
        for pattern in self.HIDDEN_PARAM_PATTERNS:
            matches = re.findall(pattern, search_text, re.IGNORECASE)
            if matches:
                self._candidates.append(FindingCandidate(
                    smell_type=SmellType.HIDDEN_PARAM,
                    target_url=entry.url,
                    method=entry.method,
                    evidence=f"Hidden parameter: {matches[0]}",
                    parameters={"param": matches[0]},
                    confidence=0.8,
                ))
    
    def _detect_auth_anomaly(self, entry: HttpEntry) -> None:
        """認証異常を検出"""
        has_auth_header = any(
            entry.get_header(h) for h in self.AUTH_HEADERS
        )
        has_cookie = bool(entry.get_header("cookie"))
        
        # Authヘッダーあり & Cookie無し → API認証のみ
        if has_auth_header and not has_cookie:
            self._candidates.append(FindingCandidate(
                smell_type=SmellType.AUTH_ANOMALY,
                target_url=entry.url,
                method=entry.method,
                evidence="Auth header present but no cookie - API-only auth",
                parameters={"auth_type": "header_only"},
                confidence=0.5,
            ))
        
        # Cookie有り & Authヘッダー無し & APIエンドポイントっぽい
        if has_cookie and not has_auth_header and "/api/" in entry.path.lower():
            self._candidates.append(FindingCandidate(
                smell_type=SmellType.AUTH_ANOMALY,
                target_url=entry.url,
                method=entry.method,
                evidence="API endpoint using cookie auth - may lack CSRF protection",
                parameters={"auth_type": "cookie_only"},
                confidence=0.6,
            ))
    
    def _detect_jwt(self, entry: HttpEntry) -> None:
        """JWT検出"""
        auth_header = entry.get_header("authorization")
        
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
            if token.count(".") == 2 and token.startswith("eyJ"):
                self._candidates.append(FindingCandidate(
                    smell_type=SmellType.JWT_DETECTED,
                    target_url=entry.url,
                    method=entry.method,
                    evidence=f"JWT token: {token[:50]}...",
                    parameters={"token": token},
                    confidence=0.9,
                ))
    
    def _detect_auth_flows(self, entry: HttpEntry) -> None:
        """OAuth/MFAフローを検出"""
        path_lower = entry.path.lower()
        url_lower = entry.url.lower()
        
        # OAuth検出
        oauth_patterns = ["/oauth", "/authorize", "/token", "redirect_uri=", "client_id="]
        if any(p in url_lower for p in oauth_patterns):
            self._candidates.append(FindingCandidate(
                smell_type=SmellType.OAUTH_FLOW,
                target_url=entry.url,
                method=entry.method,
                evidence="OAuth flow endpoint detected",
                parameters=dict(entry.query_params),
                confidence=0.8,
            ))
        
        # MFA検出
        mfa_patterns = ["/mfa", "/2fa", "/totp", "/verify-code", "/challenge"]
        if any(p in path_lower for p in mfa_patterns):
            self._candidates.append(FindingCandidate(
                smell_type=SmellType.MFA_FLOW,
                target_url=entry.url,
                method=entry.method,
                evidence="MFA flow endpoint detected",
                parameters={},
                confidence=0.8,
            ))
    
    def _detect_admin_endpoint(self, entry: HttpEntry) -> None:
        """管理者エンドポイント検出"""
        path_lower = entry.path.lower()
        admin_patterns = [
            "/admin",
            "/manage",
            "/dashboard",
            "/internal",
            "/staff",
            "/authbypass",
            "/get_user_data",
            "/user_data",
        ]
        
        if any(p in path_lower for p in admin_patterns):
            self._candidates.append(FindingCandidate(
                smell_type=SmellType.ADMIN_ENDPOINT,
                target_url=entry.url,
                method=entry.method,
                evidence=f"Admin endpoint: {entry.path}",
                parameters={},
                confidence=0.7,
            ))
    
    def _detect_payment_endpoint(self, entry: HttpEntry) -> None:
        """決済エンドポイント検出（検出のみ、実行せず人間に通知）"""
        path_lower = entry.path.lower()
        body_lower = entry.request_body.lower() if entry.request_body else ""
        
        # 決済関連パス
        payment_patterns = [
            "/payment", "/pay", "/checkout", "/purchase", "/order",
            "/transaction", "/billing", "/invoice", "/charge", "/subscribe"
        ]
        
        # 決済関連パラメータ
        payment_params = ["amount", "price", "quantity", "currency", "total", "discount", "coupon"]
        
        is_payment_path = any(p in path_lower for p in payment_patterns)
        has_payment_param = any(p in body_lower or p in entry.url.lower() for p in payment_params)
        
        if is_payment_path or (entry.method == "POST" and has_payment_param):
            # 検出されたリスクパラメータ
            detected_risks = []
            if "amount" in body_lower or "amount" in entry.url.lower():
                detected_risks.append("amount_manipulation")
            if "quantity" in body_lower or "quantity" in entry.url.lower():
                detected_risks.append("quantity_manipulation")
            if "coupon" in body_lower or "discount" in body_lower:
                detected_risks.append("coupon_abuse")
            if "currency" in body_lower:
                detected_risks.append("currency_mismatch")
            
            self._candidates.append(FindingCandidate(
                smell_type=SmellType.PAYMENT_ENDPOINT,
                target_url=entry.url,
                method=entry.method,
                evidence=f"Payment endpoint detected: {entry.path}",
                parameters={"risks": detected_risks, "requires_manual_testing": True},
                confidence=0.9,
            ))
    
    def _llm_rank_candidate(self, candidate: FindingCandidate, entry: HttpEntry) -> float:
        """
        LLMを使用してFindingCandidateのリスクを再評価
        
        正規表現で「曖昧（Confidence 0.4-0.7）」と判定されたエントリのみ適用。
        
        Args:
            candidate: 評価対象の候補
            entry: HTTPエントリ
        
        Returns:
            LLMによる新しいConfidence値 (0.0-1.0)
        """
        if candidate.confidence > 0.7:
            return candidate.confidence
        
        try:
            from src.core.gpu_accelerator import GPUAccelerator
            import logging
            logger = logging.getLogger(__name__)
            
            gpu = GPUAccelerator()
            
            if not gpu.is_ollama_available():
                logger.debug("Ollama not available, skipping LLM ranking")
                return candidate.confidence
            
            prompt = f"""Analyze this HTTP request/response for potential security vulnerabilities.

Request:
- Method: {entry.method}
- URL: {entry.url}
- Body: {entry.request_body[:200] if entry.request_body else "None"}

Response:
- Status: {entry.status_code}
- Body: {entry.response_body[:300] if entry.response_body else "None"}

Suspicious Pattern Detected: {candidate.smell_type.value}
Evidence: {candidate.evidence}

Question: Does this indicate a potential vulnerability?
Rate the risk from 1-10 and explain briefly (max 50 words).
Format: "RISK: X/10 - <reason>"
"""
            
            response = gpu.query_ollama(
                model="qwen2.5-coder:7b",
                prompt=prompt,
                max_tokens=100
            )
            
            match = re.search(r"RISK:\s*(\d+)/10", response, re.IGNORECASE)
            if match:
                risk_score = int(match.group(1))
                new_confidence = min(1.0, risk_score / 10.0)
                logger.debug("LLM ranked %s: %.2f -> %.2f (Risk: %d/10)", 
                           candidate.id, candidate.confidence, new_confidence, risk_score)
                return new_confidence
            
            return candidate.confidence
        
        except (IOError, ValueError, ImportError) as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.warning("LLM ranking failed: %s", e)
            return candidate.confidence
    
    def generate_attack_plans(self, use_llm_ranking: bool = True) -> list[AttackPlan]:
        """
        攻撃プランを生成（LLMランキング対応）
        
        Args:
            use_llm_ranking: 曖昧なエントリにLLMランキングを適用するか
        
        Returns:
            AttackPlanのリスト（優先度順）
        """
        plans = []
        
        # LLMランキングを適用するエントリを特定
        candidates_to_rank = []
        if use_llm_ranking:
            for candidate in self._candidates:
                if 0.4 <= candidate.confidence <= 0.7:
                    # 中間信頼度のエントリのみLLMで再評価
                    candidates_to_rank.append(candidate)
        
        # LLMランキング実行（バッチ処理ではなく1件ずつVRAM節約）
        for candidate in candidates_to_rank:
            # 対応するHTTPエントリを検索
            matching_entry = next(
                (e for e in self._entries if e.url == candidate.target_url), 
                None
            )
            if matching_entry:
                new_confidence = self._llm_rank_candidate(candidate, matching_entry)
                candidate.confidence = new_confidence
        
        for candidate in self._candidates:
            mapping = self.AGENT_MAPPING.get(candidate.smell_type)
            if not mapping:
                continue
            
            agent, priority, rationale = mapping
            
            # 攻撃パラメータを構築
            attack_params = {}
            
            if candidate.smell_type == SmellType.JWT_DETECTED:
                attack_params["token"] = candidate.parameters.get("token", "")
                attack_params["test_endpoint"] = candidate.target_url
            
            elif candidate.smell_type == SmellType.OAUTH_FLOW:
                attack_params["authorize_url"] = candidate.target_url
                attack_params["client_id"] = candidate.parameters.get("client_id", [""])[0]
            
            plan = AttackPlan(
                target_url=candidate.target_url,
                method=candidate.method,
                candidate=candidate,
                recommended_agent=agent,
                priority=priority,
                rationale=rationale,
                attack_params=attack_params,
            )
            plans.append(plan)
        
        # 優先度で降順ソート
        plans.sort(key=lambda p: p.priority, reverse=True)
        
        return plans
    
    def analyze(self, file_path: str) -> list[AttackPlan]:
        """
        ログを解析して攻撃プランを生成（メインエントリポイント）
        
        Args:
            file_path: ログファイルのパス
        
        Returns:
            AttackPlanのリスト
        """
        # 1. ログ読み込み
        total = self.load_json(file_path)
        print(f"📄 Loaded {total} entries")
        
        # 2. ノイズ除去
        filtered = self.filter_noise()
        print(f"🔇 After noise reduction: {filtered} entries")
        
        # 3. 匂い検知
        candidates = self.detect_smells()
        print(f"👃 Detected {len(candidates)} smell candidates")
        
        # 4. 攻撃プラン生成
        plans = self.generate_attack_plans()
        print(f"⚔️ Generated {len(plans)} attack plans")
        
        return plans
    
    def get_summary(self, plans: list[AttackPlan]) -> str:
        """攻撃プランのサマリーを生成"""
        lines = ["=" * 60, "🎯 Attack Plan Summary", "=" * 60, ""]
        
        if not plans:
            lines.append("No attack targets found.")
            return "\n".join(lines)
        
        # 優先度でグループ化
        by_priority = {}
        for plan in plans:
            if plan.priority not in by_priority:
                by_priority[plan.priority] = []
            by_priority[plan.priority].append(plan)
        
        priority_icons = {5: "🔴", 4: "🟠", 3: "🟡", 2: "🟢", 1: "⚪"}
        
        for priority in sorted(by_priority.keys(), reverse=True):
            icon = priority_icons.get(priority, "⚪")
            lines.append(f"{icon} Priority {priority}")
            lines.append("-" * 40)
            
            for plan in by_priority[priority]:
                lines.append(f"  [{plan.candidate.smell_type.value}]")
                lines.append(f"    URL: {plan.target_url[:60]}...")
                lines.append(f"    Agent: {plan.recommended_agent}")
                lines.append(f"    Reason: {plan.rationale}")
                lines.append("")
        
        return "\n".join(lines)


# ===== MasterConductor統合用関数 =====

def analyze_and_dispatch(log_path: str, scope_domains: Optional[list[str]] = None) -> list[AttackPlan]:
    """
    ログを解析して攻撃プランを生成（MasterConductor用インターフェース）
    
    Args:
        log_path: ログファイルのパス
        scope_domains: スコープ内ドメイン（オプション）
    
    Returns:
        AttackPlanのリスト
    """
    analyzer = ProxyLogAnalyzer(scope_domains=scope_domains)
    return analyzer.analyze(log_path)


def get_proxy_analyzer() -> ProxyLogAnalyzer:
    """ProxyLogAnalyzerのインスタンスを取得"""
    return ProxyLogAnalyzer()
