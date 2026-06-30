"""
BizLogicHunter: ビジネスロジック脆弱性検証エージェント

ProxyLogAnalyzerが検出した「匂い」（IDOR候補、隠しパラメータ、
管理者エンドポイント等）を実際に検証し、脆弱性を証明する。

検証手法:
1. IDOR: ID書き換えによる不正アクセス検証
2. Hidden Param: パラメータ操作による権限昇格
3. Admin Access: ヘッダー/メソッド操作によるアクセス制限バイパス
"""

import json
import re
import logging
import inspect
from src.core.infra.network_client import AsyncNetworkClient, NetworkClientError

logger = logging.getLogger(__name__)
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.security.ethics_guard import (
    get_ethics_guard,
    ActionType,
    ActionResult,
)
from src.core.models.finding import Finding, Evidence, Severity, VulnType
from src.intelligence.proxy_log_analyzer import FindingCandidate, SmellType
from src.config import settings
from src.core.engine.agent_registry import register_agent
from src.core.agents.base import BaseAgent, AgentConfig
from src.core.intelligence import get_diff_analyzer


class VerifyResult(Enum):
    """検証結果"""
    SUCCESS = "success"           # 脆弱性確認
    FAILED = "failed"             # 脆弱性なし
    PARTIAL = "partial"           # 部分的成功（要調査）
    BLOCKED = "blocked"           # EthicsGuardでブロック
    ERROR = "error"               # エラー発生


@dataclass
class VerifyContext:
    """検証結果コンテキスト"""
    result: VerifyResult
    method: str = ""
    details: dict = field(default_factory=dict)
    finding: Optional[Finding] = None
    recommendations: list[str] = field(default_factory=list)


@dataclass
class CriticConfig:
    """
    Critic自己検証機能の設定
    
    APIコストを考慮し、デフォルトはOFF。
    有効化すると、Finding生成前にLLMによる自己検証ループを実行。
    """
    enabled: bool = False  # デフォルトOFF (APIコスト考慮)
    max_iterations: int = 3  # 最大検証ループ回数
    min_confidence: float = 0.7  # 検証通過に必要な最小信頼度


@register_agent(
    names=["bizlogichunter", "idor_tester", "business_logic", "bizlogic"],
    tags=["web", "exploit", "all"]
)
class BizLogicHunter(BaseAgent):
    """
    ビジネスロジック脆弱性検証エージェント
    
    ProxyLogAnalyzerからの候補を受け取り、
    実際にリクエストを送信して脆弱性を検証する。
    """
    
    # IDORテストで使う代替ID
    IDOR_TEST_IDS = [
        "1", "0", "-1", "999999",
        "admin", "root", "test",
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
    ]
    
    # 隠しパラメータの書き換えパターン
    HIDDEN_PARAM_MUTATIONS = {
        "false": ["true", "1", "yes"],
        "0": ["1", "true", "yes"],
        "user": ["admin", "administrator", "root", "superuser"],
        "guest": ["user", "admin", "member"],
        "off": ["on", "true", "1"],
    }
    
    # 管理者アクセスで試すヘッダー
    ADMIN_BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
    ]
    
    # 管理者アクセスで試すメソッド
    ADMIN_BYPASS_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    
    def __init__(self, config: AgentConfig = None, workspace_root: Optional[str] = None, rag_switch=None, program_name: str = ""):
        # Allow default init if config is missing (for legacy or direct usage)
        if config is None:
            config = AgentConfig(
                name="BizLogic-Hunter",
                description="Business logic vulnerability verification agent",
                model="default",
                instructions="Verify business logic vulnerabilities"
            )
            
        super().__init__(config, workspace_root=workspace_root)
        
        # Note: self.name is inherited from BaseAgent (property accessing config.name)
        self._rag_switch = rag_switch
        self._guard = get_ethics_guard()
        self._program_name = program_name
        self._attempts: list[dict] = []
        self._session_manager = None  # マルチアカウントセッション管理
        self._cross_test_enabled = False  # クロステスト有効化フラグ
        self._critic_config = CriticConfig()  # Critic自己検証設定
        self._llm_client = None  # Critic用LLMクライアント
        self._error_counts: dict[str, int] = {}  # URL別エラーカウント

    async def process(self, input_message: str) -> str:
        """Required by BaseAgent, but BizLogicHunter primarily uses run(task)."""
        return "BizLogicHunter processes structured tasks via run()."
    
    def set_rag_switch(self, rag_switch) -> None:
        """RAGSwitchを設定"""
        self._rag_switch = rag_switch
    
    def set_llm_client(self, llm_client) -> None:
        """Critic機能用のLLMクライアントを設定"""
        self._llm_client = llm_client
    
    def set_session_manager(self, session_manager) -> None:
        """
        マルチアカウントセッションマネージャーを設定
        
        Args:
            session_manager: MultiAccountSessionManager インスタンス
        """
        self._session_manager = session_manager
        if not session_manager:
            self._cross_test_enabled = False
            return

        is_configured_fn = getattr(session_manager, "is_configured", None)
        if callable(is_configured_fn):
            try:
                self._cross_test_enabled = bool(is_configured_fn())
                return
            except Exception:
                pass

        get_alt_fn = getattr(session_manager, "get_all_alternative_sessions", None)
        if callable(get_alt_fn):
            try:
                alt = get_alt_fn()
                self._cross_test_enabled = isinstance(alt, dict) and bool(alt)
                return
            except Exception:
                pass

        get_names_fn = getattr(session_manager, "get_session_names", None)
        if callable(get_names_fn):
            try:
                names = get_names_fn() or []
                self._cross_test_enabled = len(names) >= 2
                return
            except Exception:
                pass

        self._cross_test_enabled = False
    
    def enable_cross_test(self, enabled: bool = True) -> None:
        """クロステストの有効/無効を切り替え"""
        self._cross_test_enabled = enabled and self._session_manager is not None
    
    def is_cross_test_available(self) -> bool:
        """クロステストが利用可能か確認"""
        if self._session_manager is None:
            return False

        is_configured_fn = getattr(self._session_manager, "is_configured", None)
        if callable(is_configured_fn):
            try:
                return bool(is_configured_fn())
            except Exception:
                return False

        return bool(self._cross_test_enabled)

    async def _get_secondary_session_headers(self) -> Optional[dict]:
        """セッションマネージャー実装差を吸収して第2アカウントヘッダーを取得"""
        if not self._session_manager:
            return None

        # 1) MultiSessionManager style: get_all_alternative_sessions()
        get_alt_fn = getattr(self._session_manager, "get_all_alternative_sessions", None)
        if callable(get_alt_fn):
            try:
                alt_sessions = get_alt_fn()
                if isinstance(alt_sessions, dict):
                    for payload in alt_sessions.values():
                        headers = payload.get("headers") if isinstance(payload, dict) else None
                        if isinstance(headers, dict) and headers:
                            return headers
            except Exception:
                pass

        # 2) MultiAccountSessionManager style: get_session_names() + get_session(name)
        get_names_fn = getattr(self._session_manager, "get_session_names", None)
        get_session_fn = getattr(self._session_manager, "get_session", None)
        if callable(get_names_fn) and callable(get_session_fn):
            try:
                names = list(get_names_fn() or [])
                preferred = [n for n in names if n.lower() in {"victim", "user", "user_b", "secondary"}]
                ordered = preferred + [n for n in names if n not in preferred]
                for name in ordered:
                    session_obj = get_session_fn(name)
                    if hasattr(session_obj, "get_headers") and callable(session_obj.get_headers):
                        headers = session_obj.get_headers()
                        if isinstance(headers, dict) and headers:
                            return headers
                    if isinstance(session_obj, dict):
                        headers = session_obj.get("headers")
                        if isinstance(headers, dict) and headers:
                            return headers
                        cookie = session_obj.get("cookie")
                        if cookie:
                            return {"Cookie": cookie}
            except Exception:
                pass

        # 3) Legacy style: async get_session(index=1) -> {cookie: ...}
        if callable(get_session_fn):
            try:
                maybe_session = get_session_fn(index=1)
                if inspect.isawaitable(maybe_session):
                    maybe_session = await maybe_session
                if isinstance(maybe_session, dict):
                    headers = maybe_session.get("headers")
                    if isinstance(headers, dict) and headers:
                        return headers
                    cookie = maybe_session.get("cookie")
                    if cookie:
                        return {"Cookie": cookie}
            except Exception:
                pass

        return None
    
    # ===== Critic機能 (ON/OFFトグル) =====
    
    def enable_critic(self, enabled: bool = True, max_iterations: int = 3) -> None:
        """
        Critic自己検証機能を有効化
        
        Args:
            enabled: True=有効, False=無効
            max_iterations: 最大検証ループ回数
        """
        self._critic_config.enabled = enabled
        if enabled:
            self._critic_config.max_iterations = max_iterations
    
    def disable_critic(self) -> None:
        """Critic機能を無効化 (OFFに戻す)"""
        self._critic_config.enabled = False
    
    def is_critic_enabled(self) -> bool:
        """Critic機能が有効かどうかを返す"""
        return self._critic_config.enabled
    
    async def run(self, task: dict) -> dict:
        """AgentProtocol準拠の統一実行メソッド (Phase 1: ADR-002)
        
        内部で既存の execute() を呼び出し、VerifyContext を dict に変換。
        
        Args:
            task: タスクパラメータ辞書
                - target: ターゲットURL
                - candidate: FindingCandidate 辞書または SmellType 文字列
                - params: 追加パラメータ
        
        Returns:
            実行結果辞書 (create_run_result() 形式)
        """
        from src.core.agents.protocol import create_run_result
        from src.intelligence.proxy_log_analyzer import SmellType, FindingCandidate
        
        try:
            target = task.get("target", "")
            candidate_data = task.get("candidate") or task.get("params", {})
            
            # FindingCandidate を構築
            if isinstance(candidate_data, dict):
                smell_type_str = candidate_data.get("smell_type", "idor_candidate")
                # SmellType enum に変換
                smell_type = SmellType(smell_type_str) if smell_type_str in [e.value for e in SmellType] else SmellType.IDOR_CANDIDATE
                candidate = FindingCandidate(
                    smell_type=smell_type,
                    target_url=target,
                    method=candidate_data.get("method", "GET"),
                    evidence="Manual task execution",
                    confidence=candidate_data.get("confidence", 0.5),
                    parameters=candidate_data.get("parameters", {}),
                )
            else:
                # デフォルトのIDOR候補として処理
                candidate = FindingCandidate(
                    smell_type=SmellType.IDOR_CANDIDATE,
                    target_url=target,
                    method="GET",
                    evidence="Manual default candidate",
                    confidence=0.5,
                    parameters={},
                )
            
            # execute() を呼び出し
            result = await self.execute(target, candidate)
            
            # VerifyContext を dict に変換
            data = {
                "result": result.result.value if hasattr(result.result, "value") else str(result.result),
                "method": result.method,
                "details": result.details,
                "recommendations": result.recommendations,
            }
            if result.finding:
                finding_dict = result.finding.to_dict() if hasattr(result.finding, "to_dict") else str(result.finding)
                data["finding"] = finding_dict
                if isinstance(finding_dict, dict):
                    data["findings"] = [finding_dict]
            
            success = result.result == VerifyResult.SUCCESS
            
            return create_run_result(
                success=success,
                data=data,
                agent=self.name
            )
        except Exception as e:
            return create_run_result(
                success=False,
                error=str(e),
                agent=self.name
            )

    def _resolve_idor_vuln_type(self, candidate: FindingCandidate) -> VulnType:
        """AuthZ probe が付与された IDOR は BAC として結果化する。"""
        params = getattr(candidate, "parameters", {}) or {}
        probe = str(params.get("authz_probe", "")).lower()
        if probe in {"authbypass_idor", "weak_id_idor"}:
            return VulnType.BROKEN_ACCESS_CONTROL
        return VulnType.IDOR
    
    async def _run_critic_loop(self, finding: Finding) -> tuple[bool, Finding]:
        """
        #5: Critic自己検証（1回のみ実行、コスト効率重視）
        
        LLMを使用してFindingの妥当性を1回だけ検証する。
        APIコスト削減のため、プロンプトを最小化。
        
        Args:
            finding: 検証対象のFinding
        
        Returns:
            (verified, refined_finding): 検証成功/失敗と改良済みFinding
        """
        if not self._critic_config.enabled:
            return True, finding
        
        try:
            # コンパクトなプロンプト（トークン削減）
            prompt = self._build_compact_critique_prompt(finding)
            
            # Agent基底クラスのllm (LLMClient) を使用
            # 自動ルーティングにより、この種の判定タスクはローカルLLMへ送られる
            from src.core.models.llm import LLMClient
            vuln_client = LLMClient(role="vuln_validator")
            response = vuln_client.generate(
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                force_cloud=False
            )
            
            if not response or not hasattr(response, 'choices') or not response.choices:
                return True, finding

            content = response.choices[0].message.content
            critique = json.loads(content)
            
            is_valid = critique.get("valid", True)
            confidence = critique.get("confidence", 0.5)
            
            if is_valid and confidence >= self._critic_config.min_confidence:
                finding.confidence = confidence
                return True, finding
            elif not is_valid:
                return False, finding
            else:
                # 信頼度が低いが無効ではない場合はパススルー
                return True, finding
                
        except (json.JSONDecodeError, KeyError, AttributeError, Exception) as e:
            # エラー時はパススルー
            import logging
            logging.getLogger(__name__).debug(f"Critic validation skipped: {e}")
            return True, finding
    
    def _build_critique_prompt(self, finding: Finding) -> str:
        """Criticプロンプトを構築（従来版、互換性のため残す）"""
        return f"""以下の脆弱性レポートを批判的に評価してください。

## Finding
- Type: {finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else finding.vuln_type}
- Title: {finding.title}
- Description: {finding.description}
- Target: {finding.target_url}
- Evidence:
  - Method: {finding.evidence.request_method if finding.evidence else 'N/A'}
  - Status: {finding.evidence.response_status if finding.evidence else 'N/A'}

## 評価基準
1. 証拠は十分か？（リクエスト/レスポンスで脆弱性を証明できるか）
2. 再現可能か？
3. False Positiveの可能性は？
4. 影響度の評価は適切か？

## 出力形式
```json
{{
  "is_valid": true/false,
  "confidence": 0.0-1.0,
  "reasoning": "評価理由",
  "suggestions": ["改善提案1", "改善提案2"]
}}
```"""
    
    def _build_compact_critique_prompt(self, finding: Finding) -> str:
        """
        #5: コンパクトなCriticプロンプト（トークン削減版）
        
        最小限の情報でLLMに検証を依頼する。
        """
        vuln_type = finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else str(finding.vuln_type)
        status = finding.evidence.response_status if finding.evidence else 'N/A'
        return f"Type:{vuln_type} Target:{finding.target_url} Status:{status} Valid?"
    
    def _apply_critique_suggestions(self, finding: Finding, suggestions: list) -> Finding:
        """Critiqueの提案をFindingに適用"""
        # 現時点では説明に提案を追記するだけの簡易実装
        if suggestions:
            enhanced_desc = finding.description + f"\n\n[Critic Refinement]: {'; '.join(suggestions[:2])}"
            finding.description = enhanced_desc
        return finding    
    
    def _log_request_error(self, url: str, error: Exception) -> None:
        """
        リクエストエラーをログ出力（連続5回でエスカレーション）
        
        Args:
            url: リクエスト先URL
            error: 発生した例外
        """
        import logging
        logger = logging.getLogger(__name__)
        
        self._error_counts[url] = self._error_counts.get(url, 0) + 1
        count = self._error_counts[url]
        
        if count >= 5:
            logger.error(f"Repeated failures ({count}x) for {url}: {error}")
        else:
            logger.warning(f"Request failed ({count}x) for {url}: {error}")
    
    def _strip_dynamic_content(self, text: str) -> str:
        """
        動的コンテンツ（タイムスタンプ、トークン等）を除去
        
        Args:
            text: 除去対象のテキスト
        
        Returns:
            動的コンテンツが除去されたテキスト
        """
        # タイムスタンプ除去
        text = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[.\d]*Z?', '[TIMESTAMP]', text)
        # CSRF トークン除去
        text = re.sub(r'csrf[_-]?token["\s:=]+["\']?[\w-]+', '[CSRF]', text, flags=re.I)
        # ノンス除去
        text = re.sub(r'nonce["\s:=]+["\']?[\w-]+', '[NONCE]', text, flags=re.I)
        # JSON内の *_at フィールド（created_at, updated_at等）
        text = re.sub(r'"[^"]*_at"\s*:\s*"[^"]+"', '"[DYNAMIC_TIMESTAMP]"', text)
        return text
    
    def _get_diff_only(self, original: str, test: str) -> str:
        """
        2つのテキストの差分部分のみを抽出
        
        Args:
            original: 元のテキスト
            test: 比較対象のテキスト
        
        Returns:
            差分テキスト（追加行のみ）
        """
        from difflib import unified_diff
        diff_lines = list(unified_diff(
            original.splitlines(), 
            test.splitlines(), 
            lineterm=""
        ))
        # 追加行（+で始まる）のみ抽出
        added = [line[1:] for line in diff_lines if line.startswith('+') and not line.startswith('+++')]
        return '\n'.join(added)
    
    def _is_significant_idor(self, original: str, test: str) -> tuple[bool, str]:
        """
        IDORとして意味のある差異かを判定
        
        Args:
            original: 元のレスポンスボディ
            test: テストレスポンスボディ
        
        Returns:
            (is_vulnerable, reason): 脆弱性の有無と理由
        """
        # Step 1: 動的コンテンツ除去
        orig_clean = self._strip_dynamic_content(original)
        test_clean = self._strip_dynamic_content(test)
        
        # Step 2: 同一なら脆弱性ではない
        if orig_clean == test_clean:
            return False, "identical_after_strip"
        
        # Step 3: 差分抽出
        diff_text = self._get_diff_only(orig_clean, test_clean)
        
        # Step 4: 差分にPII/意味のあるデータが含まれるか
        pii_keywords = ["email", "name", "phone", "address", "user", "account", 
                        "password", "token", "ssn", "credit", "balance"]
        has_pii = any(kw in diff_text.lower() for kw in pii_keywords)
        
        if has_pii:
            return True, "different_with_pii"
        
        # Step 5: DiffAnalyzer を使用した高度な分析
        try:
            import logging
            logger = logging.getLogger(__name__)
            from src.core.intelligence.diff_analyzer import get_diff_analyzer
            analyzer = get_diff_analyzer()
            diff_analysis = analyzer.analyze_body_diff(orig_clean, test_clean)
            if diff_analysis.get("is_significant"):
                return True, f"diff_analyzer: {diff_analysis.get('reason', 'significant_change')}"
        except Exception as e:
            logger.debug(f"DiffAnalyzer analysis failed: {e}")

        # Step 6: フォールバック: 長さによる単純比較
        if len(diff_text) > 20:
            return True, "significant_difference"
        
        return False, "no_significant_difference"
    
    async def execute(self, target: str, candidate: Optional[FindingCandidate] = None, **kwargs) -> VerifyContext:
        """
        候補に基づいて適切な検証を実行
        
        Args:
            target: ターゲットURL
            candidate: ProxyLogAnalyzerからの候補 (Optional)
            **kwargs: 互換性のための追加パラメータ (params 等)
        
        Returns:
            VerifyContext
        """
        if candidate is None:
            # params から candidate を復元試行
            params = kwargs.get("params", {})
            smell_type_str = params.get("smell_type", "idor_candidate")
            smell_type = SmellType(smell_type_str) if smell_type_str in [e.value for e in SmellType] else SmellType.IDOR_CANDIDATE
            candidate = FindingCandidate(
                smell_type=smell_type,
                target_url=target,
                method=params.get("method", "GET"),
                evidence="Conductor-initiated execution",
                confidence=params.get("confidence", 0.5),
                parameters=params.get("parameters", {}),
            )

        # EthicsGuard: スコープチェック (復元)
        is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, target)
        if is_allowed != ActionResult.ALLOWED:
            return VerifyContext(
                result=VerifyResult.BLOCKED,
                details={"blocked_reason": reason}
            )

        # modifications の取得 (直接引数 or kwargs)
        modifications = kwargs.get("modifications")
        
        # SmellTypeに応じた検証を実行
        if candidate.smell_type == SmellType.IDOR_CANDIDATE:
            ctx = await self.verify_idor(target, candidate, modifications=modifications)
            if ctx.result == VerifyResult.SUCCESS:
                return ctx
            return await self.verify_cookie_priv_esc(target, candidate, modifications=modifications)
        elif candidate.smell_type == SmellType.HIDDEN_PARAM:
            ctx = await self.verify_hidden_param(target, candidate, modifications=modifications)
            if ctx.result == VerifyResult.SUCCESS:
                return ctx
            return await self.verify_cookie_priv_esc(target, candidate, modifications=modifications)
        elif candidate.smell_type == SmellType.ADMIN_ENDPOINT:
            ctx = await self.verify_admin_access(target, candidate, modifications=modifications)
            if ctx.result == VerifyResult.SUCCESS:
                return ctx
            return await self.verify_cookie_priv_esc(target, candidate, modifications=modifications)
        elif candidate.smell_type == SmellType.PAYMENT_ENDPOINT:
            if candidate.method in ["POST", "PUT", "PATCH"]:
                race_ctx = await self.verify_race_condition(target, candidate, modifications=modifications)
                if race_ctx.result == VerifyResult.SUCCESS:
                    return race_ctx
            return await self.detect_payment_risks(target, candidate)
        elif candidate.smell_type == SmellType.STATE_MACHINE_SMELL:
            # ドメイン単位での検証が必要なため、URLからドメインを抽出
            from urllib.parse import urlparse
            domain = urlparse(target).netloc
            return await self.verify_state_machine_bypass(domain, modifications=modifications)
        else:
            return VerifyContext(
                result=VerifyResult.ERROR,
                details={"error": f"Unsupported smell type: {candidate.smell_type}"}
            )
    
    async def verify_idor(self, target: str, candidate: FindingCandidate, modifications: Optional[dict] = None) -> VerifyContext:
        """
        IDOR脆弱性を検証
        
        IDを書き換えたリクエストを送信し、
        不正アクセスが可能かを確認する。
        """
        context = VerifyContext(result=VerifyResult.FAILED, method="idor")
        vuln_type_for_result = self._resolve_idor_vuln_type(candidate)
        probe_name = str((candidate.parameters or {}).get("authz_probe", "")).lower()
        title_prefix = "Broken Access Control" if vuln_type_for_result == VulnType.BROKEN_ACCESS_CONTROL else "IDOR"
        
        # RAGから追加のIDORパターンを取得
        test_ids = self.IDOR_TEST_IDS.copy()
        if self._rag_switch and self._rag_switch.enabled:
            rag_patterns = self._rag_switch.get_bypass_techniques("idor")
            for pattern in rag_patterns:
                if pattern.get("test_id"):
                    test_ids.append(pattern["test_id"])
        
        # 元のレスポンスを取得
        try:
            original_response = await self._make_request("GET", target, modifications=modifications)
            if not original_response:
                return context
            original_body = original_response.text
            original_status = original_response.status_code
        except NetworkClientError as e:
            self._log_request_error(target, e)
            return context
        
        # IDパターンを解析
        parsed = urlparse(target)
        path = parsed.path
        
        # URLパス内のIDを検出して置換
        ID_PATTERNS = [
            (r"/(\d+)(?=/|$)", "numeric"),              # /123 or /123/
            (r"/([a-f0-9-]{36})(?=/|$)", "uuid"),       # UUID
            (r"/([a-f0-9]{24})(?=/|$)", "objectid"),    # MongoDB ObjectId
            (r"/([a-zA-Z0-9_-]{8,22})(?=/|$)", "alphanumeric"),  # 英数字ID (8-22文字)
        ]
        
        for pattern, _ in ID_PATTERNS:
            matches = re.findall(pattern, path)
            if not matches:
                continue
            
            original_id = matches[0]
            
            for test_id in test_ids:
                if test_id == original_id:
                    continue
                
                # IDを置換
                new_path = re.sub(pattern, f"/{test_id}", path, count=1)
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, new_path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                
                # EthicsGuardチェック
                is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, new_url)
                if is_allowed != ActionResult.ALLOWED:
                    continue
                
                try:
                    test_response = await self._make_request("GET", new_url, modifications=modifications)
                    if not test_response:
                        continue
                    
                    # クロステスト（第2アカウント）が有効な場合、そちらでも検証
                    if self._cross_test_enabled:
                        is_vuln_cross, reason_cross, cross_resp = await self._verify_idor_with_second_account(
                            new_url, original_body, modifications=modifications
                        )
                        if is_vuln_cross:
                            context.result = VerifyResult.SUCCESS
                            context.details = {
                                "original_id": original_id,
                                "test_id": test_id,
                                "cross_test": True,
                                "reason": reason_cross
                            }
                            # Finding生成... (既存のロジックに合流させるため、ここではフラグ立てのみでもよいが、ひとまず完成させる)
                            context.finding = self._create_finding(
                                vuln_type=vuln_type_for_result,
                                target=new_url,
                                method="GET",
                                title=f"{title_prefix}: Cross-Account Access to Object ID {test_id}",
                                description=f"Accessed object {test_id} using a different user session.",
                                response_status=cross_resp.status_code if cross_resp else 0,
                                response_body=cross_resp.text[:500] if cross_resp else "",
                                additional_info={"authz_probe": probe_name} if probe_name else None,
                            )
                            return context

                    # 成功判定: 200 OKで異なるデータが返る
                    if test_response.status_code == 200:
                        test_body = test_response.text
                        
                        # PIIベース意味的差異検出
                        is_vuln, reason = self._is_significant_idor(original_body, test_body)
                        
                        if is_vuln:
                            context.result = VerifyResult.SUCCESS
                            context.details = {
                                "original_id": original_id,
                                "test_id": test_id,
                                "original_url": target,
                                "test_url": new_url,
                                "detection_reason": reason,
                            }
                            context.finding = self._create_finding(
                                vuln_type=vuln_type_for_result,
                                target=new_url,
                                method="GET",
                                title=f"{title_prefix}: Unauthorized Access to Object ID {test_id}",
                                description=(
                                    f"By changing the object identifier from {original_id} to {test_id}, "
                                    f"it was possible to access another user's data."
                                ),
                                response_status=test_response.status_code,
                                response_body=test_body[:500],
                                reproduction_steps=[
                                    f"1. Intercept request to {target}",
                                    f"2. Change ID from {original_id} to {test_id}",
                                    f"3. Observe that different user's data is returned",
                                ],
                                additional_info={"authz_probe": probe_name} if probe_name else None,
                            )
                            
                            # 共有ワークスペースに保存 (Phase 3)
                            try:
                                from src.core.workspace.shared_workspace import SharedWorkspace
                                ws = SharedWorkspace()
                                if context.finding:
                                    ws.save_finding(context.finding.to_dict())
                            except ImportError:
                                pass
                            
                            return context
                    
                    # 403/401なら安全
                    elif test_response.status_code in (401, 403):
                        continue
                        
                except NetworkClientError as e:
                    self._log_request_error(new_url, e)
                    continue
        
        # クエリパラメータ内のIDもチェック
        query_params = parse_qs(parsed.query)
        for param_name, values in query_params.items():
            if any(kw in param_name.lower() for kw in ["id", "uid", "user"]):
                original_id = values[0] if values else ""
                
                for test_id in test_ids:
                    if test_id == original_id:
                        continue
                    
                    new_params = query_params.copy()
                    new_params[param_name] = [test_id]
                    new_query = urlencode(new_params, doseq=True)
                    new_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, new_query, parsed.fragment
                    ))
                    
                    is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, new_url)
                    if is_allowed != ActionResult.ALLOWED:
                        continue
                    
                    try:
                        test_response = await self._make_request("GET", new_url, modifications=modifications)
                        if test_response and test_response.status_code == 200:
                            if test_response.text != original_body:
                                context.result = VerifyResult.SUCCESS
                                context.details = {
                                    "param": param_name,
                                    "original_id": original_id,
                                    "test_id": test_id,
                                }
                                context.finding = self._create_finding(
                                    vuln_type=vuln_type_for_result,
                                    target=new_url,
                                    method="GET",
                                    title=f"{title_prefix} via {param_name} Parameter",
                                    description=(
                                        f"The {param_name} parameter allows unauthorized object access. "
                                        f"Changing it from {original_id} to {test_id} returns different data."
                                    ),
                                    response_status=test_response.status_code,
                                    response_body=test_response.text[:500],
                                    reproduction_steps=[
                                        f"1. Capture request with {param_name}={original_id}",
                                        f"2. Change {param_name} to {test_id}",
                                        f"3. Observe different user's data",
                                    ],
                                    additional_info={"authz_probe": probe_name} if probe_name else None,
                                )
                        
                        # 共有ワークスペースに保存 (Phase 3)
                        try:
                            from src.core.workspace.shared_workspace import SharedWorkspace
                            ws = SharedWorkspace()
                            if context.finding:
                                ws.save_finding(context.finding.to_dict())
                        except ImportError:
                            pass
                        
                        return context
                    except NetworkClientError as e:
                        self._log_request_error(new_url, e)
                        continue
        
        return context
    
    async def verify_hidden_param(self, target: str, candidate: FindingCandidate, modifications: Optional[dict] = None) -> VerifyContext:
        """
        隠しパラメータの操作による権限昇格を検証
        
        検出されたパラメータを書き換えて再送信し、
        レスポンスの変化を検知する。
        """
        context = VerifyContext(result=VerifyResult.FAILED, method="hidden_param")
        
        params = candidate.parameters.get("param", ())
        if not params or len(params) < 2:
            return context
        
        param_name, param_value = params[0], params[1]
        
        # RAGから追加の変異パターンを取得
        mutations = self.HIDDEN_PARAM_MUTATIONS.get(param_value.lower(), ["true", "1", "admin"])
        if self._rag_switch and self._rag_switch.enabled:
            rag_patterns = self._rag_switch.get_bypass_techniques("privilege_escalation")
            for pattern in rag_patterns:
                if pattern.get("mutation"):
                    mutations.append(pattern["mutation"])
        
        # 元のレスポンスを取得
        try:
            original_response = await self._make_request(candidate.method, target, modifications=modifications)
            if not original_response:
                return context
            
            original_body = original_response.text
            original_size = len(original_body)
            original_status = original_response.status_code
        except NetworkClientError as e:
            self._log_request_error(target, e)
            return context
        
        parsed = urlparse(target)
        
        for new_value in mutations:
            # クエリパラメータを書き換え
            query_params = parse_qs(parsed.query)
            if param_name in query_params:
                query_params[param_name] = [new_value]
                new_query = urlencode(query_params, doseq=True)
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
            else:
                # ボディ内のパラメータの場合
                # JSONボディを想定
                new_url = target
            
            is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, new_url)
            if is_allowed != ActionResult.ALLOWED:
                continue
            
            try:
                test_response = await self._make_request(candidate.method, new_url, modifications=modifications)
                if not test_response:
                    continue
                
                test_body = test_response.text
                test_size = len(test_body)
                test_status = test_response.status_code
                
                # 成功判定
                # 1. ステータスが良くなった（403→200等）
                # 2. レスポンスサイズが大きく増加
                # 3. 管理者データが返ってきた
                
                status_improved = (
                    original_status in (401, 403) and test_status == 200
                )
                size_increased = test_size > original_size * 1.5
                has_admin_data = any(
                    kw in test_body.lower()
                    for kw in ["admin", "administrator", "superuser", "all_users", "dashboard"]
                )
                
                if status_improved or size_increased or has_admin_data:
                    context.result = VerifyResult.SUCCESS
                    context.details = {
                        "param_name": param_name,
                        "original_value": param_value,
                        "new_value": new_value,
                        "original_status": original_status,
                        "new_status": test_status,
                        "size_change": test_size - original_size,
                    }
                    context.finding = self._create_finding(
                        vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                        target=new_url,
                        method=candidate.method,
                        title=f"Privilege Escalation via {param_name} Parameter",
                        description=(
                            f"By changing {param_name} from '{param_value}' to '{new_value}', "
                            f"elevated privileges were obtained."
                        ),
                        response_status=test_status,
                        response_body=test_body[:500],
                        reproduction_steps=[
                            f"1. Intercept request to {target}",
                            f"2. Change {param_name} from '{param_value}' to '{new_value}'",
                            f"3. Observe privilege escalation",
                        ],
                    )
                    
                    # 共有ワークスペースに保存 (Phase 3)
                    try:
                        from src.core.workspace.shared_workspace import SharedWorkspace
                        ws = SharedWorkspace()
                        if context.finding:
                            ws.save_finding(context.finding.to_dict())
                    except ImportError:
                        pass
                    
                    return context
                    
            except NetworkClientError as e:
                self._log_request_error(new_url, e)
                continue
        
        return context
    
    async def verify_admin_access(self, target: str, candidate: FindingCandidate, modifications: Optional[dict] = None) -> VerifyContext:
        """
        管理者エンドポイントへのアクセス制限バイパスを検証
        
        ヘッダー操作やメソッド変更で認証をバイパスできるか確認する。
        """
        context = VerifyContext(result=VerifyResult.FAILED, method="admin_access")
        
        # RAGから追加のバイパスヘッダーを取得
        bypass_headers = self.ADMIN_BYPASS_HEADERS.copy()
        if self._rag_switch and self._rag_switch.enabled:
            rag_patterns = self._rag_switch.get_bypass_techniques("admin_bypass")
            for pattern in rag_patterns:
                if pattern.get("header"):
                    bypass_headers.append(pattern["header"])
        
        # 元のレスポンスを取得（認証なし）
        try:
            original_response = await self._make_request("GET", target, headers={}, modifications=modifications)
            original_status = original_response.status_code if original_response else 0
        except NetworkClientError as e:
            self._log_request_error(target, e)
            original_status = 0
        
        # ヘッダーバイパステスト
        for headers in bypass_headers:
            is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, target)
            if is_allowed != ActionResult.ALLOWED:
                continue
            
            try:
                test_response = await self._make_request("GET", target, headers=headers, modifications=modifications)
                if not test_response:
                    continue
                
                # 成功判定: 元が403/401で、ヘッダー追加で200になった
                if original_status in (401, 403, 0) and test_response.status_code == 200:
                    context.result = VerifyResult.SUCCESS
                    context.details = {
                        "bypass_headers": headers,
                        "original_status": original_status,
                        "new_status": test_response.status_code,
                    }
                    context.finding = self._create_finding(
                        vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                        target=target,
                        method="GET",
                        title="Admin Endpoint Access Control Bypass",
                        description=(
                            f"The admin endpoint can be accessed by adding the header: {headers}. "
                            f"This bypasses authentication/authorization controls."
                        ),
                        request_headers=headers,
                        response_status=test_response.status_code,
                        response_body=test_response.text[:500],
                        reproduction_steps=[
                            f"1. Request {target} without authentication",
                            f"2. Add header: {headers}",
                            f"3. Observe successful access to admin endpoint",
                        ],
                    )
                    
                    # 共有ワークスペースに保存 (Phase 3)
                    try:
                        from src.core.workspace.shared_workspace import SharedWorkspace
                        ws = SharedWorkspace()
                        if context.finding:
                            ws.save_finding(context.finding.to_dict())
                    except ImportError:
                        pass
                    
                    return context
                    
            except NetworkClientError as e:
                self._log_request_error(target, e)
                continue
        
        # メソッド変更テスト
        for method in self.ADMIN_BYPASS_METHODS:
            if method == "GET":
                continue
            
            is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, target)
            if is_allowed != ActionResult.ALLOWED:
                continue
            
            try:
                test_response = await self._make_request(method, target, modifications=modifications)
                if not test_response:
                    continue
                
                # OPTIONSで許可メソッドが漏洩
                if method == "OPTIONS" and test_response.status_code == 200:
                    allow_header = test_response.headers.get("Allow", "")
                    if allow_header:
                        context.result = VerifyResult.PARTIAL
                        context.details = {
                            "method": method,
                            "allowed_methods": allow_header,
                        }
                        context.recommendations.append(
                            f"OPTIONS reveals allowed methods: {allow_header}"
                        )
                
                # 他のメソッドで200が返る
                elif test_response.status_code == 200:
                    context.result = VerifyResult.SUCCESS
                    context.details = {
                        "method": method,
                        "status": test_response.status_code,
                    }
                    context.finding = self._create_finding(
                        vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                        target=target,
                        method=method,
                        title=f"Admin Endpoint Accessible via {method} Method",
                        description=(
                            f"The admin endpoint blocks GET but allows {method}. "
                            f"This is a method-based access control bypass."
                        ),
                        response_status=test_response.status_code,
                        response_body=test_response.text[:500],
                        reproduction_steps=[
                            f"1. Request {target} with GET (blocked)",
                            f"2. Change method to {method}",
                            f"3. Observe successful access",
                        ],
                    )
                    
                    # 共有ワークスペースに保存 (Phase 3)
                    try:
                        from src.core.workspace.shared_workspace import SharedWorkspace
                        ws = SharedWorkspace()
                        if context.finding:
                            ws.save_finding(context.finding.to_dict())
                    except ImportError:
                        pass
                    
                    return context
                    
            except NetworkClientError as e:
                self._log_request_error(target, e)
                continue
        
        return context
    
    async def detect_payment_risks(self, target: str, candidate: FindingCandidate) -> VerifyContext:
        """
        決済ロジックのリスクを検出（検出のみ、リクエスト実行はしない）
        
        人間に手動テストを推奨するレコメンデーションを生成。
        """
        risks = candidate.parameters.get("risks") or []
        
        recommendations = []
        if "amount_manipulation" in risks:
            recommendations.append("⚠️ 手動テスト推奨: amount=-1 や amount=0.001 で金額操作を確認")
        if "quantity_manipulation" in risks:
            recommendations.append("⚠️ 手動テスト推奨: quantity=-1 や quantity=999999 で数量操作を確認")
        if "coupon_abuse" in risks:
            recommendations.append("⚠️ 手動テスト推奨: クーポン多重適用、他ユーザーのクーポンコード使用を確認")
        if "currency_mismatch" in risks:
            recommendations.append("⚠️ 手動テスト推奨: currency=JPY→USD 変更で通貨不一致攻撃を確認")
        
        # 常に追加するレコメンデーション
        recommendations.append("⚠️ 手動テスト推奨: Race Condition (二重決済)")
        
        context = VerifyContext(
            result=VerifyResult.PARTIAL,
            method="payment_detection",
            details={"risks": risks, "requires_manual_testing": True, "endpoint": target},
            recommendations=recommendations,
        )
        
        return context

    def _identify_sensitive_cookie_names(self, cookies: dict) -> list[str]:
        if not isinstance(cookies, dict):
            return []

        sensitive_keywords = ["admin", "role", "user", "id", "uid", "login", "perm", "auth", "priv"]
        candidates: list[str] = []
        for key, value in cookies.items():
            key_lower = str(key).lower()
            value_lower = str(value).lower()
            if any(kw in key_lower for kw in sensitive_keywords):
                candidates.append(key)
            elif value_lower in {"0", "1", "true", "false", "user", "guest", "viewer"}:
                candidates.append(key)
        deduped: list[str] = []
        for key in candidates:
            if key not in deduped:
                deduped.append(key)
        return deduped

    def _generate_cookie_mutations(self, cookie_name: str, original_value: str) -> list[str]:
        key = str(cookie_name).lower()
        value = str(original_value)
        value_lower = value.lower()

        mutations: list[str] = []

        if "admin" in key and value_lower in {"0", "false", "no"}:
            mutations.extend(["1", "true"])
        if "role" in key and value_lower in {"user", "guest", "viewer"}:
            mutations.append("admin")
        if "user" in key and value_lower not in {"attacker", "admin"}:
            mutations.append("attacker")

        mutations.extend(["1", "true", "admin", "root", "yes", "on", "administrator"])

        if value.isdigit():
            base = int(value)
            if base > 0:
                mutations.append(str(base - 1))
            mutations.append(str(base + 1))

        deduped: list[str] = []
        for token in mutations:
            if token == value:
                continue
            if token not in deduped:
                deduped.append(token)
        return deduped

    async def verify_cookie_priv_esc(self, target: str, candidate: FindingCandidate, modifications: Optional[dict] = None) -> VerifyContext:
        """
        Cookieの操作による権限昇格を検証
        
        機微な名称のCookie（admin, role, uid等）を改変し、権限が昇格するか確認する。
        """
        context = VerifyContext(result=VerifyResult.FAILED, method="cookie_priv_esc")
        
        # EthicsGuardチェック
        is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, target)
        if is_allowed != ActionResult.ALLOWED:
            return VerifyContext(result=VerifyResult.BLOCKED, details={"blocked_reason": reason})

        # 現在のCookieを取得
        client = getattr(self, "network_client", None)
        should_close = False
        if not client:
            client = AsyncNetworkClient()
            should_close = True

        try:
            resp = await client.request("GET", target, use_proxy=True)
            if not resp:
                return context
            cookies = client.get_cookies()
            original_status = resp.status_code
            original_body = resp.text or ""
            original_size = len(original_body)
        except Exception as e:
            logger.error(f"Error getting cookies for priv_esc test: {e}")
            return context
        finally:
            if should_close:
                try:
                    await client.close()
                except Exception:
                    pass
            
        if not cookies:
            return context

        # 機微なCookie名を特定 (admin, role, user, id, uid, login, perm)
        # または値が 0, 1, true, false のもの
        potential_cookies = self._identify_sensitive_cookie_names(cookies)

        for cookie_name in potential_cookies:
            original_value = cookies[cookie_name]
            
            # 変異パターンを生成
            mutations = self._generate_cookie_mutations(cookie_name, original_value)
            
            for new_value in mutations:
                if new_value == original_value:
                    continue
                
                # Cookieヘッダーを作成
                test_cookies = cookies.copy()
                test_cookies[cookie_name] = new_value
                cookie_str = "; ".join([f"{k}={v}" for k, v in test_cookies.items()])
                test_headers = {"Cookie": cookie_str}
                
                try:
                    test_response = await self._make_request(candidate.method, target, headers=test_headers, modifications=modifications)
                    if not test_response:
                        continue
                    
                    test_body = test_response.text
                    test_size = len(test_body)
                    test_status = test_response.status_code
                    
                    # 成功判定
                    status_improved = (original_status in (401, 403) and test_status == 200)
                    size_increased = test_size > original_size * 1.5
                    has_admin_data = any(
                        kw in test_body.lower()
                        for kw in ["admin", "administrator", "superuser", "all_users", "dashboard", "settings"]
                    )
                    response_identity_changed = (
                        test_status == 200
                        and original_status == 200
                        and test_body != original_body
                        and any(
                            kw in test_body.lower()
                            for kw in ["first_name", "last_name", "username", "user_id", "email", "profile"]
                        )
                    )
                    
                    if (status_improved or size_increased or has_admin_data or response_identity_changed) and test_status == 200:
                        context.result = VerifyResult.SUCCESS
                        context.details = {
                            "cookie_name": cookie_name,
                            "original_value": original_value,
                            "new_value": new_value,
                            "new_status": test_status,
                        }
                        authz_diff = {
                            "scenario": "cookie_privilege_escalation",
                            "confidence": 0.81,
                            "signals": [s for s in [
                                "status_improved" if status_improved else "",
                                "response_size_increase" if size_increased else "",
                                "admin_keyword_exposed" if has_admin_data else "",
                                "response_identity_data_changed" if response_identity_changed else "",
                            ] if s],
                            "baseline_status": original_status,
                            "test_status": test_status,
                            "original_id": f"{cookie_name}:{original_value}",
                            "test_id": f"{cookie_name}:{new_value}",
                            "cookie_name": cookie_name,
                            "original_value": original_value,
                            "new_value": new_value,
                        }
                        context.finding = self._create_finding(
                            vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                            target=target,
                            method=candidate.method,
                            title=f"Privilege Escalation via {cookie_name} Cookie",
                            description=(
                                f"By changing cookie '{cookie_name}' from '{original_value}' to '{new_value}', "
                                f"elevated privileges or unauthorized access was obtained."
                            ),
                            request_headers=test_headers,
                            response_status=test_status,
                            response_body=test_body[:500],
                            reproduction_steps=[
                                f"1. Request {target}",
                                f"2. Modify cookie '{cookie_name}' to '{new_value}'",
                                f"3. Observe administrative features or different user's data",
                            ],
                            additional_info={"authz_differential": authz_diff},
                        )
                        return context
                except Exception as e:
                    logger.debug(f"Error in cookie_priv_esc test for {cookie_name}: {e}")
                    continue

        return context
    
    async def verify_race_condition(self, target: str, candidate: FindingCandidate, modifications: Optional[dict] = None) -> VerifyContext:
        """
        競合状態（Race Condition）の脆弱性を検証
        
        同一のエンドポイントに対して同時に複数のリクエストを送信し、
        処理の競合によって意図しない状態（二重決済、限度額超えなど）が発生するか確認する。
        """
        context = VerifyContext(result=VerifyResult.FAILED, method="race_condition")
        
        if candidate.method not in ["POST", "PUT", "PATCH", "DELETE"]:
            return context
            
        is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, target)
        if is_allowed != ActionResult.ALLOWED:
            return VerifyContext(result=VerifyResult.BLOCKED, details={"blocked_reason": reason})
            
        import asyncio
        import time
        from aiohttp import ClientSession
        
        concurrent_requests = 5
        
        async def make_concurrent_request():
            try:
                # 簡易的にセッションを共有せずに一気に実行
                return await self._make_request(candidate.method, target, modifications=modifications)
            except Exception as e:
                self._log_request_error(target, e)
                return None
                
        # 同時発火
        tasks = [make_concurrent_request() for _ in range(concurrent_requests)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_responses = [r for r in responses if r is not None and not isinstance(r, Exception)]
        
        if not valid_responses:
            return context
            
        status_counts = {}
        for r in valid_responses:
            status_counts[r.status_code] = status_counts.get(r.status_code, 0) + 1
            
        success_count = sum( count for status, count in status_counts.items() if 200 <= status < 300 )
        
        # 複数回成功した場合、競合状態の可能性があると判定
        if success_count > 1:
            context.result = VerifyResult.SUCCESS
            context.details = {
                "concurrent_requests": concurrent_requests,
                "successful_requests": success_count,
                "status_distribution": status_counts,
            }
            context.finding = self._create_finding(
                vuln_type=VulnType.RACE_CONDITION,
                target=target,
                method=candidate.method,
                title="Potential Race Condition Vulnerability",
                description=(
                    f"By sending {concurrent_requests} concurrent requests to the {candidate.method} endpoint, "
                    f"{success_count} requests were successfully processed (2xx status). "
                    f"This may indicate a race condition vulnerability, potentially leading to double-spending "
                    f"or bypassing business constraints."
                ),
                response_status=valid_responses[0].status_code,
                response_body=valid_responses[0].text[:500],
                reproduction_steps=[
                    f"1. Prepare a valid state-changing request (e.g., checkout, apply coupon)",
                    f"2. Send {concurrent_requests} identical requests simultaneously",
                    f"3. Observe that multiple requests succeed instead of being rejected",
                ],
            )
            
            try:
                from src.core.workspace.shared_workspace import SharedWorkspace
                ws = SharedWorkspace()
                if context.finding:
                    ws.save_finding(context.finding.to_dict())
            except ImportError:
                pass
                
        return context
    
    async def _make_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        body: Optional[str] = None,
        timeout: int = 10,
        modifications: Optional[dict] = None,
    ) -> Optional[object]:
        """
        リクエストを送信 (modifications による変異対応)
        """
        req_headers = (headers or {}).copy()
        req_url = url
        req_body = body
        
        # modifications (WAF回避パターン等) を適用
        if modifications:
            # ヘッダー追加/上書き
            if "headers" in modifications:
                req_headers.update(modifications["headers"])
            
            # URL変異 (パスの大文字小文字化、末尾スラッシュ等)
            if "url_mutation" in modifications:
                mutation = modifications["url_mutation"]
                if mutation == "trailing_slash":
                    req_url = req_url.rstrip("/") + "/"
                elif mutation == "upper_case":
                    # パス部分のみ大文字化
                    p = urlparse(req_url)
                    req_url = urlunparse(p._replace(path=p.path.upper()))
            
            # エンコーディング変更
            if "encoding" in modifications:
                # TODO: 実装
                pass

        try:
            async with AsyncNetworkClient() as client:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers or {},
                    data=body,
                    timeout=timeout,
                    follow_redirects=False,
                    use_proxy=True,
                )
            self._attempts.append({
                "method": method,
                "url": url,
                "status": response.status_code,
                "timestamp": datetime.now().isoformat(),
            })
            return response
        except NetworkClientError as e:
            self._attempts.append({
                "method": method,
                "url": url,
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
            })
            return None
    
    def _create_finding(
        self,
        vuln_type: VulnType,
        target: str,
        method: str,
        title: str,
        description: str,
        response_status: int = 0,
        response_body: str = "",
        request_headers: Optional[dict] = None,
        reproduction_steps: Optional[list[str]] = None,
        additional_info: Optional[dict] = None,
    ) -> Optional[Finding]:
        """Finding生成 (Critic検証含む)"""
        cwe_map = {
            VulnType.IDOR: "CWE-639",
            VulnType.BROKEN_ACCESS_CONTROL: "CWE-284",
        }
        
        finding = Finding(
            vuln_type=vuln_type,
            severity=Severity.HIGH,
            title=title,
            description=description,
            target_url=target,
            target_program=self._program_name,
            evidence=Evidence(
                request_method=method,
                request_url=target,
                request_headers=request_headers or {},
                response_status=response_status,
                response_body=response_body,
            ),
            reproduction_steps=reproduction_steps or [],
            impact=(
                "An attacker can access or modify resources belonging to other users, "
                "leading to unauthorized data access, privilege escalation, or account takeover."
            ),
            source_agent="bizlogic_hunter",
            confidence=0.85,
            cwe_id=cwe_map.get(vuln_type, "CWE-284"),
            additional_info=additional_info or {},
        )
        
        # Critic検証 (有効時)
        if self._critic_config.enabled:
            verified, refined_finding = self._run_critic_loop(finding)
            if not verified:
                # 検証失敗時はNoneを返し、呼び出し元で処理させる
                return None
            return refined_finding
            
        return finding
    
    async def _verify_idor_with_second_account(self, url: str, original_body: str, modifications: Optional[dict] = None) -> tuple[bool, str, Optional[object]]:
        """
        別のアカウントのセッションを使用してIDORを検証
        """
        if not self._session_manager or not self.is_cross_test_available():
            return False, "no_session_manager", None
        
        second_headers = await self._get_secondary_session_headers()
        if not second_headers:
            return False, "second_account_not_available", None
        
        try:
            # リクエスト送信
            test_response = await self._make_request("GET", url, headers=second_headers, modifications=modifications)
            if not test_response:
                return False, "request_failed", None
            
            # 200 OK であれば、データが異なるかを確認
            if test_response.status_code == 200:
                is_vuln, reason = self._is_significant_idor(original_body, test_response.text)
                return is_vuln, reason, test_response
                
            return False, f"status_{test_response.status_code}", test_response
            
        except Exception as e:
            return False, f"error_{str(e)}", None

    async def verify_state_machine_bypass(self, domain: str, modifications: Optional[dict] = None) -> VerifyContext:
        """
        重要フローをスキップして「成功ページ」等にアクセスできるか検証
        """
        from src.core.infra.knowledge_graph import KnowledgeGraph
        kg = KnowledgeGraph()
        flows = kg.get_contextual_flows(domain)
        
        context = VerifyContext(result=VerifyResult.FAILED, method="state_machine_bypass")
        
        if not flows:
            context.details = {"reason": "no_flows_found_in_kg"}
            return context
            
        for flow in flows:
            result_page = flow.get("result_page")
            critical_endpoint = flow.get("state_changing_endpoint")
            
            if not result_page: continue
            
            # Step 1: 正常なフローを踏まずに結果ページにアクセス
            try:
                # EthicsGuardチェック
                is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, result_page)
                if is_allowed != ActionResult.ALLOWED:
                    continue
                    
                # セッションなし（または新規セッション）でのアクセスを試行
                response = await self._make_request("GET", result_page, modifications=modifications)
                
                if response and response.status_code == 200:
                    # 成功判定: 支払い/注文確定ページ等に直接アクセスできてしまった場合
                    content_lower = response.text.lower()
                    success_keywords = ["success", "thank", "complete", "order", "done", "confirmed"]
                    
                    if any(kw in content_lower for kw in success_keywords):
                        context.result = VerifyResult.SUCCESS
                        context.details = {
                            "vulnerable_flow": flow,
                            "bypass_type": "direct_access_to_result",
                            "evidence": f"Accessed {result_page} skipping {critical_endpoint}"
                        }
                        context.finding = self._create_finding(
                            vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                            target=result_page,
                            method="GET",
                            title="State Machine Bypass: Direct Access to Result Page",
                            description=(
                                f"The application allows direct access to the success/result page '{result_page}' "
                                f"without completing the preceding critical state-changing steps (e.g., {critical_endpoint})."
                            ),
                            response_status=response.status_code,
                            response_body=response.text[:500],
                        )
                        return context
                        
            except Exception as e:
                logger.error(f"Error in state_machine_bypass for {result_page}: {e}")

        return context

    def get_attempts(self) -> list[dict]:
        """実行した試行を取得"""
        return self._attempts.copy()


# ===== Factory関数 =====

def create_bizlogic_hunter(rag_switch=None, program_name: str = "") -> BizLogicHunter:
    """BizLogicHunterを作成"""
    return BizLogicHunter(rag_switch=rag_switch, program_name=program_name)
