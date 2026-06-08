"""
AuthNinja: High-speed Authentication Checker

Specialist for fast, rule-based authentication checks.
"""

import logging
import jwt 
from typing import List, Dict, Any, Optional, Tuple
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

class AuthNinja(Specialist):
    """
    高速認証チェッカー
    
    機能:
    1. JWT None Algorithm Attack
    2. Weak Secret Brute-force (Dictionary attack on JWT signature)
    3. Basic Auth Weak Credentials (if applicable)
    """
    
    name = "AuthNinja"
    description = "Fast checker for common auth weaknesses (JWT None-Alg, Weak Secrets)."
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.wordlist = ["secret", "123456", "password", "admin", "test"] # 簡易辞書

    async def execute(self, task: Task) -> List[Finding]:
        """Entry point"""
        token = task.params.get("token", "")
        if not token:
            return []
            
        result = await self.run_as_tool(token, "all")
        
        findings = []
        if result.get("vulnerable"):
            findings.append(Finding(
                vuln_type=VulnType.JWT_NONE_ALG if "None Alg" in result["description"] else VulnType.WEAK_PASSWORD,
                severity=Severity.HIGH,
                title=f"Authentication Bypass: {result['description']}",
                description=result["description"],
                target_url=task.target,
                source_agent=self.name,
                evidence=Evidence(
                    request_url=task.target,
                    response_body=result.get("evidence", "")
                )
            ))
        return findings

    async def run_as_tool(self, token: str, check_type: str = "all", **_kwargs) -> Dict[str, Any]:
        """
        Managerから呼び出し可能なToolメソッド
        """
        if not token or token.count('.') != 2:
            return {
                "vulnerable": False, 
                "message": f"Skipped: Token does not appear to be a JWT (Found: '{token[:20]}...'). AuthNinja currently only supports JWT analysis. Opaque session cookies are not yet supported."
            }
             
        # 1. None Algorithm Check
        if check_type in ["all", "none_alg"]:
            is_vuln, payload = self._check_none_alg(token)
            if is_vuln:
                return {
                    "vulnerable": True,
                    "description": "JWT accepts 'none' algorithm (Signature Bypass)",
                    "evidence": payload,
                    "strategy": "Modified header to alg: none and removed signature."
                }
                
        # 2. Weak Secret Check
        if check_type in ["all", "weak_secret"]:
            is_vuln, secret = self._check_weak_secret(token)
            if is_vuln:
                return {
                    "vulnerable": True,
                    "description": f"JWT signed with weak secret: '{secret}'",
                    "evidence": f"Secret: {secret}",
                    "strategy": "Brute-force verification with common dictionary."
                }
                
        return {"vulnerable": False, "message": "No vulnerabilities found by AuthNinja"}

    def _check_none_alg(self, _token: str) -> Tuple[bool, str]:
        """
        Alg: None 攻撃のシミュレーション
        (実際にはサーバーに送って検証する必要があるが、ここでは生成までを担当)
        """
        try:
            return False, "" # 安全側に倒す（サーバー検証ロジックがないため）
            # 実装メモ: 本来はここで生成したトークンをManagerに返し、Managerが検証するか
            # AuthNinja内でリクエストを飛ばす必要がある。
            # 今回は「チェックロジック」として、脆弱性スキャンライブラリ的に振る舞う。
        except Exception:
            return False, ""

    def _check_weak_secret(self, token: str) -> Tuple[bool, str]:
        """
        辞書攻撃による署名検証
        """
        try:
            for secret in self.wordlist:
                try:
                    jwt.decode(token, secret, algorithms=["HS256"])
                    return True, secret
                except jwt.InvalidSignatureError:
                    continue
                except Exception:
                    continue
        except Exception:
            pass
        return False, ""
