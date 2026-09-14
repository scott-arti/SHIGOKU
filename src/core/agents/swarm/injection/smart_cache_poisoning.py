"""
Smart Cache Poisoning Hunter - Web キャッシュポイズニング 検出スペシャリスト (SGK-2026-0492)

キャッシュ鍵に含まれない入力（unkeyed input・例 X-Forwarded-Host）が応答に反映され、その
応答がキャッシュされると、後続の**クリーンなリクエスト（victim）**にも攻撃者制御の内容が
配信される（Web キャッシュポイズニング）。

確定は**決定論的差分**で行う：
  - poison（unkeyed ヘッダ＝一意 marker＋一意 cache-buster） → marker が応答に反映＋キャッシュ格納
  - victim（同 URL・クリーン＝ヘッダ無し） → marker が応答に出る（キャッシュ HIT で毒が配信）
  - control（別 cache-buster・クリーン） → marker が出ない
「クリーンな victim に攻撃者 marker が出る」ことがキャッシュ配信の決定的証拠。marker は一意の
攻撃者ホストで偶然混入・捏造不可。非破壊（一意 cache-buster で隔離した鍵に良性 marker のみ・
実ユーザー経路は汚さない）。unkeyed ヘッダ候補は汎用（製品固有ハードコードなし）。
"""
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

_CACHE_UNKEYED_HEADERS: Tuple[str, ...] = (
    "X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host",
    "X-Forwarded-Server", "X-Forwarded-Proto",
)
_CACHE_BUSTER_PARAM = "shigoku_cp"
_CACHE_SNIPPET_CAP = 1500


def _with_cache_buster(url: str, value: str) -> str:
    """URL に一意 cache-buster クエリを付けて新しいキャッシュ鍵を作る。"""
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    q.append((_CACHE_BUSTER_PARAM, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


def _snip_centered(text: str, anchor: str) -> str:
    text = text or ""
    idx = text.find(anchor)
    if idx < 0:
        return text[:_CACHE_SNIPPET_CAP]
    start = max(0, idx - _CACHE_SNIPPET_CAP // 2)
    return text[start:start + _CACHE_SNIPPET_CAP]


class SmartCachePoisoningHunter(Specialist):
    name = "SmartCachePoisoningHunter"
    description = "Web cache poisoning detector (unkeyed input cached and served to a clean victim)"
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

    def _base_url(self, task: Task) -> str:
        params = self._params(task)
        obs = params.get("cache_observe")
        if isinstance(obs, dict) and str(obs.get("url") or "").strip():
            return str(obs["url"])
        return str(task.target)

    def _headers_to_try(self, task: Task) -> Tuple[str, ...]:
        params = self._params(task)
        provided = params.get("cache_unkeyed_headers")
        if isinstance(provided, (list, tuple)) and provided:
            return tuple(str(h) for h in provided)
        return _CACHE_UNKEYED_HEADERS

    async def _probe(self, task: Task) -> Optional[Dict[str, Any]]:
        base = self._base_url(task)
        auth = self._auth_headers(task)

        for header in self._headers_to_try(task):
            marker = "shigoku-cp-" + uuid.uuid4().hex[:12] + ".evil.example"
            cb = uuid.uuid4().hex[:16]
            poison_url = _with_cache_buster(base, cb)

            # ① 毒入り: unkeyed ヘッダに一意 marker を入れて送る（キャッシュに格納させる）。
            try:
                p_status, p_body = await self._send(poison_url, {**auth, header: marker})
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] poison send failed (%s): %s", self.name, header, exc)
                continue
            if marker not in p_body:
                continue  # unkeyed ヘッダが反映されない → このヘッダはスキップ

            # ② victim: 同 URL をクリーン（ヘッダ無し）で送る。marker が出れば毒が配信された。
            try:
                v_status, v_body = await self._send(poison_url, dict(auth))
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] victim send failed: %s", self.name, exc)
                continue
            if not (200 <= v_status < 300) or marker not in v_body:
                continue  # キャッシュされず victim に配信されない → キャッシュポイズニングでない

            # ③ control: 別 cache-buster をクリーンで送る。marker が出ない（毒った鍵だけが汚染）。
            control_url = _with_cache_buster(base, uuid.uuid4().hex[:16])
            try:
                _c_status, c_body = await self._send(control_url, dict(auth))
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] control send failed: %s", self.name, exc)
                continue
            if marker in c_body:
                continue  # 別鍵にも出る＝キャッシュ配信の証明にならない

            return {
                "request_url": poison_url,
                "base_url": base,
                "injected_header": header,
                "marker": marker,
                "poison_status": p_status,
                "poison_served_body": _snip_centered(p_body, marker),
                "victim_status": v_status,
                "victim_served_body": _snip_centered(v_body, marker),
                "control_served_body": c_body[:_CACHE_SNIPPET_CAP],
                "auth_headers": auth,
            }
        return None

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
        url = proof["request_url"]
        header = proof["injected_header"]
        marker = proof["marker"]
        p_status = proof["poison_status"]
        p_body = proof["poison_served_body"]
        v_status = proof["victim_status"]
        v_body = proof["victim_served_body"]
        c_body = proof["control_served_body"]

        poc_request = (
            f"# Step 1 — poison (unkeyed header injected, cached under this URL)\r\n"
            f"GET {url} HTTP/1.1\r\n"
            f"{header}: {marker}\r\n"
            "\r\n"
            f"# Step 2 — victim (same URL, CLEAN, no injected header)\r\n"
            f"GET {url} HTTP/1.1\r\n"
            "\r\n"
            f"# Step 3 — control (different cache key, CLEAN)\r\n"
            f"GET {proof['base_url']} (+ fresh cache-buster) HTTP/1.1\r\n"
        )
        poc_response = (
            f"# Step 1 response — attacker marker '{marker}' reflected (HTTP {p_status})\r\n"
            f"{p_body}\r\n"
            "\r\n"
            f"# Step 2 response — CLEAN victim receives the marker from cache (HTTP {v_status})\r\n"
            f"{v_body}\r\n"
            "\r\n"
            f"# Step 3 response — control (different key) does NOT contain the marker\r\n"
            f"{c_body}"
        )
        impact = (
            f"キャッシュ鍵に含まれない '{header}' ヘッダに一意の攻撃者ホスト '{marker}' を入れて "
            f"要求すると応答に反映され（HTTP {p_status}）、その応答がキャッシュされる。以降、同じ URL への"
            f"**クリーンなリクエスト（victim・ヘッダ無し）にも攻撃者 marker が配信される**（HTTP {v_status}）。"
            "別キャッシュ鍵（control）には出ない。この差分から Web キャッシュポイズニングが確定。攻撃者は"
            "unkeyed 入力経由で他ユーザーへ任意コンテンツ（XSS・リダイレクト・改ざん）を配信できる実害。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.CACHE_POISONING,
            severity=Severity.HIGH,
            title=f"Web Cache Poisoning via unkeyed '{header}'",
            description=(
                "Web cache poisoning confirmed by differential: an attacker marker injected via the "
                f"unkeyed '{header}' header is cached and then served to a CLEAN victim request "
                f"(marker present, HTTP {v_status}) while a different cache key (control) is not "
                "poisoned."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                f"一意 cache-buster 付き URL に '{header}: {marker}' を入れて要求し、marker が応答に"
                f"反映される（HTTP {p_status}）ことを確認する（毒入り＋キャッシュ格納）。",
                f"同じ URL をクリーン（ヘッダ無し）で要求すると、marker が配信される（HTTP {v_status}）"
                "ことを確認する（キャッシュ HIT ＝毒が victim に届く）。",
                "別 cache-buster のクリーン要求では marker が出ないことを確認する（毒った鍵だけが汚染＝差分）。",
            ],
            tags=["cache_poisoning", "high", "cache_poisoning_confirmed"],
            evidence=Evidence(
                request_method="GET",
                request_url=url,
                request_headers={**proof.get("auth_headers", {})},
                request_body="",
                response_status=v_status,
                response_headers={},
                response_body=v_body,
            ),
            additional_info={
                "cache_poisoning_evidence": {
                    "request_url": url,
                    "injected_header": header,
                    "marker": marker,
                    "poison_status": p_status,
                    "poison_served_body": p_body,
                    "victim_status": v_status,
                    "victim_served_body": v_body,
                    "control_served_body": c_body,
                },
                "cache_poisoning_replay": {
                    "base_url": proof["base_url"],
                    "header": header,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
