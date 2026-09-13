"""
Smart NoSQL Hunter - NoSQL(MongoDB) オペレータ注入 検出スペシャリスト (SGK-2026-0487)

JSON ボディのフィールドに MongoDB 演算子（``{"$ne": null}`` 等）を注入すると、
本来は文字列一致で照合されるはずのフィールドがクエリ演算子として解釈され、
有効な値を知らなくてもレコードが返る（認可/検証バイパス・データ抽出）。

確定は「決定論的差分」で行う（IDOR の authz_diff と同型）:
  - 負のコントロール（無効なリテラル値）→ 失敗（非 2xx / データなし）
  - 演算子ペイロード → 成功（2xx + データ）
両者の差分が「演算子が実際にクエリとして解釈された」証拠になる。
製品固有のエンドポイント/フィールド名はハードコードしない（候補リスト＋task 由来）。
"""
import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

META_KEYS = {
    "_auth", "method", "content_type", "task_id", "targets", "targets_file",
    "source_file", "cookies", "tags", "category", "_context", "extra_targets",
    "auth_headers", "headers", "count", "forms", "url_evidence", "scan_profile",
    "profile", "detection_mode", "phase", "phase_hint", "nosql_base_body",
    "nosql_fields",
}

# MongoDB 演算子ペイロード（クエリ演算子として解釈されると常に真になる系）。
_NOSQL_OPERATORS: Tuple[Dict[str, Any], ...] = (
    {"$ne": None},
    {"$regex": ".*"},
    {"$gt": ""},
)
# 演算子検出（payload/evidence 側の検証用・確定バーと共有語彙）。
_NOSQL_OPERATOR_RE = re.compile(r"\$(?:ne|gt|gte|lt|lte|regex|in|nin|where|exists)\b")
# 注入対象になりやすい汎用 JSON フィールド名（task 由来を優先し、これは補完）。
_NOSQL_FALLBACK_FIELDS: Tuple[str, ...] = (
    "coupon_code", "username", "email", "user", "password",
    "id", "name", "q", "search", "filter", "token",
)
_NOSQL_SNIPPET_CAP = 1500


def _body_has_data(status: int, body: str) -> bool:
    """2xx かつ本文が非空の実データ（空 dict/list/null/エラーでない）か。"""
    if not (200 <= status < 300):
        return False
    text = (body or "").strip()
    if text in ("", "{}", "[]", "null", "false"):
        return False
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return bool(text)
    if isinstance(parsed, dict):
        return len(parsed) > 0
    if isinstance(parsed, list):
        return len(parsed) > 0
    return parsed not in (None, "", 0, False)


def _mask_auth(headers: Dict[str, str]) -> Dict[str, str]:
    """Authorization / Cookie の値をマスク（秘密値を evidence/poc に残さない）。"""
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in ("authorization", "cookie", "x-api-key"):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


class SmartNoSQLHunter(Specialist):
    name = "SmartNoSQLHunter"
    description = "NoSQL(MongoDB) operator injection detector (differential confirmation)"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe_nosql(task)
        if result is None:
            return []
        return [self._build_finding(task.target, result)]

    def _auth_headers(self, task: Task) -> Dict[str, str]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        headers = dict(_auth.get("auth_headers", {}) or {})
        cookies = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies and "Cookie" not in headers:
            headers["Cookie"] = cookies
        return headers

    def _candidate_fields(self, task: Task) -> List[str]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        provided = params.get("nosql_fields")
        fields = list(provided) if isinstance(provided, (list, tuple)) else []
        for f in _NOSQL_FALLBACK_FIELDS:
            if f not in fields:
                fields.append(f)
        return fields

    def _base_body(self, task: Task) -> Dict[str, Any]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        base = params.get("nosql_base_body")
        return dict(base) if isinstance(base, dict) else {}

    async def _probe_nosql(self, task: Task) -> Optional[Dict[str, Any]]:
        url = task.target
        headers = self._auth_headers(task)
        base_body = self._base_body(task)
        for field in self._candidate_fields(task):
            control_val = "shigoku_nosql_" + uuid.uuid4().hex[:10]
            ctrl_body_obj = {**base_body, field: control_val}
            try:
                ctrl_status, ctrl_text = await self._post_json(url, ctrl_body_obj, headers)
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] control send failed (%s): %s", self.name, field, exc)
                continue
            # 負のコントロールが成功してしまうフィールドは差分が作れない → skip
            if _body_has_data(ctrl_status, ctrl_text):
                continue
            for operator in _NOSQL_OPERATORS:
                op_body_obj = {**base_body, field: operator}
                try:
                    op_status, op_text = await self._post_json(url, op_body_obj, headers)
                except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                    logger.debug("[%s] operator send failed (%s): %s", self.name, field, exc)
                    continue
                if _body_has_data(op_status, op_text):
                    return {
                        "request_url": url,
                        "field": field,
                        "operator_body": op_body_obj,
                        "operator_payload": json.dumps(op_body_obj),
                        "operator_status": op_status,
                        "operator_served_body": op_text[:_NOSQL_SNIPPET_CAP],
                        "control_value": control_val,
                        "control_status": ctrl_status,
                        "control_served_body": ctrl_text[:_NOSQL_SNIPPET_CAP],
                        "auth_headers": headers,
                    }
        return None

    async def _post_json(
        self, url: str, body: Dict[str, Any], headers: Dict[str, str]
    ) -> Tuple[int, str]:
        """JSON を POST（``self._client`` 注入 seam or AsyncNetworkClient）。"""
        h = dict(headers or {})
        h["Content-Type"] = "application/json"
        data = json.dumps(body)

        async def _do(client):
            return await client.request("POST", url, data=data, headers=h, use_proxy=True)

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
        field = proof["field"]
        operator_payload = proof["operator_payload"]
        op_status = proof["operator_status"]
        op_body = proof["operator_served_body"]
        ctrl_status = proof["control_status"]
        ctrl_body = proof["control_served_body"]
        control_value = proof["control_value"]
        masked_headers = _mask_auth(proof.get("auth_headers", {}))
        control_payload = json.dumps({field: control_value})

        header_lines = "".join(f"{k}: {v}\r\n" for k, v in masked_headers.items())
        # 差分の両ステップを poc に載せる（判定には演算子成功だけでなく
        # 無効リテラル失敗の対比が必須＝SGK-2026-0487 の教訓）。
        poc_request = (
            "# Step 1 — negative control (invalid literal, expected to FAIL)\r\n"
            f"POST {url} HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            f"{header_lines}"
            "\r\n"
            f"{control_payload}\r\n"
            "\r\n"
            "# Step 2 — NoSQL operator injection (expected to SUCCEED)\r\n"
            f"POST {url} HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            f"{header_lines}"
            "\r\n"
            f"{operator_payload}"
        )
        poc_response = (
            "# Step 1 response — invalid literal is rejected\r\n"
            f"HTTP/1.1 {ctrl_status}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{ctrl_body}\r\n"
            "\r\n"
            "# Step 2 response — operator returns a valid record (injection)\r\n"
            f"HTTP/1.1 {op_status}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{op_body}"
        )
        impact = (
            f"JSON フィールド '{field}' に MongoDB 演算子（例 {{\"$ne\": null}}）を注入すると、"
            f"有効な値を知らないのにレコードが返る（HTTP {op_status}）。無効なリテラル値では"
            f"失敗する（HTTP {ctrl_status}）のとの差分から、フィールドがクエリ演算子として"
            "解釈される NoSQL 注入が確定。認可/検証バイパスやデータ抽出に直結する実害。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.NOSQL_INJECTION,
            severity=Severity.HIGH,
            title=f"NoSQL Operator Injection in field '{field}'",
            description=(
                "NoSQL (MongoDB) operator injection confirmed by differential: a "
                f"query operator in '{field}' returns a record (HTTP {op_status}) "
                f"while an invalid literal fails (HTTP {ctrl_status})."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                f"認証付きで JSON ボディの '{field}' に無効なリテラル値を送り、失敗"
                f"（HTTP {ctrl_status}）することを確認する。",
                f"同じ '{field}' に MongoDB 演算子 {{\"$ne\": null}} を送ると、有効な"
                f"レコードが返る（HTTP {op_status}）ことを確認する（差分＝演算子注入）。",
            ],
            tags=["nosql_injection", "high", "nosql_operator_injection"],
            evidence=Evidence(
                request_method="POST",
                request_url=url,
                # 封印再現は evidence.request_headers を用いて元リクエストを再送する
                # （ssrf_inband/SGK-2026-0482 と同型）。認証付きエンドポイントの
                # 再現に必要なため実 auth ヘッダを保持する（表示用 poc_request は
                # マスク済み）。
                request_headers={"Content-Type": "application/json",
                                 **proof.get("auth_headers", {})},
                request_body=operator_payload,
                response_status=op_status,
                response_headers={"Content-Type": "application/json"},
                response_body=op_body,
            ),
            additional_info={
                "nosql_evidence": {
                    "request_url": url,
                    "field": field,
                    "operator_payload": operator_payload,
                    "operator_status": op_status,
                    "operator_served_body": op_body,
                    "control_value": proof["control_value"],
                    "control_status": ctrl_status,
                    "control_served_body": ctrl_body,
                },
                "nosql_replay": {
                    "method": "POST",
                    "url": url,
                    "body": proof["operator_body"],
                    "field": field,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
