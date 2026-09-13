"""
Smart Mass Assignment Hunter - 特権フィールド昇格 検出スペシャリスト (SGK-2026-0488)

API リクエストの JSON ボディに、本来サーバ側でしか設定できないはずの特権フィールド
（``role``/``is_admin``/``verified``/``credit`` 等）を攻撃者値で紛れ込ませると、
フレームワークの一括代入（mass assignment / auto-binding）でそのままモデルに反映され、
権限昇格や検証バイパスに繋がる。

確定は「決定論的差分」で行う（IDOR の authz_diff と同型だが専用マーカー）:
  - control（当該フィールドを送らない） → 応答にサーバ既定値が入る（例 role="customer"）
  - injection（当該フィールドを攻撃者値で送る） → 応答に攻撃者値が反映（例 role="admin"）
両者の差分が「送ってはいけないフィールドが client 制御で上書きされた」証拠になる。

echo（単なる入力反響）は control でフィールドが応答に現れない（present=False）ため発火しない。
製品固有のエンドポイント/フィールドはハードコードしない（候補リスト＋task 由来 base body）。
"""
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

META_KEYS = {
    "_auth", "method", "content_type", "task_id", "targets", "targets_file",
    "source_file", "cookies", "tags", "category", "_context", "extra_targets",
    "auth_headers", "headers", "count", "forms", "url_evidence", "scan_profile",
    "profile", "detection_mode", "phase", "phase_hint",
    "mass_assignment_base_body", "mass_assignment_fields", "mass_assignment_unique_fields",
}

# 本来サーバ側でしか設定できない特権フィールド候補と、対応する攻撃者値。
# （task 由来を優先し、これは補完。攻撃者値は「昇格した状態」を表す値。）
_PRIVILEGED_FIELDS: Tuple[Tuple[str, Any], ...] = (
    ("role", "admin"),
    ("isAdmin", True),
    ("is_admin", True),
    ("admin", True),
    ("isVerified", True),
    ("verified", True),
    ("is_verified", True),
    ("email_verified", True),
    ("account_verified", True),
    ("credit", 999999),
    ("available_credit", 999999),
    ("balance", 999999),
    ("account_balance", 999999),
    ("wallet_balance", 999999),
)

# create エンドポイントの一意制約に当たりやすいフィールド（送信毎に uuid で更新）。
_UNIQUE_FIELDS: Tuple[str, ...] = ("email", "username", "user", "login", "userName")
_MA_SNIPPET_CAP = 1500
_READ_MAX_DEPTH = 6


def _norm(value: Any) -> str:
    """比較用にスカラを正規化（None→"" / bool→true|false / 数値→str / str→trim）。"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return str(value).strip()


def _read_field(text: str, field: str) -> Tuple[bool, Any]:
    """応答本文(JSON)から field を再帰探索。(present, value) を返す。

    top-level を優先し、無ければ data/user/result などのネストも探索する。
    JSON でない/見つからない場合は (False, None)。
    """
    try:
        parsed = json.loads((text or "").strip() or "null")
    except (ValueError, TypeError):
        return (False, None)

    def _walk(obj: Any, depth: int) -> Tuple[bool, Any]:
        if depth > _READ_MAX_DEPTH:
            return (False, None)
        if isinstance(obj, dict):
            if field in obj:
                return (True, obj[field])
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    found, val = _walk(v, depth + 1)
                    if found:
                        return (True, val)
        elif isinstance(obj, list):
            for v in obj:
                if isinstance(v, (dict, list)):
                    found, val = _walk(v, depth + 1)
                    if found:
                        return (True, val)
        return (False, None)

    return _walk(parsed, 0)


def _mask_auth(headers: Dict[str, str]) -> Dict[str, str]:
    """Authorization / Cookie の値をマスク（秘密値を evidence/poc 表示に残さない）。"""
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in ("authorization", "cookie", "x-api-key"):
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


class SmartMassAssignmentHunter(Specialist):
    name = "SmartMassAssignmentHunter"
    description = "Mass assignment (privileged field elevation) detector (differential confirmation)"
    timeout_seconds = 120
    is_aggressive = False

    def __init__(self, config: Dict = None):
        super().__init__()
        self.config = config or {}

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self._probe_mass_assignment(task)
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

    def _base_body(self, task: Task) -> Dict[str, Any]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        base = params.get("mass_assignment_base_body")
        return dict(base) if isinstance(base, dict) else {}

    def _unique_fields(self, task: Task) -> Tuple[str, ...]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        provided = params.get("mass_assignment_unique_fields")
        if isinstance(provided, (list, tuple)) and provided:
            return tuple(str(f) for f in provided)
        return _UNIQUE_FIELDS

    def _candidate_fields(self, task: Task) -> List[Tuple[str, Any]]:
        params = task.params if isinstance(getattr(task, "params", None), dict) else {}
        provided = params.get("mass_assignment_fields")
        fields: List[Tuple[str, Any]] = []
        if isinstance(provided, dict):
            fields.extend((str(k), v) for k, v in provided.items())
        elif isinstance(provided, (list, tuple)):
            for item in provided:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    fields.append((str(item[0]), item[1]))
        seen = {f for f, _ in fields}
        for f, v in _PRIVILEGED_FIELDS:
            if f not in seen:
                fields.append((f, v))
        return fields

    def _freshen(self, body: Dict[str, Any], unique_fields: Tuple[str, ...]) -> Dict[str, Any]:
        """一意制約フィールドを uuid で更新したコピーを返す（重複回避）。"""
        out = dict(body)
        token = uuid.uuid4().hex[:12]
        for uf in unique_fields:
            if uf in out and isinstance(out[uf], str) and out[uf]:
                val = out[uf]
                if "@" in val:
                    domain = val.split("@", 1)[1]
                    out[uf] = f"ma_{token}@{domain}"
                else:
                    out[uf] = f"{val}_{token}"
        return out

    async def _probe_mass_assignment(self, task: Task) -> Optional[Dict[str, Any]]:
        url = task.target
        headers = self._auth_headers(task)
        base_body = self._base_body(task)
        if not base_body:
            return None
        unique_fields = self._unique_fields(task)

        for field, attacker_value in self._candidate_fields(task):
            attacker_norm = _norm(attacker_value)
            if attacker_norm == "":
                continue
            # control: 当該フィールドを送らない（base_body から除去）。
            control_body = {k: v for k, v in base_body.items() if k != field}
            control_body = self._freshen(control_body, unique_fields)
            try:
                ctrl_status, ctrl_text = await self._post_json(url, control_body, headers)
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] control send failed (%s): %s", self.name, field, exc)
                continue
            # control が成功しないと「サーバ既定値」を観測できない → skip。
            if not (200 <= ctrl_status < 300):
                continue
            ctrl_present, ctrl_val = _read_field(ctrl_text, field)
            # echo 排除: control でフィールドが応答に現れない＝server-controlled でない → skip。
            if not ctrl_present:
                continue
            if _norm(ctrl_val) == attacker_norm:
                continue  # 既定値が既に攻撃者値と同じ＝昇格にならない → skip。

            # injection: 当該フィールドを攻撃者値で送る。
            inj_body = self._freshen({**base_body, field: attacker_value}, unique_fields)
            try:
                inj_status, inj_text = await self._post_json(url, inj_body, headers)
            except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
                logger.debug("[%s] injection send failed (%s): %s", self.name, field, exc)
                continue
            if not (200 <= inj_status < 300):
                continue
            inj_present, inj_val = _read_field(inj_text, field)
            if not inj_present or _norm(inj_val) != attacker_norm:
                continue

            # 差分確定: injection=攻撃者値・control=別の既定値。封印再現用に fresh body を予約。
            replay_body = self._freshen({**base_body, field: attacker_value}, unique_fields)
            return {
                "request_url": url,
                "field": field,
                "attacker_value": attacker_value,
                "attacker_norm": attacker_norm,
                "injected_body": inj_body,
                "injected_payload": json.dumps(inj_body),
                "injected_status": inj_status,
                "injected_served_body": inj_text[:_MA_SNIPPET_CAP],
                "injected_observed": _norm(inj_val),
                "control_body": control_body,
                "control_payload": json.dumps(control_body),
                "control_status": ctrl_status,
                "control_served_body": ctrl_text[:_MA_SNIPPET_CAP],
                "control_observed": _norm(ctrl_val),
                "replay_body": replay_body,
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
        attacker_norm = proof["attacker_norm"]
        inj_status = proof["injected_status"]
        inj_body = proof["injected_served_body"]
        inj_payload = proof["injected_payload"]
        ctrl_status = proof["control_status"]
        ctrl_body = proof["control_served_body"]
        ctrl_payload = proof["control_payload"]
        control_observed = proof["control_observed"]
        masked_headers = _mask_auth(proof.get("auth_headers", {}))

        header_lines = "".join(f"{k}: {v}\r\n" for k, v in masked_headers.items())
        # 差分の両ステップを poc に載せる（判定には injection 反映だけでなく
        # control の既定値との対比が必須＝SGK-2026-0487 の教訓）。
        poc_request = (
            "# Step 1 — control (privileged field NOT sent)\r\n"
            f"POST {url} HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            f"{header_lines}"
            "\r\n"
            f"{ctrl_payload}\r\n"
            "\r\n"
            f"# Step 2 — injection (privileged field '{field}' sent as attacker value)\r\n"
            f"POST {url} HTTP/1.1\r\n"
            "Content-Type: application/json\r\n"
            f"{header_lines}"
            "\r\n"
            f"{inj_payload}"
        )
        poc_response = (
            f"# Step 1 response — server assigns its own default for '{field}' "
            f"({control_observed!r})\r\n"
            f"HTTP/1.1 {ctrl_status}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{ctrl_body}\r\n"
            "\r\n"
            f"# Step 2 response — attacker value for '{field}' ({attacker_norm!r}) is persisted\r\n"
            f"HTTP/1.1 {inj_status}\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            f"{inj_body}"
        )
        impact = (
            f"リクエストボディに特権フィールド '{field}' を攻撃者値（{attacker_norm!r}）で紛れ込ませると、"
            f"サーバがそのまま受理して応答（永続レコード）に反映（HTTP {inj_status}）。同じ '{field}' を"
            f"送らない control ではサーバ既定値（{control_observed!r}）になる（HTTP {ctrl_status}）。"
            "この差分から、本来サーバ側でしか設定できないフィールドを client が上書きできる mass "
            "assignment が確定。権限昇格・検証バイパス等の実害に直結する。"
        )
        return Finding(
            target_url=target_url,
            vuln_type=VulnType.MASS_ASSIGNMENT,
            severity=Severity.HIGH,
            title=f"Mass Assignment: privileged field '{field}' elevation",
            description=(
                "Mass assignment confirmed by differential: injecting the privileged field "
                f"'{field}' persists the attacker value ({attacker_norm!r}, HTTP {inj_status}) "
                f"while a control request without it yields the server default "
                f"({control_observed!r}, HTTP {ctrl_status})."
            ),
            source_agent=self.name,
            confidence=0.95,
            impact=impact,
            reproduction_steps=[
                f"特権フィールド '{field}' を送らずにリクエストし、応答にサーバ既定値"
                f"（{control_observed!r}）が入る（HTTP {ctrl_status}）ことを確認する。",
                f"同じリクエストに '{field}' を攻撃者値（{attacker_norm!r}）で加えて送ると、応答"
                f"（永続レコード）に攻撃者値が反映される（HTTP {inj_status}）ことを確認する（差分＝"
                "特権フィールドの一括代入）。",
            ],
            tags=["mass_assignment", "high", "privileged_field_assigned"],
            evidence=Evidence(
                request_method="POST",
                request_url=url,
                # 封印再現は evidence.request_headers を用いて元リクエストを再送する
                # （ssrf_inband/SGK-2026-0482 同型）。authed 対象の再現に必要なため実 auth
                # ヘッダを保持する（表示用 poc_request はマスク済み）。
                request_headers={"Content-Type": "application/json",
                                 **proof.get("auth_headers", {})},
                request_body=inj_payload,
                response_status=inj_status,
                response_headers={"Content-Type": "application/json"},
                response_body=inj_body,
            ),
            additional_info={
                "mass_assignment_evidence": {
                    "request_url": url,
                    "field": field,
                    "injected_value": attacker_norm,
                    "injected_payload": inj_payload,
                    "injected_status": inj_status,
                    "injected_field_value": proof["injected_observed"],
                    "injected_served_body": inj_body,
                    "control_payload": ctrl_payload,
                    "control_status": ctrl_status,
                    "control_field_value": control_observed,
                    "control_served_body": ctrl_body,
                },
                "mass_assignment_replay": {
                    "method": "POST",
                    "url": url,
                    "body": proof["replay_body"],
                    "field": field,
                    "expected_value": attacker_norm,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
            },
        )
