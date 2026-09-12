"""
Smart SSRF Hunter - 決定論的 SSRF スペシャリスト

LLM を使用せず SSRFTester のレスポンス判定で SSRF を検出する。
"""
import asyncio
import json
import logging
from itertools import islice
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

# in-band SSRF 応答本文の証跡を保持する最大長（生本文を審査へ渡すが上限を設ける）。
_INBAND_BODY_CAP = 4000

META_KEYS = {
    "_auth", "method", "content_type", "task_id",
    "targets", "targets_file", "source_file", "cookies",
    "tags", "category", "_context", "extra_targets",
    "auth_headers", "headers", "count",
    "race_profile", "safe_variations",
    "forms", "url_evidence", "scan_profile", "profile",
    "detection_mode", "phase", "phase_hint",
    "phase2_on_empty_phase1", "phase2_max_seconds",
    "phase2_max_seconds_risk_forced", "phase2_risk_force_vuln_types",
    "phase1_force_full_coverage", "phase1_stop_on_first_hit",
    "phase1_early_return_on_findings", "per_url_timeout_seconds",
    "per_url_timeout_by_type", "unknown_classification_only",
    "phase1_auto_early_return_on_findings", "phase1_auto_early_return_cmd",
}


class SmartSSRFHunter(Specialist):
    name: str = "SmartSSRFHunter"
    description: str = "Deterministic SSRF detector using response-based analysis"
    timeout_seconds: int = 180
    is_aggressive: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.last_results: list = []
        self.last_tested_params: list = []

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        # SGK-2026-0482: in-band SSRF 専用経路（opt-in）。サーバに任意 URL を
        # 取得させ、その応答本文を in-band で返す型を、製品非依存のパラメータで
        # 検出する。従来の GET クエリ走査経路は ssrf_inband 未指定時そのまま。
        params = task.params or {}
        if isinstance(params.get("ssrf_inband"), dict):
            return await self._execute_inband_ssrf(task, params["ssrf_inband"])
        result = await self.run_as_tool(task.target, params)
        return self._convert_to_findings(result, task.target)

    async def _execute_inband_ssrf(
        self, task: Task, spec: Dict[str, Any]
    ) -> List[Finding]:
        """URL 値フィールドを持つ（認証付き）リクエストでサーバに任意 URL を
        取得させ、応答本文が in-band 反映されるかを検証する。

        実害の正当な証拠 = 「クライアントが直接到達できない URL を、サーバが
        取得して本文を返す」差分（内部ネットワークへのサーバ視点到達）。
        反映本文が空、またはクライアントが probe_url に直接到達できてしまう
        場合は Finding を出さない（fail-closed・偽◎なし）。非破壊（サーバに
        読み取り GET を行わせるのみ）。
        """
        endpoint = str(spec.get("endpoint") or task.target or "").strip()
        method = str(spec.get("method") or "POST").strip().upper()
        url_field = str(spec.get("url_field") or "").strip()
        probe_url = str(spec.get("probe_url") or "").strip()
        reflect_key = str(spec.get("reflect_key") or "").strip()
        headers = dict(spec.get("headers") or {})
        body_template = spec.get("body_template")
        if not isinstance(body_template, dict):
            body_template = {}
        if not (endpoint and url_field and probe_url):
            return []

        client = self._inband_client()
        if client is None:
            return []

        body = {**body_template, url_field: probe_url}
        send_headers = {**headers, "Content-Type": "application/json"}
        try:
            resp = await client.request(
                method, endpoint, headers=send_headers,
                data=json.dumps(body), timeout=20,
            )
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] in-band SSRF request failed: %s", self.name, exc)
            return []
        status = int(getattr(resp, "status", 0) or 0)
        resp_text = str(getattr(resp, "text", "") or getattr(resp, "body", "") or "")
        reflected = self._extract_reflected_body(resp_text, reflect_key)
        if not reflected:
            return []

        # 差分: スキャナ自身が probe_url に直接到達できるか。到達できなければ
        # 「サーバ視点でのみ到達＝in-band SSRF」の実害証拠。
        client_direct_unreachable = await self._client_cannot_reach(client, probe_url, headers)
        if not client_direct_unreachable:
            return []

        roundtrip_body = (
            "[In-band SSRF server-side fetch reflected]\n"
            f"trigger_endpoint={endpoint}\n"
            f"fetched_url={probe_url}\n"
            f"client_direct_unreachable=True\n"
            f"server_response_status={status}\n"
            "--- raw server-reflected body of fetched_url ---\n"
            f"{reflected[:_INBAND_BODY_CAP]}"
        )
        finding = Finding(
            target_url=endpoint,
            vuln_type=VulnType.SSRF,
            severity=Severity.HIGH,
            title="In-band SSRF via server-side URL fetch",
            description=(
                "The server fetches a client-supplied URL and reflects the "
                "response body in-band. The fetched URL is not directly "
                "reachable by the client, proving a server-side request "
                "forgery with internal network reach."
            ),
            evidence=Evidence(
                request_method=method,
                request_url=endpoint,
                request_headers=dict(headers),
                response_status=status if status > 0 else 200,
                response_body=roundtrip_body,
            ),
            source_agent=self.name,
            confidence=0.9,
            impact=(
                "サーバが任意の URL を取得し応答本文を返す in-band SSRF。"
                "クライアントが直接到達できない内部サービスへサーバ経由で到達でき、"
                "内部ネットワークの探索・機微情報取得の起点となる。"
            ),
            reproduction_steps=[
                "URL 値フィールドに内部/任意 URL を入れて対象エンドポイントへ送信",
                "応答に取得本文が in-band 反映されることを確認",
                "同じ URL へクライアントから直接到達できないこと（差分）を確認",
            ],
            tags=["ssrf", "inband", "high"],
            additional_info={
                "ssrf_inband_evidence": {
                    "fetched_url": probe_url,
                    "server_reflected_body": reflected[:_INBAND_BODY_CAP],
                    "client_direct_unreachable": True,
                    "server_status": status,
                    "trigger_endpoint": endpoint,
                },
                "ssrf_inband_replay": {
                    "method": method,
                    "url": endpoint,
                    "body": body,
                    "content_type": "application/json",
                    "url_field": url_field,
                    "probe_url": probe_url,
                    "reflect_key": reflect_key,
                },
                # 審査が参照する生の PoC 対（注入した URL 値フィールドを含む
                # 送信ペイロードと、サーバ側フェッチ結果の生応答）。
                "poc_request": (
                    f"{method} {endpoint} HTTP/1.1\r\n"
                    "Content-Type: application/json\r\n\r\n"
                    f"{json.dumps(body)}"
                ),
                "poc_response": (
                    f"HTTP/1.1 {status if status > 0 else 200}\r\n\r\n"
                    f"{reflected[:_INBAND_BODY_CAP]}"
                ),
            },
        )
        return [finding]

    def _inband_client(self) -> Any:
        """注入済みクライアント優先（E2E/テスト）。無ければ AsyncNetworkClient。"""
        client = getattr(self, "_client", None)
        if client is not None:
            return client
        try:
            from src.core.infra.network_client import AsyncNetworkClient
            self._client = AsyncNetworkClient()
            return self._client
        except Exception as exc:  # noqa: BLE001 — optional dependency boundary
            logger.debug("[%s] no in-band client available: %s", self.name, exc)
            return None

    @staticmethod
    def _extract_reflected_body(resp_text: str, reflect_key: str) -> str:
        """reflect_key が与えられれば応答 JSON からその値を取り出す。
        無ければ応答本文全体を反映本文とみなす（fail-closed は呼び出し側）。"""
        if reflect_key:
            try:
                parsed = json.loads(resp_text)
            except (ValueError, TypeError):
                return ""
            value = parsed.get(reflect_key) if isinstance(parsed, dict) else None
            if value is None:
                return ""
            return value if isinstance(value, str) else json.dumps(value)
        return resp_text

    @staticmethod
    async def _client_cannot_reach(client: Any, probe_url: str, headers: Dict[str, str]) -> bool:
        """スキャナからの probe_url 直接取得が失敗/到達不可なら True。"""
        try:
            resp = await client.request("GET", probe_url, headers=dict(headers or {}), timeout=10)
        except Exception:  # noqa: BLE001 — unreachable is the expected signal
            return True
        status = int(getattr(resp, "status", 0) or 0)
        err = getattr(resp, "error", None)
        return status <= 0 or bool(err)

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None, **_kwargs) -> Dict[str, Any]:
        params = params or {}

        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        auth_headers: Dict[str, str] = self._build_auth_headers(
            dict(_auth.get("auth_headers", {}) or {}),
            params,
        )
        cookies_str: str = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        execution_profile = self._extract_execution_profile(params, auth_headers)
        tested_params = self._extract_test_params(url, params)
        self.last_tested_params = tested_params
        if not tested_params:
            return self._empty_result(tested_params, execution_profile)

        from src.core.attack.ssrf_tester import SSRFTester
        scanner = SSRFTester(auth_headers=auth_headers)
        try:
            results = []
            race_attempts = 0
            for attempt in self._build_race_attempt_plan(tested_params, execution_profile):
                delay_seconds = float(attempt.get("delay_seconds", 0.0) or 0.0)
                if delay_seconds > 0:
                    await asyncio.sleep(delay_seconds)
                race_attempts = int(attempt.get("attempt", 1) or 1)
                results = await scanner.scan_async(url, attempt.get("ordered_params", tested_params))
                if any(result.vulnerable for result in results):
                    break
        except Exception as exc:
            logger.error("[%s] SSRFTester error for %s: %s", self.name, url, exc)
            return self._empty_result(tested_params, execution_profile)

        vuln_results = [r for r in results if r.vulnerable]
        self.last_results = vuln_results
        if not vuln_results:
            return self._empty_result(tested_params, execution_profile)

        first = vuln_results[0]
        return {
            "vulnerable": True,
            "findings_count": len(vuln_results),
            "tested_params": self._sanitize_params(tested_params),
            "payload_type": first.payload_type.value,
            "payload": first.payload,
            "evidence": first.evidence,
            "response_code": first.response_code,
            "matched_variant": first.matched_variant,
            "matched_variant_source": first.matched_variant_source,
            "execution_profile": execution_profile,
            "race_attempts": race_attempts,
            "all_results": [
                {
                    "parameter": r.parameter,
                    "payload_type": r.payload_type.value,
                    "payload": r.payload,
                    "evidence": r.evidence,
                    "response_code": r.response_code,
                    "response_length": r.response_length,
                    "matched_variant": r.matched_variant,
                    "matched_variant_source": r.matched_variant_source,
                }
                for r in vuln_results
            ],
        }

    def _convert_to_findings(self, result: Dict[str, Any], target_url: str) -> List[Finding]:
        if not result.get("vulnerable"):
            return []

        payload = str(result.get("payload", ""))
        payload_type = str(result.get("payload_type", "unknown"))
        evidence_text = str(result.get("evidence", ""))
        response_code = int(result.get("response_code", 0) or 0)
        matched_variant = str(result.get("matched_variant", "") or "")
        matched_variant_source = str(result.get("matched_variant_source", "") or "")
        tested_params = list(result.get("tested_params", []) or [])
        param = tested_params[0] if tested_params else "unknown"

        finding = Finding(
            target_url=target_url,
            vuln_type=VulnType.SSRF,
            severity=Severity.HIGH,
            title=f"SSRF detected via parameter '{param}'",
            description=(
                f"Response-based SSRF indicator matched for payload type '{payload_type}'. "
                f"Payload '{payload}' triggered response evidence suggesting server-side fetch behavior."
            ),
            evidence=Evidence(
                request_method="GET",
                request_url=f"{target_url}?{param}={payload}",
                response_status=response_code,
                response_body=evidence_text[:500],
            ),
            source_agent=self.name,
            confidence=0.90,
            tags=["ssrf", "high"],
            additional_info={
                "tested_params": tested_params,
                "payload_type": payload_type,
                "payload": payload,
                "evidence": evidence_text,
                "matched_variant": matched_variant,
                "matched_variant_source": matched_variant_source,
                "execution_profile": dict(result.get("execution_profile", {}) or {}),
                "poc_request": (
                    f"GET {target_url}?{param}={payload} HTTP/1.1\r\n"
                    f"Host: <target>\r\n\r\n"
                ),
                "poc_response": (
                    f"HTTP/1.1 {response_code}\r\n"
                    f"\r\n"
                    f"{evidence_text[:300]}"
                ),
                "poc_html": (
                    "<!doctype html>\n"
                    "<meta charset=\"utf-8\">\n"
                    f"<form method=\"GET\" action=\"{target_url}\">\n"
                    f"  <input name=\"{param}\" value=\"{payload}\">\n"
                    "  <button type=\"submit\">Send</button>\n"
                    "</form>\n"
                ),
            },
        )
        return [finding]

    def _build_auth_headers(
        self,
        base_headers: Dict[str, str],
        params: Dict[str, Any],
    ) -> Dict[str, str]:
        auth_headers = dict(base_headers)
        for variation in params.get("safe_variations", []) or []:
            if not isinstance(variation, dict):
                continue
            headers = variation.get("headers", {})
            if not isinstance(headers, dict):
                continue
            for key, value in headers.items():
                if key and value is not None:
                    auth_headers[str(key)] = str(value)
        return auth_headers

    def _extract_execution_profile(
        self,
        params: Dict[str, Any],
        auth_headers: Dict[str, str],
    ) -> Dict[str, Any]:
        race_profile = params.get("race_profile", {})
        if not isinstance(race_profile, dict):
            race_profile = {}

        mutation_types: List[str] = []
        applied_header_keys: List[str] = []
        for variation in params.get("safe_variations", []) or []:
            if not isinstance(variation, dict):
                continue
            mutation_type = str(variation.get("mutation_type", "") or "").strip()
            if mutation_type and mutation_type not in mutation_types:
                mutation_types.append(mutation_type)
            headers = variation.get("headers", {})
            if not isinstance(headers, dict):
                continue
            for key in headers.keys():
                header_name = str(key or "").strip()
                if header_name and header_name in auth_headers and header_name not in applied_header_keys:
                    applied_header_keys.append(header_name)

        return {
            "race_profile": dict(race_profile),
            "applied_mutation_types": mutation_types,
            "applied_header_keys": applied_header_keys,
        }

    def _build_race_attempt_plan(
        self,
        tested_params: List[str],
        execution_profile: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        race_profile = execution_profile.get("race_profile", {}) or {}
        if not isinstance(race_profile, dict):
            race_profile = {}

        mode = str(race_profile.get("mode", "") or "").strip().lower() or "single"
        order_permutations = max(1, int(race_profile.get("order_permutations", 1) or 1))
        interval_seconds = float(race_profile.get("interval", 0.0) or 0.0)
        burst_count = max(1, int(race_profile.get("burst", 1) or 1))

        if mode == "interval":
            attempt_count = order_permutations
        elif mode == "burst":
            attempt_count = min(max(order_permutations, 1), burst_count)
        else:
            attempt_count = 1

        ordered_sets: List[List[str]] = []
        for idx in range(attempt_count):
            if not tested_params:
                ordered_sets.append([])
                continue
            rotation = idx % len(tested_params)
            ordered = tested_params[rotation:] + tested_params[:rotation]
            if ordered not in ordered_sets:
                ordered_sets.append(ordered)
        if not ordered_sets:
            ordered_sets = [list(tested_params)]

        plan: List[Dict[str, Any]] = []
        for idx, ordered_params in enumerate(islice(ordered_sets, attempt_count)):
            delay_seconds = interval_seconds if mode == "interval" and idx > 0 else 0.0
            plan.append({
                "attempt": idx + 1,
                "delay_seconds": delay_seconds,
                "ordered_params": ordered_params,
                "mode": mode,
            })
        return plan or [{"attempt": 1, "delay_seconds": 0.0, "ordered_params": list(tested_params), "mode": "single"}]

    def _extract_test_params(self, url: str, params: Dict[str, Any]) -> List[str]:
        parsed = urlparse(url)
        query_keys = list(parse_qs(parsed.query).keys())
        extra_keys: List[str] = []
        for k, v in (params or {}).items():
            if not k or k in META_KEYS or str(k).startswith("_"):
                continue
            if isinstance(v, (dict, list, tuple, set)):
                continue
            extra_keys.append(str(k))

        seen: set = set()
        result: List[str] = []
        for k in query_keys + extra_keys:
            if k not in seen:
                seen.add(k)
                result.append(k)
        return self._sanitize_params(result)

    def _sanitize_params(self, params: List[str]) -> List[str]:
        return [
            p for p in params
            if p and str(p).lower() not in META_KEYS and not str(p).startswith("_")
        ]

    @staticmethod
    def _empty_result(
        tested_params: List[str],
        execution_profile: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "vulnerable": False,
            "findings_count": 0,
            "tested_params": tested_params,
            "payload_type": "",
            "payload": "",
            "evidence": "",
            "response_code": 0,
            "matched_variant": "",
            "matched_variant_source": "",
            "execution_profile": dict(execution_profile or {}),
            "race_attempts": 0,
            "all_results": [],
        }
