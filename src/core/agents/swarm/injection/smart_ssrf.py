"""
Smart SSRF Hunter - 決定論的 SSRF スペシャリスト

LLM を使用せず SSRFTester のレスポンス判定で SSRF を検出する。
"""
import asyncio
import logging
from itertools import islice
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)

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
        result = await self.run_as_tool(task.target, task.params or {})
        return self._convert_to_findings(result, task.target)

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
