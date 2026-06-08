"""
Smart CRLF Hunter - 決定論的 CRLF インジェクション スペシャリスト

LLM を使用せず CRLFTester（http.client 生CRLF送信）でヘッダー注入を検出する。
"""
import logging
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
    "forms", "url_evidence", "scan_profile", "profile",
    "detection_mode", "phase", "phase_hint",
    "phase2_on_empty_phase1", "phase2_max_seconds",
    "phase2_max_seconds_risk_forced", "phase2_risk_force_vuln_types",
    "phase1_force_full_coverage", "phase1_stop_on_first_hit",
    "phase1_early_return_on_findings", "per_url_timeout_seconds",
    "per_url_timeout_by_type", "unknown_classification_only",
    "phase1_auto_early_return_on_findings", "phase1_auto_early_return_cmd",
}

# tested_params が空の場合のフォールバック（CRLFが頻出するパラメータ名）
FALLBACK_PARAMS = [
    "url", "redirect", "next", "return", "dest", "location",
    "forward", "goto", "redir", "lang", "charset", "filename",
]


class SmartCRLFHunter(Specialist):
    """
    決定論的 CRLF インジェクション スペシャリスト。

    CRLFTester（http.client 生CRLF送信 + _is_vulnerable 判定）を非同期で呼び出し、
    CRLFResult を Finding(VulnType.CRLF_INJECTION) へ変換する。
    LLM は使用しない。
    """

    name: str = "SmartCRLFHunter"
    description: str = "Deterministic CRLF injection scanner"
    is_aggressive: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.last_results: list = []
        self.last_tested_params: list = []

    # ------------------------------------------------------------------
    # Specialist interface
    # ------------------------------------------------------------------

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        result = await self.run_as_tool(task.target, task.params or {})
        return self._convert_to_findings(result, task.target)

    # ------------------------------------------------------------------
    # InjectionManager tool interface
    # ------------------------------------------------------------------

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None, **_kwargs) -> Dict[str, Any]:
        """InjectionManager から呼ばれるエントリポイント。"""
        params = params or {}

        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        auth_headers: Dict[str, str] = dict(_auth.get("auth_headers", {}) or {})
        cookies_str: str = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        # META_KEYS 除外（B4対応含む）
        tested_params = self._extract_test_params(url, params, "GET")
        self.last_tested_params = tested_params

        # B4対応: tested_params が空でもフォールバックパラメータでスキャン継続
        scan_params = tested_params if tested_params else FALLBACK_PARAMS

        # B8対応: auth_headers は __init__ で一本化
        from src.core.attack.crlf_tester import CRLFTester
        scanner = CRLFTester(auth_headers=auth_headers)
        try:
            results = await scanner.scan_async(url, scan_params)
        except Exception as exc:
            logger.error("[%s] CRLFTester error for %s: %s", self.name, url, exc)
            return {
                "vulnerable": False,
                "findings_count": 0,
                "tested_params": tested_params,
                "injected_header": "",
                "payload": "",
                "results": [],
            }

        vuln = [r for r in results if r.vulnerable]
        self.last_results = vuln
        return {
            "vulnerable": bool(vuln),
            "findings_count": len(vuln),
            "tested_params": tested_params,
            "injected_header": vuln[0].injected_header if vuln else "",
            "payload": vuln[0].payload if vuln else "",
            "results": [
                {
                    "parameter": r.parameter,
                    "payload": r.payload,
                    "injected_header": r.injected_header,
                    "severity": r.severity,
                }
                for r in vuln
            ],
        }

    # ------------------------------------------------------------------
    # Finding conversion
    # ------------------------------------------------------------------

    def _convert_to_findings(self, result: Dict[str, Any], target_url: str) -> List[Finding]:
        findings = []
        for r in result.get("results", []):
            evidence = Evidence(
                request_method="GET",
                request_url=target_url,
                request_headers={},
                response_status=302,
                response_headers={r["injected_header"]: "injected-via-crlf"},
            )
            findings.append(Finding(
                target_url=target_url,
                vuln_type=VulnType.CRLF_INJECTION,
                severity=Severity.MEDIUM,
                title=f"CRLF Injection via parameter '{r['parameter']}'",
                description=(
                    f"Parameter '{r['parameter']}' reflects CRLF sequence into response headers. "
                    f"Injected header: {r['injected_header']}. "
                    f"Payload: {r['payload']!r}"
                ),
                evidence=evidence,
                reproduction_steps=[
                    f"1. Send: GET {target_url}?{r['parameter']}={r['payload']} HTTP/1.1",
                    f"2. Observe response header: {r['injected_header']}: (injected value)",
                    "3. Confirm the header appears in the response independent of request input.",
                ],
                impact=(
                    "An attacker can inject arbitrary HTTP response headers, enabling "
                    "session fixation via Set-Cookie, open redirect via Location, "
                    "and cache poisoning via Link or Content-Type manipulation."
                ),
                source_agent="SmartCRLFHunter",
                confidence=0.90,
                tags=["crlf", "medium"],
                additional_info={
                    "parameter": r["parameter"],
                    "payload": r["payload"],
                    "injected_header": r["injected_header"],
                    "tested_params": result.get("tested_params", []),
                    "poc_request": (
                        f"GET {target_url}?{r['parameter']}={r['payload']} HTTP/1.1\r\n"
                        f"Host: <target>\r\n\r\n"
                    ),
                    "poc_response": (
                        f"HTTP/1.1 302 Found\r\n"
                        f"Location: /\r\n"
                        f"{r['injected_header']}: injected-via-crlf\r\n\r\n"
                    ),
                    "poc_html": (
                        f"<!-- CRLF Injection PoC -->\n"
                        f"<!-- Parameter: {r['parameter']} -->\n"
                        f"<!-- Payload (URL-encoded): {r['payload']!r} -->\n"
                        f"<!-- Injected header: {r['injected_header']} -->"
                    ),
                },
            ))
        return findings

    # ------------------------------------------------------------------
    # Helpers（SmartSSTIHunter と同一パターン）
    # ------------------------------------------------------------------

    def _extract_test_params(self, url: str, params: Dict[str, Any], method: str) -> List[str]:
        """URL クエリ + params から注入対象パラメータ名を抽出する（META_KEYS 除外）。"""
        parsed = urlparse(url)
        query_keys: List[str] = list(parse_qs(parsed.query).keys())
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
        return result

    def _sanitize_tested_params(self, params: List[str]) -> List[str]:
        """内部制御パラメータを除外する。"""
        return [
            p for p in params
            if p and str(p).lower() not in META_KEYS and not str(p).startswith("_")
        ]
