"""
Smart CORS Hunter - 決定論的 CORS スペシャリスト

LLM を使用せず CORSTester でOrigin検証バイパスを検出する。
"""
import logging
from typing import Dict, Any, List, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity

logger = logging.getLogger(__name__)


class SmartCORSHunter(Specialist):
    """
    決定論的 CORS スペシャリスト。

    CORSTester（15種Origin + _is_vulnerable判定）を非同期で呼び出し、
    CORSResult を Finding(VulnType.CORS_MISCONFIGURATION) へ変換する。
    LLM は使用しない。
    """

    name: str = "SmartCORSHunter"
    description: str = "Deterministic CORS misconfiguration scanner"
    is_aggressive: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.last_results: list = []

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

        from src.core.attack.cors_tester import CORSTester
        scanner = CORSTester(auth_headers=auth_headers)
        try:
            results = await scanner.scan_async(url)
        except Exception as exc:
            logger.error("[%s] CORSTester error for %s: %s", self.name, url, exc)
            return {"vulnerable": False, "findings_count": 0, "tested_params": [], "results": []}

        vuln = [r for r in results if r.vulnerable]
        self.last_results = vuln
        return {
            "vulnerable": bool(vuln),
            "findings_count": len(vuln),
            "tested_params": [],
            "results": [
                {
                    "test_origin": r.test_origin,
                    "acao": r.acao_header,
                    "acac": r.acac_header,
                    "misconfiguration": r.misconfiguration,
                    "severity": r.severity,
                }
                for r in vuln
            ],
        }

    # ------------------------------------------------------------------
    # Finding conversion
    # ------------------------------------------------------------------

    def _convert_to_findings(self, result: Dict[str, Any], target_url: str) -> List[Finding]:
        from src.core.attack.cors_tester import CORSTester
        from src.core.models.finding import Evidence
        findings = []
        for r in result.get("results", []):
            sev = Severity.HIGH if str(r.get("acac", "")).lower() == "true" else Severity.MEDIUM
            poc = CORSTester.generate_poc_html(
                target_url, r["test_origin"], r["misconfiguration"]
            )
            evidence = Evidence(
                request_method="GET",
                request_url=target_url,
                request_headers={"Origin": r["test_origin"]},
                response_status=200,
                response_headers={
                    "Access-Control-Allow-Origin": r.get("acao", ""),
                    "Access-Control-Allow-Credentials": r.get("acac", ""),
                },
            )
            findings.append(Finding(
                target_url=target_url,
                vuln_type=VulnType.CORS_MISCONFIGURATION,
                severity=sev,
                title=f"CORS Misconfiguration: {r['misconfiguration']}",
                description=(
                    f"Origin '{r['test_origin']}' was reflected in Access-Control-Allow-Origin header. "
                    f"Type: {r['misconfiguration']}. "
                    f"Access-Control-Allow-Credentials: {r.get('acac', '')}"
                ),
                evidence=evidence,
                reproduction_steps=[
                    f"1. Send GET {target_url} with header: Origin: {r['test_origin']}",
                    f"2. Observe response header: Access-Control-Allow-Origin: {r.get('acao', '')}",
                    f"3. If Access-Control-Allow-Credentials: true, cross-origin requests with cookies are possible.",
                    f"4. Use the PoC HTML to confirm data exfiltration from a controlled origin.",
                ],
                impact=(
                    "An attacker can read sensitive cross-origin responses (tokens, PII) "
                    "if the victim visits a malicious page while authenticated."
                    if str(r.get("acac", "")).lower() == "true"
                    else "An attacker can read unauthenticated cross-origin responses."
                ),
                source_agent="SmartCORSHunter",
                confidence=0.95,
                tags=["cors", sev.value],
                additional_info={
                    "test_origin": r["test_origin"],
                    "acao": r.get("acao", ""),
                    "acac": r.get("acac", ""),
                    "misconfiguration": r["misconfiguration"],
                    "tested_params": [],
                    "poc_html": poc,
                    "poc_request": (
                        f"GET {target_url} HTTP/1.1\n"
                        f"Origin: {r['test_origin']}\n"
                    ),
                    "poc_response": (
                        f"HTTP/1.1 200 OK\n"
                        f"Access-Control-Allow-Origin: {r.get('acao', '')}\n"
                        f"Access-Control-Allow-Credentials: {r.get('acac', '')}\n"
                    ),
                },
            ))
        return findings
