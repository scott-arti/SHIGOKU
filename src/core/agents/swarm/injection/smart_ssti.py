"""
Smart SSTI Hunter - 決定論的 SSTI スペシャリスト

LLM を使用せず SSTIScanner の算術確認ペア方式で判定する。
誤検知率が低く、ターゲット問わず安定した精度を発揮する。
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


class SmartSSTIHunter(Specialist):
    """
    決定論的 SSTI スペシャリスト。

    SSTIScanner（算術確認ペア + ユニークマーカー方式）を非同期で呼び出し、
    SSTIResult を Finding(VulnType.SSTI) へ変換する。
    LLM は使用しない。
    """

    name: str = "SmartSSTIHunter"
    description: str = "Deterministic SSTI scanner using arithmetic confirmation pairs"
    is_aggressive: bool = False

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.last_tested_params: List[str] = []

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

        # --- auth 情報抽出 ---
        _auth = params.get("_auth", {}) if isinstance(params.get("_auth"), dict) else {}
        auth_headers: Dict[str, str] = dict(_auth.get("auth_headers", {}) or {})
        cookies_str: str = str(_auth.get("cookies", "") or params.get("cookies", "") or "")
        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        # --- HTTP メソッド / エンコードオプション ---
        method: str = str(params.get("method", "GET") or "GET").upper()
        use_encoding: bool = bool(params.get("use_encoding", False))

        # --- テスト対象パラメータ抽出 ---
        tested_params = self._extract_test_params(url, params, method)
        self.last_tested_params = tested_params

        if not tested_params:
            logger.info("[%s] No injectable parameters found for %s", self.name, url)
            return self._empty_result(tested_params)

        # --- tech_stack 取得（Recon 結果から、存在すれば利用） ---
        tech_stack: List[str] = []
        _context = params.get("_context", {})
        if isinstance(_context, dict):
            tech_stack = list(_context.get("tech_stack", []) or [])

        # --- SSTIScanner 実行 ---
        from src.core.attack.ssti_scanner import SSTIScanner
        scanner = SSTIScanner(timeout=10.0, delay=0.3, auth_headers=auth_headers)
        try:
            if tech_stack:
                results = await scanner.scan_with_fingerprint_async(
                    url=url,
                    parameters=tested_params,
                    tech_stack=tech_stack,
                    method=method,
                    auth_headers=auth_headers,
                )
            else:
                results = await scanner.scan_async(
                    url=url,
                    parameters=tested_params,
                    method=method,
                    use_encoding=use_encoding,
                    auth_headers=auth_headers,
                )
        except Exception as exc:
            logger.error("[%s] SSTIScanner failed for %s: %s", self.name, url, exc)
            return self._empty_result(tested_params)
        finally:
            scanner.close()

        # --- 最初の脆弱結果を返す（複数検出は上位で集約） ---
        vuln_results = [r for r in results if r.vulnerable]
        if vuln_results:
            r = vuln_results[0]
            return {
                "vulnerable": True,
                "findings_count": len(vuln_results),
                "param": r.parameter,
                "engine": r.engine.value,
                "payload": r.payload,
                "confidence": r.confidence,
                "evidence": r.evidence,
                "tested_params": self._sanitize_params(tested_params),
                "all_results": [
                    {
                        "parameter": x.parameter,
                        "engine": x.engine.value,
                        "payload": x.payload,
                        "confidence": x.confidence,
                    }
                    for x in vuln_results
                ],
            }

        return self._empty_result(tested_params)

    # ------------------------------------------------------------------
    # Finding 変換
    # ------------------------------------------------------------------

    def _convert_to_findings(self, result: Dict[str, Any], target_url: str) -> List[Finding]:
        if not result.get("vulnerable"):
            return []

        param = result.get("param", "unknown")
        engine = result.get("engine", "unknown")
        payload = result.get("payload", "")
        evidence_text = result.get("evidence", "")
        confidence = float(result.get("confidence", 0.95))

        finding = Finding(
            vuln_type=VulnType.SSTI,
            severity=Severity.CRITICAL,
            title=f"SSTI ({engine}) in parameter '{param}'",
            description=(
                f"Server-Side Template Injection confirmed in '{param}' "
                f"using {engine} engine payload. "
                f"Arithmetic evaluation confirmed (49-marker pair test)."
            ),
            target_url=target_url,
            evidence=Evidence(
                request_url=target_url,
                response_body=evidence_text[:500],
            ),
            source_agent=self.name,
            confidence=confidence,
            tags=["ssti", "critical", engine],
            additional_info={
                "parameter": param,
                "tested_params": result.get("tested_params", [param]),
                "engine": engine,
                "payload": payload,
                "confidence": confidence,
                "all_results": result.get("all_results", []),
            },
        )
        return [finding]

    # ------------------------------------------------------------------
    # ヘルパー
    # ------------------------------------------------------------------

    def _extract_test_params(self, url: str, params: Dict[str, Any], method: str) -> List[str]:
        """URL クエリ + params から注入対象パラメータ名を抽出する。"""
        # URL クエリから取得
        parsed = urlparse(url)
        url_param_keys = list(parse_qs(parsed.query).keys())

        # params dict から追加（メタキー・内部制御キーを除外）
        extra_keys: List[str] = []
        for k, v in (params or {}).items():
            if not k or k in META_KEYS or str(k).startswith("_"):
                continue
            if isinstance(v, (dict, list, tuple, set)):
                continue
            if k not in url_param_keys and k not in extra_keys:
                extra_keys.append(k)

        all_keys = url_param_keys + extra_keys
        return self._sanitize_params(all_keys)

    def _sanitize_params(self, params: List[str]) -> List[str]:
        """内部制御パラメータを除外する。"""
        return [
            p for p in params
            if p and str(p).lower() not in META_KEYS and not str(p).startswith("_")
        ]

    @staticmethod
    def _empty_result(tested_params: List[str]) -> Dict[str, Any]:
        return {
            "vulnerable": False,
            "findings_count": 0,
            "param": None,
            "engine": "unknown",
            "payload": "",
            "confidence": 0.0,
            "evidence": "",
            "tested_params": tested_params,
            "all_results": [],
        }
