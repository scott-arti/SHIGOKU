"""
Smart SSTI Hunter - 決定論的 SSTI スペシャリスト

LLM を使用せず SSTIScanner の算術確認ペア方式で判定する。
誤検知率が低く、ターゲット問わず安定した精度を発揮する。
"""
import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode, urlunparse

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
            # SGK-2026-0485: 確定バー用に生証拠を捕捉する。確定済み payload を
            # 1 回だけ再送し、算術積 expected（例 "49<marker>"・一意マーカー付き
            # で自然混入・捏造不可）を含む生応答本文と実 HTTP status を取得する。
            proof = await self._capture_ssti(
                url, r.parameter, r.payload, r.expected, method, auth_headers
            )
            return {
                "vulnerable": True,
                "findings_count": len(vuln_results),
                "param": r.parameter,
                "engine": r.engine.value,
                "payload": r.payload,
                "expected": r.expected,
                "method": method,
                "confidence": r.confidence,
                "evidence": r.evidence,
                "proof": proof,
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

    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        """GET 注入用に url の param を payload に置き換えた URL を組み立てる
        （記録・再現用の単一エンコード済み URL）。"""
        parsed = urlparse(url)
        pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                 if k != param]
        pairs.append((param, payload))
        return urlunparse(parsed._replace(query=urlencode(pairs)))

    @staticmethod
    def _evidence_snippet(body: str, expected: str, radius: int = 400) -> str:
        """expected（算術積）を中心とした本文スニペットを返す。expected が本文に
        無ければ先頭 2000 文字（fail-open せず・発火は expected 実在で判定）。"""
        if expected and expected in body:
            i = body.find(expected)
            start = max(0, i - radius)
            end = min(len(body), i + len(expected) + radius)
            return body[start:end]
        return body[:2000]

    def _base_url_without_param(self, url: str, param: str) -> str:
        """url から対象 param を除いた base URL（送信時に params で 1 回だけ
        エンコードさせるため。事前エンコード URL の二重エンコードを避ける）。"""
        parsed = urlparse(url)
        pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                 if k != param]
        return urlunparse(parsed._replace(query=urlencode(pairs)))

    async def _capture_ssti(
        self, url: str, param: str, payload: str, expected: str,
        method: str, auth_headers: Dict[str, str],
    ) -> Dict[str, Any]:
        """確定済み payload を 1 回再送し (request_url, request_body, status,
        served_body) を捕捉する。``self._client`` 注入 seam（E2E/テスト）or
        AsyncNetworkClient。読み取りのみ（テンプレート評価は状態変更なし）。
        失敗時は空 dict（呼び出し側で fail-closed）。"""
        headers = dict(auth_headers or {})
        is_get = str(method or "GET").upper() == "GET"
        # 記録・再現用の単一エンコード済み URL（送信は params/data で 1 回だけ
        # エンコードさせ、事前エンコード URL の二重エンコードを避ける）。
        request_url = self._build_payload_url(url, param, payload) if is_get else url
        request_body = "" if is_get else urlencode({param: payload})
        base_url = self._base_url_without_param(url, param) if is_get else url

        async def _send(client):
            if is_get:
                return await client.request(
                    "GET", base_url, params={param: payload},
                    headers=headers, use_proxy=True,
                )
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            return await client.request("POST", url, data={param: payload},
                                        headers=headers, use_proxy=True)

        try:
            injected = getattr(self, "_client", None)
            if injected is not None:
                resp = await _send(injected)
            else:
                from src.core.infra.network_client import AsyncNetworkClient
                async with AsyncNetworkClient() as client:
                    resp = await _send(client)
        except Exception as exc:  # noqa: BLE001 — network boundary, fail closed
            logger.debug("[%s] SSTI proof capture failed for %s: %s",
                         self.name, url, exc)
            return {}
        status = int(getattr(resp, "status", 0) or 0)
        body = getattr(resp, "body", None)
        if body is None:
            body = getattr(resp, "text", "") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="replace")
        return {
            "request_method": "GET" if is_get else "POST",
            "request_url": request_url,
            "request_body": request_body,
            "response_status": status,
            "served_body": str(body),
            "observed": bool(expected and expected in str(body)),
        }

    # ------------------------------------------------------------------
    # Finding 変換
    # ------------------------------------------------------------------

    def _convert_to_findings(self, result: Dict[str, Any], target_url: str) -> List[Finding]:
        if not result.get("vulnerable"):
            return []

        param = result.get("param", "unknown")
        engine = result.get("engine", "unknown")
        payload = result.get("payload", "")
        expected = str(result.get("expected") or "")
        method = str(result.get("method") or "GET").upper()
        evidence_text = result.get("evidence", "")
        confidence = float(result.get("confidence", 0.95))
        proof = result.get("proof") if isinstance(result.get("proof"), dict) else {}

        # 生証拠（捕捉できていれば実 status＋算術積を含む本文、無ければ
        # scanner の raw evidence にフォールバック）。served_body は算術積
        # expected を含む＝評価の実体。秘密値は扱わない（算術のみ）。
        request_method = str(proof.get("request_method") or method)
        request_url = str(proof.get("request_url") or target_url)
        request_body = str(proof.get("request_body") or "")
        response_status = int(proof.get("response_status") or 0)
        raw_body = str(proof.get("served_body") or evidence_text or "")
        # 期待積 expected を中心にしたスニペットを保存する（先頭固定切り詰め
        # だと反映が本文後方にある場合に証拠が落ちるため）。expected が無い
        # ときは先頭 2000 文字にフォールバック。
        served_body = self._evidence_snippet(raw_body, expected)

        poc_request = (
            f"{request_method} {request_url} HTTP/1.1\r\n"
            + ("Content-Type: application/x-www-form-urlencoded\r\n\r\n"
               f"{request_body}" if request_body else "\r\n")
        )
        poc_response = (
            f"HTTP/1.1 {response_status}\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            f"{served_body}"
        )
        impact = (
            f"パラメータ '{param}' が {engine} テンプレートエンジンで評価される"
            f"（サーバサイドテンプレートインジェクション）。算術ペイロード "
            f"'{payload}' が期待積 '{expected}' としてサーバ側で評価・反映された"
            "（一意マーカー付きで自然混入・テンプレ捏造不可）。テンプレート評価は"
            "任意コード実行（RCE）に直結し得る重大な実害。"
        )

        finding = Finding(
            vuln_type=VulnType.SSTI,
            severity=Severity.CRITICAL,
            title=f"SSTI ({engine}) in parameter '{param}'",
            description=(
                f"Server-Side Template Injection confirmed in '{param}' "
                f"using {engine} engine payload. "
                f"Arithmetic evaluation confirmed (marker-tagged pair test)."
            ),
            target_url=target_url,
            evidence=Evidence(
                request_method=request_method,
                request_url=request_url,
                request_headers={},
                request_body=request_body,
                response_status=response_status,
                response_headers={"Content-Type": "text/html"},
                response_body=served_body,
            ),
            source_agent=self.name,
            confidence=confidence,
            impact=impact,
            reproduction_steps=[
                f"パラメータ '{param}' に算術テンプレートペイロード '{payload}' を"
                f"付けて {request_method} リクエストを送る。",
                f"応答本文に評価済みの期待積 '{expected}' が現れることを確認する。",
            ],
            tags=["ssti", "critical", "template_evaluated", engine],
            additional_info={
                "parameter": param,
                "tested_params": result.get("tested_params", [param]),
                "engine": engine,
                "payload": payload,
                "expected": expected,
                "confidence": confidence,
                "all_results": result.get("all_results", []),
                "ssti_evidence": {
                    "parameter": param,
                    "engine": engine,
                    "payload": payload,
                    "expected": expected,
                    "request_method": request_method,
                    "request_url": request_url,
                    "response_status": response_status,
                    "served_body": served_body,
                },
                "ssti_replay": {
                    "method": request_method,
                    "url": request_url,
                    "param": param,
                    "payload": payload,
                    "body": request_body,
                    "expected": expected,
                },
                "poc_request": poc_request,
                "poc_response": poc_response,
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
