#!/usr/bin/env python3
import logging
import json
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.thought_loop import ThoughtLoop, ThoughtStep
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.models.llm import LLMClient
from src.core.infra.network_client import AsyncNetworkClient
from src.core.infra.smart_request import SmartRequest
from src.core.agents.swarm.injection.form_parsing import fetch_and_parse_form as _fetch_and_parse_form  # noqa: F811 – shared via form_parsing.py
from src.core.agents.swarm.injection.smart_sqli_payloads import (
    generate_time_based_payloads as _generate_time_based_payloads_ext,
    generate_waf_evasion_payloads as _generate_waf_evasion_payloads_ext,
    detect_payload_technique as _detect_payload_technique_ext,
)
from src.core.agents.swarm.injection.smart_sqli_runtime import (
    detect_database_type as _detect_database_type_ext,
    classify_sql_error as _classify_sql_error_ext,
)
from src.core.agents.swarm.injection.smart_sqli_orchestration import (
    sqli_execute,
    sqli_run_as_tool,
    sqli_decide,
    sqli_act,
)
from src.core.agents.swarm.injection.smart_sqli_dispatch import sqli_send_request
from src.core.agents.swarm.injection.smart_sqli_blind import (
    run_time_based_blind_precheck_sqli as _run_time_based_blind_precheck_ext,
    build_blind_correlation_sqli as _build_blind_correlation_ext,
)

logger = logging.getLogger(__name__)

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
        """Specialist entry point. Delegates to smart_sqli_orchestration.sqli_execute."""
        return await sqli_execute(self, task, quick_mode)

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Manager-callable tool method. Delegates to smart_sqli_orchestration.sqli_run_as_tool."""
        return await sqli_run_as_tool(self, url, params)

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        """ThoughtLoop abstract method. Delegates to smart_sqli_orchestration.sqli_decide."""
        return await sqli_decide(self, turn)

    async def act(self, action: str, action_input: Any) -> str:
        """ThoughtLoop abstract method. Delegates to smart_sqli_orchestration.sqli_act."""
        return await sqli_act(self, action, action_input)

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
        """Build blind correlation. Delegates to smart_sqli_blind.build_blind_correlation_sqli."""
        return _build_blind_correlation_ext(self)

    async def _run_time_based_blind_precheck(
        self, param_name: str, baseline_value: Any
    ) -> Dict[str, Any]:
        """Blind SQLi time-based precheck. Delegates to smart_sqli_blind.run_time_based_blind_precheck_sqli."""
        return await _run_time_based_blind_precheck_ext(self, param_name, baseline_value)

    # Day 2強化: DB別Time-basedペイロード生成
    def _generate_time_based_payloads(self, param_name: str) -> List[str]:
        """データベース別のTime-basedペイロードを生成。

        Delegates to smart_sqli_payloads.generate_time_based_payloads.
        """
        return _generate_time_based_payloads_ext(param_name)

    # Day 2強化: WAF回避ペイロード生成
    def _generate_waf_evasion_payloads(self, param_name: str) -> List[str]:
        """WAF回避用の難読化ペイロードを生成。

        Delegates to smart_sqli_payloads.generate_waf_evasion_payloads.
        """
        return _generate_waf_evasion_payloads_ext(param_name)

    # Day 2強化: ペイロード技術検出
    def _detect_payload_technique(self, payload: str) -> str:
        """使用されたペイロード技術を検出。

        Delegates to smart_sqli_payloads.detect_payload_technique.
        """
        return _detect_payload_technique_ext(payload)

    async def _send_request(self, payload: str) -> Dict[str, Any]:
        """Send HTTP request and classify SQL response. Delegates to smart_sqli_dispatch.sqli_send_request."""
        return await sqli_send_request(self, payload)

    # Day 1強化: DB別エラー検出メソッド
    def _detect_database_type(self, body: str) -> Dict[str, Any]:
        """レスポンスボディからデータベースタイプを検出。

        Delegates to smart_sqli_runtime.detect_database_type.
        """
        return _detect_database_type_ext(body)

    def _classify_sql_error(self, body: str) -> Dict[str, Any]:
        """SQLエラーを詳細に分類。

        Delegates to smart_sqli_runtime.classify_sql_error.
        """
        return _classify_sql_error_ext(body)
