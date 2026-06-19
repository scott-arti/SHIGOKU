#!/usr/bin/env python3
import logging
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.agents.swarm.thought_loop import ThoughtLoop, ThoughtStep
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding
from src.core.models.llm import LLMClient
from src.core.infra.network_client import AsyncNetworkClient
from src.core.infra.smart_request import SmartRequest
from src.core.payloads.xss_waf_evasion import XSSWAFEvasionSuite
from src.core.agents.swarm.injection.form_parsing import fetch_and_parse_form as _fetch_and_parse_form  # noqa: F811 – shared via form_parsing.py
from src.core.agents.swarm.injection.smart_xss_reflection import (
    analyze_reflection as _analyze_reflection_ext,
    generate_polyglot_payloads as _generate_polyglot_payloads_ext,
    generate_dom_xss_payloads as _generate_dom_xss_payloads_ext,
    is_suspicious_observation as _is_suspicious_observation_ext,
)
from src.core.agents.swarm.injection.smart_xss_runtime import (
    build_playwright_cookies as _build_playwright_cookies_ext,
    validate_dom_runtime_xss as _validate_dom_runtime_xss_ext,
    check_dom_xss as _check_dom_xss_ext,
)
from src.core.agents.swarm.injection.smart_xss_orchestration import (
    xss_execute,
    xss_run_as_tool,
    xss_decide,
    xss_act,
)
from src.core.agents.swarm.injection.smart_xss_dispatch import xss_send_request

logger = logging.getLogger(__name__)

class SmartXSSHunter(Specialist, ThoughtLoop):
    """
    Stateful Loop-based Agent for XSS (The Brain).

    Strategies:
    1. Probe: Check parameter reflections and error messages.
    2. Hypothesize: Determine DB type (MySQL, Postgres, etc.) and error type.
    3. Exploit: Craft payloads (UNION, Error-based, Time-based) based on hypothesis.
    4. Verify: Confirm vulnerability.

    MEDIUM/HIGH SECURITY AWARENESS:
    - If input characters like ' or \" are filtered, use numeric injections (e.g., id=1 OR 1=1).
    - If the target is a POST form with dropdowns/radio buttons, manipulate the raw POST values.
    - Test for blind XSS using conditional timing (SLEEP/BENCHMARK) if no errors are visible.
    """

    name = "SmartXSSHunter"
    description = "Stateful reasoning agent for deep XSS detection."
    MAX_PARAMS_TO_TEST = 5
    PROFILE_PRIORITY_PARAMS: Dict[str, Dict[str, List[str]]] = {
        "bbpt": {
            "stored": ["name", "message", "comment", "body", "text", "content"],
            "reflected": ["name", "q", "query", "search", "keyword", "term", "s"],
            "dom": ["default", "lang", "locale", "hash", "fragment"],
            "generic": ["name", "message", "q", "query", "search"],
        },
        "ctf": {
            "stored": ["name", "message", "msg", "comment", "body", "text"],
            "reflected": ["name", "q", "query", "id", "search", "s"],
            "dom": ["default", "lang", "hash", "next", "redirect"],
            "generic": ["name", "q", "id", "message", "search"],
        },
    }

    SYSTEM_PROMPT = """You are an expert XSS Penetration Tester.
You must work in a thought loop to detect XSS vulnerabilities.

Commands:
- ACTION: request
  INPUT: [The payload]

- ACTION: finish
  INPUT: [vulnerable|safe|unknown]

CRITICAL FORMAT RULES:
1. You MUST use EXACTLY this format for EVERY turn:
   THOUGHT: [Analyze the reflection context, escaping, and filtering observed in the response.]
   ACTION: [request|finish]
   INPUT: [payload or vulnerable/safe/unknown]

2. NEVER write "Observation:" yourself.
3. NEVER write "Final Answer:" - use "ACTION: finish" instead.
4. If you write an invalid format, it will trigger a retry.
5. If you write invalid format, the system will FORCE RETRY.

Guidelines:
1. Start with basic payloads like <script>alert('XSS')</script> or <img src=x onerror=alert(1)>.
2. If quotes are escaped, try payloads without quotes or use backticks.
3. For reflected XSS, check if your payload appears in the response.
4. For stored XSS, submit the payload and verify it's stored and executed.
5. Support for POST forms and JSON bodies is available. If methodology involves POST, payloads will be placed in the body.

VULNERABILITY DETECTION CRITERIA:
- If your XSS payload (e.g., <script>, alert, onerror) appears in the response WITHOUT proper encoding, the target IS VULNERABLE.
- If you see your payload executed (e.g., JavaScript in response), the target IS VULNERABLE.
- When you confirm vulnerability, immediately use "ACTION: finish" with INPUT: "vulnerable" and include evidence in your THOUGHT.

Format:
THOUGHT: [Reasoning about the next payload strategy based on previous observations]
ACTION: [Command]
INPUT: [Input]
"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        Specialist.__init__(self, config)
        ThoughtLoop.__init__(self, max_turns=8)

        mode = "ctf"  # CTF モードで POST リクエストを許可
        from src.config import settings as app_settings
        model = getattr(app_settings, "model", None) or getattr(app_settings, "model_output", "deepseek/deepseek-chat")
        rejudge_model = getattr(app_settings, "llm_xss_rejudge_model", "openai/gpt-4o-mini")
        final_model = getattr(app_settings, "llm_xss_final_model", "openai/gpt-4o")
        try:
            from src.core.config.settings import get_settings
            settings = get_settings()
            rejudge_model = getattr(settings, "llm_xss_rejudge_model", rejudge_model)
            final_model = getattr(settings, "llm_xss_final_model", final_model)
        except Exception:
            pass
        if config and isinstance(config, dict):
            mode = config.get("mode", mode)
            model = config.get("model", model) if isinstance(config, dict) else getattr(config, "model", model)
            rejudge_model = config.get("llm_xss_rejudge_model", config.get("xss_rejudge_model", rejudge_model))
            final_model = config.get("llm_xss_final_model", config.get("xss_final_model", final_model))

        self.primary_model = model
        self.rejudge_model = rejudge_model
        self.final_model = final_model
        self.llm = LLMClient(model=self.primary_model, use_local=False)

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
        self.reflection_observed = False
        self.used_payloads = []
        self.history_messages = []
        self.last_tested_params: List[str] = []
        self._consecutive_blocked_observations = 0
        self._no_signal_turns = 0
        self._suspicious_signal_observed = False
        self._used_rejudge_model = False
        self._used_final_model = False
        self._dom_xss_verifier = None
        self._waf_suite = XSSWAFEvasionSuite()

    def _compute_adaptive_turn_budget(self, quick_mode: bool, candidate_count: int, variant: str) -> int:
        base = 4 if quick_mode else 6
        if variant in {"stored", "dom"}:
            base += 1
        if candidate_count >= 4:
            base -= 1
        return max(4, min(8, base))

    def _is_suspicious_observation(self, observation: Dict[str, Any]) -> bool:
        """Check if an observation contains XSS-relevant signals.

        Delegates to smart_xss_reflection.is_suspicious_observation.
        """
        return _is_suspicious_observation_ext(observation)

    def _choose_decision_model(self) -> Tuple[str, str]:
        if self._suspicious_signal_observed and not self._used_rejudge_model:
            if self.rejudge_model and self.rejudge_model != self.primary_model:
                self._used_rejudge_model = True
                return self.rejudge_model, "rejudge"
            self._used_rejudge_model = True

        if self._suspicious_signal_observed and self._used_rejudge_model and not self._used_final_model:
            if self.final_model and self.final_model not in {self.primary_model, self.rejudge_model}:
                self._used_final_model = True
                return self.final_model, "final"
            self._used_final_model = True

        return self.primary_model, "primary"

    @staticmethod
    def _detect_xss_variant(target: str) -> str:
        path = urlparse(target).path.lower()
        if "xss_s" in path:
            return "stored"
        if "xss_r" in path:
            return "reflected"
        if "xss_d" in path or "javascript" in path:
            return "dom"
        return "generic"

    def _prioritize_candidate_params(
        self,
        payload_params: Dict[str, Any],
        url_params_flat: Dict[str, Any],
        target: str,
        scan_profile: str,
    ) -> List[str]:
        """URL種別とscan_profileに基づき、試行パラメータ順を決定する。"""
        if not payload_params and not url_params_flat:
            return []

        variant = self._detect_xss_variant(target)
        profile_map = self.PROFILE_PRIORITY_PARAMS.get(scan_profile, self.PROFILE_PRIORITY_PARAMS["bbpt"])
        priority_names = profile_map.get(variant, []) + profile_map.get("generic", [])

        combined_params: Dict[str, Any] = {}
        for key, value in url_params_flat.items():
            combined_params[key] = value
        for key, value in payload_params.items():
            combined_params[key] = value

        all_names = list(combined_params.keys())
        ordered: List[str] = []

        for preferred in priority_names:
            for candidate in all_names:
                if candidate.lower() == preferred.lower() and candidate not in ordered:
                    ordered.append(candidate)

        for candidate in all_names:
            if candidate not in ordered:
                ordered.append(candidate)

        return ordered[:self.MAX_PARAMS_TO_TEST]

    @staticmethod
    def _build_playwright_cookies(target: str, cookies_str: str) -> List[Dict[str, Any]]:
        """Cookie文字列をPlaywright context.add_cookies形式へ変換する。

        Delegates to smart_xss_runtime.build_playwright_cookies.
        """
        return _build_playwright_cookies_ext(target, cookies_str)

    async def _validate_dom_runtime_xss(
        self,
        target: str,
        payload: str,
        cookies_str: str,
        param_name: str = "default",
    ) -> bool:
        """DOM型を想定し、query/fragment 両方でブラウザ実行を検証する。

        Delegates to smart_xss_runtime.validate_dom_runtime_xss.
        """
        return await _validate_dom_runtime_xss_ext(
            target=target,
            payload=payload,
            cookies_str=cookies_str,
            param_name=param_name,
            dom_xss_verifier=self._dom_xss_verifier,
            hunter_name=self.name,
        )

    async def close(self):
        """リソース解放"""
        if self._dom_xss_verifier is not None:
            try:
                await self._dom_xss_verifier.close()
            except Exception:
                pass
        if self.smart_client and hasattr(self.smart_client, "client"):
            await self.smart_client.client.close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """Specialist entry point. Delegates to smart_xss_orchestration.xss_execute."""
        return await xss_execute(self, task, quick_mode)

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Manager-callable tool method. Delegates to smart_xss_orchestration.xss_run_as_tool."""
        return await xss_run_as_tool(self, url, params)

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        """ThoughtLoop abstract method. Delegates to smart_xss_orchestration.xss_decide."""
        return await xss_decide(self, turn)

    async def act(self, action: str, action_input: Any) -> str:
        """ThoughtLoop abstract method. Delegates to smart_xss_orchestration.xss_act."""
        return await xss_act(self, action, action_input)

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

        if self._no_signal_turns >= 3 and not self.reflection_observed:
            if self._suspicious_signal_observed and not (self._used_rejudge_model and self._used_final_model):
                return False
            logger.info(
                "[%s] Early stop on param '%s' due to repeated no-signal normal responses.",
                self.name,
                self.context.get("param"),
            )
            return True

        if step.action == "finish":
            return True
        return False

    def get_result(self) -> Dict[str, Any]:
        """Override to return XSS-specific result."""
        return {
            "status": self.status.value,
            "turns": len(self.history),
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "payloads_used": self.used_payloads
        }

    async def _send_request(self, payload: str) -> Dict[str, Any]:
        """Send HTTP request and check XSS reflection. Delegates to smart_xss_dispatch.xss_send_request."""
        return await xss_send_request(self, payload)

    # Day 3強化: Polyglotペイロード生成
    def _analyze_reflection(self, html: str, marker: str) -> List[Dict[str, str]]:
        """HTML内の反射コンテキストを簡易分類して返す。

        Delegates to smart_xss_reflection.analyze_reflection.
        """
        return _analyze_reflection_ext(html, marker)

    def _generate_polyglot_payloads(self) -> List[str]:
        """複数コンテキストで動作する Polyglot XSS ペイロードを生成。

        Delegates to smart_xss_reflection.generate_polyglot_payloads.
        """
        return _generate_polyglot_payloads_ext()

    # Day 3強化: DOM XSS検出メソッド
    def _generate_dom_xss_payloads(self, target_url: str) -> List[Dict[str, Any]]:
        """DOM-based XSS 用ペイロードを生成。

        Delegates to smart_xss_reflection.generate_dom_xss_payloads.
        """
        return _generate_dom_xss_payloads_ext(target_url)

    # Day 3強化: DOM XSS検出実行
    async def _check_dom_xss(self, target_url: str, param_name: str) -> Dict[str, Any]:
        """DOM-based XSS 静的ヒューリスティクス（Juice Shop 対応）。

        Delegates to smart_xss_runtime.check_dom_xss.
        """
        return await _check_dom_xss_ext(target_url, param_name)
