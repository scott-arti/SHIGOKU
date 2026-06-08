
import logging
import asyncio
import time
import re
import json
import os
from typing import Dict, Any, Tuple, Optional, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from itertools import islice

from src.core.agents.swarm.thought_loop import ThoughtLoop, ThoughtStep, LoopStatus
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.swarm import SwarmResult
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.models.llm import LLMClient
from src.core.infra.network_client import AsyncNetworkClient
from src.core.infra.smart_request import SmartRequest
from src.tools.oob.interactsh_client import InteractshOOBClient
from src.core.agents.swarm.injection.cmd_wordlists import generate_wordlist, PAYLOAD_MAP
from src.tools.custom.ffuf import FfufTool

logger = logging.getLogger(__name__)

# 破壊的コマンドのブロックリスト（不完全一致でもブロック対象）
BLOCKED_COMMANDS = frozenset([
    "rm", "rmdir", "del", "format", "mkfs", "dd",
    "reboot", "shutdown", "halt", "poweroff", "init",
    "kill", "killall", "pkill",
    "useradd", "userdel", "passwd", "chown", "chmod",
    "iptables", "ufw", "firewall-cmd",
    "mv /", "cp /dev/null", "> /dev/", ">> /dev/"
])


async def _fetch_and_parse_form(url: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """HTML を取得してフォーム情報を抽出する。"""
    from bs4 import BeautifulSoup

    forms: List[Dict[str, Any]] = []
    client = AsyncNetworkClient()
    try:
        resp = await client.request("GET", url, headers=auth_headers, use_cache=False, timeout=20)
        body = ""
        if isinstance(resp, dict):
            body = str(resp.get("body", "") or "")
        else:
            body = str(getattr(resp, "body", "") or "")
        if not body:
            return forms

        soup = BeautifulSoup(body, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = str(form.get("method", "GET")).upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                if not name:
                    continue
                value = inp.get("value", "") if hasattr(inp, "get") else ""
                input_type = inp.get("type", "text") if hasattr(inp, "get") else "text"
                inputs.append({"name": name, "value": value, "type": input_type})
            forms.append({"action": action, "method": method, "inputs": inputs})
    except Exception as exc:
        logger.debug("[%s] form parsing failed for %s: %s", SmartCmdSSRFHunter.name, url, exc)
    finally:
        await client.close()
    return forms

class SmartCmdSSRFHunter(Specialist, ThoughtLoop):
    """
    Expert Agent for Command Injection and SSRF.
    Supports Reflected, Blind (Time-based/OOB), and SSRF (Metadata/Bypass).
    Integrates with Exa MCP for dynamic exploit POC search.
    """
    
    name = "SmartCmdSSRFHunter"
    description = "Critical specialist for OS Command Injection and SSRF with OOB and Exa integration."
    EXCLUDED_META_PARAM_NAMES = {"scan_profile", "profile", "_auth", "method"}
    NON_ATTACK_PARAM_NAMES = {"submit", "change", "token", "csrf", "csrf_token", "user_token"}
    MAX_PARAMS_TO_TEST = 5

    @classmethod
    def _is_attack_param(cls, name: str) -> bool:
        normalized = str(name or "").strip().lower()
        if not normalized:
            return False
        if normalized in cls.EXCLUDED_META_PARAM_NAMES:
            return False
        return normalized not in cls.NON_ATTACK_PARAM_NAMES
    
    SYSTEM_PROMPT = """You are a senior security engineer and expert penetration tester.
You specialize in OS Command Injection and Server-Side Request Forgery (SSRF).

Commands:
- ACTION: cmd_probe    INPUT: {"payload": "string", "marker": "string"}
  -> Test reflected command injection. Check if marker or output is in response.
- ACTION: cmd_blind    INPUT: {"payload": "string", "delay": int}
  -> Test time-based blind injection (e.g., sleep 5). SHIGOKU will measure timing.
- ACTION: cmd_oob      INPUT: {"template": "string"}
  -> Test OOB injection (DNS/HTTP). Use '{{OOB_DOMAIN}}' in template.
- ACTION: cmd_fuzz     INPUT: {"category": "basic|blind_oob|waf_bypass"}
  -> Bulk fuzzing with FFUF tool for high-coverage testing.
- ACTION: ssrf_probe   INPUT: {"url": "string"}
  -> Test SSRF (Internal/Bypass).
- ACTION: ssrf_oob     INPUT: {"template": "string"}
  -> Test SSRF using OOB domain (e.g., "http://{{OOB_DOMAIN}}").
- ACTION: search_exploit INPUT: {"tech": "string"}
  -> Search for latest POCs via Exa MCP if tech/version is found.
- ACTION: finish       INPUT: {"status": "Vulnerable/Safe", "reason": "string"}

Guidelines:
1. NEVER use destructive commands (rm, reboot, etc.). Focus on: id, whoami, uname, sleep.
2. For SSRF, prioritize AWS/GCP/Azure metadata and localhost ports.
3. Use '{{OOB_DOMAIN}}' for OOB tests; SHIGOKU will replace it with a real domain.
4. Try to bypass WAFs with encoding or IP integer formats for SSRF.
5. If common separators like ';' or '&&' are filtered (e.g. Medium level), use alternative separators such as '|' (pipe), '||' (logical OR), or backticks (`` ` ``).
6. For SSRF, if hostname 'localhost' or '127.0.0.1' is blocked, use alternative formats like decimal IPs, octal IPs, or wildcard DNS (e.g. 127.0.0.1.nip.io).

Format:
THOUGHT: [Reasoning about the next payload strategy based on previous observations]
ACTION: [Command]
INPUT: [Input]

CRITICAL RULES:
- NEVER write "Observation:" yourself - it is PROVIDED BY THE TOOL
- NEVER write "Final Answer:" - use "ACTION: finish" instead
- If you write invalid format, the system will FORCE RETRY"""

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

        self.network_client = AsyncNetworkClient(proxy_manager=proxy_manager, mode=mode)
        self.smart_client = SmartRequest(network_client=self.network_client, request_guard=get_request_guard(mode=mode))

        # State
        self.vulnerable = False
        self.evidence = ""
        self.used_payloads = []
        self.history_messages = []
        self.context: Dict[str, Any] = {}
        self.blind_correlation: Dict[str, Any] = {}
        self.last_tested_params: List[str] = []
        self.last_blind_correlation: Dict[str, Any] = {}

    async def close(self):
        """リソース解放"""
        if self.network_client:
            await self.network_client.close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """
        Specialist としてのエントリーポイント

        Args:
            task: タスク情報
            quick_mode: True の場合、ThoughtLoop のターン数を制限して高速化
        """
        logger.info(f"[{self.name}] Starting ThoughtLoop for {task.target} (quick_mode={quick_mode})")

        original_max_turns = self.max_turns
        if quick_mode:
            self.max_turns = 8

        timeout = 300 if quick_mode else 600
        self.last_tested_params = []
        self.last_blind_correlation = {}
        try:
            result = await asyncio.wait_for(
                self.run_as_tool(task.target, task.params),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] Timeout after {timeout}s for {task.target}")
            return []
        finally:
            self.max_turns = original_max_turns

        findings = []
        if result.get("vulnerable"):
            vuln_type = VulnType.OS_COMMAND_INJECTION if result.get("vuln_type") == "cmd" else VulnType.SSRF
            tested_param = result.get("param")
            finding = Finding(
                vuln_type=vuln_type,
                severity=Severity.CRITICAL,
                title=f"Command Injection/SSRF in parameter '{result.get('param', 'unknown')}'",
                description=result.get("description", "Detected by SmartCmdSSRFHunter."),
                target_url=task.target,
                evidence=Evidence(
                    request_url=task.target,
                    response_body=str(result.get("evidence", ""))
                ),
                source_agent=self.name,
                confidence=0.9,
                tags=["cmd_injection", "ssrf", "smart_agent"],
                additional_info={
                    "parameter": tested_param,
                    "tested_params": [tested_param] if tested_param else [],
                    "payload": result.get("payloads_used", [""])[-1] if result.get("payloads_used") else "",
                    "blind_correlation": result.get("blind_correlation", {}),
                    "execution_profile": dict(result.get("execution_profile", {}) or {}),
                }
            )
            findings.append(finding)

        return findings

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Manager から呼び出し可能な Tool メソッド。"""
        params = params or {}
        _auth = params.get("_auth", {})
        auth_headers = self._build_auth_headers(
            dict(_auth.get("auth_headers", {}) or {}),
            params,
        )
        cookies_str = _auth.get("cookies", "")
        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        method = params.get("method", "GET").upper()
        target = url
        execution_profile = self._extract_execution_profile(params, auth_headers)

        META_KEYS = {
            "_auth", "method", "content_type", "task_id",
            "targets", "targets_file", "source_file", "cookies",
            "tags", "category", "_context", "extra_targets",
            "auth_headers", "headers", "count",
            "race_profile", "safe_variations",
        }
        payload_params = {k: v for k, v in params.items() if k not in META_KEYS}

        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target)
        url_params = parse_qs(parsed.query)
        url_params_flat = {k: v[0] if v else "" for k, v in url_params.items()}

        forms = params.get("forms", [])
        if not payload_params and isinstance(forms, list):
            for form in forms:
                if not isinstance(form, dict):
                    continue
                form_method = str(form.get("method", "GET")).upper()
                if form_method == "POST":
                    method = "POST"
                for input_field in form.get("inputs", []):
                    if not isinstance(input_field, dict):
                        continue
                    param_name = str(input_field.get("name", "")).strip()
                    if not param_name:
                        continue
                    if param_name.lower() in self.EXCLUDED_META_PARAM_NAMES:
                        continue
                    payload_params[param_name] = input_field.get("value", "127.0.0.1")

        forms_from_html = await _fetch_and_parse_form(target, auth_headers)
        if forms_from_html:
            for form in forms_from_html:
                if not isinstance(form, dict):
                    continue
                form_method = str(form.get("method", "GET")).upper()
                if form_method == "POST":
                    method = "POST"
                for input_field in form.get("inputs", []):
                    if not isinstance(input_field, dict):
                        continue
                    param_name = str(input_field.get("name", "")).strip()
                    if not param_name or param_name.lower() in self.EXCLUDED_META_PARAM_NAMES:
                        continue
                    if param_name not in payload_params:
                        payload_params[param_name] = input_field.get("value", "127.0.0.1")

        if not payload_params and url_params_flat:
            payload_params = {
                k: v for k, v in url_params_flat.items()
                if str(k).lower() not in self.EXCLUDED_META_PARAM_NAMES
            }

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
                            param_name = str(input_field.get("name", "")).strip()
                            if not param_name or param_name.lower() in self.EXCLUDED_META_PARAM_NAMES:
                                continue
                            payload_params[param_name] = "127.0.0.1"
            except Exception as exc:
                logger.debug("[%s] Playwright form extraction failed: %s", self.name, exc)

        if payload_params:
            deduped_params: Dict[str, Any] = {}
            for key, value in payload_params.items():
                if key in deduped_params:
                    continue
                deduped_params[key] = value
            payload_params = deduped_params

        tested_param_names = [
            key for key in payload_params.keys()
            if self._is_attack_param(key)
        ][:self.MAX_PARAMS_TO_TEST]
        if not tested_param_names and payload_params:
            fallback_param = next(iter(payload_params.keys()))
            tested_param_names = [fallback_param]
        self.last_tested_params = list(tested_param_names)

        # ThoughtLoop コンテキスト設定
        self.context = {
            "target": target,
            "param": tested_param_names[0] if tested_param_names else None,
            "method": method,
            "params": payload_params,
            "auth_headers": auth_headers,
            "cookies": cookies_str,
            "execution_profile": execution_profile,
        }

        # State 初期化
        self.vulnerable = False
        self.evidence = ""
        self.used_payloads = []
        self.blind_correlation = {
            "time_based": {
                "confirmed": False,
            },
            "oob": {
                "confirmed": False,
                "hits": [],
            },
            "dns": {
                "confirmed": False,
                "hits": [],
            },
            "correlated": False,
        }
        loop_result: Dict[str, Any] = {"status": "not_run"}
        deterministic = await self._run_cmd_deterministic_precheck(tested_param_names)
        if deterministic.get("confirmed"):
            self.vulnerable = True
            self.evidence = str(deterministic.get("evidence", "Command injection signal confirmed"))
            payload = str(deterministic.get("payload", "") or "")
            if payload and payload not in self.used_payloads:
                self.used_payloads.append(payload)
            deterministic_blind = deterministic.get("blind_correlation", {})
            if isinstance(deterministic_blind, dict) and deterministic_blind:
                self.blind_correlation = deterministic_blind
            loop_result = {"status": "deterministic_precheck_confirmed", **deterministic}
        else:
            self.history_messages = []
            self.history_messages.append({"role": "system", "content": self.SYSTEM_PROMPT})

            initial_prompt = f"""Target URL: {target}
Method: {method}
Parameter: {self.context['param']}
Original Value: {payload_params.get(self.context['param'], '') if payload_params else ''}

Start your Command Injection / SSRF testing.
"""
            self.history_messages.append({"role": "user", "content": initial_prompt})

            try:
                loop_result = await self.run_loop(self.context)
            except Exception as e:
                logger.error(f"[{self.name}] ThoughtLoop failed: {e}")
                loop_result = {"status": "failed", "error": str(e)}

        result = {
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "param": self.context.get("param"),
            "tested_params": tested_param_names,
            "payloads_used": self.used_payloads,
            "description": f"Command Injection/SSRF detected." if self.vulnerable else "No Command Injection/SSRF detected.",
            "loop_result": loop_result,
            "vuln_type": "cmd",  # デフォルト
            "blind_correlation": self.blind_correlation,
            "execution_profile": execution_profile,
        }
        self.last_blind_correlation = dict(result.get("blind_correlation", {}) or {})
        return result

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

    def _build_race_attempt_plan(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        execution_profile = self.context.get("execution_profile", {}) or {}
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

        base_keys = list(params.keys())
        ordered_key_sets: List[List[str]] = []
        for idx in range(attempt_count):
            if not base_keys:
                ordered_key_sets.append([])
                continue
            rotation = idx % len(base_keys)
            ordered = base_keys[rotation:] + base_keys[:rotation]
            if ordered not in ordered_key_sets:
                ordered_key_sets.append(ordered)
        if not ordered_key_sets:
            ordered_key_sets = [base_keys]

        plan: List[Dict[str, Any]] = []
        for idx, ordered_keys in enumerate(islice(ordered_key_sets, attempt_count)):
            delay_seconds = interval_seconds if mode == "interval" and idx > 0 else 0.0
            plan.append({
                "attempt": idx + 1,
                "delay_seconds": delay_seconds,
                "ordered_keys": ordered_keys,
                "mode": mode,
            })
        return plan or [{"attempt": 1, "delay_seconds": 0.0, "ordered_keys": base_keys, "mode": "single"}]

    def _ordered_params_for_attempt(
        self,
        params: Dict[str, Any],
        ordered_keys: List[str],
    ) -> List[Tuple[str, Any]]:
        seen = set()
        ordered_items: List[Tuple[str, Any]] = []
        for key in ordered_keys:
            if key in params and key not in seen:
                ordered_items.append((key, params[key]))
                seen.add(key)
        for key, value in params.items():
            if key in seen:
                continue
            ordered_items.append((key, value))
        return ordered_items

    async def _run_cmd_deterministic_precheck(self, tested_params: List[str]) -> Dict[str, Any]:
        """
        LLM 前段で軽量な reflected command injection 判定を実施する。
        """
        if not tested_params:
            return {"confirmed": False}

        reflected_payloads = [
            "127.0.0.1;id",
            "127.0.0.1&&id",
            "127.0.0.1|id",
            "127.0.0.1;whoami",
        ]
        timing_payloads = [
            ("127.0.0.1;sleep 3", 3.0),
            ("127.0.0.1&&sleep 3", 3.0),
            ("127.0.0.1|sleep 3", 3.0),
        ]
        for param_name in tested_params:
            self.context["param"] = param_name
            for payload in reflected_payloads:
                obs = await self._send_request(payload)
                if obs.get("diff") == "cmd_injection_found":
                    return {
                        "confirmed": True,
                        "param": param_name,
                        "payload": payload,
                        "evidence": f"Deterministic command injection signal on '{param_name}'",
                    }

            baseline_obs = await self._send_request("127.0.0.1")
            baseline_latency = float(baseline_obs.get("elapsed_seconds") or 0.0)
            baseline_status = int(baseline_obs.get("status", 0) or 0)
            if baseline_status == 0:
                continue

            for payload, expected_delay in timing_payloads:
                obs = await self._send_request(payload)
                observed_latency = float(obs.get("elapsed_seconds") or 0.0)
                status = int(obs.get("status", 0) or 0)
                if status == 0:
                    continue

                # baseline との差分で time-based command injection を判定
                if observed_latency >= max(expected_delay - 0.6, baseline_latency + 2.0):
                    return {
                        "confirmed": True,
                        "param": param_name,
                        "payload": payload,
                        "evidence": (
                            f"Deterministic time-based command injection signal on '{param_name}' "
                            f"(baseline={baseline_latency:.3f}s, observed={observed_latency:.3f}s)."
                        ),
                        "blind_correlation": {
                            "time_based": {
                                "confirmed": True,
                                "payload": payload,
                                "expected_delay_seconds": expected_delay,
                                "observed_latency_seconds": round(observed_latency, 3),
                                "baseline_latency_seconds": round(baseline_latency, 3),
                            },
                            "oob": {
                                "confirmed": False,
                                "hits": [],
                            },
                            "dns": {
                                "confirmed": False,
                                "hits": [],
                            },
                            "correlated": False,
                        },
                    }

        return {"confirmed": False}

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        """LLM decides the next move."""
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

Decide next step for Command Injection / SSRF testing.
"""
        response = await self.llm.agenerate([
            {"role": "system", "content": self.SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ])

        content = response.choices[0].message.content if response and response.choices else ""

        if not content:
            logger.warning(f"Turn {turn}: LLM returned empty content. Forcing finish.")
            return "Analysis complete (LLM empty)", "finish", "safe"

        # Layer 2: LLM 出力の厳密な検証
        if "Observation:" in content or "observation" in content.lower():
            logger.warning(f"Turn {turn}: LLM wrote 'Observation:'! Forcing retry...")
            self.history.append({
                "role": "user",
                "content": "ERROR: Do NOT write 'Observation:'. Observation is PROVIDED BY THE TOOL."
            })
            if turn < self.max_turns:
                return await self.decide(turn)
            else:
                return "Analysis complete (invalid format)", "finish", "safe"

        if "Final Answer:" in content or "final answer" in content.lower():
            logger.warning(f"Turn {turn}: LLM wrote 'Final Answer:'! Forcing retry...")
            self.history.append({
                "role": "user",
                "content": "ERROR: Use 'ACTION: finish' instead of 'Final Answer:'."
            })
            if turn < self.max_turns:
                return await self.decide(turn)
            else:
                return "Analysis complete (invalid format)", "finish", "safe"

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
        """Execute action."""
        if action == "finish":
            if "vulnerable" in str(action_input).lower():
                self.vulnerable = True
                self.evidence = str(action_input)
            return f"Finished: {action_input}"

        if action in ["cmd_probe", "cmd_blind", "cmd_oob", "cmd_fuzz", "ssrf_probe", "ssrf_oob", "request"]:
            payload = str(action_input) if isinstance(action_input, str) else json.dumps(action_input)
            self.used_payloads.append(payload)

            obs = await self._send_request(payload)
            self._record_blind_signal(payload, obs)
            self._record_dns_signal(payload, obs)
            return f"Observation: Status={obs['status']}, Diff={obs['diff']}, Body={obs['body_snippet']}"

        return f"Unknown action: {action}"

    async def should_stop(self, step: ThoughtStep) -> bool:
        """Check if we should stop."""
        if step.action == "finish":
            return True
        return False

    def get_result(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "turns": len(self.history),
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "payloads_used": self.used_payloads,
            "blind_correlation": self.blind_correlation,
        }

    def _record_blind_signal(self, payload: str, observation: Dict[str, Any]) -> None:
        if not isinstance(observation, dict):
            return
        elapsed = observation.get("elapsed_seconds")
        if elapsed is None:
            return
        expected_delay = self._extract_expected_delay_seconds(payload)
        if expected_delay is None:
            return
        if elapsed >= max(1.0, expected_delay - 1.0):
            time_based = self.blind_correlation.get("time_based", {})
            time_based.update({
                "confirmed": True,
                "payload": payload,
                "expected_delay_seconds": expected_delay,
                "observed_latency_seconds": round(float(elapsed), 3),
            })
            self.blind_correlation["time_based"] = time_based
            self._recompute_blind_correlation()

    def _record_dns_signal(self, payload: str, observation: Dict[str, Any]) -> None:
        """
        DNS rebinding / wildcard DNS 系ペイロードの応答シグナルを blind_correlation.dns に反映する。
        """
        if not isinstance(observation, dict):
            return
        status = int(observation.get("status", 0) or 0)
        if status <= 0:
            return
        payload_l = str(payload or "").lower()
        body_l = str(observation.get("body_snippet", "") or "").lower()
        diff = str(observation.get("diff", "") or "").lower()

        dns_tokens = ("nip.io", "xip.io", "sslip.io", "localtest.me")
        has_dns_payload = any(tok in payload_l for tok in dns_tokens)
        if not has_dns_payload:
            return

        evidence_hit = (diff == "ssrf_found") or any(tok in body_l for tok in dns_tokens)
        if not evidence_hit:
            return

        dns = self.blind_correlation.get("dns", {})
        if not isinstance(dns, dict):
            dns = {}
        hits = dns.get("hits", [])
        if not isinstance(hits, list):
            hits = []
        hit_record = {
            "payload": payload,
            "status": status,
            "diff": diff,
        }
        hits.append(hit_record)
        dns["hits"] = hits[-10:]
        dns["confirmed"] = True
        self.blind_correlation["dns"] = dns
        self._recompute_blind_correlation()

    def _recompute_blind_correlation(self) -> None:
        tb = bool((self.blind_correlation.get("time_based") or {}).get("confirmed", False))
        oob = bool((self.blind_correlation.get("oob") or {}).get("confirmed", False))
        dns = bool((self.blind_correlation.get("dns") or {}).get("confirmed", False))
        self.blind_correlation["correlated"] = sum(1 for v in (tb, oob, dns) if v) >= 2

    def _extract_expected_delay_seconds(self, payload: str) -> Optional[float]:
        if not payload:
            return None
        sleep_match = re.search(r"sleep\s*\(?\s*(\d+(?:\.\d+)?)\s*\)?", payload, re.IGNORECASE)
        if sleep_match:
            try:
                return float(sleep_match.group(1))
            except ValueError:
                return None
        return None

    async def _send_request(self, payload: str) -> Dict[str, Any]:
        """実際のリクエストを送信し、結果を返す"""
        param = self.context.get("param")
        target = self.context.get("target")
        method = self.context.get("method", "GET")
        auth_headers = self.context.get("auth_headers", {})
        params = self.context.get("params", {}).copy()

        if param and param in params:
            params[param] = payload

        try:
            last_observation = {"status": 0, "diff": "error", "body_snippet": "", "elapsed_seconds": 0.0, "race_attempts": 0}
            attempt_plan = self._build_race_attempt_plan(params)
            for attempt in attempt_plan:
                delay_seconds = float(attempt.get("delay_seconds", 0.0) or 0.0)
                if delay_seconds > 0:
                    await asyncio.sleep(delay_seconds)

                request_start = time.perf_counter()
                if method == "POST":
                    ordered_payload = dict(self._ordered_params_for_attempt(params, attempt.get("ordered_keys", [])))
                    resp = await self.smart_client.request(
                        "POST",
                        target,
                        data=ordered_payload,
                        headers=auth_headers,
                        timeout=60
                    )
                else:
                    parsed = urlparse(target)
                    ordered_query = urlencode(self._ordered_params_for_attempt(params, attempt.get("ordered_keys", [])))
                    new_url = urlunparse(parsed._replace(query=ordered_query))

                    resp = await self.smart_client.request(
                        "GET",
                        new_url,
                        headers=auth_headers,
                        timeout=60
                    )
                elapsed_seconds = time.perf_counter() - request_start

                body = resp.get("body", "")[:500] if resp.get("body") else ""
                status = resp.get("status", 0)
                error = resp.get("error")

                if error or status == 0:
                    logger.warning(f"[{self.name}] Request blocked or failed: {error}")
                    last_observation = {
                        "status": status,
                        "diff": "blocked",
                        "body_snippet": f"Blocked: {error}",
                        "elapsed_seconds": elapsed_seconds,
                        "race_attempts": int(attempt.get("attempt", 1) or 1),
                    }
                    continue

                cmd_indicators = [
                    "uid=",
                    "gid=",
                    "groups=",
                    "root:",
                    "daemon:",
                    "www-data:",
                    "www-data",
                    "/bin/bash",
                ]
                ssrf_indicators = ["aws", "metadata", "169.254", "localhost", "127.0.0.1"]

                diff = "normal"
                if any(ind.lower() in body.lower() for ind in cmd_indicators):
                    diff = "cmd_injection_found"
                elif any(ind.lower() in body.lower() for ind in ssrf_indicators):
                    diff = "ssrf_found"

                last_observation = {
                    "status": status,
                    "diff": diff,
                    "body_snippet": body[:200],
                    "elapsed_seconds": elapsed_seconds,
                    "race_attempts": int(attempt.get("attempt", 1) or 1),
                }
                if diff != "normal":
                    return last_observation

            return last_observation

        except Exception as e:
            logger.error(f"[{self.name}] Request failed: {e}")
            return {"status": 0, "diff": "error", "body_snippet": str(e), "elapsed_seconds": 0.0, "race_attempts": 0}
