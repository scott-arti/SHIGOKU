#!/usr/bin/env python3
"""SmartSQLiHunter orchestration helpers (Phase 2 extraction).

Contains execute, run_as_tool, decide, act logic extracted from
SmartSQLiHunter to keep the facade thin.
"""

import asyncio
import logging
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse

from src.core.models.finding import Finding, VulnType, Severity, Evidence

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------

async def sqli_execute(hunter, task, quick_mode: bool = False) -> List[Finding]:
    logger.info("[%s] Starting ThoughtLoop for %s (quick_mode=%s)", hunter.name, task.target, quick_mode)

    original_max_turns = hunter.max_turns
    if quick_mode:
        hunter.max_turns = 4
    hunter.context["quick_mode"] = quick_mode

    timeout = 300 if quick_mode else 600
    try:
        result = await asyncio.wait_for(
            hunter.run_as_tool(task.target, task.params),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("[%s] Timeout after %ss for %s", hunter.name, timeout, task.target)
        return []
    finally:
        hunter.max_turns = original_max_turns
        hunter.context.pop("quick_mode", None)

    findings: List[Finding] = []
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
                response_body=evidence_text,
            ),
            source_agent=hunter.name,
            confidence=0.9,
            tags=["sqli", "smart_agent"],
            additional_info={
                "parameter": result.get("param"),
                "payload": (result.get("payloads_used") or [""])[-1],
                "payloads_used": result.get("payloads_used", []) or [],
                "tested_params": result.get("tested_params", []),
                "blind_correlation": blind_correlation,
                "blind_time_based_confirmed": blind_time_based_confirmed,
            },
        )
        findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# run_as_tool
# ---------------------------------------------------------------------------

async def sqli_run_as_tool(hunter, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
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

    forms = params.get("forms", [])

    if not payload_params:
        if forms:
            for form in forms:
                form_method = form.get("method", "GET").upper()
                if form_method == "POST":
                    method = "POST"
                for input_field in form.get("inputs", []):
                    param_name = input_field.get("name", "")
                    if param_name and not hunter._is_excluded_param(param_name):
                        payload_params[param_name] = input_field.get("value", "1")
            logger.info("[%s] Extracted %d params from provided forms: %s",
                       hunter.name, len(payload_params), list(payload_params.keys()))

    from src.core.agents.swarm.injection.form_parsing import fetch_and_parse_form
    forms_from_html = await fetch_and_parse_form(target, auth_headers)
    if forms_from_html:
        for form in forms_from_html:
            form_method = form.get("method", "GET").upper()
            if form_method == "POST":
                method = "POST"
            for input_field in form.get("inputs", []):
                param_name = input_field.get("name", "")
                if (
                    param_name
                    and not hunter._is_excluded_param(param_name)
                    and param_name not in payload_params
                ):
                    payload_params[param_name] = input_field.get("value", "1")
        if forms_from_html:
            logger.info("[%s] Extracted %d additional params from HTML forms: %s",
                       hunter.name, len(payload_params), list(payload_params.keys()))

    forms = forms or forms_from_html

    if not payload_params and url_params_flat:
        payload_params = {
            key: value
            for key, value in url_params_flat.items()
            if not hunter._is_excluded_param(key)
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
                        param_name = input_field.get("name", "")
                        if param_name and not hunter._is_excluded_param(param_name):
                            payload_params[param_name] = "1"
                logger.info("[%s] Extracted %d params from Playwright forms: %s",
                           hunter.name, len(payload_params), list(payload_params.keys()))
        except Exception as e:
            logger.debug("[%s] Playwright form extraction failed: %s", hunter.name, e)

    if 'forms' not in locals():
        forms = []

    candidate_params = [
        name for name in list(payload_params.keys())
        if not hunter._is_excluded_param(name) and not hunter._is_non_attack_param(name)
    ][:hunter.MAX_PARAMS_TO_TEST] if payload_params else []
    quick_mode_flag = bool(hunter.context.get("quick_mode", False))
    tested_params: List[str] = []
    hunter.last_tested_params = tested_params
    hunter.last_blind_correlation = {}
    hunter._max_observed_latency = 0.0
    hunter._time_signal_payload = ""
    hunter._time_signal_latency = 0.0
    hunter._consecutive_blocked_observations = 0
    hunter._no_signal_turns = 0
    loop_result: Dict[str, Any] = {"status": "not_run", "reason": "no_parameters"}

    for param_name in candidate_params:
        tested_params.append(param_name)
        original_param_max_turns = hunter.max_turns
        hunter.max_turns = hunter._compute_adaptive_turn_budget(
            quick_mode_flag, len(candidate_params), param_name, target,
        )
        logger.debug(
            "[%s] Adaptive turn budget for param '%s': %d (candidates=%d)",
            hunter.name, param_name, hunter.max_turns, len(candidate_params),
        )

        hunter.context = {
            "target": target,
            "param": param_name,
            "method": method,
            "params": payload_params,
            "auth_headers": auth_headers,
            "cookies": cookies_str,
            "forms": forms if forms else [],
        }

        hunter.vulnerable = False
        hunter.evidence = ""
        hunter.used_payloads = []
        hunter.history_messages = []
        if "sqli_blind" in target.lower():
            from src.core.agents.swarm.injection.smart_sqli_blind import run_time_based_blind_precheck_sqli
            precheck = await run_time_based_blind_precheck_sqli(
                hunter,
                param_name=param_name,
                baseline_value=payload_params.get(param_name, "1"),
            )
            if precheck.get("confirmed"):
                hunter.vulnerable = True
                hunter.evidence = (
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
                hunter.max_turns = original_param_max_turns
                break
        hunter.history_messages.append({"role": "system", "content": hunter.SYSTEM_PROMPT})

        initial_prompt = (
            f"Target URL: {target}\n"
            f"Method: {method}\n"
            f"Parameter: {param_name}\n"
            f"Original Value: {payload_params.get(param_name, '') if payload_params else ''}\n\n"
            "Start your SQL injection testing.\n"
        )
        hunter.history_messages.append({"role": "user", "content": initial_prompt})

        try:
            loop_result = await hunter.run_loop(hunter.context)
        except Exception as e:
            logger.error("[%s] ThoughtLoop failed for param %s: %s", hunter.name, param_name, e)
            loop_result = {"status": "failed", "error": str(e), "param": param_name}
        finally:
            hunter.max_turns = original_param_max_turns

        if hunter.vulnerable:
            break

    from src.core.agents.swarm.injection.smart_sqli_blind import build_blind_correlation_sqli
    blind_correlation = build_blind_correlation_sqli(hunter)
    hunter.last_blind_correlation = blind_correlation

    return {
        "vulnerable": hunter.vulnerable,
        "evidence": hunter.evidence,
        "param": hunter.context.get("param"),
        "tested_params": tested_params,
        "payloads_used": hunter.used_payloads,
        "description": "SQLi detected." if hunter.vulnerable else "No SQLi detected.",
        "loop_result": loop_result,
        "blind_correlation": blind_correlation,
    }


# ---------------------------------------------------------------------------
# decide
# ---------------------------------------------------------------------------

import re  # noqa: E402


async def sqli_decide(hunter, turn: int) -> Tuple[str, str, Any]:
    history_text = "\n".join([
        f"Turn {s.turn}: Act={s.action}({s.action_input}) -> {s.observation}"
        for s in hunter.history
        if hasattr(s, "turn")
    ])

    prompt = (
        f"Target: {hunter.context['target']}\n"
        f"Testing Parameter: {hunter.context['param']}\n"
        f"Method: {hunter.context['method']}\n"
        f"Current Turn: {turn}\n\n"
        f"History:\n{history_text if history_text else 'No previous actions'}\n\n"
        "Decide next step for SQLi testing.\n"
    )

    response = await hunter.llm.agenerate([
        {"role": "system", "content": hunter.SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ])

    content = response.choices[0].message.content if response and response.choices else ""
    if not content:
        logger.warning("Turn %d: LLM returned empty content. Forcing finish.", turn)
        return "Analysis complete (LLM empty)", "finish", "safe"

    if "Observation:" in content or "observation" in content.lower():
        logger.warning("Turn %d: LLM wrote 'Observation:'! Forcing retry...", turn)
        hunter.history_messages.append({
            "role": "user",
            "content": (
                "ERROR: You wrote 'Observation:' in your output. This is INVALID. "
                "Do NOT write 'Observation:' yourself. Observation is PROVIDED BY THE TOOL. "
                "Your output should ONLY contain THOUGHT, ACTION, and INPUT. Please retry."
            ),
        })
        return "Fallback: send basic SQLi probe", "request", "' OR 1=1--"

    if "Final Answer:" in content or "final answer" in content.lower():
        logger.warning("Turn %d: LLM wrote 'Final Answer:'! Forcing retry...", turn)
        hunter.history_messages.append({
            "role": "user",
            "content": (
                "ERROR: You wrote 'Final Answer:' in your output. This is INVALID. "
                "Use 'ACTION: finish' instead of 'Final Answer:'. Please retry."
            ),
        })
        return "Fallback: send basic SQLi probe", "request", "' OR 1=1--"

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


# ---------------------------------------------------------------------------
# act
# ---------------------------------------------------------------------------

async def sqli_act(hunter, action: str, action_input: Any) -> str:
    if action in ["finish", "final", "final_answer", "conclusion"]:
        action_input_lower = str(action_input).lower()
        if any(kw in action_input_lower for kw in ["vulnerable", "found", "confirmed", "detected", "success"]):
            hunter.vulnerable = True
            hunter.evidence = str(action_input)
        return f"Finished: {action_input}"

    if action in {"request", "probe"}:
        payload = str(action_input)
        hunter.used_payloads.append(payload)
        obs = await hunter._send_request(payload)

        diff_type = str(obs.get("diff", "")).lower()
        if diff_type in {"blocked", "error"}:
            hunter._consecutive_blocked_observations += 1
        else:
            hunter._consecutive_blocked_observations = 0
        if diff_type == "normal":
            hunter._no_signal_turns += 1
        else:
            hunter._no_signal_turns = 0

        error_type = obs.get("error_classification", {}).get("type", "")
        if error_type in {"syntax", "schema", "data"}:
            hunter.vulnerable = True
            hunter.evidence = (
                f"SQL error: type={error_type}, param={hunter.context.get('param')}, "
                f"payload={payload}"
            )
        elapsed = float(obs.get("elapsed_seconds", 0.0) or 0.0)
        if elapsed > hunter._max_observed_latency:
            hunter._max_observed_latency = elapsed
        if elapsed >= 2.0 and elapsed >= hunter._max_observed_latency:
            hunter._time_signal_payload = payload
            hunter._time_signal_latency = elapsed
        return (
            f"Observation: Status={obs['status']}, Diff={obs['diff']}, "
            f"Body={obs['body_snippet']}, Elapsed={obs.get('elapsed_seconds', 0):.3f}s"
        )

    return f"Unknown action: {action}"
