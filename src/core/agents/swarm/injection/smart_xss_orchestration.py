#!/usr/bin/env python3
"""SmartXSSHunter orchestration helpers (Phase 2 extraction).

Contains execute, run_as_tool, decide, act logic extracted from
SmartXSSHunter to keep the facade thin (400-450 line target).

The pattern: each function receives `hunter: SmartXSSHunter` as its
first argument, replicating the original method body. The facade
methods become thin delegation wrappers.
"""

import asyncio
import logging
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse, urlencode, urlunparse

from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.payloads.xss_waf_evasion import XSSContext

from src.core.agents.swarm.injection.form_parsing import fetch_and_parse_form
from src.core.agents.swarm.injection.smart_xss_reflection import is_suspicious_observation as _is_suspicious

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Parameter normalization helpers
# ---------------------------------------------------------------------------

def normalize_name_hints(raw: Any) -> List[str]:
    """Flatten param/parameter hints from various input shapes into a list of names."""
    names: List[str] = []

    def _add(candidate: Any) -> None:
        token = str(candidate or "").strip()
        if not token:
            return
        if token not in names:
            names.append(token)

    if isinstance(raw, str):
        _add(raw)
    elif isinstance(raw, dict):
        for key in raw.keys():
            _add(key)
    elif isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, dict):
                for key in item.keys():
                    _add(key)
            else:
                _add(item)
    return names


META_KEYS = {
    "_auth", "method", "content_type", "task_id",
    "targets", "targets_file", "source_file", "cookies",
    "tags", "category", "_context", "extra_targets",
    "auth_headers", "headers", "count", "forms",
    "scan_profile", "profile",
    "body",
    "param", "parameter", "payload",
    "discovered_params", "candidate_params", "params_list",
    "reflection_url",
}


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------

async def xss_execute(hunter, task, quick_mode: bool = False) -> List[Finding]:
    """Orchestration: execute (delegated from SmartXSSHunter.execute)."""
    logger.info("[%s] Starting ThoughtLoop for %s (quick_mode=%s)", hunter.name, task.target, quick_mode)

    original_max_turns = hunter.max_turns
    if quick_mode:
        hunter.max_turns = 4

    hunter.context["quick_mode"] = quick_mode

    timeout = 120 if quick_mode else 220
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
    confirmed_vulnerable = bool(result.get("vulnerable")) and bool(result.get("reflection_observed"))
    if confirmed_vulnerable:
        finding = Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="XSS in parameter '%s'" % result.get("param", "unknown"),
            description=result.get("description", "Detected by SmartXSSHunter."),
            target_url=task.target,
            evidence=Evidence(
                request_url=task.target,
                response_body=str(result.get("evidence", "")),
            ),
            source_agent=hunter.name,
            confidence=0.9,
            tags=["xss", "smart_agent"],
            additional_info={
                "parameter": result.get("param"),
                "payload": (result.get("payloads_used") or [""])[-1],
                "tested_params": result.get("tested_params", []),
                "reflection_observed": result.get("reflection_observed", False),
            },
        )
        findings.append(finding)
    elif result.get("vulnerable"):
        logger.warning(
            "[%s] Ignoring vulnerable finish without reflection evidence for %s",
            hunter.name,
            task.target,
        )

    return findings


# ---------------------------------------------------------------------------
# run_as_tool
# ---------------------------------------------------------------------------

async def xss_run_as_tool(hunter, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    """Orchestration: run_as_tool (delegated from SmartXSSHunter.run_as_tool)."""
    params = params or {}
    _auth = params.get("_auth", {})
    auth_headers = _auth.get("auth_headers", {})
    cookies_str = _auth.get("cookies", "")

    method = params.get("method", "GET").upper()
    target = url
    scan_profile = str(params.get("scan_profile", "bbpt") or "bbpt").lower()
    if scan_profile not in {"bbpt", "ctf"}:
        scan_profile = "bbpt"

    explicit_param_names = normalize_name_hints(params.get("param") or params.get("parameter"))
    explicit_param = explicit_param_names[0] if explicit_param_names else ""
    explicit_payload = params.get("payload")
    discovered_hints: List[str] = []
    for source in [params.get("discovered_params"), params.get("candidate_params"), params.get("params_list")]:
        for name in normalize_name_hints(source):
            if name not in discovered_hints:
                discovered_hints.append(name)

    payload_params = {k: v for k, v in params.items() if k not in META_KEYS}
    if method == "POST" and isinstance(params.get("body"), dict):
        for k, v in params["body"].items():
            payload_params.setdefault(k, v)

    if explicit_param:
        payload_params.setdefault(explicit_param, explicit_payload if explicit_payload is not None else "1")
    for discovered_name in discovered_hints:
        payload_params.setdefault(discovered_name, "1")

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
                    if param_name:
                        payload_params[param_name] = input_field.get("value", "1")
            logger.info("[%s] Extracted %d params from provided forms: %s",
                       hunter.name, len(payload_params), list(payload_params.keys()))

    forms_from_html = await fetch_and_parse_form(target, auth_headers)
    if forms_from_html:
        for form in forms_from_html:
            form_method = form.get("method", "GET").upper()
            if form_method == "POST":
                method = "POST"
            for input_field in form.get("inputs", []):
                param_name = input_field.get("name", "")
                if param_name and param_name not in payload_params:
                    payload_params[param_name] = input_field.get("value", "1")
        if forms_from_html:
            logger.info("[%s] Extracted %d additional params from HTML forms: %s",
                       hunter.name, len(payload_params), list(payload_params.keys()))

    forms = forms or forms_from_html

    if not payload_params and url_params_flat:
        payload_params = url_params_flat

    if not payload_params:
        try:
            from src.tools.browser.playwright_validator import PlaywrightValidator
            pw_forms = await PlaywrightValidator().extract_forms(
                target,
                timeout=10.0,
                cookies=[{"name": cookie.split("=")[0].strip(), "value": cookie.split("=")[1].strip(), "domain": urlparse(target).hostname} for cookie in cookies_str.split(";") if "=" in cookie] if cookies_str else None
            )
            if pw_forms:
                for form in pw_forms:
                    if form.get("method", "get").upper() == "POST":
                        method = "POST"
                    for input_field in form.get("inputs", []):
                        param_name = input_field.get("name", "")
                        if param_name:
                            payload_params[param_name] = "1"
                logger.info("[%s] Extracted %d params from Playwright forms: %s",
                           hunter.name, len(payload_params), list(payload_params.keys()))
        except Exception as e:
            logger.debug("[%s] Playwright form extraction failed: %s", hunter.name, e)

    if cookies_str and "Cookie" not in auth_headers:
        auth_headers["Cookie"] = cookies_str

    if 'forms' not in locals():
        forms = []

    candidate_params = hunter._prioritize_candidate_params(
        payload_params=payload_params,
        url_params_flat=url_params_flat,
        target=target,
        scan_profile=scan_profile,
    )
    quick_mode_flag = bool(hunter.context.get("quick_mode", False))
    variant = hunter._detect_xss_variant(target)
    logger.info(
        "[%s] Candidate params prioritized (%s/%s): %s",
        hunter.name, scan_profile, variant, candidate_params,
    )
    tested_params: List[str] = []
    hunter.last_tested_params = tested_params
    loop_result: Dict[str, Any] = {"status": "not_run", "reason": "no_parameters"}

    for param_name in candidate_params:
        tested_params.append(param_name)
        original_param_max_turns = hunter.max_turns
        hunter.max_turns = hunter._compute_adaptive_turn_budget(
            quick_mode_flag, len(candidate_params), variant,
        )
        logger.debug(
            "[%s] Adaptive turn budget for param '%s': %d (variant=%s, candidates=%d)",
            hunter.name, param_name, hunter.max_turns, variant, len(candidate_params),
        )

        hunter.context = {
            "target": target,
            "param": param_name,
            "method": method,
            "params": payload_params,
            "auth_headers": auth_headers,
            "cookies": cookies_str,
            "forms": forms if forms else [],
            "content_type": str(params.get("content_type", "")).lower(),
            "reflection_url": params.get("reflection_url"),
        }

        hunter.vulnerable = False
        hunter.evidence = ""
        hunter.reflection_observed = False
        hunter.used_payloads = []
        hunter.history_messages = []
        hunter._consecutive_blocked_observations = 0
        hunter._no_signal_turns = 0
        hunter._suspicious_signal_observed = False
        hunter._used_rejudge_model = False
        hunter._used_final_model = False
        hunter.history_messages.append({"role": "system", "content": hunter.SYSTEM_PROMPT})

        initial_prompt = (
            f"Target URL: {target}\n"
            f"Method: {method}\n"
            f"Parameter: {param_name}\n"
            f"Original Value: {payload_params.get(param_name, '') if payload_params else ''}\n\n"
            "Start your XSS (Cross-Site Scripting) testing. "
            "First, send a simple marker to see if it reflects in the response.\n"
        )
        hunter.history_messages.append({"role": "user", "content": initial_prompt})

        skip_deterministic_precheck = (
            method == "POST" and isinstance(params.get("body"), dict)
        )
        if not skip_deterministic_precheck:
            deterministic_payloads = [
                "\"><script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
            ]
            for deterministic_payload in deterministic_payloads:
                hunter.used_payloads.append(deterministic_payload)
                try:
                    precheck_obs = await hunter._send_request(deterministic_payload)
                except Exception as exc:
                    precheck_obs = {
                        "status": 0, "diff": "error", "body_snippet": f"precheck_error: {exc}",
                    }
                if precheck_obs.get("diff") == "reflected":
                    hunter.vulnerable = True
                    hunter.reflection_observed = True
                    hunter.evidence = (
                        f"Deterministic payload reflected without encoding: param={param_name}, "
                        f"payload={deterministic_payload}, status={precheck_obs.get('status')}"
                    )
                    loop_result = {
                        "status": "completed",
                        "reason": "deterministic_precheck_reflection",
                        "param": param_name,
                    }
                    break

        if not hunter.vulnerable and hunter._detect_xss_variant(target) == "dom":
            dom_payloads = [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
            ]
            for dom_payload in dom_payloads:
                hunter.used_payloads.append(dom_payload)
                triggered = await hunter._validate_dom_runtime_xss(
                    target, dom_payload, cookies_str, param_name=param_name,
                )
                if triggered:
                    hunter.vulnerable = True
                    hunter.reflection_observed = True
                    hunter.evidence = (
                        f"DOM runtime execution observed via fragment payload: "
                        f"param={param_name}, payload={dom_payload}"
                    )
                    loop_result = {
                        "status": "completed",
                        "reason": "dom_runtime_fragment_execution",
                        "param": param_name,
                    }
                    logger.info("[%s] DOM runtime execution detected via Playwright.", hunter.name)
                    break

        if hunter.vulnerable:
            break

        try:
            loop_result = await hunter.run_loop(hunter.context)
        except Exception as e:
            logger.error("[%s] ThoughtLoop failed for param %s: %s", hunter.name, param_name, e)
            loop_result = {"status": "failed", "error": str(e), "param": param_name}
        finally:
            hunter.max_turns = original_param_max_turns

        if hunter.vulnerable:
            break

    return {
        "vulnerable": hunter.vulnerable,
        "reflection_observed": hunter.reflection_observed,
        "evidence": hunter.evidence,
        "param": hunter.context.get("param"),
        "tested_params": tested_params,
        "payloads_used": hunter.used_payloads,
        "description": "XSS detected." if hunter.vulnerable else "No XSS detected.",
        "loop_result": loop_result,
    }


# ---------------------------------------------------------------------------
# decide
# ---------------------------------------------------------------------------

async def xss_decide(hunter, turn: int) -> Tuple[str, str, Any]:
    """Orchestration: decide (delegated from SmartXSSHunter.decide)."""
    history_lines = []
    for s in hunter.history:
        if hasattr(s, "turn"):
            history_lines.append(
                f"Turn {s.turn}: Act={s.action}({s.action_input}) -> {s.observation}"
            )
        elif isinstance(s, dict):
            history_lines.append(
                f"Turn {s.get('turn', '?')}: Act={s.get('action', '?')}({s.get('action_input', s.get('input', ''))}) -> {s.get('observation', '')}"
            )
    history_text = "\n".join(history_lines)

    prompt = (
        f"Target: {hunter.context['target']}\n"
        f"Testing Parameter: {hunter.context['param']}\n"
        f"Method: {hunter.context['method']}\n"
        f"Current Turn: {turn}\n\n"
        f"History:\n{history_text if history_text else 'No previous actions'}\n\n"
        "Decide next step for XSS testing. Focus on reflection context and escaping mechanisms.\n"
    )

    decision_model, decision_stage = hunter._choose_decision_model()
    if decision_stage != "primary":
        logger.info(
            "[%s] XSS %s rejudge model selected for param '%s': %s",
            hunter.name, decision_stage, hunter.context.get("param"), decision_model,
        )

    original_model = hunter.llm.model
    hunter.llm.model = decision_model
    try:
        response = await hunter.llm.agenerate([
            {"role": "system", "content": hunter.SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ])
    finally:
        hunter.llm.model = original_model

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
        return "Fallback: send deterministic XSS marker payload", "request", "\"><script>alert(1)</script>"

    if "Final Answer:" in content or "final answer" in content.lower():
        logger.warning("Turn %d: LLM wrote 'Final Answer:'! Forcing retry...", turn)
        hunter.history_messages.append({
            "role": "user",
            "content": (
                "ERROR: You wrote 'Final Answer:' in your output. This is INVALID. "
                "Use 'ACTION: finish' instead of 'Final Answer:'. Please retry."
            ),
        })
        return "Fallback: continue with deterministic request", "request", "\"><script>alert(1)</script>"

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

async def xss_act(hunter, action: str, action_input: Any) -> str:
    """Orchestration: act (delegated from SmartXSSHunter.act)."""
    if action in ["finish", "final", "final_answer", "conclusion"]:
        action_input_lower = str(action_input).lower()
        if any(kw in action_input_lower for kw in ["vulnerable", "found", "confirmed", "detected", "success"]):
            if hunter.reflection_observed:
                hunter.vulnerable = True
                hunter.evidence = str(action_input)
            else:
                logger.info(
                    "[%s] Ignoring finish=vulnerable without reflection evidence (param=%s)",
                    hunter.name, hunter.context.get("param"),
                )
        return f"Finished: {action_input}"

    if action in {"request", "probe", "stored_probe"}:
        payload = str(action_input)
        hunter.used_payloads.append(payload)

        obs = await hunter._send_request(payload)
        if _is_suspicious(obs):
            hunter._suspicious_signal_observed = True
        diff_type = str(obs.get("diff", "")).lower()
        if diff_type in {"blocked", "error"}:
            hunter._consecutive_blocked_observations += 1
        else:
            hunter._consecutive_blocked_observations = 0
        if diff_type == "normal":
            hunter._no_signal_turns += 1
        else:
            hunter._no_signal_turns = 0

        if obs.get("diff") == "reflected":
            hunter.reflection_observed = True
            payload_lower = payload.lower()
            xss_markers = ["<script", "</script>", "onerror=", "onload=", "javascript:", "alert("]
            if any(marker in payload_lower for marker in xss_markers):
                hunter.vulnerable = True
                hunter.evidence = (
                    f"Payload reflected without encoding: param={hunter.context.get('param')}, "
                    f"payload={payload}, status={obs.get('status')}"
                )

        if action == "stored_probe":
            reflection_url = hunter.context.get("reflection_url") or hunter.context.get("params", {}).get("reflection_url")
            if reflection_url:
                try:
                    resp = await hunter.smart_client.request(
                        "GET", reflection_url,
                        headers=hunter.context.get("auth_headers", {}),
                        timeout=60,
                    )
                    body = resp.get("body", "") if isinstance(resp, dict) else ""
                    if payload.lower() in str(body).lower():
                        hunter.vulnerable = True
                        hunter.reflection_observed = True
                        hunter.evidence = (
                            f"Stored reflection observed at {reflection_url}: "
                            f"param={hunter.context.get('param')}, payload={payload}"
                        )
                except Exception:
                    pass
        return f"Observation: Status={obs['status']}, Diff={obs['diff']}, Body={obs['body_snippet']}"

    return f"Unknown action: {action}"
