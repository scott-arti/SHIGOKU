#!/usr/bin/env python3
"""SmartSQLiHunter blind correlation / time-based precheck helpers (Phase 2 extraction).

Extracted from SmartSQLiHunter to keep the facade thin.
"""

import logging
import re
import time
from typing import Any, Dict, List

from src.core.agents.swarm.injection.smart_sqli_payloads import (
    generate_time_based_payloads,
    generate_waf_evasion_payloads,
    detect_payload_technique,
)

logger = logging.getLogger(__name__)


def _looks_like_time_payload_sqli(payload: str) -> bool:
    payload_lower = str(payload or "").lower()
    markers = ["sleep(", "sleep ", "pg_sleep", "waitfor delay", "benchmark(", "dbms_lock.sleep"]
    return any(marker in payload_lower for marker in markers)


def _estimate_expected_delay_sqli(payload: str) -> float:
    payload_text = str(payload or "")
    patterns = [
        r"sleep\s*\(\s*(\d+)\s*\)",
        r"pg_sleep\s*\(\s*(\d+)\s*\)",
        r"waitfor\s+delay\s+['\"]0:0:(\d+)['\"]",
        r"benchmark\s*\(\s*(\d+)\s*,",
    ]
    for pattern in patterns:
        m = re.search(pattern, payload_text, re.IGNORECASE)
        if m:
            try:
                return float(m.group(1))
            except (TypeError, ValueError):
                continue
    return 5.0


def _extract_oob_tokens_sqli(text: str) -> List[str]:
    """Extract 8-hex-char OOB callback tokens from text."""
    if not text:
        return []
    pattern = re.compile(r"/(?:callback/)?([0-9a-fA-F]{8})(?:\b|/|\?)")
    tokens: List[str] = []
    for m in pattern.finditer(text):
        normalized = m.group(1).lower()
        if normalized not in tokens:
            tokens.append(normalized)
    return tokens


def build_blind_correlation_sqli(hunter) -> Dict[str, Any]:
    """Build blind correlation dict from time-based signals + OOB listener hits.

    Delegated from SmartSQLiHunter._build_blind_correlation.
    """
    time_based_confirmed = bool(hunter._time_signal_payload)
    expected_delay = _estimate_expected_delay_sqli(hunter._time_signal_payload) if hunter._time_signal_payload else 0.0
    time_based = {
        "confirmed": time_based_confirmed,
        "payload": hunter._time_signal_payload,
        "observed_latency_seconds": round(hunter._time_signal_latency, 3),
        "expected_delay_seconds": expected_delay,
        "technique": detect_payload_technique(hunter._time_signal_payload) if hunter._time_signal_payload else None,
    }

    oob_hits: List[str] = []
    try:
        from src.core.utils.oob_listener import get_oob_listener
        oob = get_oob_listener()
        if oob is not None:
            oob_hits = oob.get_recent_hits(limit=20) or []
    except Exception:
        pass

    oob = {
        "confirmed": bool(oob_hits),
        "hits": oob_hits,
    }

    return {
        "verdict": "tentative" if time_based_confirmed else "none",
        "time_based": time_based,
        "oob": oob,
        "correlated": bool(time_based_confirmed and oob_hits),
    }


async def run_time_based_blind_precheck_sqli(
    hunter, param_name: str, baseline_value: Any
) -> Dict[str, Any]:
    """Pre-check for blind SQLi: send baseline + time-based/WAF-evasion payloads.

    Delegated from SmartSQLiHunter._run_time_based_blind_precheck.
    """
    baseline_payload = f"{param_name}={baseline_value}"
    baseline_obs = await hunter._send_request(baseline_payload)
    baseline_elapsed = float(baseline_obs.get("elapsed_seconds", 0.0) or 0.0)
    hunter._max_observed_latency = baseline_elapsed

    all_payloads: List[str] = []
    all_payloads.extend(generate_time_based_payloads(param_name))
    all_payloads.extend(generate_waf_evasion_payloads(param_name))

    best_confirmed = False
    best_payload = ""
    best_latency = 0.0
    best_technique: Any = None

    for idx, payload in enumerate(all_payloads):
        obs = await hunter._send_request(payload)
        elapsed = float(obs.get("elapsed_seconds", 0.0) or 0.0)
        if elapsed > hunter._max_observed_latency:
            hunter._max_observed_latency = elapsed

        expected = _estimate_expected_delay_sqli(payload)
        technique = detect_payload_technique(payload)

        if elapsed >= (baseline_elapsed + expected * 0.5) and _looks_like_time_payload_sqli(payload):
            best_confirmed = True
            best_payload = payload
            best_latency = elapsed
            best_technique = technique
            logger.info(
                "[%s] Blind time-based signal detected: param=%s payload=%s elapsed=%.2fs (base=%.2fs expected=%.2fs)",
                hunter.name, param_name, payload, elapsed, baseline_elapsed, expected,
            )
            break

        if elapsed >= baseline_elapsed + 2.0:
            if not best_confirmed:
                best_payload = payload
                best_latency = elapsed
                best_technique = technique

    if best_confirmed:
        hunter._time_signal_payload = best_payload
        hunter._time_signal_latency = best_latency
    elif best_payload:
        hunter._time_signal_payload = best_payload
        hunter._time_signal_latency = best_latency

    return {
        "confirmed": best_confirmed,
        "payload": best_payload,
        "baseline_latency_seconds": round(baseline_elapsed, 3),
        "observed_latency_seconds": round(best_latency, 3),
        "latency_delta_seconds": round(max(0.0, best_latency - baseline_elapsed), 3),
        "expected_delay_seconds": _estimate_expected_delay_sqli(best_payload) if best_payload else 0.0,
        "technique": best_technique,
    }
