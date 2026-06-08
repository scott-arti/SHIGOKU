from typing import Any, Dict, List, Optional


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    ordered: List[str] = []
    seen: set[str] = set()
    for value in values:
        token = str(value or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        ordered.append(token)
    return ordered


def build_authz_differential(
    *,
    scenario: str,
    baseline_status: int,
    test_status: int,
    baseline_body: str,
    test_body: str,
    baseline_json_like: bool,
    test_json_like: bool,
    length_close: bool,
    extra_signals: Optional[List[str]] = None,
) -> Dict[str, Any]:
    baseline_len = len(str(baseline_body or ""))
    test_len = len(str(test_body or ""))
    body_delta = abs(test_len - baseline_len)
    body_delta_ratio = round(body_delta / max(baseline_len, test_len, 1), 4)

    signals: List[str] = []
    if baseline_status in {200, 201, 202, 204}:
        signals.append("auth_success")
    if test_status in {200, 201, 202, 204}:
        signals.append("unauth_success")
    if baseline_json_like:
        signals.append("auth_json_like")
    if test_json_like:
        signals.append("unauth_json_like")
    if length_close:
        signals.append("body_length_close")
    for signal in extra_signals or []:
        token = str(signal or "").strip()
        if token:
            signals.append(token)

    normalized_signals = _dedupe_preserve_order(signals)

    confidence = 0.35
    if baseline_status in {200, 201, 202, 204} and test_status in {200, 201, 202, 204}:
        confidence += 0.20
    if test_json_like:
        confidence += 0.15
    if baseline_json_like:
        confidence += 0.05
    if length_close or body_delta_ratio <= 0.2:
        confidence += 0.10
    if "status_improved_with_auth" in normalized_signals:
        confidence += 0.10
    if "discovered_from_landing" in normalized_signals:
        confidence += 0.05

    return {
        "scenario": scenario,
        "confidence": min(0.95, round(confidence, 2)),
        "baseline_status": int(baseline_status or 0),
        "test_status": int(test_status or 0),
        "signals": normalized_signals,
        "auth_body_length": baseline_len,
        "test_body_length": test_len,
        "body_length_delta": body_delta,
        "body_length_delta_ratio": body_delta_ratio,
    }
