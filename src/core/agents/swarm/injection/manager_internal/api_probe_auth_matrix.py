from typing import Any, Dict, List


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


def finalize_auth_context_matrix(
    *,
    rows: List[Dict[str, Any]],
    auth_status: int,
    unauth_status: int,
) -> Dict[str, Any]:
    matrix = {
        "mode": "unauth_authA_authB",
        "available": len(rows) >= 3,
        "rows": rows,
        "signals": [],
    }
    signals: List[str] = []
    auth_a_ok = auth_status in {200, 201, 202, 204}
    unauth_ok = unauth_status in {200, 201, 202, 204}
    if auth_a_ok:
        signals.append("authA_success")
    if unauth_ok:
        signals.append("unauth_success")
    if auth_a_ok and not unauth_ok:
        signals.append("auth_boundary_observed")
    if matrix["available"]:
        auth_b_row = next((row for row in rows if str(row.get("actor", "")) == "authB"), {})
        auth_b_status = int(auth_b_row.get("status", 0) or 0)
        if auth_b_status in {200, 201, 202, 204}:
            signals.append("authB_success")
        if auth_a_ok and auth_b_status in {200, 201, 202, 204}:
            signals.append("authA_authB_both_success")
    matrix["signals"] = _dedupe_preserve_order(signals)
    return matrix
