import json
from typing import Any, Dict, List, Tuple


def build_mass_assignment_probe_payload(schema_probe_fields: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    probe_payload = {"__shigoku_probe": "mass_assignment"}
    for key, value in (schema_probe_fields or {}).items():
        token = str(key or "").strip()
        if not token or token == "__shigoku_probe":
            continue
        probe_payload[token] = value
    schema_candidate_params = [
        key
        for key in probe_payload.keys()
        if str(key or "").strip() and str(key or "").strip() != "__shigoku_probe"
    ]
    return probe_payload, schema_candidate_params


def parse_json_dict(text: str) -> Dict[str, Any]:
    raw = str(text or "").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def mutate_schema_candidate_value(key: str, value: Any) -> Any:
    token = str(key or "").strip().lower()
    if not token:
        return None

    if isinstance(value, bool):
        return (not value)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            return int(value) + 1 if int(value) >= 0 else 1
        except Exception:
            return 1
    if isinstance(value, list):
        if not value:
            return ["admin"] if any(k in token for k in ("role", "perm", "scope")) else None
        first = value[0]
        mutated = mutate_schema_candidate_value(token, first)
        if mutated is None:
            return None
        return [mutated]
    if isinstance(value, str):
        if any(k in token for k in ("role", "admin", "privilege", "permission", "scope", "access")):
            return "admin"
        if any(k in token for k in ("status", "state")):
            return "active"
        if any(k in token for k in ("plan", "tier")):
            return "premium"
        if any(k in token for k in ("quota", "limit", "credit", "balance")):
            return "99999"
        if any(k in token for k in ("verified", "staff", "internal")):
            return "true"
        return None

    if any(k in token for k in ("role", "admin", "privilege", "permission", "scope", "access")):
        return "admin"
    if any(k in token for k in ("verified", "staff", "internal")):
        return True
    return None


def extract_mass_assignment_schema_candidates(
    *,
    response_bodies: List[str],
    excluded_params: set,
    cap: int = 6,
) -> Dict[str, Any]:
    risk_tokens = (
        "role",
        "admin",
        "privilege",
        "permission",
        "scope",
        "access",
        "status",
        "state",
        "plan",
        "tier",
        "quota",
        "limit",
        "credit",
        "balance",
        "verified",
        "staff",
        "internal",
        "type",
        "flag",
    )
    container_hints = {"data", "user", "profile", "account", "result", "item", "payload"}

    candidates: Dict[str, Any] = {
        "role": "admin",
        "is_admin": True,
    }

    for body in response_bodies:
        parsed = parse_json_dict(body)
        if not parsed:
            continue

        containers: List[Dict[str, Any]] = [parsed]
        for key, value in parsed.items():
            if isinstance(value, dict) and str(key or "").strip().lower() in container_hints:
                containers.append(value)

        for container in containers:
            for key, value in container.items():
                name = str(key or "").strip()
                if not name:
                    continue
                lowered = name.lower()
                if lowered in excluded_params or lowered.startswith("__"):
                    continue
                if name in candidates:
                    continue
                if not any(token in lowered for token in risk_tokens):
                    continue
                mutated = mutate_schema_candidate_value(name, value)
                if mutated is None:
                    continue
                candidates[name] = mutated
                if len(candidates) >= max(2, int(cap)):
                    return candidates

    return candidates


def build_mass_assignment_variant_payload(probe_payload: Dict[str, Any], marker: str) -> Dict[str, Any]:
    variant: Dict[str, Any] = {"__shigoku_probe": marker}
    for key, value in (probe_payload or {}).items():
        if str(key or "").strip() == "__shigoku_probe":
            continue
        if isinstance(value, bool):
            variant[key] = not value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            try:
                variant[key] = int(value) + 1
            except Exception:
                variant[key] = 1
        elif isinstance(value, list):
            if value:
                first = value[0]
                if isinstance(first, bool):
                    variant[key] = [not first]
                elif isinstance(first, (int, float)) and not isinstance(first, bool):
                    variant[key] = [int(first) + 1]
                elif isinstance(first, str):
                    variant[key] = ["auditor" if first == "admin" else "admin"]
            else:
                variant[key] = ["auditor"]
        elif isinstance(value, str):
            variant[key] = "auditor" if value == "admin" else "admin"
        else:
            variant[key] = value
    return variant
