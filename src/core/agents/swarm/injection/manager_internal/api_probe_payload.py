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
