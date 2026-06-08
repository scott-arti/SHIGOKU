from typing import Any, Dict


async def run_object_ab_comparison(
    *,
    request_client: Any,
    url: str,
    auth_headers: Dict[str, Any],
    object_ab_candidate: Dict[str, Any],
) -> Dict[str, Any]:
    candidate_url = str(object_ab_candidate.get("mutated_url", "") or "").strip()
    if not candidate_url:
        return {
            "performed": False,
            "comparison": {"performed": False},
            "baseline_body": "",
            "variant_body": "",
            "param_name": "",
        }

    baseline_ab_resp = await request_client.request(
        method="GET",
        url=url,
        headers=auth_headers,
        timeout=20,
        use_cache=False,
        allow_redirects=True,
    )
    variant_ab_resp = await request_client.request(
        method="GET",
        url=candidate_url,
        headers=auth_headers,
        timeout=20,
        use_cache=False,
        allow_redirects=True,
    )
    baseline_ab_status = int(getattr(baseline_ab_resp, "status", 0) or 0)
    variant_ab_status = int(getattr(variant_ab_resp, "status", 0) or 0)
    baseline_ab_body = str(getattr(baseline_ab_resp, "body", "") or "")
    variant_ab_body = str(getattr(variant_ab_resp, "body", "") or "")
    comparison = {
        "performed": True,
        "param": str(object_ab_candidate.get("param", "") or ""),
        "location": str(object_ab_candidate.get("location", "") or ""),
        "resource_a": str(object_ab_candidate.get("resource_a", "") or ""),
        "resource_b": str(object_ab_candidate.get("resource_b", "") or ""),
        "url_a": url,
        "url_b": candidate_url,
        "status_a": baseline_ab_status,
        "status_b": variant_ab_status,
        "body_length_a": len(baseline_ab_body),
        "body_length_b": len(variant_ab_body),
    }
    return {
        "performed": True,
        "comparison": comparison,
        "baseline_body": baseline_ab_body,
        "variant_body": variant_ab_body,
        "param_name": str(object_ab_candidate.get("param", "") or "").strip(),
    }
