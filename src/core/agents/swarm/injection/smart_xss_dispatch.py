#!/usr/bin/env python3
"""SmartXSSHunter request dispatch helper (Phase 2 extraction).

Extracted _send_request from SmartXSSHunter.
"""

import logging
from typing import Any, Dict
from urllib.parse import urlparse, urlencode, urlunparse

from src.core.payloads.xss_waf_evasion import XSSContext

logger = logging.getLogger(__name__)


async def xss_send_request(hunter, payload: str) -> Dict[str, Any]:
    """Send an HTTP request with the given XSS payload and check for reflection.

    Delegated from SmartXSSHunter._send_request.
    """
    param = hunter.context.get("param")
    target = hunter.context.get("target")
    method = hunter.context.get("method", "GET")
    auth_headers = hunter.context.get("auth_headers", {})
    params = hunter.context.get("params", {}).copy()

    if param and param in params:
        params[param] = payload

    try:
        if method == "POST":
            content_type = str(hunter.context.get("content_type", "")).lower()
            if content_type == "json":
                resp = await hunter.smart_client.request(
                    "POST", target,
                    json=params,
                    headers=auth_headers,
                    timeout=60,
                )
            else:
                resp = await hunter.smart_client.request(
                    "POST", target,
                    data=params,
                    headers=auth_headers,
                    timeout=60,
                )
        else:
            parsed = urlparse(target)
            new_query = urlencode(params)
            new_url = urlunparse(parsed._replace(query=new_query))
            resp = await hunter.smart_client.request(
                "GET", new_url,
                headers=auth_headers,
                timeout=60,
            )

        full_body = resp.get("body", "") if resp.get("body") else ""
        status = resp.get("status", 0)
        error = resp.get("error")

        if error or status == 0:
            hunter._waf_suite.record_payload_outcome(
                context=XSSContext.UNKNOWN,
                payload_id=payload,
                success=False,
                blocked=True,
                timed_out=False,
                parse_error=False,
            )
            logger.warning("[%s] Request blocked or failed: %s", hunter.name, error)
            return {"status": status, "diff": "blocked", "body_snippet": f"Blocked: {error}"}

        is_reflected = payload.lower() in full_body.lower()
        diff = "reflected" if is_reflected else "normal"

        if is_reflected:
            logger.info("[%s] Payload reflection detected in response body.", hunter.name)
        hunter._waf_suite.record_payload_outcome(
            context=XSSContext.UNKNOWN,
            payload_id=payload,
            success=is_reflected,
            blocked=False,
            timed_out=False,
            parse_error=False,
        )

        return {"status": status, "diff": diff, "body_snippet": full_body[:300]}

    except Exception as e:
        hunter._waf_suite.record_payload_outcome(
            context=XSSContext.UNKNOWN,
            payload_id=payload,
            success=False,
            blocked=False,
            timed_out=False,
            parse_error=True,
        )
        logger.error("[%s] Request failed: %s", hunter.name, e)
        return {"status": 0, "diff": "error", "body_snippet": str(e)}
