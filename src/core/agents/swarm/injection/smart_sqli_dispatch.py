#!/usr/bin/env python3
"""SmartSQLiHunter request dispatch helper (Phase 2 extraction).

Extracted _send_request from SmartSQLiHunter.
"""

import logging
import time
from typing import Any, Dict
from urllib.parse import urlparse, urlencode, urlunparse

from src.core.agents.swarm.injection.smart_sqli_runtime import (
    detect_database_type,
    classify_sql_error,
)

logger = logging.getLogger(__name__)


async def sqli_send_request(hunter, payload: str) -> Dict[str, Any]:
    """Send an HTTP request with the given SQLi payload and classify response.

    Delegated from SmartSQLiHunter._send_request.
    """
    param = hunter.context.get("param")
    target = hunter.context.get("target")
    method = hunter.context.get("method", "GET")
    auth_headers = hunter.context.get("auth_headers", {})
    params = hunter.context.get("params", {}).copy()

    payload_value = payload
    if '=' in payload and payload.startswith(param + '='):
        payload_value = payload[len(param) + 1:]
        logger.debug("[%s] Extracted payload value: '%s' from '%s'",
                    hunter.name, payload_value, payload)

    if param and param in params:
        params[param] = payload_value

    try:
        start = time.perf_counter()
        if method == "POST":
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

        body = resp.get("body", "")[:500] if resp.get("body") else ""
        status = resp.get("status", 0)
        error = resp.get("error")
        elapsed = max(0.0, time.perf_counter() - start)

        if error or status == 0:
            logger.warning("[%s] Request blocked or failed: %s", hunter.name, error)
            return {
                "status": status,
                "diff": "blocked",
                "body_snippet": f"Blocked: {error}",
                "elapsed_seconds": elapsed,
            }

        db_detection = detect_database_type(body)
        error_classification = classify_sql_error(body)

        sql_errors = [
            "SQL syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite",
            "ODBC", "JDBC", "unclosed quotation mark", "syntax error",
            "mariadb",
        ]
        basic_diff = "error" if any(err.lower() in body.lower() for err in sql_errors) else "normal"
        diff = error_classification["type"] if error_classification["type"] != "none" else basic_diff

        return {
            "status": status,
            "diff": diff,
            "body_snippet": body[:200],
            "elapsed_seconds": elapsed,
            "db_detection": db_detection,
            "error_classification": error_classification,
        }

    except Exception as e:
        logger.error("[%s] Request failed: %s", hunter.name, e)
        return {
            "status": 0,
            "diff": "error",
            "body_snippet": str(e),
            "elapsed_seconds": 0.0,
        }
