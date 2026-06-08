"""Admin エンドポイント認可バイパス試行（BizLogicSwarm 代替実装）。

ネットワーク I/O に aiohttp.ClientSession を内部生成する点が
CSRF probe と異なる。plan 文書 5.4 CTO 視点で許容判断済み。
"""

import asyncio
import logging
import time
from typing import Any, Dict, List

from src.core.models.finding import Evidence, Finding, Severity, VulnType

logger = logging.getLogger(__name__)


async def run_admin_check(
    *,
    url: str,
    params: Dict[str, Any],
    findings_sink: List[Any],
) -> Dict[str, Any]:
    import aiohttp

    tested_params: List[str] = []
    findings: List[Any] = []

    auth_headers = params.get("auth_headers", {})
    cookies = params.get("cookies", "")

    bypass_attempts = [
        {
            "name": "jwt_missing",
            "description": "JWT認証情報なしでadminエンドポイントにアクセス",
            "headers": {},
            "expected_success": False,
        },
        {
            "name": "role_escalation",
            "description": "role=adminパラメータでの権限昇格試行",
            "modification": lambda u: f"{u}{'&' if '?' in u else '?'}role=admin",
        },
    ]

    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.path.startswith("/rest/admin/"):
        return {"findings_count": 0, "tested_params": [], "findings_list": []}

    http_methods = ["GET", "POST", "PUT", "DELETE"]

    async with aiohttp.ClientSession() as session:
        for method in http_methods:
            for attempt in bypass_attempts:
                target_url = attempt.get("modification", lambda u: u)(url) if "modification" in attempt else url
                headers = attempt.get("headers", auth_headers)

                start_time = time.time()

                try:
                    async with session.request(
                        method, target_url, headers=headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        latency_ms = (time.time() - start_time) * 1000
                        body = await resp.text()

                        error_type = None
                        if resp.status == 401:
                            error_type = "AUTHENTICATION_REQUIRED"
                        elif resp.status == 403:
                            error_type = "FORBIDDEN"
                        elif resp.status == 404:
                            error_type = "NOT_FOUND"
                        elif resp.status >= 500:
                            error_type = "SERVER_ERROR"

                        if resp.status == 200 and len(body) > 100:
                            if "application" in body.lower() or "configuration" in body.lower():
                                finding = Finding(
                                    vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                                    severity=Severity.HIGH,
                                    title="Admin Endpoint Accessible Without Authentication",
                                    target_url=url,
                                    description=f"Admin endpoint {method} accessible without auth: {attempt['name']}",
                                    evidence=Evidence(
                                        request_url=target_url,
                                        request_headers=str(headers),
                                        response_status=resp.status,
                                        response_body=body[:500],
                                        response_headers=dict(resp.headers),
                                    ),
                                    additional_info={
                                        "bypass_method": attempt["name"],
                                        "tested_params": ["authorization", "role"],
                                        "http_method": method,
                                        "latency_ms": round(latency_ms, 2),
                                        "response_size": len(body),
                                    }
                                )
                                findings.append(finding)
                                tested_params.extend(["authorization", "role", f"method:{method}"])

                                logger.warning(
                                    "[ADMIN BYPASS] %s %s - %s (latency: %.2fms, size: %d bytes)",
                                    method, target_url, attempt["name"], latency_ms, len(body)
                                )

                        elif method in ["POST", "PUT", "DELETE"] and resp.status in [200, 201, 204]:
                            finding = Finding(
                                vuln_type=VulnType.BROKEN_ACCESS_CONTROL,
                                severity=Severity.CRITICAL if method == "DELETE" else Severity.HIGH,
                                title="Write Operation Allowed on Admin Endpoint Without Authentication",
                                target_url=url,
                                description=f"Write method {method} allowed without auth on admin endpoint: {attempt['name']}",
                                evidence=Evidence(
                                    request_url=target_url,
                                    request_headers=str(headers),
                                    response_status=resp.status,
                                    response_body=body[:500] if body else "",
                                    response_headers=dict(resp.headers),
                                ),
                                additional_info={
                                    "bypass_method": attempt["name"],
                                    "tested_params": ["authorization", "role", f"method:{method}"],
                                    "http_method": method,
                                    "latency_ms": round(latency_ms, 2),
                                    "error_type": error_type,
                                }
                            )
                            findings.append(finding)
                            tested_params.extend([f"method:{method}"])

                            logger.warning(
                                "[ADMIN WRITE BYPASS] %s %s - %s (status: %d, latency: %.2fms)",
                                method, target_url, attempt["name"], resp.status, latency_ms
                            )

                except asyncio.TimeoutError:
                    latency_ms = (time.time() - start_time) * 1000
                    logger.warning(
                        "[TIMEOUT] %s %s - timeout after %.2fms",
                        method, target_url, latency_ms
                    )
                    continue
                except aiohttp.ClientError as e:
                    logger.debug(
                        "[CLIENT ERROR] %s %s - %s: %s",
                        method, target_url, type(e).__name__, e
                    )
                    continue
                except Exception as e:
                    logger.debug(
                        "[UNEXPECTED ERROR] %s %s - %s: %s",
                        method, target_url, type(e).__name__, e
                    )
                    continue

    if findings:
        findings_sink.extend(findings)

    return {
        "findings_count": len(findings),
        "tested_params": list(set(tested_params)) if tested_params else ["authorization"],
        "findings_list": findings,
    }
