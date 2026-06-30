"""Takeover.yaml step executor handlers (SGK-2026-0283 Step 9).

Plan sections 4.4, 4.11, 4.12: Concrete executors for the three takeover recipe actions.

Provides:
  - ``TakeoverStepResult``: structured result dataclass.
  - ``execute_cname_resolve()``: read-only DNS CNAME chain resolution.
  - ``execute_http_probe()``: read-only HTTP GET for provider error tokens.
  - ``execute_check_takeover()``: orchestrate subjack/subzy/nuclei execution.
  - ``EXECUTOR_REGISTRY``: action → executor function mapping.
  - ``dispatch_takeover_step()``: unified entry-point for ``OptimizedRecipeRunner``.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Optional DNS library ───────────────────────────────────────────────────
try:
    import dns.resolver as _dns_resolver
    _HAS_DNSPYTHON = True
except ImportError:  # pragma: no cover
    _dns_resolver = None  # type: ignore[assignment]
    _HAS_DNSPYTHON = False


# ── Data model ─────────────────────────────────────────────────────────────

@dataclass
class TakeoverStepResult:
    """Structured result from a takeover recipe step executor.

    Fields:
        status: One of ``success``, ``failed``, ``blocked``, ``skipped``.
        output: Arbitrary data produced by the step (cname_chain, http_status, etc.).
        error: Human-readable error description when status is ``failed``.
        infrastructure_state: Infrastructure classification when available
            (e.g. ``probe_failed``, ``timeout``).
    """
    status: str
    output: dict
    error: Optional[str] = None
    infrastructure_state: Optional[str] = None


# ── cname_resolve ─────────────────────────────────────────────────────────

async def execute_cname_resolve(
    subdomain: str,
    resolver_timeout: float = 5.0,
) -> TakeoverStepResult:
    """Resolve CNAME chain for a dead candidate subdomain (read-only DNS).

    Uses ``socket.getaddrinfo`` (stdlib) or ``dns.resolver`` (optional) to
    perform a read-only DNS query without external proxy dependencies.

    Args:
        subdomain: The subdomain to resolve (e.g. ``dead.example.com``).
        resolver_timeout: Timeout in seconds for DNS resolution.

    Returns:
        ``TakeoverStepResult`` with ``output`` containing:
          - ``cname_chain``: list of CNAME entries (empty for NXDOMAIN).
          - ``addresses``: list of resolved IP addresses.
          - ``rcode``: DNS response code string when available.
    """
    try:
        if _HAS_DNSPYTHON and _dns_resolver is not None:
            return await _cname_resolve_with_dnspython(subdomain, resolver_timeout)
        return await _cname_resolve_with_socket(subdomain, resolver_timeout)
    except asyncio.TimeoutError:
        return TakeoverStepResult(
            status="failed",
            output={"cname_chain": [], "addresses": [], "rcode": "timeout"},
            error=f"DNS resolution timed out after {resolver_timeout}s for {subdomain}",
            infrastructure_state="probe_failed",
        )
    except Exception as exc:
        logger.warning("Unexpected error resolving %s: %s", subdomain, exc)
        return TakeoverStepResult(
            status="failed",
            output={"cname_chain": [], "addresses": [], "rcode": "error"},
            error=f"DNS resolution error: {exc}",
            infrastructure_state="probe_failed",
        )


async def _cname_resolve_with_dnspython(
    subdomain: str, timeout: float
) -> TakeoverStepResult:
    """Resolve CNAME chain using dnspython (preferred when available)."""
    cname_chain: list[str] = []
    addresses: list[str] = []
    rcode = "UNKNOWN"

    def _resolve():
        answers = _dns_resolver.resolve(subdomain, "CNAME", lifetime=timeout)
        for record in answers:
            target = str(record.target).rstrip(".")
            cname_chain.append(target)
        # Also resolve A records for the final target
        try:
            a_answers = _dns_resolver.resolve(subdomain, "A", lifetime=timeout)
            for record in a_answers:
                addresses.append(str(record))
        except _dns_resolver.NoAnswer:
            pass
        rcode_str = "NOERROR"
        return cname_chain, addresses, rcode_str

    try:
        cname_chain, addresses, rcode = await asyncio.to_thread(_resolve)
        return TakeoverStepResult(
            status="success",
            output={
                "cname_chain": cname_chain,
                "addresses": addresses,
                "rcode": rcode,
            },
        )
    except _dns_resolver.NXDOMAIN:
        return TakeoverStepResult(
            status="success",
            output={"cname_chain": [], "addresses": [], "rcode": "NXDOMAIN"},
        )
    except _dns_resolver.NoAnswer:
        return TakeoverStepResult(
            status="success",
            output={"cname_chain": [], "addresses": [], "rcode": "NOANSWER"},
        )
    except _dns_resolver.Timeout:
        return TakeoverStepResult(
            status="failed",
            output={"cname_chain": [], "addresses": [], "rcode": "timeout"},
            error=f"DNS timeout after {timeout}s for {subdomain}",
            infrastructure_state="probe_failed",
        )


async def _cname_resolve_with_socket(
    subdomain: str, timeout: float
) -> TakeoverStepResult:
    """Resolve hostname using socket.getaddrinfo (stdlib fallback).

    socket.getaddrinfo does not directly expose CNAME chains, so we
    return resolved addresses and attempt to infer CNAME via a
    subprocess call to ``nslookup`` when available.
    """
    addresses: list[str] = []
    cname_chain: list[str] = []
    rcode = "UNKNOWN"

    def _resolve():
        try:
            results = socket.getaddrinfo(subdomain, None, family=socket.AF_UNSPEC)
            for result in results:
                addr = result[4][0]
                if addr not in addresses:
                    addresses.append(str(addr))
        except socket.gaierror as e:
            err_code = getattr(e, "errno", None)
            if err_code == socket.EAI_NONAME:
                raise  # NXDOMAIN
            raise

    try:
        await asyncio.wait_for(asyncio.to_thread(_resolve), timeout=timeout)
        rcode = "NOERROR"
    except socket.gaierror as e:
        gaierr_str = str(e)
        if "Name or service not known" in gaierr_str or "nodename nor servname" in gaierr_str:
            # NXDOMAIN-like: return success with empty chain
            return TakeoverStepResult(
                status="success",
                output={"cname_chain": [], "addresses": [], "rcode": "NXDOMAIN"},
            )
        return TakeoverStepResult(
            status="failed",
            output={"cname_chain": [], "addresses": [], "rcode": "error"},
            error=f"DNS error: {gaierr_str}",
            infrastructure_state="probe_failed",
        )
    except asyncio.TimeoutError:
        # asyncio.TimeoutError is a subclass of TimeoutError, which socket.timeout
        # aliases in modern Python — catches both asyncio and socket timeouts.
        return TakeoverStepResult(
            status="failed",
            output={"cname_chain": [], "addresses": [], "rcode": "timeout"},
            error=f"DNS resolution timed out after {timeout}s for {subdomain}",
            infrastructure_state="probe_failed",
        )

    # Try to get CNAME via nslookup subprocess (best-effort, non-blocking)
    try:
        cname_chain = await _resolve_cname_via_nslookup(subdomain, timeout)
    except Exception:
        cname_chain = []

    return TakeoverStepResult(
        status="success",
        output={
            "cname_chain": cname_chain,
            "addresses": addresses,
            "rcode": rcode,
        },
    )


async def _resolve_cname_via_nslookup(
    subdomain: str, timeout: float
) -> list[str]:
    """Best-effort CNAME resolution via nslookup subprocess."""
    # subprocess-based resolution with a generous but bounded timeout
    cmd_timeout = min(timeout, 5.0)
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                "nslookup", "-type=cname", subdomain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=cmd_timeout,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(), timeout=cmd_timeout,
        )
        output = stdout.decode("utf-8", errors="replace")
        cnames: list[str] = []
        for line in output.splitlines():
            line_lower = line.lower()
            if "canonical name" in line_lower and "=" in line_lower:
                # nslookup format: "subdomain.example.com  canonical name = target.example.com"
                parts = line.split("canonical name", 1)
                if len(parts) == 2:
                    target = parts[1].strip().lstrip("=").strip().rstrip(".")
                    if target and target != subdomain:
                        cnames.append(target)
        return cnames
    except (FileNotFoundError, asyncio.TimeoutError, subprocess.SubprocessError):
        return []


# ── http_probe ────────────────────────────────────────────────────────────

async def execute_http_probe(
    url: str,
    timeout: float = 10.0,
) -> TakeoverStepResult:
    """Perform a read-only HTTP GET to check provider error tokens.

    Uses ``aiohttp`` for async HTTP. Minimal: returns status, body excerpt
    (first 1000 chars), selected headers, and redirect chain.

    Args:
        url: The target URL (e.g. ``http://dead.example.com``).
        timeout: Total timeout in seconds for the request.

    Returns:
        ``TakeoverStepResult`` with ``output`` containing:
          - ``http_status``: integer HTTP status code.
          - ``body_excerpt``: first 1000 characters of the response body.
          - ``headers``: selected response headers (Content-Type, Server, etc.).
          - ``redirect_chain``: list of redirect steps (url, status).
    """
    try:
        import aiohttp
    except ImportError:  # pragma: no cover
        return TakeoverStepResult(
            status="failed",
            output={},
            error="aiohttp is required for HTTP probing",
            infrastructure_state="probe_failed",
        )

    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=timeout_obj) as session:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                body = await resp.text()
                # Collect redirect chain from history
                redirect_chain = [
                    {"url": str(h.url), "status": h.status} for h in resp.history
                ]

                return TakeoverStepResult(
                    status="success",
                    output={
                        "http_status": resp.status,
                        "body_excerpt": body[:1000] if body else "",
                        "headers": {
                            "Content-Type": resp.headers.get("Content-Type", ""),
                            "Server": resp.headers.get("Server", ""),
                            "Location": resp.headers.get("Location", ""),
                        },
                        "redirect_chain": redirect_chain,
                    },
                )
    except asyncio.TimeoutError:
        return TakeoverStepResult(
            status="failed",
            output={},
            error=f"HTTP request to {url} timed out after {timeout}s",
            infrastructure_state="probe_failed",
        )
    except aiohttp.ClientConnectorError as exc:
        return TakeoverStepResult(
            status="failed",
            output={},
            error=f"Connection error for {url}: {exc}",
            infrastructure_state="probe_failed",
        )
    except aiohttp.ClientError as exc:
        return TakeoverStepResult(
            status="failed",
            output={},
            error=f"HTTP client error for {url}: {exc}",
            infrastructure_state="probe_failed",
        )
    except Exception as exc:
        logger.warning("Unexpected error probing %s: %s", url, exc)
        return TakeoverStepResult(
            status="failed",
            output={},
            error=f"Unexpected error probing {url}: {exc}",
            infrastructure_state="probe_failed",
        )


# ── check_takeover ────────────────────────────────────────────────────────

async def execute_check_takeover(
    subdomain: str,
    tools: list[str],
    provider_id: Optional[str] = None,
    matrix: Any = None,
) -> TakeoverStepResult:
    """Orchestrate subjack/subzy/nuclei tool execution with provider-aware ordering.

    Uses ``resolve_tool_chain()`` from the provider matrix to determine the
    ordered tool list. Runs each tool via subprocess, collects outputs, and
    normalizes them through ``takeover_tool_result_adapter``.

    Args:
        subdomain: The target subdomain.
        tools: List of tool names (e.g. ``["subjack", "subzy", "nuclei"]``).
        provider_id: Optional provider ID to resolve tool_preference from matrix.
        matrix: Optional ``TakeoverProviderMatrix`` instance for tool ordering.

    Returns:
        ``TakeoverStepResult`` with ``output.tool_results`` as a list of
        ``NormalizedTakeoverToolResult`` dicts.
    """
    # Resolve ordered tool chain
    ordered_tools: list[str] = list(tools)
    if matrix is not None and provider_id is not None:
        try:
            from src.core.adapters.external.takeover_provider_matrix_adapter import (
                resolve_tool_chain,
            )
            ordered_tools = resolve_tool_chain(provider_id, matrix)
        except Exception as exc:
            logger.warning(
                "Failed to resolve tool chain for provider=%s: %s", provider_id, exc
            )

    if not ordered_tools:
        return TakeoverStepResult(
            status="success",
            output={"tool_results": []},
        )

    # Run each tool and collect normalized results
    from src.core.adapters.external.takeover_tool_result_adapter import (
        normalize_tool_result,
    )

    normalized_results: list[dict] = []
    for tool_name in ordered_tools:
        try:
            tool_result = await _run_tool(tool_name, subdomain)
            normalized = normalize_tool_result(
                tool=tool_name,
                raw_output=tool_result.get("raw_output"),
                subdomain=subdomain,
                provider_matrix=matrix,
            )
            normalized_results.append(asdict(normalized))
        except Exception as exc:
            logger.warning("Tool %s failed for %s: %s", tool_name, subdomain, exc)
            normalized_results.append({
                "tool": tool_name,
                "subdomain": subdomain,
                "matched": False,
                "evidence_type": "none",
                "confidence": "none",
                "tool_error": str(exc),
            })

    return TakeoverStepResult(
        status="success",
        output={"tool_results": normalized_results},
    )


_TOOL_COMMAND_MAP: dict[str, list[str]] = {
    "subjack": ["subjack", "-w", "{subdomain_file}", "-o", "-", "-ssl", "-a"],
    "subzy": ["subzy", "run", "--target", "{subdomain}"],
    "nuclei": [
        "nuclei", "-u", "http://{subdomain}", "-t", "takeover/", "-silent", "-jsonl",
    ],
}


async def _run_tool(tool_name: str, subdomain: str) -> dict[str, Any]:
    """Run a single takeover detection tool via subprocess.

    Returns a dict with ``raw_output`` (stdout + stderr).
    On failure (missing binary, non-zero exit), includes ``tool_error``.
    """
    command_template = _TOOL_COMMAND_MAP.get(tool_name)
    if command_template is None:
        return {
            "raw_output": "",
            "tool_error": f"Unknown tool: {tool_name}",
        }

    import tempfile
    import os

    # For subjack, we need a temp file with the subdomain
    temp_file = None
    try:
        command = []
        for part in command_template:
            if "{subdomain}" in part:
                command.append(part.replace("{subdomain}", subdomain))
            elif "{subdomain_file}" in part:
                # Write subdomain to a temp file for subjack
                temp_fd, temp_path = tempfile.mkstemp(suffix=".txt")
                temp_file = temp_path
                with os.fdopen(temp_fd, "w") as f:
                    f.write(subdomain)
                command.append(temp_path)
            else:
                command.append(part)

        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            ),
            timeout=30,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=120,
        )
        raw_output = stdout.decode("utf-8", errors="replace")
        stderr_output = stderr.decode("utf-8", errors="replace")
        if stderr_output and not raw_output:
            raw_output = stderr_output
        elif stderr_output:
            raw_output += "\n" + stderr_output

        return {"raw_output": raw_output}
    except FileNotFoundError:
        return {
            "raw_output": "",
            "tool_error": f"Tool binary not found: {tool_name}",
        }
    except (asyncio.TimeoutError, subprocess.TimeoutExpired):
        return {
            "raw_output": "",
            "tool_error": f"Tool {tool_name} timed out for {subdomain}",
        }
    except Exception as exc:
        return {
            "raw_output": "",
            "tool_error": f"Tool {tool_name} error: {exc}",
        }
    finally:
        if temp_file is not None:
            try:
                os.unlink(temp_file)
            except OSError:
                pass


# ── Executor registry ─────────────────────────────────────────────────────

EXECUTOR_REGISTRY: dict[str, Any] = {
    "cname_resolve": execute_cname_resolve,
    "http_probe": execute_http_probe,
    "check_takeover": execute_check_takeover,
}


async def dispatch_takeover_step(
    action: str,
    params: dict,
    context: dict,
) -> TakeoverStepResult:
    """Unified dispatch entry-point for takeover recipe steps.

    Looks up *action* in ``EXECUTOR_REGISTRY`` and calls the corresponding
    executor with parameters derived from *params* and *context*.

    Args:
        action: The step action name (e.g. ``cname_resolve``).
        params: Step parameters from the recipe YAML.
        context: Execution context (target, previous results, etc.).

    Returns:
        ``TakeoverStepResult`` from the executor, or a failed result if the
        action is unknown.
    """
    executor = EXECUTOR_REGISTRY.get(action)
    if executor is None:
        return TakeoverStepResult(
            status="failed",
            output={},
            error=f"Unknown takeover step action: {action}",
        )

    if action == "cname_resolve":
        subdomain = context.get("subdomain") or params.get("subdomain", "")
        timeout = params.get("resolver_timeout", 5.0)
        return await executor(subdomain=subdomain, resolver_timeout=timeout)

    if action == "http_probe":
        subdomain = context.get("subdomain") or params.get("subdomain", "")
        url = params.get("url") or f"http://{subdomain}"
        timeout = float(params.get("timeout", 10.0))
        return await executor(url=url, timeout=timeout)

    if action == "check_takeover":
        subdomain = context.get("subdomain") or params.get("subdomain", "")
        tools = params.get("tools", ["subjack", "subzy", "nuclei"])
        provider_id = context.get("provider_id")
        matrix = context.get("provider_matrix")
        return await executor(
            subdomain=subdomain,
            tools=tools,
            provider_id=provider_id,
            matrix=matrix,
        )

    # Generic fallback for future actions
    return await executor(**params)
