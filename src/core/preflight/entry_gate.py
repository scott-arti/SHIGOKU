"""
Strict entry gate orchestration for the SHIGOKU preflight module.

EntryGate runs all preflight checks in order based on active GatePhases.
EntryGateFacade provides the single `run_once()` entry point that guarantees
the gate is called exactly once per execution and never bypassed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import socket
import time
from typing import List, Optional
from urllib.parse import urlparse

from src.core.preflight.models import (
    PreflightResult,
    PreflightFailure,
    PreflightStatus,
    PreflightContext,
    PreflightSnapshot,
    AuthClassification,
    AuthProbeResult,
    GatePhase,
    GatePolicy,
)
from src.core.preflight.caido_check import CaidoCheck
from src.core.preflight.tool_check import ToolChecker
from src.core.preflight.tool_update_policy import ToolUpdatePolicy
from src.core.preflight.auth_probe import AuthProbe
from src.core.preflight.ai_classifier import AIClassifier

logger = logging.getLogger(__name__)


class EntryGate:
    """Orchestrates all preflight checks for the strict entry gate.

    Runs checks in order according to the active GatePhases configured
    in the PreflightContext.  Follows fail-close: any critical failure
    stops execution immediately.

    Usage::

        gate = EntryGate()
        result = await gate.run(context)
        if result.failed:
            for f in result.failures:
                print(f"{f.reason_code}: {f.remediation}")
    """

    def __init__(
        self,
        caido_check: Optional[CaidoCheck] = None,
        tool_checker: Optional[ToolChecker] = None,
        auth_probe: Optional[AuthProbe] = None,
        ai_classifier: Optional[AIClassifier] = None,
    ) -> None:
        self._caido_check = caido_check or CaidoCheck()
        self._tool_checker = tool_checker or ToolChecker()
        self._auth_probe = auth_probe or AuthProbe()
        self._ai_classifier = ai_classifier

    # ----------------------------------------------------------------
    # Main entry point
    # ----------------------------------------------------------------

    async def run(self, context: PreflightContext) -> PreflightResult:
        """Execute all active preflight checks against *context*.

        Returns a ``PreflightResult`` with structured pass/fail status
        and collected failures.
        """
        start = time.monotonic()
        snapshot = PreflightSnapshot(
            context_summary=self._mask_secrets(context),
        )
        all_failures: List[PreflightFailure] = []

        phases = set(context.active_phases)

        # ---- Phase 1: Deterministic gate (always runs) ----
        if GatePhase.PHASE_1_DETERMINISTIC in phases:
            # Caido check
            caido_failures = await self._run_caido_check(context, snapshot)
            all_failures.extend(caido_failures)

            # Target basic check (DNS + TCP)
            target_failures = await self._run_target_basic_check(context)
            all_failures.extend(target_failures)

            # Fail-fast: if Caido or target unreachable, stop immediately
            if all_failures:
                return self._build_fail_result(all_failures, snapshot, start)

        # ---- Phase 2: Tool update check ----
        if GatePhase.PHASE_2_TOOL_UPDATE in phases and not all_failures:
            tool_failures, tool_results = await self._run_tool_check(context)
            snapshot.tool_results = tool_results
            all_failures.extend(tool_failures)

            critical_tool_failures = [
                f for f in tool_failures if f.severity == "critical"
            ]
            if critical_tool_failures:
                return self._build_fail_result(all_failures, snapshot, start)

        # ---- Phase 3: AI classifier (auth probe + AI fallback) ----
        if GatePhase.PHASE_3_AI_CLASSIFIER in phases and not all_failures:
            auth_failures, auth_result = await self._run_auth_probe(context)
            snapshot.auth_result = auth_result
            all_failures.extend(auth_failures)

        # ---- Phase 4: Resume hardening ----
        if (
            GatePhase.PHASE_4_RESUME_HARDENING in phases
            and context.resume_session_id
            and not all_failures
        ):
            resume_failures = await self._run_resume_hardening(context, snapshot)
            all_failures.extend(resume_failures)

        # ---- Build final result ----
        snapshot.elapsed_ms = (time.monotonic() - start) * 1000.0
        snapshot.status = (
            PreflightStatus.PASS if not all_failures else PreflightStatus.FAIL
        )
        snapshot.failures = all_failures

        if all_failures:
            logger.warning(
                "Preflight FAILED: %d failure(s) in %.0fms",
                len(all_failures),
                snapshot.elapsed_ms,
            )
        else:
            logger.info(
                "Preflight PASSED in %.0fms", snapshot.elapsed_ms
            )

        return PreflightResult(
            status=snapshot.status,
            failures=all_failures,
            snapshot=snapshot,
            resume_allowed=not any(
                f.reason_code.startswith("CAIDO_") for f in all_failures
            ),
        )

    # ----------------------------------------------------------------
    # Phase runners
    # ----------------------------------------------------------------

    async def _run_caido_check(
        self, context: PreflightContext, snapshot: PreflightSnapshot
    ) -> List[PreflightFailure]:
        """Run Caido TCP + HTTP checks."""
        check = CaidoCheck(
            caido_url=context.caido_url,
            caido_token=context.caido_token,
        )

        # TCP check
        tcp_ok, _ = await check.check_tcp()
        snapshot.caido_tcp_ok = tcp_ok

        # HTTP check
        http_ok, _ = await check.check_http()
        snapshot.caido_http_ok = http_ok

        # Full run for structured failures
        _, failures = await check.run()
        return failures

    async def _run_target_basic_check(
        self, context: PreflightContext
    ) -> List[PreflightFailure]:
        """Check DNS resolution and TCP connectivity to the target."""
        if not context.target:
            return []

        parsed = urlparse(context.target if "://" in context.target else f"https://{context.target}")
        host = parsed.hostname
        if not host:
            return []

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        failures: List[PreflightFailure] = []

        # DNS check
        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().getaddrinfo(host, port),
                timeout=3.0,
            )
        except asyncio.TimeoutError:
            failures.append(PreflightFailure(
                reason_code="TARGET_DNS_FAILURE",
                severity="critical",
                category="Target Reachability",
                remediation=f"DNS resolution timed out for {host}. Check the target URL.",
                evidence={"host": host, "error": "timeout"},
            ))
            return failures
        except socket.gaierror as exc:
            failures.append(PreflightFailure(
                reason_code="TARGET_DNS_FAILURE",
                severity="critical",
                category="Target Reachability",
                remediation=f"DNS resolution failed for {host}. Verify the target URL is correct.",
                evidence={"host": host, "error": str(exc)},
            ))
            return failures

        # TCP check
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            failures.append(PreflightFailure(
                reason_code="TARGET_CONNECTION_FAILURE",
                severity="critical",
                category="Target Reachability",
                remediation=(
                    f"Cannot connect to {host}:{port}. "
                    "Check the target is online and the port is correct."
                ),
                evidence={"host": host, "port": port, "error": str(exc)},
            ))

        return failures

    async def _run_tool_check(
        self, context: PreflightContext
    ) -> tuple[List[PreflightFailure], dict]:
        """Run tool existence/version checks for the goal/profile.

        Injects ToolUpdatePolicy so that managed tools receive
        auto-install/update via BinaryManager.
        """
        auto_update = context.gate_policy == GatePolicy.STRICT_PROD
        try:
            from src.core.adapters.external.binary_manager import BinaryManager
            bm = BinaryManager()
        except Exception:
            bm = None
        policy = ToolUpdatePolicy(binary_manager=bm, auto_update=auto_update)
        # Rebuild tool checker with update policy
        self._tool_checker = ToolChecker(update_policy=policy)
        all_ok, failures = await self._tool_checker.check(
            goal=context.goal,
            profile=context.profile,
        )
        return failures, self._tool_checker.results

    async def _run_auth_probe(
        self, context: PreflightContext
    ) -> tuple[List[PreflightFailure], Optional[AuthProbeResult]]:
        """Run authenticated reachability probe.

        Uses the injected (or default) AuthProbe with context cookies,
        bearer token, and auth headers. Passes the AI classifier for
        supplementary fallback when available.

        Auth is considered required when the context provides credentials
        (cookies, bearer_token, or auth_headers).  For public recon without
        any credentials, ``auth_required=False`` allows ``UNKNOWN``
        classification to pass the gate.
        """
        if not context.target:
            return [], None

        auth_required = bool(
            context.cookies
            or context.bearer_token
            or context.auth_headers
        )

        _, failures = await self._auth_probe.probe_and_validate(
            target=context.target,
            cookies=context.cookies if context.cookies else None,
            bearer_token=context.bearer_token,
            auth_headers=context.auth_headers if context.auth_headers else None,
            ai_classifier=self._ai_classifier,
            auth_required=auth_required,
        )
        return failures, self._auth_probe.last_result

    async def _run_resume_hardening(
        self, context: PreflightContext, snapshot: PreflightSnapshot
    ) -> List[PreflightFailure]:
        """Compare current snapshot with previous preflight snapshot on resume.

        If the previous run passed but the current run shows a regression
        (Caido unreachable or auth state changed), escalate as
        ``RESUME_ENV_CHANGED``.
        """
        prev = context.previous_preflight_snapshot
        if prev is None:
            return []

        # Only escalate if previous was valid
        if prev.status != PreflightStatus.PASS:
            return []

        # Caido was ok before but not now
        if prev.caido_tcp_ok and not snapshot.caido_tcp_ok:
            return [PreflightFailure(
                reason_code="RESUME_ENV_CHANGED",
                severity="critical",
                category="Resume Hardening",
                remediation=(
                    "Caido was reachable when the session was created but is "
                    "no longer available. Restart Caido before resuming."
                ),
                evidence={
                    "reason": "caido_lost",
                    "previous_caido_tcp": "ok",
                    "current_caido_tcp": "tcp_unreachable",
                },
            )]

        # Auth state was authenticated before but not now
        if (
            prev.auth_result is not None
            and prev.auth_result.classification == AuthClassification.AUTHENTICATED
            and snapshot.auth_result is not None
            and snapshot.auth_result.classification != AuthClassification.AUTHENTICATED
        ):
            return [PreflightFailure(
                reason_code="RESUME_ENV_CHANGED",
                severity="critical",
                category="Resume Hardening",
                remediation=(
                    "Authentication state has changed since the session "
                    "was created. Refresh credentials and retry."
                ),
                evidence={
                    "reason": "auth_changed",
                    "previous_auth": prev.auth_result.classification.value,
                    "current_auth": snapshot.auth_result.classification.value,
                },
            )]

        return []

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    @staticmethod
    def _mask_secrets(context: PreflightContext) -> dict:
        """Create a safe context summary for the snapshot with secrets masked.

        Cookies, tokens, and custom auth headers are not exposed in the
        snapshot — only their presence/absence is recorded.
        """
        return {
            "mode": context.mode,
            "goal": context.goal,
            "target": context.target,
            "profile": context.profile,
            "has_cookies": bool(context.cookies),
            "has_bearer_token": bool(context.bearer_token),
            "has_auth_headers": bool(context.auth_headers),
            "resume_session_id": (
                context.resume_session_id[:8] + "..."
                if len(context.resume_session_id) > 8
                else context.resume_session_id
            ),
            "gate_policy": context.gate_policy.value,
            "active_phases": [p.value for p in context.active_phases],
            "caido_url": context.caido_url,
            "has_caido_token": bool(context.caido_token),
        }

    @staticmethod
    def _build_fail_result(
        failures: List[PreflightFailure],
        snapshot: PreflightSnapshot,
        start: float,
    ) -> PreflightResult:
        """Build a fail result with timing."""
        snapshot.elapsed_ms = (time.monotonic() - start) * 1000.0
        snapshot.status = PreflightStatus.FAIL
        snapshot.failures = failures
        return PreflightResult(
            status=PreflightStatus.FAIL,
            failures=failures,
            snapshot=snapshot,
        )


class EntryGateFacade:
    """Single entry point for all execution paths.

    .. code-block:: python

        facade = EntryGateFacade()
        result = await facade.run_once(context)
        if result.failed:
            print("Gate check failed — aborting.")
            return

    This is a process-level singleton. ``run_once()`` caches results
    per-context (keyed by target + goal + profile + resume_session_id +
    auth presence), so repeated calls with the same context are cheap
    but different contexts always trigger a fresh evaluation.
    """

    _instance: Optional["EntryGateFacade"] = None
    _cache: dict = {}
    _gate: "EntryGate"

    def __new__(cls) -> "EntryGateFacade":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._gate = EntryGate()
            cls._instance._cache = {}
        return cls._instance

    @staticmethod
    def _cache_key(context: PreflightContext) -> str:
        """Build a deterministic cache key from the preflight context.

        Includes a hash of credential values so that changing cookies/bearer
        token forces re-evaluation.  The raw secrets are never stored in the
        key — only a one-way hash is used.
        """
        # Hash credential payload (never include raw secrets in key)
        auth_payload = json.dumps({
            "cookies": dict(sorted(context.cookies.items())) if context.cookies else {},
            "bearer": context.bearer_token,
            "headers": dict(sorted(context.auth_headers.items())) if context.auth_headers else {},
            "caido_token": context.caido_token,
        }, sort_keys=True)
        auth_hash = hashlib.sha256(auth_payload.encode()).hexdigest()[:16]

        # Include all context-sensitive fields in the key
        return (
            f"{context.target}|{context.goal}|{context.profile}|"
            f"{context.resume_session_id}|{auth_hash}|"
            f"{context.caido_url}|"
            f"{context.gate_policy.value}|"
            f"{','.join(str(p.value) for p in sorted(context.active_phases, key=lambda x: x.value))}"
        )

    async def run_once(self, context: PreflightContext) -> PreflightResult:
        """Run the entry gate. Returns cached result for identical context."""
        key = self._cache_key(context)
        if key in self._cache:
            logger.debug("EntryGateFacade: cache hit for key=%s", key[:80])
            return self._cache[key]
        result = await self._gate.run(context)
        self._cache[key] = result
        return result

    def reset(self) -> None:
        """Reset all cached state (for testing)."""
        self._cache.clear()
