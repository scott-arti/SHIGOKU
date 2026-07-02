
import logging
import asyncio
import difflib
from typing import Optional, Dict, Any

from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)

class SmartRequest:
    """
    Intelligent HTTP Client wrapper for Brain Agents.
    Features:
    - Execution safeguard integration (method + payload risk)
    - WAF Detection (403/406 analysis)
    - Diff Analysis (Content comparison)
    - Automatic Retry/Backoff
    """
    
    def __init__(self, network_client: AsyncNetworkClient, request_guard=None,
                 execution_safeguard=None, guard_context: Optional[Dict[str, Any]] = None):
        self.client = network_client
        # Preferred: execution_safeguard (ExecutionSafeguardService)
        self.safeguard = execution_safeguard
        # Legacy fallback: request_guard (RequestGuard)
        self.guard = request_guard
        # Phase 2 (SGK-2026-0335): Always pull guard_context from the
        # underlying network_client at request time (never cache at
        # construction time — shared updates must propagate).
        self._explicit_guard_context = guard_context
        self.waf_detected = False
        self.last_response = None
        self.last_status = None

    def _get_guard_context(self) -> Optional[Dict[str, Any]]:
        """Resolve active guard context at call time.

        Priority: explicit > client default > shared module-level.
        """
        if self._explicit_guard_context:
            return self._explicit_guard_context
        nc_default = getattr(self.client, "_default_guard_context", None)
        if nc_default and isinstance(nc_default, dict) and nc_default:
            return nc_default
        # Fall back to module-level shared context directly
        from src.core.infra import network_client as _nc
        shared = getattr(_nc, "_shared_guard_context", None)
        if shared and isinstance(shared, dict) and shared:
            return dict(shared)
        return None
        
    async def request(
        self, 
        method: str, 
        url: str, 
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute smart request.
        Returns a dict with 'status', 'headers', 'body', 'diff', 'waf_suspected'.
        """
        source_agent = kwargs.pop("source_agent", "")

        # Extract payload for safeguard evaluation
        payload = kwargs.get("data") or kwargs.get("json") or None
        
        # 0. Safeguard Check (preferred: ExecutionSafeguardService)
        if self.safeguard is not None:
            from src.core.security.execution_safeguard import SafeguardDecision
            decision: SafeguardDecision = await self.safeguard.evaluate(
                method=method,
                url=url,
                payload=payload,
                source_agent=source_agent,
            )
            if not decision.allowed:
                logger.warning(
                    "Request blocked by execution safeguard: method=%s url=%s "
                    "reason_code=%s matched_rules=%s",
                    method, url, decision.reason_code, decision.matched_rules,
                )
                return {
                    "status": 0,
                    "headers": {},
                    "body": "",
                    "diff": "",
                    "waf_suspected": False,
                    "error": f"Blocked by ExecutionSafeguard: {decision.reason_code}"
                }
        elif self.guard is not None:
            # Legacy path: direct RequestGuard usage (backward compat)
            approved = await self.guard.check(method, url, source_agent=source_agent)
            if not approved:
                logger.warning(f"Request blocked by guard: {method} {url}")
                return {
                    "status": 0,
                    "headers": {},
                    "body": "",
                    "diff": "",
                    "waf_suspected": False,
                    "error": "Blocked by RequestGuard"
                }

        result = {
            "status": 0,
            "headers": {},
            "body": "",
            "diff": "",
            "waf_suspected": False,
            "error": None
        }
        
        try:
            # 1. Automatic Retry for 429
            max_retries = 3
            for attempt in range(max_retries):
                # Phase 2 (SGK-2026-0335): pass guard context to network layer
                request_kwargs = dict(kwargs)
                gc = self._get_guard_context()
                if gc:
                    request_kwargs["guard_context"] = dict(gc)
                    request_kwargs["guard_context"].setdefault("phase", kwargs.get("phase", ""))
                    request_kwargs["guard_context"].setdefault("attack_class", kwargs.get("attack_class", ""))
                    request_kwargs["guard_context"].setdefault("source_agent", source_agent)
                    request_kwargs["guard_context"].setdefault("requested_action", kwargs.get("requested_action", "http_request"))
                    request_kwargs["guard_context"].setdefault("proposed_tool", kwargs.get("proposed_tool", ""))
                response = await self.client.request(method, url, **request_kwargs)
                
                if response.status == 429:
                    wait_time = 2 ** (attempt + 1)
                    logger.warning(f"Rate limited (429). Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                    continue
                
                # Check for WAF signs (403/406 with specific headers/body patterns)
                if response.status in [403, 406]:
                    self.waf_detected = True
                    result["waf_suspected"] = True
                    # Simple heuristic: if server keyword in body
                    body_lower = response.body.lower()
                    if "waf" in body_lower or "firewall" in body_lower or "blocked" in body_lower:
                        result["waf_confirmed"] = True
                
                result["status"] = response.status
                result["headers"] = dict(response.headers)
                result["body"] = response.body
                
                # 2. Diff Calculation
                if self.last_response:
                    diff = self._calculate_diff(self.last_response, response.body, response.status)
                    result["diff"] = diff
                else:
                    result["diff"] = "Baseline (First Request)"
                
                self.last_response = response.body
                self.last_status = response.status
                break
                
        except Exception as e:
            logger.error(f"SmartRequest failed: {e}")
            result["error"] = str(e)
            
        return result

    def _calculate_diff(self, old_text: str, new_text: str, new_status: int) -> str:
        """
        Calculate meaningful difference between two responses.
        Returns a summary string (e.g., "+ 50 chars", "Status changed 200->500").
        """
        if self.last_status and self.last_status != new_status:
             return f"Status Changed: {self.last_status} -> {new_status}"

        # Simple length check first
        len_diff = len(new_text) - len(old_text)
        
        # Threshold: 1 char (Test sensitivity)
        if abs(len_diff) < 1:
             return "No significant change."
             
        # Text diff (truncated)
        diff = difflib.unified_diff(
            old_text.splitlines(),
            new_text.splitlines(),
            fromfile='baseline',
            tofile='current',
            lineterm=''
        )
        
        # Only take first few lines of diff
        diff_lines = list(diff)[:10]
        return "\n".join(diff_lines)
