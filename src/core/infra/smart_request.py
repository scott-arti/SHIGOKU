
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
    - WAF Detection (403/406 analysis)
    - Diff Analysis (Content comparison)
    - Automatic Retry/Backoff
    """
    
    def __init__(self, network_client: AsyncNetworkClient, request_guard=None):
        self.client = network_client
        self.guard = request_guard
        self.waf_detected = False
        self.last_response = None
        self.last_status = None
        
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
        
        # 0. Request Guard Check
        if self.guard:
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
                response = await self.client.request(method, url, **kwargs)
                
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
