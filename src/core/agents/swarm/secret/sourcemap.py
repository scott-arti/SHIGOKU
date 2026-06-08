import logging
import json
import re
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)

class SourceMapSpecialist(Specialist):
    name = "SourceMapSpecialist"
    description = "Checks for exposed JavaScript source maps (.js.map) and extracts secrets."
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.client = AsyncNetworkClient()

    async def execute(self, task: Task) -> List[Finding]:
        target_url = task.target
        findings = []
        logger.info("[%s] Checking for source maps at %s", self.name, target_url)

        if target_url.endswith(".js.map"):
            map_url = target_url
        elif target_url.endswith(".js"):
            map_url = f"{target_url}.map"
        else:
            # We assume the crawler or previous agent identified a JS file and passed it here
            logger.debug("[%s] Target %s is not a .js or .js.map file, skipping...", self.name, target_url)
            return findings

        try:
            resp = await self.client.request("GET", map_url, timeout=10)
            if resp.status == 200 and ("version" in resp.text and "sources" in resp.text):
                # Attempt to parse json
                try:
                    data = json.loads(resp.text)
                    sources = data.get("sourcesContent", [])
                    combined_source = "\n".join(sources) if isinstance(sources, list) else ""
                    
                    if not combined_source:
                        return findings

                    # Very basic regex for typical hardcoded secrets (API keys, tokens, etc.)
                    # In a real scenario, this would use a robust secrets regex library.
                    secret_patterns = {
                        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
                        "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
                        "Generic Bearer Token": r"Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*"
                    }
                    
                    found_secrets = []
                    for name, pattern in secret_patterns.items():
                        matches = re.finditer(pattern, combined_source)
                        for match in matches:
                            found_secrets.append(f"{name}: {match.group(0)}")
                    
                    if found_secrets:
                        # Limit evidence size
                        evidence_text = "\n".join(found_secrets)[:1000]
                        findings.append(Finding(
                            vuln_type=VulnType.SECRET_LEAK,
                            severity=Severity.HIGH,
                            title=f"Exposed Source Map w/ Secrets on {target_url}",
                            description=f"Source map found at {map_url} contains potentially sensitive information.",
                            evidence=Evidence(
                                request_url=map_url,
                                request_method="GET",
                                response_body=evidence_text
                            ),
                            target_url=target_url,
                            source_agent=self.name,
                            tags=["sourcemap", "secret"]
                        ))
                    else:
                        # Log existence even if no obvious secret
                        findings.append(Finding(
                            vuln_type=VulnType.OTHER,
                            severity=Severity.INFO,
                            title=f"Exposed Source Map on {target_url}",
                            description=f"Source map found at {map_url} but no obvious secrets found in quick scan.",
                            evidence=Evidence(
                                request_url=map_url,
                                request_method="GET",
                                response_body="Source map detected."
                            ),
                            target_url=target_url,
                            source_agent=self.name,
                            tags=["sourcemap"]
                        ))

                except json.JSONDecodeError:
                    logger.debug("[%s] Failed to parse JSON at %s", self.name, map_url)
        except Exception as e:
            logger.debug("[%s] Error checking %s: %s", self.name, map_url, e)

        return findings
