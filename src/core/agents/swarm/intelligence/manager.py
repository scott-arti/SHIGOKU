import logging

from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import SwarmManager, Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.tools.osint.github_recon import GitHubClient
from src.tools.osint.leak_detector import LeakDetector

logger = logging.getLogger(__name__)

class GitHubReconSpecialist(Specialist):
    name = "GitHubReconSpecialist"
    description = "GitHub OSINT & Secret Scanning"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.github = GitHubClient()
        self.detector = LeakDetector()

    def set_network_client(self, network_client: Any) -> None:
        """Inject shared network client into GitHub client"""
        super().set_network_client(network_client)
        if self.github:
            self.github.network_client = network_client
        
    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        org_name = task.target
        
        # 簡易的なターゲット検証
        if "github.com" in org_name:
            org_name = org_name.rstrip("/").split("/")[-1]
            
        logger.info("[%s] Starting Deep Recon for Org: %s", self.name, org_name)
        
        # 1. Repos List
        repos = await self.github.search_org_repos(org_name)
        if not repos:
            logger.warning("No repositories found for %s", org_name)
            return []
            
        logger.info("Found %d repositories. Scanning top 5 actively...", len(repos))
        
        # Limit to top 5 for demo/performance (sort by updated is default in client)
        target_repos = repos[:5]
        
        for repo in target_repos:
            repo_name = repo["name"]
            clone_url = repo["clone_url"]
            html_url = repo["html_url"]
            
            logger.info("Scanning %s...", repo_name)

            # A. Code Scan
            leaks = await self.detector.scan_repo(clone_url)
            for leak in leaks:
                findings.append(Finding(
                    vuln_type=VulnType.SECRET_LEAK,
                    severity=Severity.HIGH,
                    title=f"Secret Leak in {repo_name}",
                    description=f"GitLeaks found {leak['rule']} in {leak['file']}",
                    evidence=Evidence(
                        request_url=html_url,
                        response_body=f"Snippet: {leak['snippet'][:20]}..."
                    ),
                    target_url=html_url,
                    source_agent=self.name,
                    tags=["osint", "secret_leak"]
                ))
                
            # B. Comment Scan
            owner = repo["full_name"].split("/")[0] # repo["full_name"] = "owner/name"
            # github_client search_org_repos might return full_name which is correct
            
            comments = await self.github.get_recent_issue_comments(owner, repo["name"])
            for com in comments:
                context_leaks = self.detector.scan_text(com["body"], com["url"])
                for cl in context_leaks:
                    findings.append(Finding(
                        vuln_type=VulnType.SECRET_LEAK,
                        severity=Severity.MEDIUM,
                        title=f"Context Leak in Comment ({repo_name})",
                        description=f"User {com['user']} posted potential secret.",
                        evidence=Evidence(
                            request_url=com["url"],
                            response_body=f"Match: {cl['evidence']}"
                        ),
                        target_url=com["url"],
                        source_agent=self.name,
                        tags=["osint", "context_leak"]
                    ))
                    
        return findings

class IntelligenceSwarm(SwarmManager):
    """Intelligence Swarm: OSINT & Background Investigation"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.register_specialists([
            GitHubReconSpecialist(self.config),
        ])
        
    async def dispatch(self, task: Task) -> Any:
        # Simplified dispatch
        return await super().dispatch(task)

    def get_specialists(self, tags: List[str]) -> List[Specialist]:
        return self._specialists
