import logging
import os
import aiohttp
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class GitHubClient:
    """GitHub API Client for Reconnaissance"""
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None, network_client: Any = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.network_client = network_client
        if not self.token:
            logger.warning("GITHUB_TOKEN not set. API rate limits will be restricted and private repos inaccessible.")
            
    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json"
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    async def _fetch(self, url: str, params: Optional[Dict] = None) -> Any:
        """Helper to fetch URL using either shared NetworkClient or local session"""
        if self.network_client:
            # Use Shared AsyncNetworkClient (Preferred)
            # Returns NetworkResponse (sync properties)
            return await self.network_client.request(
                "GET", 
                url, 
                headers=self._get_headers(), 
                params=params, 
                use_proxy=True
            )
        else:
            # Fallback: Create ephemeral session (Legacy/Standalone mode)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=self._get_headers(), params=params) as resp:
                    # Create a compatible response object
                    class CompatibleResponse:
                        def __init__(self, s, t, j_coro):
                            self.status = s
                            self.text = t
                            self._j_coro = j_coro
                        
                        def json(self):
                            # NetworkResponse.json() is sync, but aiohttp is async
                            # For compatibility in fallback, we return the data directly
                            # invoking coroutine logic here is tricky.
                            # Standard pattern: return the json object directly if text is read.
                            import json
                            return json.loads(self.text)

                    text_content = await resp.text()
                    return CompatibleResponse(resp.status, text_content, None)

    async def search_org_repos(self, org_name: str) -> List[Dict[str, Any]]:
        """Search repositories for an organization or user"""
        url = f"{self.BASE_URL}/users/{org_name}/repos"
        
        resp = await self._fetch(url)
        
        if resp.status == 404:
            # Try orgs
            url = f"{self.BASE_URL}/orgs/{org_name}/repos"
            resp = await self._fetch(url)
        
        if resp.status != 200:
            logger.error("GitHub API Error: %s %s", resp.status, resp.text)
            return []
            
        return resp.json()

    async def get_recent_issue_comments(self, repo_full_name: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent issue comments to find leaked secrets"""
        url = f"{self.BASE_URL}/repos/{repo_full_name}/issues/comments"
        params = {"sort": "created", "direction": "desc", "per_page": limit}
        
        resp = await self._fetch(url, params)
        
        if resp.status != 200:
            logger.error("GitHub API Error: %s %s", resp.status, resp.text)
            return []
            
        return resp.json()
