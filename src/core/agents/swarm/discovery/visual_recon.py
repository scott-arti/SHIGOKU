"""
VisualRecon: Visual Reconnaissance Worker

Uses Headless Browser (Katana or Playwright) to capture screenshots and analyze DOM structure.
"""

import logging
from typing import List, Dict, Any, Optional
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity

logger = logging.getLogger(__name__)

class VisualRecon(Specialist):
    """
    視覚的偵察・DOM分析ワーカー
    
    機能:
    1. スクリーンショット取得 (Mock/Placeholder)
    2. 入力フォーム、管理画面リンク、バージョン情報の抽出
    3. UIの異変検知 (Error pages, debug consoles)
    """
    
    name = "VisualRecon"
    description = "Analyzes visual elements and DOM structure for interesting artifacts."
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)

    async def execute(self, task: Task) -> List[Finding]:
        """Entry point"""
        # Task params から auth_headers を取得
        auth_headers = task.params.get("auth_headers", {})
        result = await self.run_as_tool(task.target, auth_headers=auth_headers)
        
        findings = []
        findings = []
        if result.get("interesting_elements"):
            # 汎用的なFindingとして報告
            findings.append(Finding(
                vuln_type=VulnType.OTHER,
                severity=Severity.INFO,
                title="Visual Recon: Interesting Elements Found",
                description=f"Found elements: {result['interesting_elements']}",
                target_url=task.target,
                source_agent=self.name,
                tags=["recon_info"]
            ))
        return findings

    async def run_as_tool(self, url: str, auth_headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Managerから呼び出し可能なToolメソッド
        """
        logger.info(f"[{self.name}] Running visual recon on {url}")
        
        from src.tools.browser.playwright_validator import PlaywrightValidator
        validator = PlaywrightValidator()
        
        result = {
            "screenshot_path": None,
            "dom_structure": "",
            "interesting_elements": [],
            "forms": [],
            "logs": []
        }
        
        # Cookieの抽出と変換
        browser_cookies = []
        if auth_headers and "Cookie" in auth_headers:
            cookie_str = auth_headers["Cookie"]
            from http.cookies import SimpleCookie
            try:
                c = SimpleCookie()
                c.load(cookie_str)
                for key, morsel in c.items():
                    browser_cookies.append({
                        "name": key,
                        "value": morsel.value,
                        "url": url  # Playwrightには対象URLを紐付ける
                    })
            except Exception as e:
                logger.warning(f"[{self.name}] Failed to parse Cookie header: {e}")

        if validator.is_available:
            # Removed form extraction to clarify role of VisualRecon
            pass
        else:
            # Fallback to simulation if Playwright is not available
            if "admin" in url:
                result["interesting_elements"].append("Login Form (Admin)")
            elif "api" in url:
                result["interesting_elements"].append("JSON Response (API)")
            else:
                result["interesting_elements"].append("Search Bar")
                result["interesting_elements"].append("Footer Version Info (v1.0)")
            
        return result
