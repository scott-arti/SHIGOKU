"""
GitHubRecon: GitHub MCP Serverを用いたDorks検索 (情報漏洩チェック)
"""

import logging
import asyncio
from typing import Dict, Any, Optional

from src.config import settings
from src.mcp.mcp_client import add_mcp_server, get_mcp_client
from src.core.models.finding import Finding, VulnType, Severity

logger = logging.getLogger(__name__)

class GitHubRecon:
    """
    ターゲットドメインに関するGitHub上の情報漏洩を調査するWorker。
    github-mcp-serverを利用してDorks検索を実行します。
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.target_url = ""
        self.mcp_name = "github-mcp"
        
    async def run_as_tool(self, url: str) -> Dict[str, Any]:
        """ツールとしてのエントリポイント"""
        self.target_url = url
        
        # URLからドメインを抽出 (簡易的)
        domain = url.replace("https://", "").replace("http://", "").split("/")[0]
        
        if not settings.github_token:
            logger.info("GitHub Token is not set. Skipping GitHub Recon.")
            return {"status": "skipped", "reason": "No github_token configured."}
            
        logger.info("[GitHubRecon] Starting GitHub Dorks scan for %s...", domain)
        
        # MCP Client setup
        try:
            client = get_mcp_client(self.mcp_name)
            if not client:
                command = ["npx", "-y", "@modelcontextprotocol/server-github"]
                client = add_mcp_server(self.mcp_name, command)
        except Exception as e:
            logger.error("[GitHubRecon] Failed to start GitHub MCP server: %s", e)
            return {"status": "error", "error": f"MCP init failed: {str(e)}"}
            
        try:
            # 1. 検索クエリの作成
            query = f'"{domain}" (password OR secret OR token OR key OR credential)'
            
            arguments = {
                "q": query
            }
            
            tools = client.list_tools()
            if "search_code" not in tools:
                return {"status": "error", "error": f"search_code tool not found in GitHub MCP. Available tools: {tools}"}
                
            logger.info("Executing GitHub code search with query: %s", query)
            
            # MCP通信 (同期のcall_toolを非同期的に呼び出し)
            result = await asyncio.to_thread(client.call_tool, "search_code", arguments)
            
            # 2. 結果の解析とFindingの生成
            findings_generated = []
            
            result_str = str(result).lower()
            
            if "api_key" in result_str or "password" in result_str or "secret" in result_str or "token" in result_str:
                finding = Finding(
                    title=f"Potential Secret Leak on GitHub for {domain}",
                    description=f"GitHub search revealed potential leaked secrets using the query: {query}",
                    target_url=url, # Finding requires target_url
                    vuln_type=VulnType.SECRET_LEAK,
                    severity=Severity.HIGH
                )
                
                finding.evidence.request_method = "MCP"
                finding.evidence.request_url = "github-mcp-server"
                finding.evidence.request_body = query
                finding.evidence.response_body = str(result)[:500]
                
                findings_generated.append(finding.to_dict())
                
            return {
                "status": "success",
                "findings": findings_generated,
                "raw_result_preview": str(result)[:200]
            }
            
        except Exception as e:
            err_msg = str(e)
            if "Authentication Failed" in err_msg or "Bad credentials" in err_msg:
                logger.warning("[GitHubRecon] GitHub authentication failed. skipping: %s", err_msg)
                return {"status": "skipped", "reason": f"GitHub auth failed: {err_msg}"}
            logger.error("[GitHubRecon] Error during GitHub search: %s", e)
            return {"status": "error", "error": str(e)}
