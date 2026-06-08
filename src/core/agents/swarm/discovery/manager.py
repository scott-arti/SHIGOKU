"""
DiscoveryManagerAgent: Strategy manager for Reconnaissance & Discovery

This agent orchestrates workers (VisualRecon, GraphQLNavigator, etc.) to perform deep discovery.
"""

import logging
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.base import Task
from src.core.engine.agent_registry import AgentRegistry
from src.core.agents.swarm.discovery.graphql import CONTRACT_VERSION

logger = logging.getLogger(__name__)


@dataclass
class GraphQLNavigatorContractAdapter:
    contract_version: str = CONTRACT_VERSION
    introspection_enabled: bool = False
    graphiql_enabled: bool = False
    field_suggestions_enabled: bool = False
    error_code: Optional[str] = None
    internal_error_detail: str = ""
    internal_error_category: str = ""
    error_policy_version: str = "1"
    evidence: Optional[List[str]] = None
    latency_ms: Optional[int] = None
    schema_snippet: str = ""
    logs: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "introspection_enabled": self.introspection_enabled,
            "graphiql_enabled": self.graphiql_enabled,
            "field_suggestions_enabled": self.field_suggestions_enabled,
            "error_code": self.error_code,
            "internal_error_detail": self.internal_error_detail,
            "internal_error_category": self.internal_error_category,
            "error_policy_version": self.error_policy_version,
            "evidence": self.evidence or [],
            "latency_ms": self.latency_ms,
            "schema_snippet": self.schema_snippet,
            "logs": self.logs or [],
        }

    @classmethod
    def normalize(cls, raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        payload = raw or {}
        adapter = cls(
            contract_version=str(payload.get("contract_version") or "1.0.0"),
            introspection_enabled=bool(payload.get("introspection_enabled", False)),
            graphiql_enabled=bool(payload.get("graphiql_enabled", False)),
            field_suggestions_enabled=bool(payload.get("field_suggestions_enabled", False)),
            error_code=payload.get("error_code"),
            internal_error_detail=str(payload.get("internal_error_detail", "") or ""),
            internal_error_category=str(payload.get("internal_error_category", "") or ""),
            error_policy_version=str(payload.get("error_policy_version", "1") or "1"),
            evidence=list(payload.get("evidence", []) or []),
            latency_ms=payload.get("latency_ms"),
            schema_snippet=str(payload.get("schema_snippet", "") or ""),
            logs=list(payload.get("logs", []) or []),
        )
        return adapter.to_dict()

@AgentRegistry.register(
    names=["DiscoveryManager", "DiscoveryManagerAgent", "discovery_manager", "DiscoverySwarm"],
    tags=["recon", "discovery", "visual", "api_discovery"]
)
class DiscoveryManagerAgent(BaseManagerAgent):
    """
    偵察・発見フェーズを統括するマネージャー
    
    役割:
    1. アタックサーフェスの洗い出し (Visual Recon, API Discovery)
    2. 特殊なエンドポイント (GraphQL, Swagger) の特定と深堀り
    """
    
    name: str = "DiscoveryManager"
    description: str = "Expert in Reconnaissance, API Discovery, and Visual Inspection."
    system_prompt_template: str = "agents/discovery_manager.md"
    
    def __init__(self, config: Optional[Union[Dict[str, Any], 'AgentConfig']] = None, project_manager: Any = None, master_conductor: Any = None, workspace_root: Optional[str] = None, project_id: Optional[str] = None, session_id: Optional[str] = None):
        super().__init__(
            config=config,
            project_manager=project_manager,
            master_conductor=master_conductor,
            workspace_root=workspace_root,
            project_id=project_id,
            session_id=session_id,
        )
        self._register_initial_tools()
        
    def _worker_config(self) -> Dict[str, Any]:
        """Worker に渡す config dict。project_id を current_context から注入する。"""
        if isinstance(self.config, dict):
            base: Dict[str, Any] = dict(self.config)
        elif hasattr(self.config, "model_dump"):
            base = self.config.model_dump()
        elif hasattr(self.config, "__dict__"):
            base = {k: v for k, v in vars(self.config).items() if not k.startswith("_")}
        else:
            base = {}
        project_id = self.current_context.get("project_id")
        if project_id:
            base["project_id"] = project_id
        session_id = self.current_context.get("session_id")
        if session_id:
            base["session_id"] = session_id
        return base

    def _register_initial_tools(self):
        """初期ツール/Worker登録"""
        
        # Worker: VisualRecon (スクリーンショット & DOM分析)
        self.register_tool(
            "run_visual_recon",
            self.run_visual_recon,
            "Run visual reconnaissance to identify UI elements and interesting areas. Args: url (str)"
        )
        
        # Woker: GraphQLNavigator (GraphQL Introspection & Querying)
        self.register_tool(
            "run_graphql_navigator",
            self.run_graphql_navigator,
            "Explore GraphQL endpoints. Args: url (str)"
        )

        # Tool: APISpecReconstructor (JS解析によるAPIパス抽出)
        self.register_tool(
            "reconstruct_api_spec",
            self.reconstruct_api_spec,
            "Analyze JS files to reconstruct API specification. Args: url (str)"
        )

        # Worker: PlaywrightCrawler (動的通信傍受 & フォーム抽出)
        self.register_tool(
            "run_playwright_recon",
            self.run_playwright_recon,
            "Run dynamic reconnaissance with Playwright to intercept XHR/Fetch and extract forms. Args: url (str)"
        )
        
        # Worker: GitHubRecon (MCP経由でのGitHub Dorks情報漏洩調査)
        self.register_tool(
            "run_github_dorks",
            self.run_github_dorks,
            "Run GitHub Dorks search via MCP to find potential leaked secrets. Args: url (str)"
        )

        # Worker: TakeoverSpecialist
        self.register_tool(
            "run_takeover_scan",
            self.run_takeover_scan,
            "Check for subdomain takeover vulnerabilities. Args: url (str)"
        )

    async def run_github_dorks(self, url: str, **kwargs) -> Dict[str, Any]:
        """GitHubRecon (Worker) を実行"""
        logger.info(f"[{self.name}] Delegating to GitHubRecon")
        try:
            from src.core.agents.swarm.discovery.github_recon import GitHubRecon
            worker = GitHubRecon(self.config)
            result = await worker.run_as_tool(url)
            self.history.append({"role": "user", "content": f"Tool run_github_dorks result: {result}"})
            return result
        except ImportError:
            return {"error": "GitHubRecon not found"}
        except Exception as e:
            return {"error": str(e)}

    async def run_visual_recon(self, url: str, **kwargs) -> Dict[str, Any]:
        """VisualRecon (Worker) を実行"""
        logger.info(f"[{self.name}] Delegating to VisualRecon")
        try:
            from src.core.agents.swarm.discovery.visual_recon import VisualRecon
            worker = VisualRecon(self._worker_config())
            
            # マネージャーのコンテキストから認証情報を引き継ぐ
            auth_headers = self.current_context.get("auth_headers", {})

            if auth_headers:
                result = await worker.run_as_tool(url, auth_headers=auth_headers)
            else:
                result = await worker.run_as_tool(url)
            self.history.append({"role": "user", "content": f"Tool run_visual_recon result: {result}"})
            return result
        except ImportError:
            return {"error": "VisualRecon not found"}
        except Exception as e:
            return {"error": str(e)}

    async def run_graphql_navigator(self, url: str, **kwargs) -> Dict[str, Any]:
        """GraphQLNavigator (Worker) を実行"""
        logger.info(f"[{self.name}] Delegating to GraphQLNavigator")
        try:
            from src.core.agents.swarm.discovery.graphql import GraphQLNavigator
            worker = GraphQLNavigator(self._worker_config())
            raw_result = await worker.run_as_tool(url)
            result = GraphQLNavigatorContractAdapter.normalize(raw_result)
            self.history.append({"role": "user", "content": f"Tool run_graphql_navigator result: {result}"})
            return result
        except ImportError:
            return GraphQLNavigatorContractAdapter.normalize(
                {"error_code": "invalid_response", "internal_error_detail": "GraphQLNavigator not found"}
            )
        except Exception as e:
            return GraphQLNavigatorContractAdapter.normalize(
                {"error_code": "invalid_response", "internal_error_detail": str(e)}
            )

    async def reconstruct_api_spec(self, url: str, **kwargs) -> Dict[str, Any]:
        """APISpecReconstructor を実行 (Katana 利用) - 軽量モード"""
        logger.info(f"[{self.name}] Running API Spec Reconstruction on {url} (light mode)")

        try:
            from src.tools.custom.katana import KatanaTool
            katana = KatanaTool()

            auth_headers = self.current_context.get("auth_headers", {})
            cookies = auth_headers.get("Cookie", "") if auth_headers else ""

            # 軽量モードで実行（fast モード）
            raw_output = katana.run(target=url, mode="fast", cookies=cookies)

            endpoints = []
            if raw_output:
                for line in raw_output.strip().split("\n"):
                    try:
                        entry = json.loads(line)
                        if "request" in entry and "endpoint" in entry["request"]:
                            endpoints.append(entry["request"]["endpoint"])
                        elif "url" in entry:
                            endpoints.append(entry["url"])
                    except:
                        continue

            endpoints = list(set(endpoints))

            return {
                "status": "completed",
                "endpoints": endpoints[:50],
                "count": len(endpoints)
            }
        except Exception as e:
            logger.error(f"API Spec Reconstruction failed: {e}")
            return {"error": str(e), "endpoints": []}


    async def run_playwright_recon(self, url: str, **kwargs) -> Dict[str, Any]:
        """PlaywrightCrawler を実行"""
        logger.info(f"[{self.name}] Running Playwright Recon on {url}")
        try:
            from src.tools.custom.playwright_recon import PlaywrightCrawler
            
            # proxy設定の取得 (Dict or AgentConfig)
            proxy = None
            if self.config:
                if hasattr(self.config, "get"):
                    proxy = self.config.get("proxy")
                else:
                    proxy = getattr(self.config, "proxy", None)
            
            # proxy がオブジェクトの場合（万が一の JSON シリアライズエラー防止）
            if proxy and not isinstance(proxy, str):
                proxy = str(proxy)
                
            crawler = PlaywrightCrawler(proxy=proxy)
            
            # 認証情報の引き継ぎとCookieの分離
            auth_headers = self.current_context.get("auth_headers", {}).copy() if self.current_context else {}
            cookies_str = auth_headers.pop("Cookie", "")
            
            result = await crawler.crawl(url, auth_headers=auth_headers, cookies_str=cookies_str)
            
            # 結果を簡略化して履歴に追加（コンテキスト節約）
            # PlaywrightCrawler の戻り値キー: urls, endpoints, js_files
            summary = {
                "status": "completed",
                "urls_found": len(result.get("urls", [])),
                "endpoints_found": len(result.get("endpoints", [])),
                "js_files_found": len(result.get("js_files", []))
            }
            if hasattr(self, "history"):
                self.history.append({"role": "user", "content": f"Tool run_playwright_recon result: {json.dumps(summary)}"})
            return result
        except Exception as e:
            logger.error(f"Playwright Recon failed: {e}")
            return {"error": str(e)}

    async def run_takeover_scan(self, url: str, **kwargs) -> Dict[str, Any]:
        """TakeoverSpecialist を実行"""
        logger.info(f"[{self.name}] Delegating to TakeoverSpecialist")
        try:
            from src.core.agents.swarm.discovery.takeover import TakeoverSpecialist
            worker = TakeoverSpecialist(self.config)
            # Specialist.run_as_tool は基底クラスで実装されていることを期待
            # (あるいは直接 execute を呼んでラップ)
            findings = await worker.execute(Task(id="takeover", name="Subdomain Takeover", target=url))
            self.history.append({"role": "user", "content": f"Tool run_takeover_scan result: found {len(findings)} issues"})
            return {"success": True, "findings": [f.to_dict() for f in findings]}
        except Exception as e:
            return {"error": str(e)}
