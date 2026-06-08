import logging
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base_manager import BaseManagerAgent
from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity
from src.core.engine.agent_registry import AgentRegistry

# Specialists are imported lazily inside _initialize_specialists or used as classes
from src.core.agents.swarm.logic.file_upload import FileUploadSpecialist

logger = logging.getLogger(__name__)


@AgentRegistry.register(
    names=["LogicManager", "LogicManagerAgent", "logic_manager", "LogicSwarm"],
    tags=["logic", "mass_assignment", "race_condition", "file_upload", "idor"]
)
class LogicManagerAgent(BaseManagerAgent):
    """
    ビジネスロジック脆弱性マネージャー (LLM駆動)
    
    役割:
    1. ターゲットの機能に応じたロジックテスト戦略の立案
    2. 適切な Specialist (MassAssignment, RaceCondition, FileUpload) の呼び出し
    3. 発見した脆弱性の集約と最終判断
    """
    
    name: str = "LogicManager"
    description: str = "Expert in Business Logic vulnerabilities like IDOR, Mass Assignment, and Race Conditions."
    system_prompt_template: str = "agents/logic_manager.md"
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self._initialize_specialists()
        self._register_initial_tools()
        
    def _initialize_specialists(self) -> None:
        """Specialist の初期化"""
        # Note: Circle imports are tricky, so we use the classes directly if possible 
        # or import inside methods. Since they are in the same package (mostly), 
        # we can use the ones defined/imported at top.
        from src.core.agents.swarm.logic.manager import MassAssignmentSpecialist, RaceConditionSpecialist
        from src.core.agents.swarm.logic.idor import IdorHunterSpecialist
        
        self.specialists = {
            "mass_assignment": MassAssignmentSpecialist(self.config),
            "race_condition": RaceConditionSpecialist(self.config),
            "file_upload": FileUploadSpecialist(self.config),
            "idor": IdorHunterSpecialist(self.config)
        }
        
    def _register_initial_tools(self) -> None:
        """LLMが使用するツールの登録"""
        self.register_tool(
            "fetch_page_content",
            self.fetch_page_content,
            "Fetch the HTML content of a page to analyze its structure (e.g., forms). Args: url (str)"
        )
        self.register_tool(
            "run_mass_assignment_check",
            self.run_mass_assignment_check,
            "Check for Mass Assignment (Parameter Pollution). Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_race_condition_check",
            self.run_race_condition_check,
            "Check for Race Condition vulnerabilities. Args: url (str), params (dict)"
        )
        self.register_tool(
            "run_file_upload_check",
            self.run_file_upload_check,
            "Test file upload functionality. Args: url (str), param_name (str), extra_params (dict)"
        )
        self.register_tool(
            "run_idor_check",
            self.run_idor_check,
            "Test for IDOR / Broken Object Level Authorization. Args: url (str), method (str), params (dict)"
        )

    # --- Tool Implementations (Delegating to Specialists) ---

    async def fetch_page_content(self, url: str) -> str:
        """指定されたURLのHTMLを取得する"""
        logger.info(f"[{self.name}] Fetching page content for analysis: {url}")
        from src.core.infra.network_client import AsyncNetworkClient
        from src.core.infra.proxy_manager import get_proxy_manager
        
        proxy_manager = None
        try:
            proxy_manager = get_proxy_manager()
        except:
            pass
            
        # タスクコンテキストから認証ヘッダーを取得
        auth_headers = self.current_context.get("auth_headers", {})
            
        async with AsyncNetworkClient(proxy_manager=proxy_manager) as client:
            try:
                resp = await client.request("GET", url, headers=auth_headers)
                return resp.text
            except Exception as e:
                return f"Error fetching page: {str(e)}"

    async def run_mass_assignment_check(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """MassAssignmentSpecialist を実行"""
        logger.info(f"[{self.name}] Delegating Mass Assignment check to specialist")
        target_task = Task(
            id=f"logic_ma_{id(url)}",
            name="Mass Assignment Check",
            target=url,
            params=params or {},
            tags=["mass_assignment"]
        )
        findings = await self.specialists["mass_assignment"].execute_with_retry(target_task)
        self.current_context["findings"].extend(findings)
        return {"findings_count": len(findings), "status": "completed"}

    async def run_race_condition_check(self, url: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """RaceConditionSpecialist を実行"""
        logger.info(f"[{self.name}] Delegating Race Condition check to specialist")
        target_task = Task(
            id=f"logic_rc_{id(url)}",
            name="Race Condition Check",
            target=url,
            params=params or {},
            tags=["race_condition"]
        )
        findings = await self.specialists["race_condition"].execute_with_retry(target_task)
        self.current_context["findings"].extend(findings)
        return {"findings_count": len(findings), "status": "completed"}

    async def run_file_upload_check(
        self, 
        url: str, 
        param_name: str = "uploaded", 
        extra_params: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """FileUploadSpecialist を実行"""
        logger.info(f"[{self.name}] Delegating File Upload check to specialist at {url}")
        target_task = Task(
            id=f"logic_fu_{id(url)}",
            name="File Upload Check",
            target=url,
            params={
                "param_name": param_name,
                "extra_params": extra_params or {},
                "headers": self.current_context.get("auth_headers", {})
            },
            tags=["file_upload"]
        )
        findings = await self.specialists["file_upload"].execute_with_retry(target_task)
        self.current_context["findings"].extend(findings)
        return {"findings_count": len(findings), "status": "completed"}

    async def run_idor_check(
        self, 
        url: str, 
        method: str = "GET", 
        params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """IdorHunterSpecialist を実行"""
        logger.info(f"[{self.name}] Delegating IDOR check to specialist at {url}")
        
        # 認証コンテキストをマージ
        task_params = params or {}
        if "headers" not in task_params:
            task_params["headers"] = self.current_context.get("auth_headers", {})
            
        target_task = Task(
            id=f"logic_idor_{id(url)}",
            name="IDOR Check",
            target=url,
            params=task_params,
            tags=["idor"]
        )
        findings = await self.specialists["idor"].execute_with_retry(target_task)
        self.current_context["findings"].extend(findings)
        return {"findings_count": len(findings), "status": "completed"}

    async def close(self) -> None:
        """リソース解放"""
        for s in self.specialists.values():
            await s.close()
        await super().close()

# =====================================================
# Specialists (Keeping original classes for backwards capability and worker usage)
# =====================================================

class MassAssignmentSpecialist(Specialist):
    """Mass Assignment Specialist"""
    name = "MassAssignmentSpecialist"
    description = "Detects Mass Assignment vulnerabilities via API param injection"
    timeout_seconds = 180
    is_aggressive = True

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        from src.core.attack.mass_assignment_tester import MassAssignmentTester
        self._tester = MassAssignmentTester()

    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        original_params = task.params.get("api_params") or task.params.get("params") or {}
        
        if not original_params:
            return []
            
        results = await self._tester.test(
            url=task.target,
            method=task.params.get("method", "POST"),
            original_params=original_params,
            auth_token=task.params.get("jwt_token")
        )
        
        for r in results:
            if r.success:
                findings.append(Finding(
                    vuln_type=VulnType.MASS_ASSIGNMENT,
                    severity=Severity.HIGH,
                    title=f"Mass Assignment: {r.description}",
                    description=f"Successfully modified protected field: {r.injected_field}",
                    evidence={"payload": r.payload, "response": r.response_diff},
                    target_url=task.target
                ))
        return findings


class RaceConditionSpecialist(Specialist):
    """Race Condition Specialist"""
    name = "RaceConditionSpecialist"
    description = "Detects Race Conditions in critical business flows"
    timeout_seconds = 300
    is_aggressive = True
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        from src.core.attack.race_condition_tester import RaceConditionTester
        from src.core.infra.network_client import AsyncNetworkClient
        
        proxy_manager = None
        try:
            from src.core.infra.proxy_manager import get_proxy_manager
            proxy_manager = get_proxy_manager()
        except Exception:
            pass

        self._client = AsyncNetworkClient(proxy_manager=proxy_manager)
        self._tester = RaceConditionTester(client=self._client) 

    async def execute(self, task: Task) -> List[Finding]:
        findings = []
        is_critical = "race_condition" in task.tags or "coupon" in task.target or "transfer" in task.target
        
        if not is_critical and not self.is_aggressive:
            return []

        # test_race の正しいシグネチャに合わせて呼び出し
        results = await self._tester.test_race(
            method=task.params.get("method", "POST"),
            url=task.target,
            json=task.params.get("params", {}), # 通常ロジックテストはJSON
            headers=task.params.get("headers", {})
        )
        
        # 結果の分析
        if self._tester.analyze_results(results):
            findings.append(Finding(
                vuln_type=VulnType.RACE_CONDITION,
                severity=Severity.HIGH,
                title="Potential Race Condition Found",
                description="The endpoint showed inconsistent behavior under concurrent requests.",
                target_url=task.target,
                source_agent=self.name
            ))
        return findings
