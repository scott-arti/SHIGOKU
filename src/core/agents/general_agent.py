"""
GeneralAgent: フォールバック探索エージェント

タグが `unknown` または Swarm にマッチしない場合に呼び出される。
LLM を使用して探索的に脆弱性を検査し、成功時は新規 Recipe を生成。

Implementation Plan Section 2.5 準拠
"""

import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ExplorationResult:
    """探索結果"""
    success: bool = False
    novel_technique: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)
    suggested_recipe: Optional[Dict[str, Any]] = None
    execution_log: List[str] = field(default_factory=list)


class GeneralAgent:
    """
    フォールバック探索エージェント
    
    MC が最適な Swarm を見つけられない場合に呼び出される。
    LLM を使用して探索的に調査を行う。
    
    フロー:
    1. 状況分析 (LLM)
    2. 検査方法推論 (LLM)
    3. Recipe 検索
    4. 実行
    5. 結果評価
    6. 学習 (新規 Recipe 保存)
    """
    
    def __init__(
        self,
        llm_client=None,
        recipe_loader=None,
        rag=None,
        config: Optional[Dict[str, Any]] = None,
    ):
        self.llm_client = llm_client
        self.recipe_loader = recipe_loader
        self.rag = rag
        self.config = config or {}
    
    def set_llm_client(self, llm_client) -> None:
        """LLM クライアントを設定"""
        self.llm_client = llm_client
    
    def set_recipe_loader(self, recipe_loader) -> None:
        """RecipeLoader を設定"""
        self.recipe_loader = recipe_loader
    
    def set_rag(self, rag) -> None:
        """RAG を設定"""
        self.rag = rag
    
    async def explore(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> ExplorationResult:
        """
        探索的脆弱性検査を実行
        
        Args:
            target: ターゲット URL
            context: コンテキスト情報 (tech_stack, response, etc.)
        
        Returns:
            ExplorationResult
        """
        result = ExplorationResult()
        result.execution_log.append(f"Starting exploration for: {target}")
        
        try:
            # 1. 状況分析
            analysis = await self._analyze_situation(target, context)
            result.execution_log.append(f"Situation analysis: {analysis.get('summary', 'N/A')}")
            
            # 2. 検査方法推論
            suggestions = await self._suggest_techniques(target, analysis)
            result.execution_log.append(f"Suggested techniques: {len(suggestions)}")
            
            # 3. Recipe 検索
            for suggestion in suggestions:
                matched_recipe = self._search_recipe(suggestion)
                
                if matched_recipe:
                    # 既存 Recipe 実行
                    result.execution_log.append(f"Found matching recipe: {matched_recipe.get('name')}")
                    # TODO: Recipe 実行ロジック
                else:
                    # Novel technique - LLM に Recipe 生成を依頼
                    result.novel_technique = True
                    result.execution_log.append(f"Novel technique detected: {suggestion}")
                    
                    # 新規 Recipe 生成
                    new_recipe = await self._generate_recipe(suggestion, target)
                    if new_recipe:
                        result.suggested_recipe = new_recipe
            
            result.success = len(result.findings) > 0 or result.novel_technique
            
        except Exception as e:
            logger.error("GeneralAgent exploration error: %s", e)
            result.execution_log.append(f"Error: {e}")
        
        return result
    
    async def _analyze_situation(
        self,
        target: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """LLM で状況を分析"""
        if not self.llm_client:
            return {"summary": "LLM not available", "suggestions": []}
        
        tech_stack = context.get("tech_stack", [])
        response_sample = context.get("response_sample", "")[:500]
        
        prompt = f"""Analyze this target for potential vulnerabilities:

Target: {target}
Tech Stack: {', '.join(tech_stack) if tech_stack else 'Unknown'}
Response Sample: {response_sample[:200]}

Output JSON with:
- summary: Brief analysis
- attack_surface: List of potential attack vectors
- priority_areas: Top 3 areas to investigate
"""
        
        try:
            from src.core.models.llm import LLMClient
            llm_client = LLMClient(role="specialist_light")
            response = llm_client.generate(
                messages=[
                    {"role": "user", "content": prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.3,
            )
            import json
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error("LLM analysis failed: %s", e)
            return {"summary": "Analysis failed", "suggestions": []}
    
    async def _suggest_techniques(
        self,
        target: str,
        analysis: Dict[str, Any],
    ) -> List[str]:
        """検査手法を提案"""
        priority_areas = analysis.get("priority_areas", [])
        attack_surface = analysis.get("attack_surface", [])
        
        # 基本的な推論
        techniques = []
        
        for area in priority_areas:
            area_lower = area.lower()
            if "api" in area_lower or "graphql" in area_lower:
                techniques.append("graphql_introspection")
            if "auth" in area_lower:
                techniques.append("auth_bypass")
            if "file" in area_lower:
                techniques.append("file_inclusion")
            if "injection" in area_lower:
                techniques.append("sql_injection")
        
        return techniques or ["general_scan"]
    
    def _search_recipe(self, technique: str) -> Optional[Dict[str, Any]]:
        """既存 Recipe を検索"""
        if not self.recipe_loader:
            return None
        
        # Recipe 検索ロジック
        # TODO: recipe_loader.find_by_technique() のような API
        return None
    
    async def _generate_recipe(
        self,
        technique: str,
        target: str,
    ) -> Optional[Dict[str, Any]]:
        """新規 Recipe を生成"""
        if not self.llm_client:
            return None
        
        prompt = f"""Generate a security testing recipe for:
Technique: {technique}
Target: {target}

Output YAML format recipe with:
- name: Recipe name
- description: What it does
- steps: List of steps with tool and action
"""
        
        try:
            from src.core.models.llm import LLMClient
            llm_client = LLMClient(role="recipe_generator")
            response = llm_client.generate(
                messages=[
                    {"role": "user", "content": prompt},
                ],
                temperature=0.3,
            )
            
            # YAML パース
            import yaml
            content = response.choices[0].message.content
            # コードブロック除去
            if "```yaml" in content:
                content = content.split("```yaml")[1].split("```")[0]
            elif "```" in content:
                content = content.split("```")[1].split("```")[0]
            
            recipe = yaml.safe_load(content)
            logger.info("Generated new recipe: %s", recipe.get("name", "Unknown"))
            return recipe
            
        except Exception as e:
            logger.error("Recipe generation failed: %s", e)
            return None
    
    def generate_recipe(self, result: ExplorationResult) -> Optional[Dict[str, Any]]:
        """探索結果から Recipe を生成（同期版）"""
        return result.suggested_recipe


# シングルトン
_general_agent: Optional[GeneralAgent] = None


def get_general_agent(
    llm_client=None,
    recipe_loader=None,
    rag=None,
) -> GeneralAgent:
    """GeneralAgent シングルトンを取得"""
    global _general_agent
    if _general_agent is None:
        _general_agent = GeneralAgent(llm_client, recipe_loader, rag)
    return _general_agent
