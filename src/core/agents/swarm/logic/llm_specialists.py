
import logging
import json
import asyncio
from typing import List, Dict, Any, Optional

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity
from src.core.models.llm import LLMClient
from src.core.agents.swarm.biz_logic_hunter import BizLogicHunter

logger = logging.getLogger(__name__)

class LLMBizLogicHunter(Specialist):
    """
    LLM 拡張型ビジネスロジックハンター

    アプリケーション構造、パラメータ名、初期レスポンスに基づき、
    LLM を活用して潜在的なビジネスロジックの欠陥（IDOR、権限昇格など）を推論します。
    """
    name = "LLMBizLogicHunter"
    description = "ビジネスロジックとアクセス制御の欠陥に関する LLM 主導の分析"
    timeout_seconds = 300
    is_aggressive = True

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        from src.config import settings
        default_model = getattr(settings, "model_output", None) or getattr(settings, "model", "deepseek/deepseek-chat")
        model = config.get("model", default_model) if isinstance(config, dict) else getattr(config, "model", default_model)
        self.llm = LLMClient(model=model)

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        findings = []
        target = task.target
        logger.info("[%s] Analyzing business logic for %s", self.name, target)

        # 1. コンテキストの収集（擬似実行または受動的分析）
        # 現時点では、BizLogicHunter の verify_idor ロジックが候補を生成するか、
        # あるいは URL 構造に基づいて LLM に攻撃ベクトルを生成させると仮定します。
        
        # 例: URL/パラメータに基づいたロジック欠陥の直接的な LLM プロンプト
        prompt = f"""
        Analyze the following target URL and parameters for potential Business Logic Vulnerabilities (IDOR, Privilege Escalation).
        
        Target: {target}
        Params: {task.params}
        
        Suggest 3 specific test cases to verify IDOR or Privilege Escalation.
        Output JSON format:
        {{
            "tests": [
                {{"type": "idor", "param": "user_id", "payload": "1", "reason": "Change user_id to 1 (admin)"}},
                {{"type": "priv_esc", "param": "role", "payload": "admin", "reason": "Mass assignment of role"}}
            ]
        }}
        """

        try:
            response = await self.llm.agenerate(prompt)
            # Markdown のコードブロックが含まれている場合は削除
            # 文字列またはオブジェクトのレスポンスに対応
            if hasattr(response, "choices"):
                response_text = response.choices[0].message.content
            else:
                response_text = str(response)

            response_text = response_text.replace("```json", "").replace("```", "").strip()
            data = json.loads(response_text)
            
            # 2. 提案されたテストの実行
            # この MVP では、信頼度が高い場合に LLM の「仮説」を Finding として報告します。
            # または、実際に実行することも可能です。ここでは簡略化されたリクエスタを使用するか、Finding を作成して実行します。
            
            for test in data.get("tests", []):
                # 実際のシナリオでは、httpx を使用してこれらを検証します。
                # 現時点では、人間または堅牢なエージェントによって検証されるべき「潜在的」な Finding として登録します。
                f = Finding(
                    vuln_type=VulnType.IDOR if test['type'] == 'idor' else VulnType.BROKEN_ACCESS_CONTROL,
                    severity=Severity.MEDIUM, # 検証されるまでは「潜在的」
                    title=f"Potential {test['type'].upper()}: {test['reason']}",
                    description=f"LLM suggested testing param '{test.get('param')}' with payload '{test.get('payload')}'.\nReason: {test['reason']}",
                    target_url=target,
                    source_agent=self.name,
                    confidence=0.6, # 要検証
                    tags=["llm_generated", "logic_candidate"]
                )
                findings.append(f)
                
        except Exception as e:
            logger.error("[%s] Error in LLM analysis: %s", self.name, e)

        return findings


class LLMCORSTester(Specialist):
    """
    LLM 拡張型 CORS テスター
    """
    name = "LLMCORSTester"
    description = "複雑な CORS 設定ミスの LLM ベースの診断"
    timeout_seconds = 180
    is_aggressive = False

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        findings = []
        # CORS 実装のプレースホルダー
        return findings
