"""
MicroAgent: LLMによるツール出力解析

LLMClient経由でツール出力を解析する。
Phase 3機能: config/features.yaml でオン/オフ可能
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Optional

from src.core.config.feature_config import get_feature_config

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """解析結果"""
    success: bool
    summary: str
    findings: list[dict]
    severity: str
    raw_response: str = ""


class MicroAgent:
    """
    LLMによるツール出力解析
    
    特徴:
    - LLMClient経由でrole=tool_output_analysisを使用
    - ツール固有の出力パターンを解析
    - 低コストでの脆弱性抽出
    """
    
    # ツール固有のプロンプトテンプレート
    ...
    ANALYSIS_PROMPTS = {
        "nuclei": """Analyze this Nuclei scan output and extract findings:

{output}

Return a JSON object with:
- "findings": list of {{"severity": "...", "name": "...", "url": "..."}}
- "summary": brief summary
- "severity": highest severity found (info/low/medium/high/critical)""",

        "httpx": """Analyze this httpx output and identify interesting endpoints:

{output}

Return a JSON object with:
- "endpoints": list of {{"url": "...", "status": ..., "tech": [...]}}
- "summary": brief summary
- "interesting": list of URLs that warrant further investigation""",

        "generic": """Analyze this security tool output:

{output}

Return a JSON object with:
- "findings": list of potential vulnerabilities or interesting items
- "summary": brief summary
- "severity": overall severity assessment""",
    }

    def __init__(self):
        self.config = get_feature_config().phase3.micro_agent
        self._llm_client = None

    def is_enabled(self) -> bool:
        """機能が有効かチェック"""
        return self.config.enabled

    def _get_llm_client(self):
        """LLMClientを取得（role=tool_output_analysis）"""
        if self._llm_client is None:
            from src.core.models.llm import LLMClient
            self._llm_client = LLMClient(role="tool_output_analysis")
        return self._llm_client

    def _call_llm(self, prompt: str) -> str:
        """LLMClient経由でツール出力解析を実行"""
        client = self._get_llm_client()
        try:
            messages = [{"role": "user", "content": prompt}]
            response = client.generate(messages)
            return response.get("choices", [{}])[0].get("message", {}).get("content", "")
        except Exception as e:
            logger.error("LLM analysis call failed: %s", e)
            raise

    def analyze(
        self, 
        tool_name: str, 
        output: str,
        custom_prompt: Optional[str] = None
    ) -> AnalysisResult:
        """
        ツール出力を解析
        
        Args:
            tool_name: ツール名
            output: ツール出力
            custom_prompt: カスタムプロンプト（オプション）
            
        Returns:
            解析結果
        """
        if not self.is_enabled():
            return AnalysisResult(
                success=False,
                summary="MicroAgent is disabled",
                findings=[],
                severity="info"
            )

        # 出力が空の場合
        if not output or not output.strip():
            return AnalysisResult(
                success=True,
                summary="No output to analyze",
                findings=[],
                severity="info"
            )

        # 出力が長すぎる場合はトランケート
        max_chars = 4000
        if len(output) > max_chars:
            output = output[:max_chars] + "\n... (truncated)"

        # プロンプト構築
        if custom_prompt:
            prompt = custom_prompt.format(output=output)
        else:
            template = self.ANALYSIS_PROMPTS.get(tool_name, self.ANALYSIS_PROMPTS["generic"])
            prompt = template.format(output=output)

        try:
            response = self._call_llm(prompt)
            return self._parse_response(response)
        except Exception as e:
            logger.error("MicroAgent analysis failed: %s", e)
            return AnalysisResult(
                success=False,
                summary=f"Analysis failed: {e}",
                findings=[],
                severity="info"
            )

    def _parse_response(self, response: str) -> AnalysisResult:
        """LLMレスポンスをパース"""
        import json
        
        # JSON部分を抽出
        json_match = re.search(r'\{[\s\S]*\}', response)
        
        if json_match:
            try:
                data = json.loads(json_match.group())
                return AnalysisResult(
                    success=True,
                    summary=data.get("summary", "Analysis complete"),
                    findings=data.get("findings", []),
                    severity=data.get("severity", "info"),
                    raw_response=response
                )
            except json.JSONDecodeError:
                pass
        
        # JSONパース失敗時はテキストとして処理
        return AnalysisResult(
            success=True,
            summary=response[:200] if response else "No summary",
            findings=[],
            severity="info",
            raw_response=response
        )

    def extract_vulnerabilities(self, output: str) -> list[dict]:
        """
        出力から脆弱性を抽出（簡易版）
        
        LLMを使わずに正規表現で抽出
        """
        vulns = []
        
        # Nucleiパターン
        nuclei_pattern = r'\[(\w+)\]\s*\[([^\]]+)\]\s*(.+)'
        for match in re.finditer(nuclei_pattern, output):
            vulns.append({
                "severity": match.group(1).lower(),
                "name": match.group(2),
                "target": match.group(3).strip(),
            })
        
        # 汎用的なエラーパターン
        error_patterns = [
            (r'SQL\s*(?:injection|error)', "sqli"),
            (r'XSS\s*(?:detected|vulnerability)', "xss"),
            (r'SSRF\s*(?:detected|vulnerability)', "ssrf"),
            (r'RCE\s*(?:detected|vulnerability)', "rce"),
        ]
        
        for pattern, vuln_type in error_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                vulns.append({
                    "severity": "high",
                    "type": vuln_type,
                    "detected": True,
                })
        
        return vulns


# シングルトンインスタンス
_agent_instance: Optional[MicroAgent] = None


def get_micro_agent() -> MicroAgent:
    """MicroAgentのシングルトンインスタンスを取得"""
    global _agent_instance
    if _agent_instance is None:
        _agent_instance = MicroAgent()
    return _agent_instance
