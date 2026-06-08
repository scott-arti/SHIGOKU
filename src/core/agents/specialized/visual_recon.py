"""
VisualReconAgent: GPU-Accelerated Screenshot Analysis

LLaVA/BakLLaVAをOllama経由で使用し、スクリーンショットを自動解析する。
GPT-4 Visionと異なり、ローカルGPUで無制限・無料で実行可能。
"""

import logging
import base64
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from src.core.engine.agent_registry import register_agent

logger = logging.getLogger(__name__)


@dataclass
class VisualAnalysisResult:
    """画像解析結果"""
    is_admin_panel: bool = False
    has_error_message: bool = False
    is_default_page: bool = False
    has_sensitive_info: bool = False
    description: str = ""
    confidence: float = 0.0


@register_agent(
    names=["visualrecon", "visual_recon", "screenshot_analyzer"],
    tags=["recon", "visual", "gpu"]
)
class VisualReconAgent:
    """
    視覚偵察エージェント (GPU Accelerated)
    
    機能:
    - スクリーンショットから管理者パネルを検出
    - エラーメッセージの識別
    - デフォルト インストールページの検出
    - 機密情報の露出チェック
    """
    
    def __init__(self, model: str = "llava:7b", workspace_root: Optional[str] = None):
        """
        Args:
            model: 使用するLLaVAモデル (llava:7b, bakllava など)
            workspace_root: ワークスペースルート（結果保存用）
        """
        self.model = model
        self.workspace_root = workspace_root
        self._check_ollama_availability()
    
    def _check_ollama_availability(self) -> bool:
        """Ollamaの利用可能性をチェック"""
        try:
            from src.core.gpu_accelerator import GPUAccelerator
            gpu = GPUAccelerator()
            if not gpu.is_ollama_available():
                logger.warning("Ollama is not available. VisualReconAgent will fail.")
                return False
            
            # LLaVAモデルの存在確認
            models = gpu.list_ollama_models()
            if not any("llava" in m.lower() or "bakllava" in m.lower() for m in models):
                logger.warning("LLaVA/BakLLaVA model not found. Pulling %s...", self.model)
                success = gpu.pull_ollama_model(self.model)
                if not success:
                    logger.error("Failed to pull LLaVA model")
                    return False
            
            return True
        except Exception as e:
            logger.error("Failed to check Ollama availability: %s", e)
            return False
    
    def _encode_image(self, image_path: str) -> str:
        """画像をBase64エンコード"""
        with open(image_path, "rb") as img_file:
            return base64.b64encode(img_file.read()).decode('utf-8')
    
    async def _query_llava(self, image_base64: str, prompt: str) -> str:
        """
        LLaVAモデルにクエリを送信
        
        Args:
            image_base64: Base64エンコードされた画像
            prompt: 質問プロンプト
        
        Returns:
            LLaVAの応答テキスト
        """
        try:
            from src.core.infra.network_client import AsyncNetworkClient
            import os
            
            ollama_base = os.getenv("OLLAMA_API_BASE", "http://localhost:11434")
            url = f"{ollama_base}/api/generate"
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "images": [image_base64],
                "stream": False
            }
            
            # Use AsyncNetworkClient (no proxy for local)
            async with AsyncNetworkClient() as client:
                response = await client.request(
                    "POST", 
                    url, 
                    json=payload, 
                    timeout=30,
                    use_proxy=False  # Localhost interaction
                )

            if response.status_code != 200:
                logger.error("LLaVA API error: %s", response.text)
                return f"Error: {response.status_code}"
            
            result = response.json()
            return result.get("response", "")
        
        except Exception as e:
            logger.error("LLaVA query failed: %s", e)
            return f"Error: {e}"
    
    async def analyze_screenshot(self, image_path: str) -> VisualAnalysisResult:
        """
        スクリーンショットを解析
        
        Args:
            image_path: 画像ファイルのパス
        
        Returns:
            VisualAnalysisResult
        """
        if not Path(image_path).exists():
            logger.error("Image not found: %s", image_path)
            return VisualAnalysisResult(description="Image file not found")
        
        logger.info("Analyzing screenshot: %s", image_path)
        
        # 画像をBase64エンコード
        image_b64 = self._encode_image(image_path)
        
        # 複数の質問を投げる
        questions = {
            "admin_panel": "Is this an admin panel or administrative interface? Answer with YES or NO, then explain briefly.",
            "error_message": "Does this page contain any error messages or stack traces? Answer with YES or NO, then explain.",
            "default_page": "Is this a default installation or welcome page (e.g., Apache, nginx, WordPress default)? Answer with YES or NO.",
            "sensitive_info": "Are there any sensitive information visible such as API keys, passwords, internal paths, or database credentials? Answer with YES or NO, then list them.",
            "general": "Describe this web page in 2-3 sentences. What is its main purpose?"
        }
        
        results = {}
        for key, question in questions.items():
            answer = await self._query_llava(image_b64, question)
            results[key] = answer
            logger.debug("Q: %s | A: %s", question, answer[:100])
        
        # 結果を解析
        analysis = VisualAnalysisResult()
        
        # 簡易的なYES/NO判定
        analysis.is_admin_panel = "yes" in results.get("admin_panel", "").lower()[:10]
        analysis.has_error_message = "yes" in results.get("error_message", "").lower()[:10]
        analysis.is_default_page = "yes" in results.get("default_page", "").lower()[:10]
        analysis.has_sensitive_info = "yes" in results.get("sensitive_info", "").lower()[:10]
        
        # 全体的な説明
        analysis.description = results.get("general", "No description available")
        
        # Confidence計算（応答の長さと明確さに基づく）
        total_chars = sum(len(v) for v in results.values())
        analysis.confidence = min(0.9, total_chars / 500.0)  # 500文字以上で高信頼
        
        logger.info("Visual analysis complete | Admin: %s | Errors: %s | Default: %s | Sensitive: %s",
                    analysis.is_admin_panel, analysis.has_error_message, 
                    analysis.is_default_page, analysis.has_sensitive_info)
        
        return analysis
    
    async def execute(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        エージェントのメイン実行関数（MasterConductor互換）
        
        Args:
            target: 対象URL（参考用）
            params: パラメータ辞書 (screenshot_path必須)
        
        Returns:
            実行結果
        """
        screenshot_path = params.get("screenshot_path")
        if not screenshot_path:
            return {
                "success": False,
                "error": "screenshot_path is required in params"
            }
        
        analysis = await self.analyze_screenshot(screenshot_path)
        
        # 発見事項をフラグ化
        findings = []
        if analysis.is_admin_panel:
            findings.append("Admin Panel Detected")
        if analysis.has_error_message:
            findings.append("Error Message/Stack Trace Visible")
        if analysis.has_sensitive_info:
            findings.append("Sensitive Information Exposure")
        
        return {
            "success": True,
            "findings": findings,
            "analysis": {
                "is_admin_panel": analysis.is_admin_panel,
                "has_error_message": analysis.has_error_message,
                "is_default_page": analysis.is_default_page,
                "has_sensitive_info": analysis.has_sensitive_info,
                "description": analysis.description,
                "confidence": analysis.confidence,
            },
            "target": target,
            "screenshot": screenshot_path,
        }

    @property
    def name(self) -> str:
        return "VisualRecon"
    
    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """AgentProtocol implementation"""
        from src.core.agents.protocol import create_run_result
        try:
            target = task.get("target", "")
            params = task.get("params", {})
            # execute is synchronous, run it directly (or in thread if heavy, but here straightforward)
            # execute returns dict with "success"
            result = await self.execute(target, params)
            return create_run_result(
                success=result.get("success", False),
                data=result,
                agent=self.name
            )
        except Exception as e:
            return create_run_result(
                success=False,
                error=str(e),
                agent=self.name
            )
