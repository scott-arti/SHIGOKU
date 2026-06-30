"""
GPU Accelerator - GPU検出・活用ヘルパー

RTX 3060等のローカルGPUを活用した処理高速化。

対応機能:
- RAG Embedding (sentence-transformers)
- パスワードクラック (hashcat連携)
"""

import subprocess
from dataclasses import dataclass
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class GPUInfo:
    """GPU情報"""
    name: str
    memory_total_mb: int
    memory_free_mb: int
    cuda_available: bool
    driver_version: str = ""


class GPUAccelerator:
    """
    GPU活用ヘルパー
    
    RTX 3060 (12GB) 向け最適化:
    - Embedding: all-MiniLM-L6-v2 (GPU)
    """
    
    # 推奨モデル (12GB GPU向け)
    RECOMMENDED_MODELS = {
        "general": "qwen3:8b",
        "coder": "qwen2.5-coder:7b",
        "embedding": "all-MiniLM-L6-v2",
    }
    
    def __init__(self, auto_detect: bool = True):
        self._gpu_info: Optional[GPUInfo] = None
        self._gpu_enabled: bool = False  # GPU使用フラグ
        
        if auto_detect:
            gpu = self.detect_gpu()
            if gpu:
                self._gpu_enabled = True
                logger.info("GPU mode enabled: %s (%d MB VRAM)", gpu.name, gpu.memory_total_mb)
            else:
                logger.info("GPU not available, using CPU mode")
    
    def detect_gpu(self) -> Optional[GPUInfo]:
        """GPU検出"""
        if self._gpu_info:
            return self._gpu_info
        
        try:
            # nvidia-smi で検出
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,memory.total,memory.free,driver_version",
                 "--format=csv,noheader,nounits"],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                parts = result.stdout.strip().split(", ")
                if len(parts) >= 4:
                    self._gpu_info = GPUInfo(
                        name=parts[0],
                        memory_total_mb=int(parts[1]),
                        memory_free_mb=int(parts[2]),
                        cuda_available=True,
                        driver_version=parts[3]
                    )
                    logger.info("GPU detected: %s (%d MB)", 
                               self._gpu_info.name, self._gpu_info.memory_total_mb)
                    return self._gpu_info
        except Exception as e:
            logger.debug("GPU detection failed: %s", e)
        
        return None
    
    def is_gpu_available(self) -> bool:
        """GPU利用可能か（検出済みかつ有効化されている場合のみTrue）"""
        return self._gpu_enabled and self._gpu_info is not None
    
    def disable_gpu(self) -> None:
        """GPU使用を無効化（CPUモードに強制切替）"""
        self._gpu_enabled = False
        logger.info("GPU disabled, forcing CPU mode")
    
    def enable_gpu(self) -> bool:
        """GPU使用を有効化（GPUが検出されている場合のみ）"""
        if self._gpu_info:
            self._gpu_enabled = True
            logger.info("GPU enabled")
            return True
        logger.warning("Cannot enable GPU: no GPU detected")
        return False
    
    def query_llm(self, prompt: str, model: Optional[str] = None, max_tokens: int = 500) -> Optional[str]:
        """Query LLM using LLMClient (role-based resolution).
        
        Uses LLMClient with role="tool_output_analysis" for cloud-based LLM access.
        
        Args:
            prompt: The prompt text to send to the LLM.
            model: Ignored (LLMClient resolves model via role configuration).
            max_tokens: Ignored (LLMClient handles token limits internally).
            
        Returns:
            LLM response text, or None on failure.
        """
        try:
            from src.core.models.llm import LLMClient
            client = LLMClient(role="tool_output_analysis")
            messages = [{"role": "user", "content": prompt}]
            response = client.generate(messages)
            if hasattr(response, 'choices') and response.choices:
                return response.choices[0].message.content
            return None
        except Exception as e:
            logger.error("LLM query failed: %s", e)
            return None
    
    def get_embedding_device(self) -> str:
        """Embedding用デバイス取得"""
        if self.is_gpu_available():
            return "cuda"
        return "cpu"
    
    def get_recommended_workers(self) -> int:
        """推奨ワーカー数取得"""
        gpu = self.detect_gpu()
        if gpu:
            # VRAM 12GBなら4ワーカー程度
            if gpu.memory_total_mb >= 12000:
                return 4
            elif gpu.memory_total_mb >= 8000:
                return 2
        return 1
    
    def get_status(self) -> dict:
        """ステータス取得"""
        gpu = self.detect_gpu()
        return {
            "gpu_available": gpu is not None,
            "gpu_name": gpu.name if gpu else None,
            "gpu_memory_mb": gpu.memory_total_mb if gpu else 0,
            "gpu_enabled": self._gpu_enabled,
            "recommended_models": self.RECOMMENDED_MODELS,
        }


# シングルトン
_accelerator: Optional[GPUAccelerator] = None

def get_gpu_accelerator() -> GPUAccelerator:
    """GPUAcceleratorシングルトン取得"""
    global _accelerator
    if _accelerator is None:
        _accelerator = GPUAccelerator()
    return _accelerator
