"""
Recon Pipeline 並行処理基盤のテスト
"""

import asyncio
import pytest
from unittest.mock import patch, AsyncMock

from src.recon.pipeline import ReconPipeline, ReconState


class TestReconState:
    """ReconState のテスト"""
    
    def test_init_default(self):
        """デフォルト値で初期化できる"""
        state = ReconState()
        assert state.current_step == 0
        assert state.completed_steps == []
        assert state.permutation_executed is False
    
    def test_mark_step_complete(self):
        """ステップを完了としてマークできる"""
        state = ReconState()
        state.mark_step_complete("step1")
        assert "step1" in state.completed_steps
        assert state.current_step == 1
    
    def test_is_step_complete(self):
        """ステップの完了状態を確認できる"""
        state = ReconState()
        assert state.is_step_complete("step1") is False
        state.mark_step_complete("step1")
        assert state.is_step_complete("step1") is True
    
    def test_save_and_load(self, tmp_path):
        """状態の保存と復元ができる"""
        state = ReconState(target="example.com")
        state.mark_step_complete("step1")
        state.live_subs = ["a.example.com", "b.example.com"]
        
        path = tmp_path / "state.json"
        state.save(path)
        
        loaded = ReconState.load(path)
        assert loaded.target == "example.com"
        assert loaded.current_step == 1
        assert "step1" in loaded.completed_steps
        assert loaded.live_subs == ["a.example.com", "b.example.com"]


class TestReconPipeline:
    """ReconPipeline のテスト"""
    
    def test_init(self):
        """初期化できる"""
        pipeline = ReconPipeline(
            target="*.example.com",
            project_manager=None,
            config={},
        )
        assert pipeline.target == "*.example.com"
        assert pipeline.state.target == "*.example.com"
    
    def test_semaphore_default(self):
        """デフォルトの Semaphore 値は 4"""
        pipeline = ReconPipeline(
            target="*.example.com",
            project_manager=None,
            config={},
        )
        assert pipeline.semaphore._value == 4
    
    def test_semaphore_custom(self):
        """Semaphore 値を設定できる"""
        pipeline = ReconPipeline(
            target="*.example.com",
            project_manager=None,
            config={"recon": {"max_concurrent_tasks": 2}},
        )
        assert pipeline.semaphore._value == 2
    
    @pytest.mark.asyncio
    async def test_run(self):
        """run() が ReconState を返す"""
        pipeline = ReconPipeline(
            target="*.example.com",
            project_manager=None,
            config={},
        )
        
        # Mock all steps to avoid actual execution and timeout
        with patch.object(pipeline, 'step1_subdomain_discovery', new=AsyncMock(return_value=["example.com"])), \
             patch.object(pipeline, 'step2_historical_discovery', new=AsyncMock(return_value=[])), \
             patch.object(pipeline, 'step3_live_check', new=AsyncMock(return_value=(["example.com"], []))), \
             patch.object(pipeline, 'step4_waf_detection', new=AsyncMock(return_value={})), \
             patch.object(pipeline, 'step5_port_scan_phase1', new=AsyncMock(return_value={})), \
             patch.object(pipeline, 'step5_port_scan_phase2', new=AsyncMock(return_value=None)), \
             patch.object(pipeline, 'step3b_hybrid_url_discovery', new=AsyncMock(return_value={})), \
             patch.object(pipeline, 'step6_classify', new=AsyncMock(return_value={})), \
             patch.object(pipeline, 'step7_save_to_project', new=AsyncMock(return_value=None)), \
             patch.object(pipeline, 'step8_return_to_mc', new=AsyncMock(return_value=[])):
             
            result = await pipeline.run()
            
        # 戻り値は ReconState
        assert isinstance(result, ReconState)
        assert result.target == "*.example.com"
