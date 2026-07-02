"""
ParallelTasks のテスト
"""

import asyncio
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch
import pytest

import pytest
import json
from src.recon.parallel_tasks import ParallelTasks
from src.recon.pipeline import ReconState


class TestParallelTasks:
    """ParallelTasks のテスト"""
    
    def test_init(self):
        """初期化できる"""
        tasks = ParallelTasks(
            config={},
            project_manager=None,
            master_conductor=None,
        )
        assert tasks.config == {}
        assert tasks.pm is None
        assert tasks.mc is None
    
    @pytest.mark.asyncio
    async def test_full_port_scan_no_subs(self, tmp_path):
        """ライブサブドメインがない場合はスキップ"""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        
        result = await tasks.full_port_scan([], tmp_path, state)
        assert result["status"] == "skipped"
        assert result["reason"] == "no_live_subs"
    
    @pytest.mark.asyncio
    async def test_full_port_scan_creates_input_file(self, tmp_path):
        """入力ファイルを作成する"""
        tasks = ParallelTasks(
            config={"recon": {"naabu_top_ports": "80,443"}},
            project_manager=None,
            master_conductor=None,
        )
        state = ReconState()
        
        live_subs = ["example.com", "test.example.com"]
        
        # naabu をモック化
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            # 出力ファイルを作成（naabu が作成する想定）
            # 命名規則に従ったファイル名にする
            output_file = tasks._get_path(tmp_path, state, "full_port_scan", "txt")
            output_file.write_text("example.com:8080\n")
            
            result = await tasks.full_port_scan(live_subs, tmp_path, state)
        
        # 入力ファイルが作成されているか確認 (glob)
        input_files = list(tmp_path.glob("*_recon_live_subdomains.txt"))
        assert len(input_files) == 1
        assert input_files[0].read_text() == "example.com\ntest.example.com"
    
    @pytest.mark.asyncio
    async def test_visual_recon_no_subs(self, tmp_path):
        """ライブサブドメインがない場合はスキップ"""
        tasks = ParallelTasks({}, None, None)
        
        result = await tasks.visual_recon([], tmp_path)
        assert result["status"] == "skipped"
        assert result["reason"] == "no_live_subs"
    
    @pytest.mark.asyncio
    async def test_visual_recon_creates_screenshots_dir(self, tmp_path):
        """スクリーンショットディレクトリを作成する"""
        tasks = ParallelTasks({}, None, None)
        live_subs = ["example.com"]
        
        # gowitness をモック化
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            result = await tasks.visual_recon(live_subs, tmp_path)
        
        # スクリーンショットディレクトリが作成されているか確認 (glob)
        screenshots_dirs = list(tmp_path.glob("*_recon_screenshots"))
        assert len(screenshots_dirs) == 1
        assert screenshots_dirs[0].is_dir()
    
    @pytest.mark.asyncio
    async def test_full_port_scan_timeout(self, tmp_path):
        """タイムアウト時は途中結果を処理"""
        tasks = ParallelTasks(
            config={"recon": {"naabu_top_ports": "80,443"}},
            project_manager=None,
            master_conductor=None,
        )
        state = ReconState()
        live_subs = ["example.com"]
        
        # タイムアウトをシミュレート
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            # communicate がタイムアウト
            mock_proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_proc.kill = AsyncMock()
            mock_proc.wait = AsyncMock()
            mock_exec.return_value = mock_proc
            
            # タイムアウトを短く設定（テスト用）
            with patch.object(asyncio, "wait_for", side_effect=asyncio.TimeoutError()):
                result = await tasks.full_port_scan(live_subs, tmp_path, state)
        
        # タイムアウト時は出力ファイルなしで no_results
        assert result["status"] == "no_results"
    
    @pytest.mark.asyncio
    async def test_permutation_scan_already_executed(self, tmp_path):
        """permutation_executed フラグがある場合はスキップ"""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        state.permutation_executed = True
        
        result = await tasks.permutation_scan(["example.com"], "example.com", tmp_path, state)
        assert result["status"] == "skipped"
        assert result["reason"] == "already_executed"
    
    @pytest.mark.asyncio
    async def test_permutation_scan_no_subs(self, tmp_path):
        """サブドメインがない場合はスキップ"""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        
        result = await tasks.permutation_scan([], "example.com", tmp_path, state)
        assert result["status"] == "skipped"
        assert result["reason"] == "no_subdomains"
    
    @pytest.mark.asyncio
    async def test_dead_subdomain_scan_no_dead(self, tmp_path):
        """Dead サブドメインがない場合はスキップ"""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        
        all_subs = ["a.example.com", "b.example.com"]
        live_subs = ["a.example.com", "b.example.com"]
        
        result = await tasks.dead_subdomain_scan(all_subs, live_subs, tmp_path, state)
        assert result["status"] == "skipped"
        assert result["reason"] == "no_dead_subs"
    
    @pytest.mark.asyncio
    async def test_dead_subdomain_scan_creates_file(self, tmp_path):
        """Dead サブドメイン入力ファイルを作成する"""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        
        all_subs = ["a.example.com", "b.example.com", "c.example.com"]
        live_subs = ["a.example.com"]
        
        # naabu をモック化
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            # 出力ファイルを作成
            output_file = tasks._get_path(tmp_path, state, "dead_subdomain_scan", "txt")
            output_file.write_text("b.example.com:8080\n")
            
            result = await tasks.dead_subdomain_scan(all_subs, live_subs, tmp_path, state)
        
        # Dead サブドメインファイルが作成されているか確認 (glob)
        dead_subs_files = list(tmp_path.glob("*_recon_dead_subdomains.txt"))
        assert len(dead_subs_files) == 1
        content = dead_subs_files[0].read_text().strip().split("\n")
        assert "b.example.com" in content or "c.example.com" in content
        assert len(content) == 2

    # ── Unit 3: Checkpoint hooks ──────────────────────────────────────

    @pytest.mark.asyncio
    async def test_full_port_scan_updates_checkpoint_on_skip(self, tmp_path):
        """No live subs records skipped in parallel_task_progress."""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        
        result = await tasks.full_port_scan([], tmp_path, state)
        assert result["status"] == "skipped"
        assert "full_port_scan" in state.parallel_task_progress
        assert state.parallel_task_progress["full_port_scan"]["status"] == "skipped"
        assert state.parallel_task_progress["full_port_scan"]["resume_reason"] == "no_live_subs"

    @pytest.mark.asyncio
    async def test_full_port_scan_updates_checkpoint_on_completed(self, tmp_path):
        """Completed full_port_scan records artifact_refs in progress."""
        tasks = ParallelTasks(
            config={"recon": {"naabu_top_ports": "80,443"}},
            project_manager=None,
            master_conductor=None,
        )
        state = ReconState()
        live_subs = ["example.com"]
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            output_file = tasks._get_path(tmp_path, state, "full_port_scan", "txt")
            output_file.write_text("example.com:8080\n")
            
            result = await tasks.full_port_scan(live_subs, tmp_path, state)
        
        assert result["status"] == "completed"
        assert "full_port_scan" in state.parallel_task_progress
        entry = state.parallel_task_progress["full_port_scan"]
        assert entry["status"] == "completed"
        assert len(entry["artifact_refs"]) >= 1

    @pytest.mark.asyncio
    async def test_visual_recon_accepts_state_and_updates_checkpoint(self, tmp_path):
        """visual_recon with state=None still works (backward compat)."""
        tasks = ParallelTasks({}, None, None)
        
        # Without state
        result = await tasks.visual_recon([], tmp_path)
        assert result["status"] == "skipped"
        
        # With state
        state = ReconState()
        result = await tasks.visual_recon([], tmp_path, state=state)
        assert result["status"] == "skipped"
        assert "visual_recon" in state.parallel_task_progress
        assert state.parallel_task_progress["visual_recon"]["status"] == "skipped"

    @pytest.mark.asyncio
    async def test_permutation_scan_records_already_executed_skip(self, tmp_path):
        """permutation_executed=True records skipped in progress."""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        state.permutation_executed = True
        
        result = await tasks.permutation_scan(["example.com"], "example.com", tmp_path, state)
        assert result["status"] == "skipped"
        assert "permutation_scan" in state.parallel_task_progress
        assert state.parallel_task_progress["permutation_scan"]["status"] == "skipped"
        assert state.parallel_task_progress["permutation_scan"]["resume_reason"] == "already_executed"

    @pytest.mark.asyncio
    async def test_dead_subdomain_scan_updates_checkpoint_on_completed(self, tmp_path):
        """Dead sub scan records artifact_refs on completion."""
        tasks = ParallelTasks({}, None, None)
        state = ReconState()
        
        all_subs = ["a.example.com", "b.example.com", "c.example.com"]
        live_subs = ["a.example.com"]
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            output_file = tasks._get_path(tmp_path, state, "dead_subdomain_scan", "txt")
            output_file.write_text("b.example.com:8080\n")
            
            result = await tasks.dead_subdomain_scan(all_subs, live_subs, tmp_path, state)
        
        assert result["status"] == "completed"
        assert "dead_subdomain_scan" in state.parallel_task_progress
        entry = state.parallel_task_progress["dead_subdomain_scan"]
        assert entry["status"] == "completed"
        assert len(entry["artifact_refs"]) >= 1
