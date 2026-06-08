from unittest.mock import MagicMock, AsyncMock, patch
import pytest
import json
from src.recon.parallel_tasks import ParallelTasks
from src.recon.pipeline import ReconState

class TestIntegration:
    """MC/Notify/LLM 統合テスト"""
    
    @pytest.mark.asyncio
    async def test_full_port_scan_mc_integration(self, tmp_path):
        """MC タスク登録と Notify テスト"""
        config = MagicMock()
        # config.get("recon", {}).get("naabu_top_ports", "...") のモック
        config.get.return_value.get.return_value = "80,443"
        
        pm = MagicMock()
        mc = MagicMock()
        
        tasks = ParallelTasks(config, pm, mc)
        state = ReconState()
        state.target = "example.com"
        state.project_name = "example_com"
        
        live_subs = ["example.com"]
        
        # naabu Mock
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            # 出力ファイル作成 (full_port_scan が出力することを期待されているファイル名を事前に作成しておいても意味がないが、
            # mock_proc が何もしないので、このファイルが作られないと "not found" になる)
            # ParallelTasks.full_port_scan は naabu を実行して output_file に書き込む。
            # mock しているので実際には書き込まれない。
            # しかし、そのあと output_file.exists() をチェックしている。
            # なので、テスト側でそのファイルを作っておく必要がある。
            output_file = tasks._get_path(tmp_path, state, "full_port_scan", "txt")
            output_file.write_text("example.com:80\nexample.com:443\n")
            
            # Notifier Mock
            with patch("src.recon.parallel_tasks.get_notifier") as mock_get_notifier:
                mock_notifier = MagicMock()
                mock_get_notifier.return_value = mock_notifier
                
                result = await tasks.full_port_scan(live_subs, tmp_path, state)
                
                # Notify 確認
                mock_notifier.notify.assert_called_once()
                assert "Full Port Scan Completed" in mock_notifier.notify.call_args[0][0]
                
                # MC 登録確認
                mc._add_tasks.assert_called_once()
                args = mc._add_tasks.call_args[0]
                added_tasks = args[0]
                assert len(added_tasks) == 1
                assert added_tasks[0].agent_type == "vuln_scanner"
                assert added_tasks[0].params["target"] == "example.com"
    
    @pytest.mark.asyncio
    async def test_permutation_scan_llm(self, tmp_path):
        """LLM 候補生成テスト"""
        config = MagicMock()
        pm = MagicMock()
        mc = MagicMock()
        
        # LLM Mock
        mock_llm = MagicMock()
        mc.llm_client = mock_llm
        mock_response = MagicMock()
        mock_response.choices[0].message.content = "llm.example.com\nai.example.com"
        mock_llm.chat.completions.create.return_value = mock_response
        
        tasks = ParallelTasks(config, pm, mc)
        state = ReconState()
        state.project_name = "example_com"
        
        all_subs = ["www.example.com"]
        
        # shuffledns Mock
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_proc = AsyncMock()
            mock_proc.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_proc
            
            # 結果ファイル
            (tasks._get_path(tmp_path, state, "alterx_candidates", "txt")).write_text("alterx.example.com\n")
            (tasks._get_path(tmp_path, state, "permutation_resolved", "txt")).write_text("llm.example.com\nalterx.example.com\n")
            
            result = await tasks.permutation_scan(all_subs, "example.com", tmp_path, state)
            
            # LLM 呼び出し確認
            mock_llm.chat.completions.create.assert_called_once()
            
            # 新規サブドメイン確認 (alterx + llm)
            assert result["new_subs_count"] == 2
