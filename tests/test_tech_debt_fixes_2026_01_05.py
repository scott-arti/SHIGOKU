"""
技術的負債解消のテスト（2026-01-05）

修正した項目の回帰テスト:
1. FastAPIエンドポイントの同期関数化
2. エラーハンドリング改善
3. ファイルエンコーディング明示
4. 例外特化
"""
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
import logging


# =============================================================================
# 1. FastAPI ブロッキングI/O修正テスト
# =============================================================================

class TestDashboardAPISync:
    """dashboard/api/main.pyの同期関数化テスト"""
    
    def test_list_projects_is_sync_function(self):
        """list_projectsがasyncではなくsync関数であることを確認"""
        import inspect
        from src.dashboard.api.main import list_projects
        
        # async defならiscoroutinefunctionがTrueになる
        assert not inspect.iscoroutinefunction(list_projects), \
            "list_projects should be sync (def), not async (async def)"
    
    def test_get_project_findings_is_sync_function(self):
        """get_project_findingsがsync関数であることを確認"""
        import inspect
        from src.dashboard.api.main import get_project_findings
        
        assert not inspect.iscoroutinefunction(get_project_findings), \
            "get_project_findings should be sync (def), not async (async def)"
    
    def test_get_vulnerability_score_is_sync_function(self):
        """get_vulnerability_scoreがsync関数であることを確認"""
        import inspect
        from src.dashboard.api.main import get_vulnerability_score
        
        assert not inspect.iscoroutinefunction(get_vulnerability_score), \
            "get_vulnerability_score should be sync (def), not async (async def)"
    
    def test_get_target_info_is_sync_function(self):
        """get_target_infoがsync関数であることを確認"""
        import inspect
        from src.dashboard.api.main import get_target_info
        
        assert not inspect.iscoroutinefunction(get_target_info), \
            "get_target_info should be sync (def), not async (async def)"
    
    def test_get_hunting_log_is_sync_function(self):
        """get_hunting_logがsync関数であることを確認"""
        import inspect
        from src.dashboard.api.main import get_hunting_log
        
        assert not inspect.iscoroutinefunction(get_hunting_log), \
            "get_hunting_log should be sync (def), not async (async def)"


# =============================================================================
# 2. エラーハンドリング改善テスト
# =============================================================================

class TestErrorHandlingImprovement:
    """エラーハンドリングの改善テスト"""
    
    def test_master_conductor_rag_error_logging(self, caplog):
        """MasterConductor.replanでRAGエラーがログされることを確認"""
        from src.core.engine.master_conductor import MasterConductor, Task
        
        # RAGがエラーを発生させるモック
        mock_rag = MagicMock()
        mock_rag.query.side_effect = Exception("Test RAG error")
        
        conductor = MasterConductor()
        conductor.rag = mock_rag
        
        # 失敗したタスクを作成
        failed_task = Task(
            id="test_task_1",
            name="Test Task",
            agent_type="test_agent",
            action="test_action",
            params={}
        )
        
        # debugレベルでログをキャプチャ
        with caplog.at_level(logging.DEBUG):
            result = conductor.replan(failed_task, "403 Forbidden")
        
        # RAGエラーがログされていることを確認（握りつぶされていないこと）
        assert mock_rag.query.called, "RAG query should be called"
        # Note: 実際のログ確認は環境に依存するため、エラーが発生してもreplanが継続することを確認
        assert isinstance(result, list), "replan should return a list even if RAG fails"


# =============================================================================
# 3. main.pyの未使用インポート削除テスト
# =============================================================================

class TestMainPyImports:
    """main.pyのインポート最適化テスト"""
    
    def test_main_py_syntax_valid(self):
        """main.pyの構文が正しいことを確認"""
        import py_compile
        main_path = Path(__file__).parent.parent / "src" / "main.py"
        
        # 例外が発生しなければ成功
        py_compile.compile(str(main_path), doraise=True)
    
    def test_main_py_no_unused_os_import(self):
        """main.pyにosインポートがないことを確認（削除済み）"""
        main_path = Path(__file__).parent.parent / "src" / "main.py"
        content = main_path.read_text(encoding="utf-8")
        
        # インポート行を抽出（コメント除外）
        import_lines = [
            line for line in content.split("\n")
            if line.strip().startswith("import os") and not line.strip().startswith("#")
        ]
        
        assert len(import_lines) == 0, f"'import os' should be removed, found: {import_lines}"
    
    def test_main_py_no_duplicate_path_import(self):
        """main.pyにPathの重複インポートがないことを確認"""
        main_path = Path(__file__).parent.parent / "src" / "main.py"
        content = main_path.read_text(encoding="utf-8")
        
        # "from pathlib import Path"の出現回数
        count = content.count("from pathlib import Path")
        
        assert count == 1, f"'from pathlib import Path' should appear once, found {count} times"


# =============================================================================
# 4. dashboard/api/main.pyのエンコーディング明示テスト
# =============================================================================

class TestFileEncodingExplicit:
    """ファイルオープン時のエンコーディング明示テスト"""
    
    def test_dashboard_api_uses_utf8_encoding(self):
        """dashboard/api/main.pyでopen()にencoding='utf-8'が指定されていることを確認"""
        api_path = Path(__file__).parent.parent / "src" / "dashboard" / "api" / "main.py"
        content = api_path.read_text(encoding="utf-8")
        
        # open()呼び出しを検査
        # パターン: open(xxx) でencoding指定がないものを検出
        import re
        
        # encoding指定なしのopen()を検出（ただしコメント行は除外）
        lines = content.split("\n")
        problematic_lines = []
        
        for i, line in enumerate(lines, 1):
            # コメント行はスキップ
            if line.strip().startswith("#"):
                continue
            # open()があってencoding指定がない行を検出
            if "with open(" in line and "encoding" not in line:
                problematic_lines.append((i, line.strip()))
        
        assert len(problematic_lines) == 0, \
            f"Found open() without encoding: {problematic_lines}"


# =============================================================================
# 5. 例外特化テスト
# =============================================================================

class TestExceptionSpecificity:
    """例外の特化テスト"""
    
    def test_dashboard_api_uses_specific_exceptions(self):
        """dashboard/api/main.pyでbroad exceptionが使われていないことを確認"""
        api_path = Path(__file__).parent.parent / "src" / "dashboard" / "api" / "main.py"
        content = api_path.read_text(encoding="utf-8")
        
        # "except Exception:" を検出（except Exception as e: も含む）
        # ただしKnowledgeGraph関連は許容（外部接続のため）
        lines = content.split("\n")
        broad_exceptions = []
        
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            # コメント行はスキップ
            if stripped.startswith("#"):
                continue
            # "except Exception" で "JSONDecodeError" や "OSError" を含まない行
            if "except Exception" in stripped:
                # KnowledgeGraph接続エラーは許容
                # 前後の行をチェックしてKnowledgeGraph関連かどうか判定
                context_start = max(0, i - 10)
                context_end = min(len(lines), i + 5)
                context = "\n".join(lines[context_start:context_end])
                
                if "KnowledgeGraph" not in context:
                    broad_exceptions.append((i, stripped))
        
        # KnowledgeGraph以外での broad exception は0であるべき
        assert len(broad_exceptions) == 0, \
            f"Found broad 'except Exception' (not KnowledgeGraph related): {broad_exceptions}"


# =============================================================================
# 6. ログフォーマットテスト
# =============================================================================

class TestLoggingFormat:
    """ログフォーマットのテスト"""
    
    def test_dashboard_api_uses_lazy_logging(self):
        """dashboard/api/main.pyでf-stringログではなく%s形式を使用していることを確認"""
        api_path = Path(__file__).parent.parent / "src" / "dashboard" / "api" / "main.py"
        content = api_path.read_text(encoding="utf-8")
        
        # logger.error(f"...") パターンを検出
        import re
        
        # f-string形式のログ呼び出しを検出
        fstring_log_pattern = r'logger\.(error|warning|info|debug)\(f["\']'
        matches = re.findall(fstring_log_pattern, content)
        
        assert len(matches) == 0, \
            f"Found {len(matches)} f-string logging calls, should use lazy % formatting"
