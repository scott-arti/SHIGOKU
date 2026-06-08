"""エントリポイントの動作確認テスト

Phase 0: ADR-001 に基づくエントリポイント統一の検証テスト
"""
import subprocess
import pytest


class TestEntryPoints:
    """エントリポイントの動作確認"""

    def test_main_help_returns_zero(self):
        """main.py --help が正常終了する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"Stderr: {result.stderr}"

    def test_main_help_shows_usage(self):
        """main.py --help が使用方法を表示する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "usage" in result.stdout.lower() or "shigoku" in result.stdout.lower()

    def test_main_interactive_option_exists(self):
        """--interactive オプションが存在する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "--interactive" in result.stdout

    def test_main_mode_option_exists(self):
        """--mode オプションが存在する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "--mode" in result.stdout

    @pytest.mark.xfail(
        reason="Known debt: __main__.py has import issues (ADR-001 will fix this)"
    )
    def test_dunder_main_executes(self):
        """__main__.py が実行可能である
        
        Note: 現状、__main__.py には import エラーがあり、
        Phase 4 (レガシー削除) で修正予定。
        """
        # 注: 現状は対話モードに入るため、--help なしでは即座に終了しない
        # このテストは python -m src が最低限動作することを確認
        result = subprocess.run(
            ["python", "-c", "import src.__main__"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # インポートエラーがないことを確認
        assert "ImportError" not in result.stderr
        assert "ModuleNotFoundError" not in result.stderr


class TestCLICommands:
    """CLIコマンドの基本動作確認"""

    def test_projects_command(self):
        """--projects コマンドが動作する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--projects"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # エラーなく終了すればOK（プロジェクトがなくても正常終了）
        assert result.returncode == 0

    def test_tools_command(self):
        """--tools コマンドが動作する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--tools"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0

    def test_rag_stats_command(self):
        """--rag-stats コマンドが動作する"""
        result = subprocess.run(
            ["python", "-m", "src.main", "--rag-stats"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        # RAGが無効の場合も正常終了する
        assert result.returncode == 0
