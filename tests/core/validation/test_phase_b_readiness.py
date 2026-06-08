"""
Phase B Readiness Tests

Phase B実行準備確認テスト
"""
import pytest
from pathlib import Path


class TestPhaseBReadiness:
    """Phase B準備テスト"""

    def test_url_classifier_output_exists(self):
        """URLClassifierの出力ファイルが生成されている"""
        output_dir = Path("workspace/projects/juice_shop_demo/tagged_urls")
        
        # 出力ディレクトリが存在する
        assert output_dir.exists(), "tagged_urls directory should exist"
        
        # 少なくとも1つのタグ付けファイルが存在する
        jsonl_files = list(output_dir.glob("tagged_*.jsonl"))
        assert len(jsonl_files) > 0, "at least one tagged file should exist"
        
        # 重要なファイルが存在する（柔軟なチェック）
        important_tags = ["admin", "auth"]
        for tag in important_tags:
            file_path = output_dir / f"tagged_{tag}.jsonl"
            # ファイルが存在すれば確認、存在しなくてもエラーにはしない（ターゲットに依存）
            if file_path.exists():
                assert file_path.stat().st_size > 0, f"tagged_{tag}.jsonl should not be empty"

    def test_uncategorized_rate_meets_kpi(self):
        """未分類率がKPI（10%以下）を満たす"""
        output_dir = Path("workspace/projects/juice_shop_demo/tagged_urls")
        
        # uncategorizedファイルの行数をカウント
        uncategorized_file = output_dir / "tagged_uncategorized.jsonl"
        if uncategorized_file.exists():
            with open(uncategorized_file) as f:
                uncategorized_count = sum(1 for _ in f)
        else:
            uncategorized_count = 0
        
        # 全ファイルの合計行数
        total_count = 0
        for jsonl_file in output_dir.glob("*.jsonl"):
            with open(jsonl_file) as f:
                total_count += sum(1 for _ in f)
        
        if total_count > 0:
            uncategorized_rate = uncategorized_count / total_count
            assert uncategorized_rate <= 0.10, f"uncategorized rate {uncategorized_rate:.1%} exceeds 10%"

    def test_admin_test_results_exist(self):
        """admin試行結果が保存されている"""
        results_file = Path("workspace/projects/juice_shop_demo/admin_test/admin_test_results.json")
        assert results_file.exists(), "admin test results should exist"

    def test_injection_manager_has_admin_check(self):
        """InjectionManagerAgentにrun_admin_checkメソッドが存在"""
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent
        
        assert hasattr(InjectionManagerAgent, 'run_admin_check'), "should have run_admin_check method"
        assert hasattr(InjectionManagerAgent, 'validate_findings'), "should have validate_findings method"
        assert hasattr(InjectionManagerAgent, 'filter_valid_findings'), "should have filter_valid_findings method"

    def test_finding_validator_integration(self):
        """FindingValidatorがInjectionManagerAgentに統合されている"""
        from src.core.agents.swarm.injection.manager import InjectionManagerAgent
        
        # 初期化時にFindingValidatorが作成される
        agent = InjectionManagerAgent()
        assert hasattr(agent, '_finding_validator'), "should have _finding_validator attribute"
