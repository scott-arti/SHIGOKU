"""
WAF Payload Mutator ユニットテスト
"""
import pytest
from src.core.attack.waf_mutator import (
    WAFPayloadMutator,
    MutationType,
    MutatedPayload,
    create_waf_mutator,
)


class TestWAFPayloadMutator:
    """WAFPayloadMutator テストクラス"""

    @pytest.fixture
    def mutator(self):
        return create_waf_mutator()

    def test_mutate_encode(self, mutator):
        """エンコードミューテーション"""
        payload = "<script>alert(1)</script>"
        result = mutator._mutate_encode(payload)
        # URLエンコードまたはUnicodeエンコード
        assert result != payload

    def test_mutate_case(self, mutator):
        """大小文字ミューテーション"""
        payload = "SELECT * FROM users"
        result = mutator._mutate_case(payload)
        # 大小文字が混合
        assert result.lower() == payload.lower()
        assert result != payload.lower()

    def test_mutate_whitespace(self, mutator):
        """空白ミューテーション"""
        payload = "SELECT * FROM users"
        result = mutator._mutate_whitespace(payload)
        # 空白が代替文字に
        assert " " not in result or result != payload

    def test_mutate_comment(self, mutator):
        """コメント挿入ミューテーション"""
        payload = "SELECT * FROM users"
        result = mutator._mutate_comment(payload)
        # コメントが挿入される
        assert len(result) >= len(payload)

    def test_mutate_syntax(self, mutator):
        """構文変更ミューテーション"""
        payload = "SELECT * FROM users"
        result = mutator._mutate_syntax(payload)
        # SELECTが変更される可能性
        # 変更がない場合もあるので長さチェック
        assert len(result) > 0

    def test_mutate_returns_list(self, mutator):
        """mutateメソッドがリストを返す"""
        payload = "<script>alert(1)</script>"
        results = mutator.mutate(payload)
        assert isinstance(results, list)
        assert len(results) > 0

    def test_mutate_different_types(self, mutator):
        """異なるミューテーションタイプが適用される"""
        payload = "SELECT * FROM users"
        results = mutator.mutate(payload)
        
        mutation_types = set()
        for r in results:
            mutation_types.update(r.mutations)
        
        # 複数のタイプが含まれる
        assert len(mutation_types) > 1

    def test_create_initial_population(self, mutator):
        """初期集団作成"""
        payload = "test payload"
        population = mutator._create_initial_population(payload)
        
        assert len(population) == mutator.population_size
        # 全てがMutatedPayload
        for p in population:
            assert isinstance(p, MutatedPayload)

    def test_evolve_with_fitness(self, mutator):
        """適合度関数での進化"""
        payload = "SELECT * FROM users"
        
        # 簡単な適合度関数（URLエンコードを好む）
        def fitness_func(p):
            return 0.8 if "%" in p else 0.2
        
        results = mutator.evolve(payload, fitness_func)
        
        assert len(results) > 0
        # 結果は適合度順
        assert results[0].fitness >= results[-1].fitness

    def test_select_parent(self, mutator):
        """親選択"""
        population = [
            MutatedPayload("a", "a", [MutationType.ENCODE], 0, 0.9),
            MutatedPayload("b", "b", [MutationType.CASE], 0, 0.1),
        ]
        
        # 複数回選択して高適合度が多く選ばれることを確認
        high_count = sum(
            1 for _ in range(100)
            if mutator._select_parent(population).fitness == 0.9
        )
        assert high_count > 50  # 50回以上は0.9が選ばれるはず

    def test_get_successful_patterns(self, mutator):
        """成功パターン取得"""
        payload = "test"
        
        def fitness_func(p):
            return 0.9 if p != "test" else 0.1
        
        mutator.evolve(payload, fitness_func)
        patterns = mutator.get_successful_patterns()
        
        # 成功したものが保存される
        assert len(patterns) > 0

    def test_get_summary(self, mutator):
        """サマリー取得"""
        payload = "test"
        mutator.mutate(payload)
        
        summary = mutator.get_summary()
        assert "successful_count" in summary
        assert "by_mutation_type" in summary
