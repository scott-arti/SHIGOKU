"""
SwarmRetryEngine - Swarm Specialist のリトライ・ミューテーション機構

WAF Blocking 検出時に自動的にペイロードをミューテーションして再試行する。
ハイブリッド戦略: Retry 1-2 はランダム選択、Retry 3 は遺伝的アルゴリズム。

用途:
- WAFでブロックされても諦めずに攻撃を継続
- Time-based攻撃での複数回確認（統計的検証）
- 誤検知を減らすための複数回試行
"""

import asyncio
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional, Callable, Awaitable, Tuple

from src.core.agents.swarm.error_detector import ErrorDetector, DetectionResult

# 遅延インポート（循環インポート回避）
# WAFPayloadMutator は __init__ 内でインポート

logger = logging.getLogger(__name__)


@dataclass
class RetryConfig:
    """リトライ設定"""
    max_attempts: int = 3              # 最大試行回数
    enable_mutation: bool = True       # ミューテーション有効化
    mutation_rate: float = 0.3         # ミューテーション確率
    detect_waf: bool = True            # WAF検出有効化
    backoff_factor: float = 1.0        # リトライ間隔の係数（秒）
    use_genetic_on_final: bool = True  # 最終試行で遺伝的アルゴリズム使用


@dataclass
class RetryMetadata:
    """リトライ実行メタデータ"""
    attempts: int                              # 実際の試行回数
    waf_detected: bool                         # WAF検出フラグ
    mutation_applied: bool                     # ミューテーション適用フラグ
    successful_mutation: Optional[str] = None  # 成功したミューテーションタイプ
    detection_results: List[Dict[str, Any]] = field(default_factory=list)  # 各試行の検出結果
    
    def to_dict(self) -> Dict[str, Any]:
        """辞書形式に変換"""
        return asdict(self)


@dataclass
class LastResponse:
    """最後のHTTPレスポンス情報（ミューテーション判断用）"""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""


class SwarmRetryEngine:
    """
    Swarm Specialist のリトライエンジン
    
    ハイブリッド戦略:
    - Retry 1-2: WAFPayloadMutator.mutate() でランダム選択（高速）
    - Retry 3: WAFPayloadMutator.evolve() で遺伝的アルゴリズム（最適化）
    """
    
    def __init__(self, config: Optional[RetryConfig] = None):
        """
        Args:
            config: リトライ設定（省略時はデフォルト）
        """
        self.config = config or RetryConfig()
        
        # 遅延インポート（循環インポート回避）
        self.mutator = None
        if self.config.enable_mutation:
            try:
                from src.core.attack.waf_mutator import WAFPayloadMutator
                self.mutator = WAFPayloadMutator(
                    mutation_rate=self.config.mutation_rate
                )
            except ImportError:
                logger.warning("WAFPayloadMutator not available, mutation disabled")
        
        self.detector = ErrorDetector() if self.config.detect_waf else None
        self.failed_payloads: List[str] = []
        self._last_response: Optional[LastResponse] = None
        self._last_mutation: Optional[List[Any]] = None  # ミューテーション履歴
    
    def set_last_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
    ) -> None:
        """
        最後のHTTPレスポンスを設定（ブロック検出用）
        
        Specialist から呼び出される。execute() 内でHTTPリクエスト後に呼ぶ。
        """
        self._last_response = LastResponse(
            status_code=status_code,
            headers=headers,
            body=body,
        )
    
    async def execute_with_retry(
        self,
        specialist_execute: Callable[[Any], Awaitable[List[Any]]],
        task: Any,
        quick_mode: bool = False,
        **kwargs
    ) -> Tuple[List[Any], RetryMetadata]:
        """
        Specialist の execute をリトライロジックでラップ

        Args:
            specialist_execute: Specialist.execute メソッド
            task: 実行タスク
            quick_mode: True の場合、軽量モードで実行
            **kwargs: 追加引数

        Returns:
            (findings, metadata): 発見リストとメタデータ
        """
        metadata = RetryMetadata(
            attempts=0,
            waf_detected=False,
            mutation_applied=False,
            successful_mutation=None,
            detection_results=[],
        )

        findings: List[Any] = []
        current_task = task

        for attempt in range(1, self.config.max_attempts + 1):
            metadata.attempts = attempt
            self._last_response = None  # リセット

            logger.debug(f"Retry attempt {attempt}/{self.config.max_attempts}")

            try:
                # Specialist 実行（quick_mode と kwargs を渡す）
                findings = await specialist_execute(current_task, quick_mode=quick_mode, **kwargs)
                
                # 成功したら終了
                if findings:
                    if metadata.mutation_applied:
                        # 成功したミューテーションを記録
                        metadata.successful_mutation = self._get_last_mutation_type()
                    
                    num_findings = 0
                    if hasattr(findings, 'findings'):
                        num_findings = len(findings.findings)
                    elif isinstance(findings, list):
                        num_findings = len(findings)
                    
                    logger.info(
                        f"Retry attempt {attempt} succeeded with {num_findings} findings"
                    )
                    break
                
                # WAF 検出チェック
                detection = self._check_waf_blocking()
                if detection:
                    metadata.detection_results.append(detection.to_dict())
                    
                    if detection.is_blocked:
                        metadata.waf_detected = True
                        logger.info(
                            f"WAF blocking detected: {detection.block_type} "
                            f"(confidence: {detection.confidence:.2f})"
                        )
                        
                        # 最終試行でなければミューテーション
                        if attempt < self.config.max_attempts:
                            current_task = await self._mutate_task(
                                current_task, 
                                attempt,
                                detection
                            )
                            metadata.mutation_applied = True
                            
                            # バックオフ待機
                            await self._backoff(attempt)
                        continue
                
                # WAF でなければリトライ不要
                logger.debug(f"No WAF blocking detected, stopping retry")
                break
                
            except Exception as e:
                logger.warning(f"Retry attempt {attempt} failed with error: {e}")
                if attempt == self.config.max_attempts:
                    raise
                await self._backoff(attempt)
        
        return findings, metadata
    
    def _check_waf_blocking(self) -> Optional[DetectionResult]:
        """WAF ブロックをチェック"""
        if not self.detector or not self._last_response:
            return None
        
        return self.detector.analyze(
            status_code=self._last_response.status_code,
            headers=self._last_response.headers,
            body=self._last_response.body,
        )
    
    async def _mutate_task(
        self,
        task: Any,
        attempt: int,
        detection: DetectionResult,
    ) -> Any:
        """
        タスクのペイロードをミューテーション
        
        ハイブリッド戦略:
        - Retry 1-2: ランダム選択
        - Retry 3: 遺伝的アルゴリズム
        """
        if not self.mutator:
            return task
        
        # タスクからペイロードを抽出
        payload = self._extract_payload(task)
        if not payload:
            return task
        
        # ハイブリッド戦略
        use_genetic = (
            self.config.use_genetic_on_final and 
            attempt == self.config.max_attempts - 1
        )
        
        if use_genetic:
            # 遺伝的アルゴリズム（最終試行前）
            logger.debug("Using genetic algorithm for mutation")
            mutated_payloads = self.mutator.evolve(
                payload,
                fitness_func=self._create_fitness_func(detection),
            )
            if mutated_payloads:
                best = mutated_payloads[0]
                mutated_payload = best.mutated
                self._last_mutation = best.mutations
        else:
            # ランダム選択（高速）
            logger.debug("Using random mutation")
            mutated_payloads = self.mutator.mutate(payload)
            if mutated_payloads:
                import random
                selected = random.choice(mutated_payloads)
                mutated_payload = selected.mutated
                self._last_mutation = selected.mutations
            else:
                return task
        
        # 失敗したペイロードを記録
        self.failed_payloads.append(payload)
        
        # タスクにミューテーション結果を適用
        return self._apply_mutation_to_task(task, mutated_payload)
    
    def _extract_payload(self, task: Any) -> Optional[str]:
        """タスクからペイロードを抽出"""
        # Task.params からペイロードを探す
        if hasattr(task, 'params') and isinstance(task.params, dict):
            # 優先順位: payload > data > body > query
            for key in ['payload', 'data', 'body', 'query']:
                if key in task.params and isinstance(task.params[key], str):
                    return task.params[key]
        
        return None
    
    def _apply_mutation_to_task(self, task: Any, mutated_payload: str) -> Any:
        """ミューテーション結果をタスクに適用"""
        if hasattr(task, 'params') and isinstance(task.params, dict):
            # 元のキーを探して置換
            for key in ['payload', 'data', 'body', 'query']:
                if key in task.params:
                    task.params[key] = mutated_payload
                    break
        
        return task
    
    def _create_fitness_func(
        self,
        detection: DetectionResult,
    ) -> Callable[[str], float]:
        """遺伝的アルゴリズム用の適合度関数を生成"""
        def fitness_func(payload: str) -> float:
            # WAF シグネチャに基づいて適合度を計算
            # 実際にはリクエストを送信して評価するが、ここでは簡易的に
            # ペイロード長やエンコーディングの多様性で評価
            base_score = 0.5
            
            # 短いペイロードは高スコア（検出されにくい）
            if len(payload) < 100:
                base_score += 0.1
            
            # エンコーディングが含まれていれば高スコア
            if '%' in payload or '\\u' in payload:
                base_score += 0.2
            
            # コメントが含まれていれば高スコア（SQL用）
            if '/**/' in payload or '/*!' in payload:
                base_score += 0.15
            
            return min(base_score, 1.0)
        
        return fitness_func
    
    def _get_last_mutation_type(self) -> Optional[str]:
        """最後に適用したミューテーションタイプを取得"""
        if hasattr(self, '_last_mutation') and self._last_mutation:
            return ','.join(m.value for m in self._last_mutation)
        return None
    
    async def _backoff(self, attempt: int) -> None:
        """リトライ前のバックオフ待機"""
        wait_time = self.config.backoff_factor * attempt
        logger.debug(f"Backing off for {wait_time:.1f}s before next attempt")
        await asyncio.sleep(wait_time)


def create_retry_engine(
    max_attempts: int = 3,
    enable_mutation: bool = True,
) -> SwarmRetryEngine:
    """SwarmRetryEngine 作成ヘルパー"""
    config = RetryConfig(
        max_attempts=max_attempts,
        enable_mutation=enable_mutation,
    )
    return SwarmRetryEngine(config)
