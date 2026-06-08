"""
RaceConditionTester - 並列リクエスト攻撃モジュール

クーポン使用、残高移動、在庫購入などの重要なトランザクションにおいて、
並列リクエストによる競合状態 (Race Condition) の脆弱性を検証する。

AsyncNetworkClient を使用して、制御された並列リクエストを送信する。
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional

from src.core.infra.network_client import AsyncNetworkClient, NetworkResponse

logger = logging.getLogger(__name__)


class RaceConditionTester:
    """
    Race Condition 攻撃実行クラス
    """

    def __init__(self, client: AsyncNetworkClient, default_concurrency: int = 3):
        """
        Args:
            client: AsyncNetworkClient インスタンス
            default_concurrency: デフォルト並列数 (安全のため 3 程度)
        """
        self.client = client
        self.default_concurrency = default_concurrency

    async def test_race(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        data: Any = None,
        json: Any = None,
        aggressive: bool = False,
        custom_concurrency: Optional[int] = None
    ) -> List[NetworkResponse]:
        """
        指定されたリクエストを並列送信する。
        
        Args:
            method: HTTPメソッド
            url: ターゲットURL
            aggressive: Trueの場合は並列数を上げる (例: 10)
            custom_concurrency: 並列数を明示的に指定
            
        Returns:
            List[NetworkResponse]: 各リクエストの結果リスト
        """
        # 並列数決定
        if custom_concurrency:
            concurrency = custom_concurrency
        elif aggressive:
            concurrency = 10  # 攻撃モード
        else:
            concurrency = self.default_concurrency

        logger.info(
            "🏎️ Starting Race Condition Test: %s %s (Concurrency: %d)",
            method, url, concurrency
        )

        # 同期バリア（すべてのアウェイト可能オブジェクトが準備完了になるまで待つ仕組み）
        start_event = asyncio.Event()
        
        async def worker(worker_id: int):
            # イベント待機
            await start_event.wait()
            
            # リクエスト送信
            logger.debug("Worker %d firing request", worker_id)
            try:
                # リクエスト毎に微妙な変化をつける（キャシュ回避など）必要がある場合はここで調整
                # 今回は純粋なRace狙いなので同一リクエスト
                return await self.client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    json=json,
                    use_proxy=True, # プロキシ分散も活用（ProxyManagerが設定されていれば）
                    retries=0       # Race時にリトライはタイミングをずらすのでOFF推奨だが、エラーハンドリング次第
                )
            except Exception as e:
                logger.warning("Worker %d failed: %s", worker_id, e)
                return None

        # タスク生成
        tasks = [worker(i) for i in range(concurrency)]
        
        # ワーカーが待機状態に入るのを少し待つ（確実性向上）
        await asyncio.sleep(0.5)
        
        # 一斉スタート
        start_event.set()
        
        # 結果収集
        results: List[Optional[NetworkResponse]] = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 例外フィルタリング
        valid_results = [r for r in results if isinstance(r, NetworkResponse)]
        
        logger.info(
            "🏁 Race Test Completed. Success: %d/%d",
            len(valid_results), concurrency
        )
        
        return valid_results

    def analyze_results(self, results: List[NetworkResponse], expected_success_count: int = 1) -> bool:
        """
        結果を分析し、Race Condition の可能性を判定する。
        
        Args:
            results: リクエスト結果リスト
            expected_success_count: 正常なロジックで期待される成功回数 (通常は 1)
            
        Returns:
            bool: 脆弱性の可能性がある場合 True
        """
        success_status_codes = [200, 201, 202, 204]
        
        success_count = 0
        for r in results:
            if r.status in success_status_codes:
                success_count += 1
                
        logger.info("Race Analysis: Success Count = %d (Expected: %d)", success_count, expected_success_count)
        
        if success_count > expected_success_count:
            return True
        
        return False
