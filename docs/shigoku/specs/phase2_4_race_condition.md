---
task_id: SGK-2026-0149
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 2.4: Race Condition Tester 仕様書

## 概要

**機能名**: `RaceConditionTester`

**目的**:
クーポン使用、残高移動、在庫購入などの重要なトランザクションにおいて、並列リクエストによる競合状態 (Race Condition) の脆弱性を検証する。

---

## 変更範囲

| ファイル                                   | 変更内容            |
| ------------------------------------------ | ------------------- |
| `src/core/attack/race_condition_tester.py` | 🆕 新規作成         |
| `src/core/agents/spec/race_verifier.py`    | 🆕 新規 - 検証Agent |

---

## 機能詳細

### 1. RaceConditionTester

`AsyncNetworkClient` を使用して、制御された並列リクエストを送信する。

#### 安全性制御

- **デフォルト**: 並列数 `3` (安全優先)
- **Aggressive モード**: 並列数 `10` 以上 (DoSリスクあり、明示的フラグが必要)

```python
class RaceConditionTester:
    def __init__(self, client: AsyncNetworkClient, concurrency: int = 3):
        self.client = client
        self.concurrency = concurrency

    async def test_race(self, request_template: Dict, aggressive: bool = False) -> List[NetworkResponse]:
        """
        指定されたリクエストを並列送信し、結果を比較する。

        Args:
            aggressive: Trueの場合は並列数を上げる (例: 10)
        """
        # 並列数決定
        target_concurrency = 10 if aggressive else self.concurrency

        tasks = []
        # 同期バリア（すべてのアウェイト可能オブジェクトが準備完了になるまで待つ仕組み）
        start_event = asyncio.Event()

        async def worker():
            await start_event.wait()
            return await self.client.request(...)

        tasks = [worker() for _ in range(target_concurrency)]

        # 一斉スタート
        start_event.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return results

    def analyze_results(self, results: List[NetworkResponse]) -> bool:
        """
        結果を分析し、成功数が期待値を超えていないか確認する。
        """
        pass
```

### 2. CLI オプション

`src.main` などCLIツールに以下のオプションを追加することを想定。

- `--aggressive`: 攻撃的なスキャンを許可する（Raceの並列数アップ、Fuzzingのレートリミット緩和など）

---

## 完了条件

- デフォルト設定でターゲットサーバーに過度な負荷をかけないこと。
- テスト環境でRace脆弱性を検知できること。
