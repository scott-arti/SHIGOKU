---
task_id: SGK-2026-0138
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Spec: AsyncNetworkClient のI/Oボトルネック解消

## 概要

`AsyncNetworkClient` の並列処理性能を向上させるため、以下の最適化を実施する:

1. **セッションプーリング機構の導入** - 複数のaiohttpセッションをプールし、高負荷時の接続待機時間を削減
2. **TCP接続パラメータの最適化** - 接続制限の調整と接続再利用の強化
3. **同期I/Oの完全削除** - ファイル操作を`aiofiles`に移行し、完全非同期化

## 背景

現状の`AsyncNetworkClient`では、以下の問題が存在する:

- 単一セッションの使い回しにより、大量の並列リクエスト時に接続待機が発生
- `limit_per_host=20` が不足し、ホストあたりの同時接続数が制限される
- `save_session_async`が内部で`run_in_executor`を使用し、スレッドプールを浪費

## 変更範囲

- `src/core/infra/network_client.py`
- 新規依存: `aiofiles` (requirements.txt)

## 詳細設計

### 1. セッションプーリング機構

```python
class OptimizedNetworkClient:
    def __init__(self):
        self._session_pool = asyncio.Queue(maxsize=100)
        self._connector = aiohttp.TCPConnector(
            limit=100,              # 同時接続数上限
            limit_per_host=30,      # ホストごとの接続数上限 (20→30)
            enable_cleanup_closed=True,
            force_close=False,      # 接続再利用を有効化
            ttl_dns_cache=300,
        )
```

**動作仕様:**

- 初期化時に`maxsize=100`のセッションプールを作成
- `request()`呼び出し時にプールからセッションを取得、使用後に返却
- プールが空の場合は新規セッションを作成（上限100まで）

### 2. TCP接続パラメータの最適化

| パラメータ              | 現在値 | 最適化後 | 理由                                     |
| ----------------------- | ------ | -------- | ---------------------------------------- |
| `limit`                 | 100    | 100      | 維持（十分）                             |
| `limit_per_host`        | 20     | 30       | Bug Bountyでの同一ホスト高速スキャン対応 |
| `force_close`           | -      | `False`  | 接続再利用でTCP handshakeコスト削減      |
| `enable_cleanup_closed` | -      | `True`   | クローズ済み接続の自動クリーンアップ     |

### 3. 同期I/Oの削除

**変更対象メソッド:**

- `save_session_async()` → 完全非同期化
- `load_session_async()` → 完全非同期化
- `_save_session_sync()` → 削除
- `_load_session_sync()` → 削除

**移行方針:**

```python
import aiofiles
import aiofiles.os

async def save_session_async(self, filepath: str) -> None:
    """完全非同期でセッション保存"""
    async with aiofiles.open(filepath, 'w') as f:
        await f.write(json.dumps(data))
```

## 制約事項

### EthicsGuard整合性

- セッションプーリングを導入しても、全セッションで同一のCookieとUser-Agentを共有
- `check_scope()`はリクエスト前に必ず呼び出されるため、影響なし

### 既存コード互換性

- 外部APIは変更しない（`async with NetworkClient() as client:` の使い方は維持）
- 内部実装のみ変更

## パフォーマンス目標

| 指標                      | 現在   | 目標    |
| ------------------------- | ------ | ------- |
| 100並列リクエスト完了時間 | 未計測 | 30%短縮 |
| セッション保存時間 (10KB) | 未計測 | 50%短縮 |

## 検証方法

1. **単体テスト**: セッションプールの取得/返却ロジック
2. **負荷テスト**: `verify_perf.py`を拡張し、100並列リクエストでの完了時間を計測
3. **E2E**: 既存のRecon Pipelineがエラーなく動作することを確認

## リスク評価

| リスク           | 重大度 | 対策                                   |
| ---------------- | ------ | -------------------------------------- |
| セッションリーク | 中     | コンテキストマネージャーで確実に返却   |
| メモリ使用量増加 | 低     | プールサイズ上限100で制限              |
| 既存バグの顕在化 | 低     | 段階的リリース、既存テスト全通過を条件 |

## 実装優先順位

1. **Phase 1**: TCP接続パラメータ最適化（低リスク・即効性）
2. **Phase 2**: 同期I/O削除（中リスク・中効果）
3. **Phase 3**: セッションプーリング（高リスク・高効果）
