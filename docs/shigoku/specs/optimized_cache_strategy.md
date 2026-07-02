---
task_id: SGK-2026-0140
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# 仕様書：最適化された階層型キャッシュ戦略

## 概要

SHIGOKUのパフォーマンス向上と分散環境での整合性維持のため、L1 (メモリ) / L2 (Redis) 階層型キャッシュを導入する。
これにより、ファイルI/Oの削減、ネットワークリクエストの重複回避、およびマルチエージェント間での情報共有を高速化する。

## 変更範囲

- `src/core/infra/cache_manager.py` [NEW]: 基盤となるキャッシュクラス。
- `src/core/infra/proxy_manager.py` [MODIFY]: プロキシスコアや状態のキャッシュ。
- `src/core/infra/network_client.py` [MODIFY]: レスポンス、指紋情報のキャッシュ。
- `src/core/workspace/shared_workspace.py` [MODIFY]: インテル情報の読み込み高速化。

## 挙動 (Input/Output)

### CacheManager.get(key)

- **Input**: `str` (key)
- **Logic**:
  1. L1 (Dictionary/LRU) をチェック。ヒットすれば返却。
  2. ヒットしなければ L2 (Redis) をチェック。
  3. ヒットすれば L1 に昇格させて返却。
- **Output**: `Optional[Any]`

### CacheManager.set(key, value, ttl)

- **Input**: `str`, `Any`, `int` (ttl)
- **Logic**: L1 と L2 (Redis + msgpack) の両方にセット。

## 制約

- **ポータビリティ**: Redis が未インストール/停止中の場合、自動的に L1 のみで動作しなければならない。
- **セキュリティ**: キャッシュに認証情報や PII が含まれる場合は `PIIMasker` との連携を検討する。
- **EthicsGuard**: キャッシュされた情報であっても、スコープ外へのリクエストを誘発してはならない。

## 依存ライブラリ

- `redis`: Redis クラスタとの通信用。
- `msgpack`: 高速シリアライズ。
