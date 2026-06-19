---
task_id: SGK-2026-0135
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: LLM API呼び出しの最適化 (LLM Optimization)

## 1. 概要

SHIGOKUのエンジンにおいて頻発している `litellm.BadRequestError` や `RateLimitError` に対処し、コスト削減とシステムスタビリティを向上させるための最適化仕様。

## 2. 変更範囲

- `src/core/models/llm.py`: `LLMClient` のコアロジック
- `src/core/utils/llm_retry.py`: [NEW] リトライアルゴリズム
- `src/core/infra/cache_manager.py`: キャッシュキー生成ロジックの補足

## 3. 詳細仕様

### 3.1 高度なリトライ戦略 (Advanced Retry)

`litellm` の組み込みリトライではなく、以下の制御を持つ独自のリトライハンドラを導入する。

- **指数バックオフ**: 失敗ごとに待機時間を 2^n 倍にする。
- **ジッター (Jitter)**: 待機時間にランダム要素を加え、複数のエージェントが同時に再試行して再度バーストが発生する「サンダリングハード（Thundering Herd）」問題を回避する。
- **対象例外**: `RateLimitError` (429), `ServiceUnavailableError` (503), `Timeout` などを対象とする。

### 3.2 階層型レスポンスキャッシュ (Response Caching)

`OptimizedCache` (L1/L2) を利用し、同一のリクエストをスキップする。

- **キャッシュキー**: `sha256(model + messages + tools + kwargs)`
- **TTL**: デフォルトで 3600秒（1時間）。
- **バイパス**: `force_cloud=True` や特定のメタデータがある場合はキャッシュをバイパス可能にする。

### 3.3 コンテキスト圧縮・バッチ化の検討 (将来拡張)

- 短いタスク（MicroAgentでの分類等）を `LocalLLMProvider` に自動的に集約し、バルク処理するインターフェースを用意する。

## 4. 制約と安全性

- **EthicsGuardの維持**: 最適化ロジックはセキュリティチェックをバイパスしてはならない。
- **PIIマスキング**: キャッシュされるデータもあらかじめマスクされたものであることを保証する（既存の `PIIMasker` の後にキャッシュを適用）。
