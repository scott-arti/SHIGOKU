---
task_id: SGK-2026-0155
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: コードプロファイリングの導入

## 1. 概要

SHIGOKUのパフォーマンスデバッグを科学的に行うため、関数の実行時間を計測するコードプロファイリング機能を導入します。
外部ツールの導入（OpenTelemetry等）ではなく、まずはプロジェクト全体で使いやすくオーバーヘッドの少ない「カスタムデコレータ」方式を採用します。

## 2. 実装要件

### 2.1. プロファイリング用デコレータ

- `src/core/utils/profiling.py` を新規作成します。
- 以下の2つのデコレータを提供します：
  - `@timed`: 同期関数用
  - `@timed_async`: 非同期関数用
- **引数**:
  - `name` (Optional[str]): ログに出力する識別名。省略時は関数名。
  - `threshold_ms` (int): 実行時間がこの値を超えた場合のみ警告ログを出力します（デフォルト: 100ms）。

### 2.2. ロギング

- 専用のロガー `shigoku.perf` を使用します。
- ログレベルは `WARNING` とし、実行時間が閾値を超えた場合にのみ `SLOW_OP` プレフィックスを付けて出力します。

### 2.3. 適用対象の選定

最初のフェーズでは、以下の「重い」ことが予想されるコア部分に適用します：

1. **MasterConductor**: タスクの実行制御ループ
2. **NetworkClient**: HTTPリクエスト送信処理
3. **ReconOrchestrator**: パイプライン全体の実行

## 3. 挙動の詳細

```python
@timed(threshold_ms=500)
def heavy_processing():
    # ...
    pass

# 出力イメージ (500msを超えた場合):
# [WARNING] SLOW_OP: heavy_processing took 1250.45ms
```

## 4. 制約・考慮事項

- **EthicsGuardとの整合性**: プロファイリングログにPII（個人情報）や機密情報（トークン等）が含まれないようにします。
- **パフォーマンス負荷**: `time.perf_counter()` を使用し、ナノ秒精度の軽量な計測を行います。
- **エラーハンドリング**: プロファイリング中に例外が発生しても、元の関数のエラー内容が正しく伝播するように `try...finally` を使用します。
