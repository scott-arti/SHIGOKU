---
task_id: SGK-2026-0120
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Spec: AsyncNetworkClient のループ耐性向上と Event loop is closed エラーの修正

## 概要

`RaceConditionTester` 等の並列処理中に `Event loop is closed` エラーが発生し、攻撃が失敗する問題を修正する。

## 根本原因

- `AsyncNetworkClient` がインスタンス化された後、異なる `asyncio` イベントループで `request()` が呼ばれると、内部の `aiohttp.ClientSession` が古いループを参照し続け、エラーが発生する。
- SHIGOKU のアーキテクチャ上、エージェントやクライアントがシングルトン的に使い回されることが多く、ループの寿命と不一致が起きやすい。

## 変更範囲

- `src/core/infra/network_client.py`

## 修正内容

### 1. `AsyncNetworkClient` の修正

- **セッション検証ロジックの追加**:
  - `request()` 呼び出し時に、現在の `_session` が存在する場合、その `_session.loop` が現在の `asyncio.get_running_loop()` と一致しているか確認する。
  - 不一致の場合、またはループが閉じている場合は、既存のセッションを破棄し、再作成 (`start()`) を行う。
- **排他制御**:
  - セッションの再作成が並列リクエストによって重複して行われないよう、`asyncio.Lock` を導入して `start()` メソッドを保護する。

### 2. `RaceConditionTester` のエラーログ改善 (Optional)

- 必要に応じてワーカーのエラーログを詳細化する。

## 検証方法

1. 再現スクリプトを作成し、イベントループを跨いで `AsyncNetworkClient` を使用した場合にエラーが発生しないことを確認する。
