---
task_id: SGK-2026-0160
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Spec: Shutdown Cleanup and Resource Management Fixes

## 概要

SHIGOKUのシャットダウン時および実行中に発生する `Unclosed client session` および `Unclosed connector` エラーを解消し、リソースリークを防止するためのグレースフルシャットダウン機能を実装します。

## 現状の課題

1.  **強制終了**: `MasterConductor._handle_signal_shutdown` が `sys.exit(0)` を直接呼び出しているため、`asyncio` のクリーンアップ処理（セッションのクローズ等）がスキップされている。
2.  **不適切なループ管理**: `MasterConductor._dispatch` 内で `SwarmDispatcher` を呼び出す際、毎回 `asyncio.new_event_loop()` を作成・閉鎖しており、内部で作成された `aiohttp` セッションが適切にクローズされないリスクがある。
3.  **クリーンアップの欠如**: `InteractiveBridge` や `main.py` において、`MasterConductor` の終了時に明示的なリソース解放処理（すべてのWorkerやClientの閉鎖）が行われていない。

## 変更内容

### 1. `MasterConductor` の拡張

- `async shutdown()` メソッドを追加:
  - 実行中の `task_queue` の保存（既存の `save_session` を呼び出し）。
  - 通知の送信。
  - （将来的に）実行中のバックグラウンドタスクのキャンセルと待機。
- `close()` メソッドを追加（同期用ラッパー）:
  - 内部で `asyncio.run(self.shutdown())` 等を安全に呼び出す（ループの状態に応じて）。
- `_handle_signal_shutdown` を非同期対応またはフラグベースに移行し、強制終了を回避。

### 2. `InteractiveBridge` の修正

- `start_interactive_session` の `try...finally` ブロックで `mc.shutdown()` を確実に呼び出すように修正。

### 3. `SwarmDispatcher` / `_dispatch` のループ管理改善

- `MasterConductor._dispatch` 内でのループ生成を避け、可能な限り既存のループを再利用するか、生成した場合は `dispatcher.close()` 等を呼び出して内部リソースを確実に解放する。

### 4. `main.py` の修正

- `ReconWorker` スレッドの待機だけでなく、`MasterConductor` のクリーンアップも行う。

## 挙動への影響

- `Ctrl+C` や終了時に、エラーメッセージ（Unclosed client session）が出力されなくなる。
- リソースが適切に解放され、ゾンビプロセスやコネクションのリークが抑制される。

## 制約

- `EthicsGuard` や既存の `save_session` ロジックを壊さないこと。
- シグナルハンドラが複数回呼ばれた場合の冪等性を確保すること。
