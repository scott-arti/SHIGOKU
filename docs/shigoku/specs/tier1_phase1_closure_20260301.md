---
task_id: SGK-2026-0161
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-03-01'
updated_at: '2026-05-19'
---

# Spec: Tier 1 (Phase 1 Closure) - `multipart/form-data` 対応 & Swarm Semaphore

## 概要

SHIGOKU 実装ロードマップ「Tier 1: クイックウィン」における Phase 1 (IDOR 検知路線の完全体化) の残タスクを実装する。

1. `BodyMutator` に `multipart/form-data` 対応を追加し、ファイルアップロード等に関する IDOR や Payload 変異テストを可能にする（これにより Phase 1 の BodyMutator 強化ステップが完了する）。
2. `SwarmManager` およびその派生クラス (`BaseManagerAgent` など) におけるタスク実行（Worker/Specialist 呼び出し）に `asyncio.Semaphore` を用いた並行実行制御を導入し、エージェントの過剰生成やAPIのレート制限・メモリ圧迫を防ぐ安定性を担保する。

## 変更範囲

- **`src/core/agents/swarm/logic/body_mutator.py`**
  - `parse`, `serialize`, `extract_ids`, `replace_value`, `inject_properties`, `duplicate_param` 等の各種メソッドに対し、`multipart` 対応の分岐を追加実装。
- **`src/core/agents/swarm/base.py`** (クラス `SwarmManager` 等)
  - タスクの並行処理を行う箇所に `asyncio.Semaphore` の導入と適用。
- **`src/core/agents/swarm/base_manager.py`** (クラス `BaseManagerAgent` 等)
  - `dispatch` のループ、またはエージェント呼び出しの非同期処理部分におけるセマフォの実装。
- （オプション）同時実行数パラメータの設定追加（config や初期化引数）

## 挙動 (Input/Output)

### 1. `multipart/form-data` 対応

- **Input**: HTTPリクエストのボディ文字列（Boundaryを含む `multipart/form-data` 形式）。
- **処理**:
  - `BodyMutator.parse` により、指定されたBoundaryを用いて各パートを解析し、ディクショナリ形式の構造データとして取り扱えるようにする。
  - `BodyMutator.serialize` により、改変後のディクショナリから再度同等のBoundaryを持つマルチパート文字列（バイト列）を再構築する。
  - `duplicate_param` メソッドなどで、HTTP Parameter Pollution（HPP）テスト用に特定の Form フィールドを複数個（同名で）含む Body を生成できるようにする。
- **Output**: 適切にパースまたは再構築・変異された multipart データとして返却する。

### 2. セマフォ制御

- **Input**: 多数の `Task` または呼び出される Agent / Worker。
- **処理**: `SwarmManager` の初期化時に `self.semaphore = asyncio.Semaphore(self.max_concurrent_tasks)` を生成する。ワーカーによる非同期処理 `await execute(...)` などの実行前に `async with self.semaphore:` のブロックで包むか、トークンを取得してから実行させる。
- **Output**: 同時に動くタスクが指定した上限数に保たれ、負荷が安定化する。

## 制約

1. **EthicsGuardの整合性**
   - Body の変異（multipart 対応）はあくまでペイロードの生成処理であり、リクエスト送信自体は従来通り `NetworkClient` および `EthicsGuard` のスコープチェックを通るため、セキュリティ検査への影響はないこと。
2. **既存アーキテクチャの維持（副作用回避）**
   - `BodyMutator` はこれまで通り「ステートレスな純粋関数」として動作すること。インスタンス変数などに依存せず処理を完結させる。
   - `Semaphore` を導入する際、例外時にも確実に `release()` が行われるよう `async with` などの安全な構文を用い、デッドロックで全体の進行が停止しないよう留意する。
