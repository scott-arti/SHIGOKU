---
task_id: SGK-2026-0287
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
title: Task Queue Pruning Policy 設計計画
created_at: '2026-06-21'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/engine/task_queue.py, src/core/engine/master_conductor.py, src/core/engine/strategy_optimizer.py
---

# 実装計画書：Task Queue Pruning Policy 設計計画

## 1. 達成したいゴール（ユーザー視点）
- [ ] MasterConductor の未処理キューから、他タスクの結果によって不要化したタスクを安全にパージできること。
- [ ] 何を、なぜ、いつパージしたかをセッション/デバッグログ/最終レポートで追跡できること。
- [ ] coverage guard、手動確認、scope検証、証跡取得などの必須タスクは誤って消さないこと。
- [ ] パージ判断は初期実装では保守的にし、 aggressive な削除は shadow mode で観測してから有効化できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/task_queue.py`: 未実行タスクの列挙、ID削除、asset単位削除、保護タスク判定の拡張。
  - `src/core/engine/master_conductor.py`: Finding/成功/失敗/chain/handoff後に prune 評価を呼び出す接続点。
  - `src/core/engine/strategy_optimizer.py`: 既存の低ROI asset pruning を新しい policy engine に寄せる。
  - `src/core/engine/task_pruning_policy.py`（新規候補）: pruning rule、shadow decision、audit record を集約。
  - `src/core/engine/master_conductor_session_service.py`: セッション保存時に prune decision を含める候補。
- **データの流れ / 依存関係:**
  - TaskResult/Finding/Context -> PruningPolicy.evaluate(queue snapshot) -> prune candidates/shadow decisions -> TaskQueue.remove_by_id/remove_matching -> audit log/session event。
  - 既存の優先度制御（boost/inject）より後段で評価し、パージより boost が妥当な場合は削除しない。
  - 初期は `shadow_only=true` を既定値にし、実行結果と削除候補の妥当性を観測する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 完了タスク、実行結果、Finding、現在の TaskQueue snapshot、ExecutionContext、KnowledgeGraph の asset/tech/finding 状態。
- **出力/結果 (Output):** prune decision list、実削除件数、skip理由、保護理由、shadow/audit event。
- **制約・ルール:**
  - scope_parser、coverage_guard、scenario_probe、manual_verify、report/evidence 系は原則 prune protected とする。
  - parent/child 依存を持つタスクは、親が成功して不要化した場合のみ削除候補にする。親が失敗した場合は代替・retry・handoff との競合を先に確認する。
  - 同一 target/agent/action/params_hash の重複、同一endpointの低価値静的資産、chain成立後に価値が下がった探索、out-of-scope確定済みtargetを初期候補にする。
  - Finding が出た場合は関連タスクを削除より優先度調整する。chainに必要な補強証跡タスクは削除しない。
  - 削除判断には `reason_code` を必須化し、後から誤削除を検証できるようにする。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `TaskPruningDecision`/`TaskPruningPolicy` の最小データモデルを定義し、shadow mode で候補だけ出せるようにする。
- [ ] ステップ2: `DynamicTaskQueue` に `remove_matching()` または安全な `remove_by_ids()` を追加し、ディスク退避タスクも含めて削除できるか確認する。
- [ ] ステップ3: MasterConductor の Finding処理、task成功処理、strategy review後に policy 評価を接続する。
- [ ] ステップ4: 初期ルールを保守的に実装する。重複タスク、out-of-scope確定、静的低価値asset、既にchainで代替済みのfollow-upを対象にする。
- [ ] ステップ5: audit event とセッション保存を追加し、レポート時に「パージされたため未実行」の説明を出せるようにする。
- [ ] ステップ6: 単体テストで protected task が残ること、shadow mode で削除されないこと、実削除時にheap/index/SQLiteが整合することを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 誤パージで検証漏れが起きる - 初期は shadow mode と protected list を厚めにし、削除は明示設定で有効化する。
- [ ] [重要度:中] parent_id だけでは依存関係が粗い - 将来は explicit DAG/PlanGraph に移行し、depends_on/invalidates/supersedes を持たせる。
- [ ] [重要度:中] 並列実行中タスクとの競合 - in-flight task は対象外にし、キューsnapshotとstate lockの境界を明確化する。
- [ ] [重要度:中] レポート上「未実行」が失敗に見える - prune reason を report/session に残し、coverage評価では別扱いにする。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0287-D01
    title: "継続監視: pruning shadow decision の妥当性レビュー"
    reason: "初期実装では保守的に候補観測を優先し、実削除の有効化判断を後続レビューへ回す"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "実セッションの prune audit を数件レビューし、実削除ルールの許可範囲を確定する"
```
