---
task_id: SGK-2026-0310
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-0_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-2-scope-admission-per-origin-budget-policy_subtask_plan.md
title: 'Swarm並列化 Phase 1: additive execution contract と debug metadata'
created_at: '2026-06-26'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/domain/model/task.py, session/report readers, debug metadata
---

# 実装計画書：Swarm並列化 Phase 1: additive execution contract と debug metadata

## 1. 達成したいゴール（ユーザー視点）
- [x] 並列化前に、task / specialist / request を同じ識別子で追跡できる互換metadata基盤を追加すること。
- [x] 既存 `TaskState` enum や report/session schema を壊さず、旧artifactも読めること。
- [x] Phase 2以降の admission、rate limit、lane、mutex、pruning が参照する `origin_key` / `target_key` / lifecycle metadata の契約を固定すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/domain/model/task.py`: Task metadata / serialization の追加候補。
  - `src/core/engine/master_conductor_session_service.py`: session保存時の追加metadata保持候補。
  - `src/core/engine/master_conductor_state_snapshot.py`: async session payload 復元時の互換 reader 確認候補。
  - `src/core/models/task_execution_log.py`: 実行記録側の既存 `metadata` 保持口との接続確認候補。
  - `src/reporting/`: report reader / formatter の互換性確認候補。
  - `tests/`: serialization、reader互換、metadata欠落時の回帰テスト。
- **データの流れ / 依存関係:**
  - Task生成 -> additive metadata付与 -> session/debug/report保存 -> downstream reader。
  - Phase 2-6 は本フェーズの識別子を前提にする。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** Task、task params、target URL、auth context、recon snapshot、generation reason、finding/evidence情報。
- **出力/結果 (Output):** `target_key`、`origin_key`、`canonical_endpoint_key`、`session_key`、`auth_context_version`、`recon_snapshot_version`、`correlation_id`、`generation_reason`、`evidence_key`、`attack_hypothesis_id`、`request_fingerprint`、`payload_fingerprint`、`mutation_chain_id`、`schema_version`。
- **制約・ルール:**
  - 既存 `TaskState` はこのフェーズでは破壊的に変更しない。
  - `waiting_dependency`、`admitted`、`invalidated`、`retired`、`superseded` は `lifecycle_status` / `lifecycle_reason` などのmetadataで表現する。
  - metadata欠落時はserial互換で動作し、active/mutating/aggressive判定は後続Phaseでfail closedへ寄せる。
  - 既存session/report fieldの削除・改名は禁止。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `Task` の現行serialization reader/writerを検索し、追加metadataの読み書き影響範囲を一覧化する。
- [x] ステップ2: metadata用の追加フィールドまたは `metadata` map の契約を決め、旧artifact読み込み時のdefault値を定義する。
- [x] ステップ3: `origin_key` / `target_key` / `canonical_endpoint_key` は Phase 1 では契約名、保存場所、欠落時default、最小導出責務だけを固定し、admission / budget 用のfail-closed判定や本格正規化は Phase 2 へ送る。
- [x] ステップ4: lifecycle metadata (`lifecycle_status` / `lifecycle_reason` / `superseded_by` / `invalidated_by`) を追加し、既存 `TaskState` と衝突しないようにする。
- [x] ステップ5: `Task.to_dict()`、`build_async_session_payload()`、`serialize_legacy_session_task_queue()`、`restore_task_queue_from_session_payload()`、`restore_completed_tasks_from_session_payload()`、`deserialize_legacy_session_task_queue()` の各境界で追加metadataを保持し、欠落時にreaderが落ちないことを確認する。
- [x] ステップ6: `.venv/bin/pytest` で Task serialization、session reader、report reader の関連テストを実行する。(149 tests PASS)

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] enumを急に増やすと既存readerが壊れる - Phase 1ではmetadata表現に留める。
- [ ] [重要度:高] origin正規化が曖昧だとrate limit/mutexが効かない - Phase 2開始前に正規化責務を固定する。
- [ ] [重要度:中] metadataが増えすぎてログが読みにくくなる - debug bundle向け詳細と通常ログ向け要約を分ける。

## 6. 実装前レビュー結果（2026-06-26）

### 6.1 Phase要約
- **目的:** Phase 2以降が同じ実行単位を参照できるように、既存 `TaskState` と既存session/report fieldを壊さず、Task / session / debug record に additive な execution contract metadata を保存・復元できるようにする。
- **Non-Goals:** 並列度変更、admission / budget のfail-closed実装、lane / mutex scheduler、Event-Driven Chaining、pruning実装、`TaskState` enum の破壊的変更、既存session/report fieldの削除・改名。
- **前提条件:** Phase 0が完了済みで、Phase 1以降の保護対象と初期非対象が親計画にトレース可能であること。現行 `Task` は `metadata` / `from_dict` を持たず `to_dict()` のみを持つため、reader/writer境界を先に固定すること。
- **完了条件:** 旧artifactを読むreaderが落ちず、新metadataがあるartifactでは `target_key` / `origin_key` / lifecycle / correlation 系の値が Task payload、async session payload、legacy checkpoint payload、task execution record のいずれかの定義済み場所に保持されること。

### 6.2 Ready / Not Ready
- **判定: Ready（本レビュー追記を実装時チェックリストとして扱う条件付き）**
- 理由: Phase順序は壊れておらず、Phase 0完了後にPhase 2のadmission/budgetへ渡す契約を固定する位置づけは妥当。ただし実装時は、下記Local Blocker相当の境界確認を最初のTDDで固定してからコード変更すること。

### 6.3 根拠
- `src/core/domain/model/task.py`: `TaskState` は `pending/running/success/failed/replanned/skipped` の既存enumで、`Task` は `metadata` field や `from_dict` を持たず、`to_dict()` が既存fieldのみを返す。
- `src/core/engine/master_conductor_session_service.py`: `build_async_session_payload()` は `task_queue` / `completed_tasks` を手書き辞書で保存し、`serialize_legacy_session_task_queue()` / `deserialize_legacy_session_task_queue()` はlegacy checkpoint用の別schemaを持つ。
- `src/core/engine/master_conductor_state_snapshot.py`: async session復元時に `TaskState(state_str)` を直接解釈し、未知stateは `PENDING` / `SUCCESS` へ倒すため、Phase 1でenum拡張すると互換性リスクが高い。
- `src/core/models/task_execution_log.py`: `TaskExecutionRecord.metadata` は既存の追加metadata保持口として利用候補だが、Task本体やsession payloadとの対応契約は未固定。
- `src/reporting/run_narrative_formatter.py` と `src/reporting/target_profile_formatter.py`: session dictの欠落fieldに比較的寛容だが、新metadataを読めることと、旧artifactで落ちないことを明示テストする必要がある。

### 6.4 Local Blocker
- [x] **LB-1: Task metadataの保存場所が未固定。** `Task` に `metadata` mapを足すのか、execution contract専用field群を足すのかを実装前に決める。解決条件: `Task.to_dict()` と復元境界のテストが先に失敗すること。→ `Task` に `metadata: Dict[str, Any]` map を追加し、TDDで完了。
- [x] **LB-2: serialization境界が複数ある。** `Task.to_dict()` だけを変更しても `build_async_session_payload()` とlegacy checkpointには反映されない。解決条件: async session、legacy checkpoint、state snapshot restore の3系統テストを追加すること。→ 6境界すべて対応済み。
- [x] **LB-3: Phase 1とPhase 2の責務境界が曖昧。** `origin_key` 正規化の本格policy、scope unknown時のreject、per-origin budgetは Phase 2 に残す。解決条件: Phase 1では「契約名・保存・欠落時default・最小導出」に限定すること。→ 契約名/保存/default/最小導出に限定して実装。
- [x] **LB-4: lifecycle metadataと `TaskState` の二重表現リスク。** `waiting_dependency/admitted/invalidated/retired/superseded` は `TaskState` に入れず、metadataとして保存し、既存state集計に影響させないテストを追加すること。→ lifecycle_status は metadata のみ、TaskState 変更なし。

### 6.5 Local Deferred
- [ ] **Phase 2 (`SGK-2026-0311`): `origin_key` 欠落時のfail-closed admission。** 安全な理由: Phase 1は挙動変更なしのmetadata保持に限定し、active/mutating/aggressiveの実行可否はまだ変えない。検出方法: Phase 2で scope unknown / out-of-scope / origin_key欠落のreject reasonテストを追加する。
- [ ] **Phase 4 (`SGK-2026-0313`): lane / mutex / budget のshadow decision記録。** 安全な理由: Phase 1ではdecisionを下す材料の識別子だけを保存し、スケジューリング判断は行わない。検出方法: Phase 4で serial実行結果を変えずに全taskへshadow decisionが付くsnapshot testを追加する。
- [ ] **Phase 6 (`SGK-2026-0315`): `invalidated_by` / `superseded_by` / `retired_by_event_id` の実運用。** 安全な理由: Phase 1ではlifecycle metadataの器だけを作り、Event-Driven Chainingやpruning decisionはまだ発生させない。検出方法: Phase 6で stale recon/auth snapshot と protected task pruning の回帰テストを追加する。
- [ ] **Phase 8 (`SGK-2026-0317`): request / payload / mutation fingerprint を使った内側並列化評価。** 安全な理由: Phase 1ではfingerprint保存契約を固定し、SwarmDispatcher / SwarmManager内側並列化は行わない。検出方法: Phase 8で specialist parity、partial failure aggregation、deterministic replay testを追加する。

### 6.6 Parent Change Request
- [ ] 親計画へ、Phase 1の必須serialization境界として `Task.to_dict()`、`build_async_session_payload()`、`serialize_legacy_session_task_queue()`、`restore_task_queue_from_session_payload()`、`restore_completed_tasks_from_session_payload()`、`deserialize_legacy_session_task_queue()` を明記する。→ **不採用（Phase 固有の実装詳細につき親計画へ昇格せず）**
- [x] 親計画へ、`execution_contract_schema_version` の互換性方針を追加する。→ **親計画 Section 3 へ昇格済み**
- [x] 親計画へ、debug metadataの秘密情報境界を追加する。→ **親計画 Section 3 へ昇格済み**

### 6.7 Out of Scope
- [ ] `TaskState` enumへの `admitted` / `invalidated` / `retired` / `superseded` 追加。
- [ ] `ActionAdmissionPolicy` / `ExecutionBudgetPolicy` の実装。
- [ ] `ParallelOrchestrator` のrate limiter入力変更。
- [ ] lane scheduler、mutex acquisition、queue admission制御、EventBus reliability classの実装。
- [ ] SwarmDispatcherやSwarmManagerの並列度変更。
- [ ] report/session既存fieldの削除・改名。

### 6.8 TDDチェックリスト
- [x] `tests/core/domain/model/test_task_execution_contract_metadata.py` などで、metadata未指定の `Task` が従来fieldだけで生成・`to_dict()` できることを先に固定する。
- [x] 同テストで、execution contract metadata指定時に `Task.to_dict()` が `metadata` または専用contract fieldをdeep copy相当で返し、呼び出し側mutationが内部状態へ逆流しないことを確認する。
- [x] `tests/core/engine/test_master_conductor_session_payload_builder.py` に、`build_async_session_payload()` が queue/completed task の追加metadataを保持し、metadata欠落taskではfieldを省略またはdefaultに倒すテストを追加する。
- [x] `tests/core/engine/test_master_conductor_session_service.py` に、legacy checkpoint serializer/deserializerが新metadataを保持し、旧JSONを読むとdefault metadataで復元するテストを追加する。
- [x] `tests/core/engine/test_master_conductor_state_snapshot.py` などで、未知lifecycle metadataが `TaskState` 変換に影響しないこと、未知 `TaskState` 文字列は既存fallbackのまま扱われることを固定する。
- [x] `tests/unit/reporting/test_run_narrative_formatter.py` / `tests/unit/reporting/test_target_profile_formatter.py` に、新metadataあり・なしのsession dictを渡してformatterが落ちないテストを追加する。
- [x] 秘密情報境界テストとして、metadataにcookie/token/header実値を入れない、またはredacted placeholderしか保存しないことを確認する。

### 6.9 Go/No-Go Gate
- [x] **Go:** 旧session artifact相当のpayloadをreader / formatterへ渡して例外が出ない。
- [x] **Go:** 新metadataありのTaskが async session payload、legacy checkpoint payload、TaskExecutionRecord metadata の定義済み場所へ保持される。
- [x] **Go:** `TaskState` enumの値は増やさず、既存state集計が変わらない。
- [x] **Go:** Phase 2が必要とする `origin_key` / `target_key` / `canonical_endpoint_key` / `schema_version` の欠落時defaultと保存場所がテストで固定されている。
- [x] **Go:** `.venv/bin/pytest` の対象テストが成功し、`python3 scripts/sync_shigoku_updated_at.py` 後に `python3 scripts/validate_shigoku_docs.py` が0エラー。
- [x] **No-Go (未該当):** 既存session/report fieldを削除・改名している。
- [x] **No-Go (未該当):** metadata欠落時にserial実行、session復元、report formatterのいずれかが落ちる。
- [x] **No-Go (未該当):** cookie/token/header実値などのsecretをdebug metadataへ保存している。
- [x] **No-Go (未該当):** Phase 1内でadmission reject、budget enforcement、lane/mutex制御、parallelism変更を実装している。

### 6.10 Shadow / Differential Testing
- [x] **Task serialization differential:** 旧 `Task.to_dict()` 相当の期待payloadと、新metadata未指定時のpayloadを比較し、既存field値が変わらないことを確認する。
- [x] **Session payload differential:** metadata未指定taskの `build_async_session_payload()` 出力を既存テスト期待値と比較し、追加fieldが不要に出ないことを確認する。（空 `metadata: {}` のみ追加）
- [x] **Legacy checkpoint differential:** 旧JSON文字列を `restore_legacy_resume_session_state()` へ渡し、復元Taskの既存属性が変わらないことを確認する。
- [x] **Reader differential:** 新metadataあり/なしのsession dictを `RunNarrativeFormatter` と `TargetProfileFormatter` に渡し、出力生成可否と主要カウントが変わらないことを確認する。
- [x] **Secret differential:** metadata候補にsecret-bearing値が混入した場合、保存対象から除外またはredactされることをsnapshotで確認する。

### 6.11 Phase順序再レビュー
- Phase 0 -> Phase 1: **順序は妥当。** Phase 0は現状正本化と非対象固定が完了済みで、Phase 1はその成果を受けて挙動変更なしの契約追加へ進む。
- Phase 1 -> Phase 2: **順序は妥当。ただし境界注意。** Phase 1で `origin_key` 等の契約・保存・欠落defaultを固定し、Phase 2でscope/admission/per-origin budgetのfail-closed実装を行う。
- Phase 1 -> Phase 3/4: **順序は妥当。** correlation / session / auth/recon versionが先に保存されることで、context isolation と shadow decision の観測が可能になる。
- Phase 1 -> Phase 5以降: **直接実並列化へ進まない限り妥当。** Phase 5以降のGo条件を壊さないため、本フェーズでは並列度・admission・mutex・pruningの実挙動変更を禁止する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0310-D01
    title: "継続監視: execution contract metadata の互換性"
    reason: "後続フェーズでmetadata参照が増えるため、reader互換性の継続確認が必要"
    impact: medium
    tracking_task_id: SGK-2026-0310
    recommended_next_action: "Phase 2以降の実装時にmetadata欠落artifactの回帰テストを追加する"
```
