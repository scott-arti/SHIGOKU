---
task_id: SGK-2026-0315
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md
title: 'Swarm並列化 Phase 6: Event-Driven Chaining と pruning invalidation 統合'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/core/infra/event_bus.py, MasterConductor event handlers, TaskPruningPolicy,
  TaskQueue
---

# 実装計画書：Swarm並列化 Phase 6: Event-Driven Chaining と pruning invalidation 統合

## 1. 達成したいゴール（ユーザー視点）
- [ ] 順序依存taskを最初から一括queue投入せず、先行event起点で後続taskを遅延生成できること。
- [ ] 未実施だが不要になったpending taskを `retired` / `superseded` / `invalidated` として失敗と区別して記録できること。
- [ ] `SGK-2026-0287` の pruning policy と矛盾せず、protected taskを誤退役しないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/infra/event_bus.py`: event reliability class、queue full、handler error、dead-letter方針。
  - `src/core/engine/master_conductor.py`: vulnerability chaining / event handler / task generation接続。
  - `src/core/engine/task_pruning_policy.py`（候補）: pruning shadow decision / retire / supersede / invalidation。
  - `src/core/engine/task_queue.py`: pending task退役の安全な反映。
  - session/debug/report保存箇所: pruning / event auditの保存。
- **データの流れ / 依存関係:**
  - Finding / task result event -> EventBus -> handler -> follow-up task generation -> pruning/invalidation evaluation -> TaskQueue decision record -> session/report audit。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** Event payload、TaskQueue snapshot、TaskResult、Finding、recon/auth snapshot version、PruningPolicy decision。
- **出力/結果 (Output):** generated follow-up task、retired/superseded/invalidated decision、event audit、dead-letter/audit metrics。
- **制約・ルール:**
  - follow-up生成に必要なeventは `critical` または `important` とし、queue fullで黙ってdropしない。
  - `best_effort` event以外はdrop時にdead-letterまたは明示errorを残す。
  - protected task（scope_parser、coverage_guard、manual_verify、report/evidence等）はpruningしない。
  - in-flight task は退役対象外にし、pending taskのみdecision recordを残す。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: EventBusの既存emit/handler/queue full挙動を棚卸しし、reliability classを追加設計する。
- [ ] ステップ2: vulnerability chaining / follow-up task generation のevent contractを定義する。
- [ ] ステップ3: `TaskPruningPolicy` のshadow decisionを `retired` / `superseded` / `invalidated` lifecycle metadataへ接続する。
- [ ] ステップ4: enqueue時、dequeue時、start直前の3点validity checkで stale recon/auth snapshot を止める。
- [ ] ステップ5: session/report/debugに「未実施だが不要化」の理由を出す。
- [ ] ステップ6: EventBus queue full、handler failure/retry、stale invalidation、protected pruning、report/session audit testを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] event dropで後続taskが生成されずFalse Negativeになる - critical/important eventのdrop禁止をテストで固定する。
- [ ] [重要度:高] 誤pruningでcoverageが欠ける - 初期はshadow優先、protected listを厚くする。
- [ ] [重要度:中] duplicate eventで後続taskが重複する - event id / generation_reason / evidence_key でdedupeする。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0315-D01
    title: "継続監視: Event-Driven Chaining と pruning decision の妥当性"
    reason: "遅延生成と退役判断は検出網羅性へ影響するため継続レビューが必要"
    impact: medium
    tracking_task_id: SGK-2026-0315
    recommended_next_action: "実セッションのevent/pruning auditをレビューし、protected listとdedupe条件を調整する"
```

---

## 6. Phase 5 レビュー由来の横断制約（2026-06-28・実装前必須・Blocker級）
Phase 5（SGK-2026-0314）完了レビューで判明した制約。Phase 6 は finding replay 点へ event を繋ぐため再入リスクが最大。実装者が間違えないよう Go/No-Go gate で固定する。

### 6.1 必須設計制約（MUST・違反は実装停止）
- [ ] **C1【再入禁止】: event handler の task_queue 同期 mutation 禁止。** event emission を `_apply_post_batch_feedback`(`mc:6123`) へ繋ぐ場合、同関数は `batch_tasks` をイテレート中（`mc:5706`・`_state_lock` 下）。event handler が同期的に `task_queue.add` を呼ぶと **イテレーション中の再入で task skip・heap 破壊** が起きる。→ event と follow-up task 生成は「replay 中に遅延キューへ溜め、loop 終了後に dispatch」設計にすること。同期 emit+handle は禁止。
- [ ] **C2【main-thread 制約】: task_queue / accumulated_context mutation は main thread のみ（PCR-4）。** `DynamicTaskQueue` は内部 lock なし（`task_queue.py` の `_heap`/`_task_index`/`_removed_seqs`）。Phase 5 が `_apply_post_batch_feedback` で main thread 集約にした。EventBus handler が別 thread で動くなら handler 内で直接 `task_queue.add/boost_priority/inject_context` を呼ばない（main thread へ marshal、または event をキューへ入れて main thread 処理）。実装前に `threading.main_thread()` assert を task_queue mutation 箇所へ入れること。
- [ ] **C3【dataclass 化】: `_post_batch_feedback` の typed dataclass 化（FU-2）。** 現在8 field・string-key dict（`mc:6610`）。Phase 6 が event/pruning field を追加する前に `PostBatchFeedback` dataclass へ移行すること（typo bug・field 衝突防止）。
- [ ] **C4【事前確認】: injection feedback 伝播の確認（FU-3）。** Phase 6 は injection finding に依存する。Phase 6 step1 の前に injection-type task の feedback が `_apply_post_batch_feedback` 経由で伝播することを test 1 本で確認（Phase 5 で未テスト）。
- [ ] **C5【lifecycle】: `retired`/`superseded`/`invalidated` は metadata 表現（TaskState enum 変更なし）。** Phase 1 で enum 追加は deferred 済み。`lifecycle_status`/`lifecycle_reason`/`retired_by_event_id`/`invalidated_by` を `Task.metadata` へ。永続 enum 化は reader 互換性確認後に別 Phase。
- [ ] **C6【sink 正規化】: decision 永続化は `decision_traces`（PCR-3）。** pruning/invalidation decision は `build_async_session_payload(decision_traces=...)` へ。debug bundle は未実装（grep 0 hit）なので依存しない。

### 6.2 Phase 6 Go/No-Go Gate（追加）
- [ ] **Go:** event handler が遅延キュー経由でのみ follow-up task を生成し、`_apply_post_batch_feedback` イテレーション中の task_queue 再入が 0 件（C1）。
- [ ] **Go:** `task_queue` mutation が全て main thread 上・`threading.main_thread()` assert 付き（C2）。
- [ ] **No-Go:** EventBus handler が別 thread から task_queue を直接 mutate する（C2 違反・queue 破壊）。
- [ ] **No-Go:** critical/important event が queue full で黙って drop される（親計画 4.1 Event reliability）。

### 6.3 参照
Phase 5 計画書 6.13（FU-2/FU-3）・親計画 PCR-3/PCR-4。参照ルール: `rules/lessons.md`・`rules/codingrules.md`。

---

## 7. 実装前レビュー結果（2026-06-29・コード根拠ベース）

### 7.1 Phase要約（コード根拠ベース）
- **目的:** (a) 順序依存taskを事前一括queue投入せず先行event起点で遅延生成、(b) 不要化pending taskを `retired`/`superseded`/`invalidated` として失敗と区別して記録、(c) SGK-2026-0287 pruning policy と矛盾せず protected task を退役しない。
- **Non-Goals:** TaskState enum 変更（C5・Phase 1 deferred）、debug bundle 標準化（C6 依存しない・未実装 grep 0件）、pool 復活（Phase 8）、protective degrade mode（Phase 7）、injection URL 並列化（Phase 8）、EventBus thread model 根本変更（SharedLoopManager → main-loop 統合は Phase 8/9）。
- **前提条件（実コード確認）:**
  - Phase 5 成果物: `_apply_post_batch_feedback`(`mc:5693`) が `_state_lock` 下・main thread で `batch_tasks`(`mc:5712`) をイテレート。`result["_post_batch_feedback"]`(`mc:6616`) は8 field の string-key dict（FU-2）。
  - Phase 4 成果物: `SchedulingDecision`(`scheduling_decision.py:18`)・`LanePolicy`(`lane_policy.py:21`)・`MutexPolicy`(`mutex_policy.py:9`) 実在。`decision_traces` は `build_async_session_payload(decision_traces=...)`(`master_conductor_session_service.py:73,141-142`) で永続化、report 側が `run_narrative_formatter.py:309` / `target_profile_formatter.py:987` で読む。
  - Phase 1 成果物: `Task.metadata: Dict[str, Any]`(`task.py:93`)・`_redact_secrets`(`task.py:31`)・`schema_version` 自動注入(`task.py:131-132`) 実装済み。lifecycle 系 field は型として存在せず runtime で詰める（grep: lifecycle_status/invalidated_by/retired_by_event_id は src 内 0件）。
- **完了条件:** 3ユーザーゴール ＋ C1-C6 設計制約 ＋ 7.5 Go/No-Go Gate。

### 7.2 Ready / Not Ready
- **判定（2026-06-29）: Not Ready — 4件の Local Blocker（LB-0〜LB-3）。** 最大は LB-0（前提Phaseの未実装）。LB-0 は親計画 SGK-2026-0291 での依存順序裁定が必須（Phase 6 単独では解決不可）。LB-1/LB-2/LB-3 は Phase 6 内部の設計で解消可能。C1-C6（section 6）はコード根拠で全て妥当確認済み（7.3 で補強）。

### 7.3 Local Blocker（Phase 6 実装前に必ず解決）
- [x] **LB-0【裁定済み 2026-06-29: 経路 (i) 選択】: SGK-2026-0287 を Phase 6 の前に完了（step1-6 全実装）。** 裁定結果: 経路 (i) — SGK-2026-0287 先行完了。0287 の step1-6（TaskPruningPolicy 本体・remove_matching/remove_by_ids・保守的実装）を実装してから Phase 6 へ進む。Phase 6 Milestone 4（pruning policy 最小）は 0287 完了成果物を接続する形に縮小される。
- [ ] **LB-1【既存race現状違反】: 既存 `_handle_vuln_found`(`mc:478-538`) が非main thread から `task_queue.add` を呼ぶ（C2 現状違反） → 既存 handler を含めて main-thread marshal 化。** EventBus worker(`_process_events`(`event_bus.py:226`)) は `asyncio.run_coroutine_threadsafe(self.event_bus.start(), loop)`(`mc:476`) で起動し、loop は `SharedLoopManager`(`async_utils.py:43-49`) が生成する `"ShigokuSharedLoop"` daemon thread 上で `run_forever`。よって `_handle_vuln_found` 内 `self._add_tasks(tasks_to_add, source="vulnerability_chaining")`(`mc:536`) → `task_queue.add` は SharedLoop thread から実行。`DynamicTaskQueue` は内部 lock なし（Phase 5 PCR-4）のため、main thread の `_apply_post_batch_feedback`(`mc:5737` の `task_queue.add`) と並行 heap mutation になる。同様に `_handle_reauth_success`/`_handle_reauth_failed`(`mc:540+`) 系も要確認。解決: Phase 6 は新 chaining を足す前に、既存 EventBus handler 群の task_queue mutation を全て (a) main-thread marshal（`run_coroutine_threadsafe` or `call_soon_threadsafe` で main loop へ） or (b) 遅延キュー経由（C1 設計を適用）へ移行。`threading.main_thread()` assert を task_queue mutation 箇所へ入れると現状落ちるはず（characterization T-0.1 で固定）。
- [ ] **LB-2【EventBus reliability】: `EventBus.emit()`(`event_bus.py:152-171`) が critical event も queue full で黙って drop する現状（親4.1 Event reliability / 本Phase Go gate 違反） → reliability class 設計に加えて drop 抑制機構を明示。** `emit` は `asyncio.wait_for(self._queue.put(event), timeout=5.0)` の `asyncio.TimeoutError` を catch して `logger.error(f"Event queue full, dropping event: {event.event_id}")` するだけ（`event_bus.py:170-171`）。reliability class 分岐・retry・dead-letter・persistence fallback 全て未実装。`emit_sync`(`event_bus.py:173-192`) も `asyncio.QueueFull` を catch して drop のみ。critical event（VULN_FOUND 等・`event_bus.py:32`）が 5s timeout で消える。design が reliability class 追加（step1）だけだと「class 分けしても全 class が同じ full-then-drop パスを使う」で解決しない。解決: critical/important は (i) blocking put（timeout 延長 or 無限待ち）(ii) persistence fallback（disk overflow queue）(iii) backpressure（producer 側で await）のいずれかを必須設計へ。best_effort のみ現状 drop 許容。`test_event_bus.py`(216行) に queue full test なし（grep 0件）。
- [ ] **LB-3【decision shape 未定義】: pruning/invalidation decision の `decision_traces` shape が未定義（C6 接続先不明） → shape を固定し report reader 互換性を保証。** `SchedulingDecision`(`scheduling_decision.py:18-32`) は lane/mutex/admission/budget 用で pruning field なし。`DecisionTrace.decision_type`(`decision_trace.py:12-21`) enum は `RECON_DISPATCH`/`VULN_HUNTER_DISPATCH`/`RECIPE_INJECTION`/`REPLAN`/`PRIORITY_BOOST`/`TARGET_ESCALATE`/`SKIP_TASK`/`FALLBACK` のみで retire/supersede/invalidate なし。`run_narrative_formatter.py:318` は `_DECISION_TYPE_JA` で既知 type のみ和訳し、未知 type は `decision_type` 生値が出力される（fallback はあるが人間可読性低下）。解決: Phase 6 step3 開始前に (a) `DecisionType` enum へ `TASK_RETIRED`/`TASK_SUPERSEDED`/`TASK_INVALIDATED` 追加 (b) pruning decision 用 dataclass（`task_id`/`lifecycle_status`/`reason_code`/`trigger_event_id`/`evidence_key`/`protected` field）を定義し `decision_traces` list へ同格納、の shape を固定。report 側の未知 type fallback test（T-5.1）を必ず追加。

### 7.4 TDDチェックリスト（C1-C6 + LB-0〜LB-3 を踏まえる）
- [ ] **T-0.1: `test_event_handler_thread_origin_characterization`** — 現状の `_handle_vuln_found`/`_handle_reauth_*` が `task_queue.add` を呼ぶ際の `threading.current_thread()` を記録し、SharedLoop thread（非 main）であることを固定。LB-1 解消後は main thread のみになることを回帰で使う（characterization）。
- [ ] **T-1.1: `test_critical_event_not_dropped_on_queue_full`** — `EventBus._queue` を maxsize=1 で飽和させた状態で critical event（reliability class=critical）を `emit` し、drop されずに最終的に handler へ到達すること（LB-2・Go）。
- [ ] **T-1.2: `test_best_effort_event_droppable_with_explicit_dead_letter`** — best_effort event は queue full で drop 許容、ただし dead-letter/明示 error 指標が残ること（LB-2・親4.1）。
- [ ] **T-2.1: `test_no_direct_task_queue_mutation_from_event_handlers`** — `task_queue.add/boost_priority/inject_context/remove_by_id` を re-entrancy/thread detector で wrap し、EventBus handler（vuln_found/reauth_*）からの直接呼出が 0件・全て main-thread marshal or 遅延キュー経由であること（C1/C2/LB-1）。
- [ ] **T-2.2: `test_no_reentrant_mutation_during_post_batch_feedback_iteration`** — `_apply_post_batch_feedback`(`mc:5712`) の `batch_tasks` イテレーション中に event handler が同期再入で `task_queue` を mutate しないこと（C1）。イベントは遅延キューへ溜まり loop 終了後に dispatch されること。
- [ ] **T-3.1: `test_post_batch_feedback_dataclass_migration`** — `PostBatchFeedback` dataclass への移行で既存8 field（deferred_findings/critical_actions/boost_event/new_assets/react_tasks/handoff/new_context/decision_enhancer_tasks）が型安全に読め、typo key で AttributeError/検出可能であること（C3・FU-2）。
- [ ] **T-3.2: `test_injection_feedback_propagates_via_post_batch`** — injection-type task を含む batch で、injection finding が `_apply_post_batch_feedback`(`mc:6123`) 経由で伝播すること（C4・FU-3・Phase 5 未テスト経路の穴埋め）。
- [ ] **T-4.1: `test_lifecycle_metadata_stored_in_task_metadata`** — retired/superseded/invalidated が `Task.metadata` の `lifecycle_status`/`lifecycle_reason`/`retired_by_event_id`/`invalidated_by` へ正しく格納され、`to_dict` で秘密情報境界（`_redact_secrets`）を破らないこと（C5・完了条件2）。
- [ ] **T-4.2: `test_report_distinguishes_retired_from_failed`** — retired/superseded/invalidated task が report/session で「失敗」と別表現されること（完了条件3・親4.1 pruning model）。report reader 互換性維持。
- [ ] **T-5.1: `test_pruning_decision_persisted_to_decision_traces`** — pruning decision が `build_async_session_payload(decision_traces=...)` 経由で永続化され、report formatter が未知 decision_type を含めて fallen-back でも可読であること（C6・LB-3）。
- [ ] **T-6.1: `test_protected_tasks_not_pruned`** — protected task（scope_parser/coverage_guard/scenario_probe/manual_verify/report/evidence 系）が prune 対象外であること（完了条件3・SGK-2026-0287 制約3.ルール）。
- [ ] **T-6.2: `test_in_flight_tasks_excluded_from_pruning`** — in-flight（running/admitted）task は退役対象外・pending のみ decision record 残すこと（制約3.ルール）。
- [ ] **T-7.1: `test_three_point_validity_check_rejects_stale_snapshot`** — enqueue時/dequeue時/start直前の3点で `recon_snapshot_version`/`auth_context_version` が古い pending task を reject し `invalidated` で記録すること（完了条件2・親5.1 SRE観点）。
- [ ] **T-8.1: `test_duplicate_event_does_not_create_duplicate_follow_ups`** — 同一 `event_id` または同一 `generation_reason`+`evidence_key` で後続 task が重複生成されないこと（リスク5.3）。
- [ ] **T-8.2: `test_critical_event_handler_failure_does_not_lose_follow_up`** — handler failure/retry 後も critical event の後続 task が最終的に生成されること（親4.1 Event reliability・LB-2）。
- [ ] **T-9.1: `test_phase5_post_batch_regression_under_event_chaining`** — Phase 5 の post-batch feedback main-thread 集約が、Phase 6 event-driven chaining 追加後も維持されること（Phase 5 T-2.1/T-2.4 回帰）。
- [ ] **T-10.1: `test_priority_booster_observe_and_rethink_safe_under_events`** — Phase 5 FU-1（`priority_booster.boost_on_discovery`(`mc:6507`)/`_observe_and_rethink`(`mc:6524`) の lock なし counter update）が Phase 6 event path でも安全なこと、または Phase 6 開始前に対処済みであること（Phase 5 FU-1・PCR-P1 関連）。

### 7.5 Go/No-Go Gate（section 6.2 を補完）
- [ ] **Go:** critical/important event が queue full で drop 0件（T-1.1, LB-2・親4.1）。
- [ ] **Go:** EventBus handler 群（vuln_found/reauth_*）からの `task_queue` 直接 mutation 0件・全て main-thread marshal or 遅延キュー経由・`threading.main_thread()` assert 付き（T-2.1/T-2.2, C1/C2・LB-1・PCR-P1）。
- [ ] **Go:** `PostBatchFeedback` dataclass 化済み・string-key dict 廃止（T-3.1, C3・FU-2）。
- [ ] **Go:** injection task の feedback 伝播 test 追加済み（T-3.2, C4・FU-3）。
- [ ] **Go:** retired/superseded/invalidated が report/session で「失敗」と区別される（T-4.2, 完了条件3）。
- [ ] **Go:** pruning decision が `decision_traces` へ永続化・report reader 互換（T-5.1, C6・LB-3）。
- [ ] **Go:** protected task 退役 0件・in-flight task 退役対象外（T-6.1/T-6.2）。
- [ ] **Go:** 3点 validity check で stale snapshot task を reject し `invalidated` 記録（T-7.1, 完了条件2）。
- [ ] **Go:** T-0.1〜T-10.1 の全テスト PASS。`python3 scripts/sync_shigoku_updated_at.py` 後に `python3 scripts/validate_shigoku_docs.py` が 0 エラー。
- [ ] **No-Go（未該当確認）:** SGK-2026-0287 (TaskPruningPolicy) 未実装のまま step3 に進む（LB-0 未解決・pruning ゴール空振り）。親裁定を得て (i) 0287 先行完了 or (ii) Phase 6 内 policy 新設 のいずれかを文書化すること。
- [ ] **No-Go（未該当確認）:** critical/important event drop 再現（T-1.1 fail → False Negative・No-Go）。
- [ ] **No-Go（未該当確認）:** EventBus handler からの direct `task_queue` mutation 残存（T-2.1 fail → C2 違反・queue 破壊）。
- [ ] **No-Go（未該当確認）:** `_apply_post_batch_feedback` イテレーション中の同期再入 mutation 発生（T-2.2 fail → C1 違反・task skip/heap 破壊）。
- [ ] **No-Go（未該当確認）:** protected task 退役（T-6.1 fail → coverage 欠損・SGK-2026-0287 矛盾）。
- [ ] **No-Go（未該当確認）:** Phase 5 post-batch main-thread 集約・finding parity 100% が崩壊（T-9.1 fail・Phase 5 回帰）。

### 7.6 Shadow / Differential Testing
- [ ] **S-1: serial-baseline vs event-driven-chaining finding parity differential** — 同一 seed で (a) 全 task 事前 queue 投入（現状）(b) event-driven 遅延生成 の2経路を走らせ、`src/reporting/finding_extractor.extract_all_findings()` で High/Critical finding（severity+id）集合の集合相等を assert（Phase 5 S-1 の拡張・rules/lessons.md 真正性ルール準拠）。
- [ ] **S-2: pruning shadow vs live coverage differential** — SGK-2026-0287 shadow decision を観測しつつ実 heap からは消さない経路（Phase 6）と実削除経路（Phase 7+）の coverage 差分を記録。Phase 6 は shadow 経路のみで Go。
- [ ] **S-3: event lifecycle 監査** — critical/important/best_effort 各 event の enqueue/dequeue/handler start-end/handler error を監査点付与し、drop 経路を differential で検出（親5.3 デバッガー観点・LB-2）。
- [ ] **S-4: duplicate event injection 監査** — 同一 vuln で N 連続 event を emit し、`event_id` と `generation_reason`+`evidence_key` の両方で dedupe が効いて後続 task が N 個生成されないことを監視（リスク5.3）。
- [ ] **S-5: stale snapshot 注入監査** — `recon_snapshot_version`/`auth_context_version` を意図的に進め、pending task が3点 check（enqueue/dequeue/start直前）で止まることを監視（完了条件2）。

### 7.7 Local Deferred（後続Phaseへ送る）
| # | 項目 | Deferred先 | 安全な理由 | 検出方法 |
|---|---|---|---|---|
| D-1 | debug bundle 形式化（task queue snapshot / event trace / mutex state の標準化）| Phase 9 (SGK-2026-0318) | Phase 6 は退役理由を `decision_traces`(`build_async_session_payload`) で残せ、Go 条件（追跡可能）を満たす。debug bundle 個別 artifact 標準化は Phase 9 release gate で reader 互換性と共に整備が自然 | Phase 9 compatibility test / downstream reader impact check |
| D-2 | pruning aggressive 実削除 enablement（SGK-2026-0287 step4-6 の保守的解除）| Phase 7 (SGK-2026-0316) / SGK-2026-0287 follow-up | Phase 6 は shadow decision と lifecycle metadata 表現（retired/superseded/invalidated）の接続が主眼。実 heap 削除は `remove_by_id`(`task_queue.py:749`) のみ・record を残す設計で Go 条件充足。aggressive 実削除は 0287 step6「保守的実装」→段階開放が前提 | Phase 7 で prune audit を実セッションレビュー / SGK-2026-0287 follow-up |
| D-3 | EventBus `_processed_ids` の eviction bug（`set(list(...) [-5000:])`(`event_bus.py:244`) は set 順序非保存で実質 random eviction）| Phase 9 (SGK-2026-0318) | 重複排除 accuracy は観測性能。Phase 6 の Go 条件（critical event drop 0・finding parity）に直接影響しない。Phase 6 は `event_id`/`generation_reason`/`evidence_key` で dedupe 設計を新設する（リスク5.3）ため、本 bug は踏襲せず新設 dedupe table で回避 | Phase 6 dedupe 実装時に併せ修正、または Phase 9 telemetry で重複 event 率監視 |

### 7.8 Parent Change Request（親計画へ反映提案・本Phaseでは適用しない）
- [x] **PCR-P1【PCR-4 強化・親計画へ昇格済み 2026-06-29】: `task_queue`/`accumulated_context` の main-thread mutation 契約へ「EventBus handler 群（`_handle_vuln_found`/`_handle_reauth_*` 等）は SharedLoop thread で動くため marshaling 必須」を明記（親 4.1 Shared-state mutation contract へ反映済み）。** 現状親の PCR-4 は Phase 5/6/7/8/9 共通だが、EventBus handler が `ShigokuSharedLoop` daemon thread（`async_utils.py:43-49`）で動くことの明示がない。Phase 6 LB-1 で既存 `_handle_vuln_found`(`mc:478-538`) が既に現状違反であることを顕在化したため、親レベルで「EventBus handler からの task_queue 直接 mutate 禁止・main-thread marshal or 遅延キュー必須」を不変条件へ昇格。既存 PCR-4 と重複せず拡張（Phase 5 の「worker 経由」に加え「EventBus handler 経由」も明示）。
- [x] **PCR-P2【依存順序裁定・親計画へ昇格済み 2026-06-29】: 親 4.1 task lifecycle metadata へ pruning lifecycle（retired/superseded/invalidated）を正式反映し、SGK-2026-0287 と Phase 6 の依存順序を裁定（親 4.1 Task lifecycle へ反映済み）。** 親 4.1 は抽象的に `lifecycle_status` 等を書くが、TaskPruningPolicy(SGK-2026-0287) が未実装（registry active・`task_pruning_policy.py` 0件）。Phase 6/7/9 が全て pruning に依存するため、親が (i) 0287 を Phase 6 前に完了 or (ii) Phase 6 内で最小 policy 新設を許容、のいずれかを裁定し依存順序を固定すべき。Phase 6 の LB-0 は親裁定なしに解決不可。

### 7.9 Out of Scope（本Phaseでは実装しない）
- [ ] TaskState enum への永続 lifecycle 追加（C5・Phase 1 で deferred、reader 互換性確認後に別 Phase）
- [ ] EventBus thread model の根本変更（SharedLoopManager → main-loop 統合）— Phase 6 は現行 SharedLoop 上で marshal/遅延キューで回避、根本変更は Phase 8/9
- [ ] SwarmDispatcher 複数 Swarm 同時呼び出し（Phase 8）
- [ ] SwarmManager specialist 内側並列化（Phase 8）
- [ ] Injection URL 処理の並列化（Phase 8）
- [ ] protective degrade mode / `mutating`/`aggressive_exclusive` lane の enablement（Phase 7）
- [ ] pruning aggressive 実削除の段階開放（D-2, Phase 7/SGK-2026-0287）
- [ ] debug bundle 形式化（D-1, Phase 9）
- [ ] 外部依存ライブラリの追加

### 7.10 Phase順序再レビュー
- **Phase 5 → Phase 6:** ✅ Phase 5 `_apply_post_batch_feedback`(`mc:5693`) main-thread 集約が Phase 6 C1/C2 の前提。Phase 6 はこれを踏襲し EventBus handler 経由の再入を禁じる。順序正当。
- **SGK-2026-0287 → Phase 6:** ⚠️ **依存未解決（LB-0）。** 0287 未実装（policy 本体なし）。親が PCR-P2 で依存順序を裁定するまで Phase 6 step3 は実装不可。Phase 6 内で最小 policy を新設する方針（PCR-P2 ii）を採る場合は step3 を「TaskPruningPolicy 新設＋shadow decision 接続」へ拡張。
- **Phase 6 → Phase 7:** ✅ Phase 7 stateful lane は Phase 6 の lifecycle metadata（retired/superseded/invalidated）と event reliability を前提。順序正当。
- **Phase 6 → Phase 8:** ✅ Phase 8 内側並列化は Phase 6 の event reliability class と main-thread mutation 契約を前提。順序正当。
- **結論:** Phase 順序自体は壊れていないが、LB-0（0287 依存）を親裁定なしに進めると step3 が空振りし完了条件3（prune protected task を退役しない）と「未実施だが不要化」記録が実装できない。PCR-P2 の親反映が Phase 6 実装開始の必要条件。

### 7.11 実装可否判定（Blocker解消後）
- **判定（2026-06-29）: 条件付き実装可能 — 4 Blocker（LB-0〜LB-3）解消後 Go。** LB-0 は親裁定（PCR-P2）必須。LB-1/LB-2/LB-3 は Phase 6 内部の設計で解消可能。
- **変更規模（局所〜中規模）:**
  - `src/core/infra/event_bus.py`: reliability class（critical/important/best_effort）追加・`emit` の drop 抑制（blocking put/persistence fallback）・dead-letter・監査点（LB-2）。`_processed_ids` eviction bug は D-3 で踏襲しない設計。
  - `src/core/engine/master_conductor.py`: EventBus handler 群（`_handle_vuln_found`/`_handle_reauth_*`）の task_queue mutation を main-thread marshal or 遅延キュー化（LB-1・C1/C2）。`threading.main_thread()` assert 追加。`PostBatchFeedback` dataclass 化（C3・FU-2）。event/pruning field 追加。injection feedback 伝播 test 追加（C4・FU-3）。
  - `src/core/engine/task_pruning_policy.py`（新設 or 0287 完了後に接続）: shadow decision 生成・protected list・reason_code（LB-0・PCR-P2 裁定次第）。
  - `src/core/models/decision_trace.py`: `DecisionType` enum へ `TASK_RETIRED`/`TASK_SUPERSEDED`/`TASK_INVALIDATED` 追加・pruning decision dataclass（LB-3）。
  - `src/core/engine/task_queue.py`: `remove_by_id`(`task_queue.py:749`) の lifecycle metadata 更新 wrapper（退役時に metadata へ reason/event_id を残す）。`remove_matching`/`remove_by_ids` は LB-0 裁定で 0287 完了なら不要・Phase 6 内新設なら追加。
  - report/session reader: 退役 task の表示分離（T-4.2）・未知 decision_type fallback（T-5.1）。
  - `tests/`: T-0.1〜T-10.1 追加。
- **TDD順序:** T-0.1（現状 race characterization）→ T-1.1/T-1.2（EventBus reliability）→ T-2.1/T-2.2（EventBus handler marshaling）→ T-3.1/T-3.2（PostBatchFeedback dataclass + injection feedback）→ T-5.1（decision shape）→ T-6.1/T-6.2（protected/in-flight）→ T-7.1（3点 validity）→ T-4.1/T-4.2（lifecycle metadata + report 区別）→ T-8.1/T-8.2（dedupe/retry）→ T-9.1/T-10.1（Phase 5 回帰）。
- **他フェーズへの影響:** なし（直接編集しない）。PCR-P1/P2 は親計画 SGK-2026-0291 への反映提案のみ。SGK-2026-0287 は親裁定（PCR-P2）を待つ。
- **残リスク（実装中に No-Go に戻す条件）:** (1) LB-0 の親裁定が「0287 先行完了」になった場合、Phase 6 スコープが縮小する（step3 は接続のみ）・「Phase 6 内新設」なら拡大する。(2) LB-2 の drop 抑制が backpressure を掛けた際 producer（specialist 等）に伝播しデッドロック・スループット崩壊を起こす場合、設計再評価。(3) LB-1 の marshaling が SharedLoop thread の待ちを生み、event 処理レイテンシ悪化で finding parity に影響する場合、設計再評価。

### 7.12 参照ルール
- 本タスクのレビュー・編集にあたり参照したルールファイル: `rules/lessons.md`（report/session 真正性・秘密境界・ドキュメント検証・CRITICAL deferred_tasks・LLM 設定）、`rules/shigoku-docs.md`（front matter・deferred_tasks・done 移動規則）、`rules/reporting.md`（gate 完了基準・report 読者互換性）、`rules/report-session-consistency.md`（finding parity の真正性原則）。
