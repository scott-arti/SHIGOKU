---
task_id: SGK-2026-0264
doc_type: work_report
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-05_sgk-2026-0264_master-conductor-split-plan_plan.md
- docs/shigoku/specs/ARCHITECTURE.md
title: "MasterConductor 分割: HITL task snapshot 切り出しの実施報告"
created_at: "2026-06-05"
updated_at: '2026-06-30'
---

# 作業報告

## 実施内容
- `MasterConductor._snapshot_task_for_hitl()` のロジックを `src/core/engine/master_conductor_hitl_snapshot.py` の `snapshot_task_for_hitl()` へ切り出した。
- `MasterConductor` 側は thin wrapper として新関数を呼ぶ形へ差し替えた。
- 既存挙動を保護するため、pending HITL ticket に保存される task snapshot の形と deep copy を確認するキャラクターテストを追加した。
- 新関数の単体テストを別ファイルで追加し、TDD の Red -> Green を確認した。
- `load_session()` の pending HITL 復元規則を `src/core/engine/master_conductor_state_snapshot.py` の `restore_pending_hitl_from_session_payload()` へ切り出した。
- `pending_hitl` はトップレベル値を優先し、未定義時は `context.pending_hitl` へフォールバックし、 deep copy される既存仕様をキャラクターテストで固定した。
- `load_session()` の `ExecutionContext` 復元規則を `src/core/engine/master_conductor_state_snapshot.py` の `restore_context_from_session_payload()` へ切り出した。
- `total_attempts` / `successful_attempts` / `bypass_methods` / `discovered_assets` / `target_info` の既存代入挙動をキャラクターテストで固定し、置換代入になることも確認した。
- `load_session()` の `completed_tasks` 復元規則を `src/core/engine/master_conductor_state_snapshot.py` の `restore_completed_tasks_from_session_payload()` へ切り出した。
- 無効 state の `SUCCESS` フォールバック、`failure_reason_code` 欠落時の補完、`timeout_retry_count` 復元をキャラクターテストと単体テストで固定した。
- `load_session()` の `task_queue` 復元規則を `src/core/engine/master_conductor_state_snapshot.py` の `restore_task_queue_from_session_payload()` へ切り出した。
- `running` -> `pending/skipped` の分岐、無効 state の `PENDING` フォールバック、invalid state warning 維持をキャラクターテストと単体テストで固定した。
- `session_service` 導入の最初の slice として、`load_session()` の RUNNING task 再実行判定を `src/core/engine/master_conductor_session_service.py` の `resolve_running_task_resume_policy()` へ切り出した。
- `n` 入力で skip、prompt 例外時は rerun 維持、running task が無いときは prompt 不要という既存挙動をキャラクターテストと単体テストで固定した。
- `session_service` の次の slice として、`load_session()` の file existence check と session payload 読み込みを `src/core/engine/master_conductor_session_service.py` の `load_session_payload_from_path()` へ切り出した。
- missing file は `None`、`safe_json_loads()` による補修後 payload はそのまま上位へ返し、非 mapping payload は `load_session()` 側で従来どおり `False` へ落ちる挙動をテストで固定した。
- `session_service` の次の slice として、`async_save_session()` の payload 組み立てを `src/core/engine/master_conductor_session_service.py` の `build_async_session_payload()` へ切り出した。
- `task_queue` / `completed_tasks` / `context` / `pending_hitl` / `adjacency_list` の保存構造を character test と単体テストで固定し、`MasterConductor` 側の save 経路を thin 化した。
- 旧 `tests/test_session_persistence.py` と `tests/test_session_resume.py` を現行 `DynamicTaskQueue`・`_deserialize_task_queue()`・`load_session()` の仕様へ更新し、 session service 導入後の回帰を再固定した。
- `resume_session()` の回帰テストで、`initialize_workspace()` が legacy settings では `multi_session` を持たずクラッシュする実バグを再現し、 legacy/core settings の両方から安全に `multi_session` を解決する最小修正を加えた。
- `session_service` の次の slice として、`_checkpoint()` の pending/completed targets と metadata 構築を `build_checkpoint_session_state()` へ切り出した。
- `_checkpoint()` の character test を追加し、 `pending_targets` / `completed_targets` / `metadata` の保存形を現行仕様で固定した。
- `MasterConductor._serialize_task_queue()` と checkpoint helper に重複していた legacy session 用 task queue JSON 変換を `serialize_legacy_session_task_queue()` へ統一した。
- `session_service` の次の slice として、legacy `Session` から in-memory state を復元する境界を `restore_legacy_resume_session_state()` と `deserialize_legacy_session_task_queue()` へ切り出した。
- `resume_session()` の character test と単体テストで、 context / pending HITL / task queue / failed deserialization の復元形を固定した。
- `MasterConductor.resume_session()` は workspace 初期化と session manager 呼び出しを残しつつ、復元データ組み立て部分を thin 化した。
- `session_service` の次の slice として、`start_session()` の session create 引数構築を `build_start_session_payload()` へ切り出した。
- `save_session()` の同期ラッパー境界も `await_session_save_future()` へ切り出し、 async save 本体には触れずに待機ポリシーだけを分離した。
- 手順6の最初の slice として、pending HITL ticket dict の組み立てを `src/core/engine/master_conductor_hitl_ticket.py` の `build_pending_hitl_ticket()` へ切り出した。
- `_register_pending_hitl_ticket()` は重複判定と store append を残しつつ、 ticket schema の組み立て部分だけを pure helper へ移した。

## 変更ファイル
- `src/core/engine/master_conductor.py`
- `src/core/engine/master_conductor_hitl_snapshot.py`
- `src/core/engine/master_conductor_state_snapshot.py`
- `tests/core/engine/test_master_conductor_hitl_pending.py`
- `tests/core/engine/test_master_conductor_hitl_snapshot.py`
- `tests/core/engine/test_master_conductor_load_session_pending_hitl.py`
- `tests/core/engine/test_master_conductor_state_snapshot.py`
- `src/core/engine/master_conductor_session_service.py`
- `tests/core/engine/test_master_conductor_session_service.py`
- `tests/core/engine/test_master_conductor_session_payload_builder.py`
- `tests/test_session_persistence.py`
- `tests/test_session_resume.py`
- `src/core/engine/master_conductor_hitl_ticket.py`
- `src/core/engine/master_conductor_session_service.py`

## 検証
- `.venv/bin/pytest tests/core/engine/test_master_conductor_hitl_pending.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_hitl_snapshot.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_hitl_snapshot.py tests/core/engine/test_master_conductor_hitl_pending.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_hitl_priority.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_hitl_snapshot.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_failure_reason_codes.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_failure_reason_codes.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_failure_reason_codes.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_failure_reason_codes.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_payload_builder.py -q`
- `.venv/bin/pytest tests/test_session_persistence.py -q`
- `.venv/bin/pytest tests/test_session_resume.py -q -k serialization_roundtrip`
- `.venv/bin/pytest tests/test_session_resume.py -q`
- `.venv/bin/pytest tests/test_session_persistence.py tests/test_session_resume.py -q`
- `.venv/bin/pytest tests/test_session_persistence.py tests/test_session_resume.py tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_session_payload_builder.py tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py tests/core/engine/test_master_conductor_failure_reason_codes.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py tests/test_session_resume.py tests/test_session_persistence.py -q`
- `.venv/bin/pytest tests/test_session_persistence.py tests/test_session_resume.py tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_session_payload_builder.py tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py tests/core/engine/test_master_conductor_failure_reason_codes.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py tests/test_session_resume.py -q -k 'build_start_session_payload or start_session'`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py -q -k await_session_save_future`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_hitl_pending.py -q`
- `.venv/bin/pytest tests/test_session_persistence.py tests/test_session_resume.py tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_session_payload_builder.py tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py tests/core/engine/test_master_conductor_failure_reason_codes.py -q`
- `.venv/bin/pytest tests/test_session_resume.py -q -k master_conductor_checkpoint tests/core/engine/test_master_conductor_session_service.py -q`
- `.venv/bin/pytest tests/test_session_resume.py tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_session_payload_builder.py tests/core/engine/test_master_conductor_state_snapshot.py tests/test_session_persistence.py -q`
- `.venv/bin/pytest tests/core/engine/test_master_conductor_session_service.py tests/test_session_resume.py tests/test_session_persistence.py -q`
- `.venv/bin/pytest tests/test_session_persistence.py tests/test_session_resume.py tests/core/engine/test_master_conductor_session_service.py tests/core/engine/test_master_conductor_session_payload_builder.py tests/core/engine/test_master_conductor_state_snapshot.py tests/core/engine/test_master_conductor_load_session_pending_hitl.py tests/core/engine/test_master_conductor_hitl_pending.py tests/core/engine/test_master_conductor_hitl_priority.py tests/core/engine/test_master_conductor_failure_reason_codes.py -q`

## 残課題
- `hitl_service.py` 本体への段階移行は未着手。
- `_build_task_from_hitl_snapshot()` や pending HITL store 操作の分離は次ステップで継続する。
- session の主要な復元ロジック、RUNNING task 再実行判定、load/save payload I/O、save payload builder、checkpoint state builder、legacy resume restore builder、start/save wrapper 境界は分離できた。残るのは `resume_session` の外側 orchestration と workspace 初期化境界の整理。
- HITL は task snapshot と ticket dict builder を分離できた。残るのは enqueue/resume/status 更新まわりの境界整理。
- `tests/unit/test_shared_session.py` など、より広い session 回帰の追加確認は次ステップへ持ち越す。

deferred_tasks:
  - deferred_id: SGK-2026-0264-D01
    title: "HITL snapshot 後続ロジックの service 分離"
    reason: "_build_task_from_hitl_snapshot と pending HITL ticket 操作はまだ MasterConductor に残っている"
    impact: medium
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "hitl_service の責務境界を先に固定し、復元ロジックと ticket 操作を段階移行する"
  - deferred_id: SGK-2026-0264-D02
    title: "Session restore の残りロジック分離"
    reason: "pending HITL・context・completed_tasks・task_queue 復元、RUNNING task 再実行判定、file I/O、save payload builder、checkpoint state builder、legacy resume restore builder は切り出せたが、save/load/resume orchestration はまだ MasterConductor に残る"
    impact: medium
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "session_service 導入時に save/load/resume orchestration の境界を整理し、workspace 初期化と session manager 呼び出しだけを facade に残す形まで thin wrapper 化する"
  - deferred_id: SGK-2026-0264-D03
    title: "Pending HITL enqueue/resume 境界の service 分離"
    reason: "ticket schema と snapshot は分離できたが、 approved ticket の enqueue / resumed task 構築 / status 更新はまだ MasterConductor に残る"
    impact: medium
    tracking_task_id: SGK-2026-0264
    recommended_next_action: "build_task_from_hitl_snapshot と approved ticket enqueue の順に小さく切り出し、 pending/approved/done の状態遷移を helper 群へ寄せる"
