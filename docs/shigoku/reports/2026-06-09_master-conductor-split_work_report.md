---
task_id: SGK-2026-0264
doc_type: work_report
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-06-05_master-conductor-split-plan_plan.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/REQ_tier4_mc_intelligence.md
created_at: '2026-06-09'
updated_at: '2026-06-09'
title: '作業報告書: MasterConductor 分割 (SGK-2026-0264)'
---

# 作業報告書: MasterConductor 分割 (SGK-2026-0264)

## 1. 実施内容

### 手順1/8: import 互換と配置の固定
- `master_conductor.py` はファイルモジュールのまま維持。平置き `master_conductor_*.py` を標準配置に統一。
- `master_conductor_dependencies.py` を作成し、依存束ね用 dataclass (`PlannerDependencies`, `HitlDependencies`, `DispatchDependencies`, `ReconExecutionDependencies`) を定義。
- shared state 所有権: `task_queue` / `context` / `phase_gate` / `event_bus` / `_state_lock` / `pending_hitl` / `project_manager` を facade に固定。

### 手順2/8: session 残りの整理
- `master_conductor_session_service.py` に `apply_restored_session_state()` を追加。`resume_session` の外側 orchestration (context / pending_hitl / task_queue の復元) を helper に抽出。
- `load_session`, `async_save_session`, `start_session`, `_checkpoint` は既存 helper 化済み。thin wrapper のまま維持。
- `initialize_workspace()` の settings 解決済み (legacy/core settings 両方対応)。

### 手順3/8: recon attack task planner 分割 (最大効果)
- `master_conductor_recon_attack_task_planner.py` を新規作成 (~1418行)。
- `_create_attack_tasks_from_recon` (旧 1327 行) を `ReconAttackTaskPlanner` クラスに抽出。
  - 依存はコンストラクタ注入: `phase_gate`, `resolve_recon_file_path`, `collect_history_replay_targets`, `get_context_cookie_string`, etc. (計 18 依存)。
  - queue mutation は持たず `list[Task]` を返す。
  - `master_conductor.py` では thin wrapper で delegation (35 行)。
- ファイルサイズ: 9777 → 8317 行 (-15%, -1460 行)。

### 手順4/8: recon planner 回帰テスト固定
- `tests/core/engine/test_master_conductor_api_candidate_routing.py` (50 tests)
- `tests/core/engine/test_master_conductor_scenario_probes.py`
- `tests/core/engine/test_master_conductor_recon_nonblocking.py`
- `tests/core/engine/test_master_conductor_recon_step_range.py`
- 全 50 tests 通過。

### 手順5/8: HITL service 分割
- `master_conductor_hitl_service.py` (~231行) を新規作成。`HitlService` クラスに以下のメソッドを抽出:
  - `register_pending_hitl_ticket()`, `list_pending_hitl_tickets()`, `set_pending_hitl_status()`
  - `enqueue_approved_hitl_tasks()`, `mark_pending_hitl_done()`
  - `build_task_from_hitl_snapshot()`, `requires_intervention_approval()`, `build_intervention_hitl_info()`
- `pending_hitl` list の所有は facade に維持。service は状態遷移のみ担当。
- facade 側は `_get_hitl_service()` による遅延初期化で後方互換維持。
- テスト: `test_master_conductor_hitl_pending.py`, `test_master_conductor_hitl_priority.py`, `test_master_conductor_hitl_snapshot.py` (8 tests 通過)。

### 手順6/8: dispatch service 構造準備
- `master_conductor_dispatch_service.py` を作成。safety character tests 追加後に本格移行予定のため、構造定義のみ。
- 計画に従い、scope guard / worker route / swarm fallback の安全境界テストを先に厚くする方針を維持。

### 手順7/8: recon execution service 構造準備
- `master_conductor_recon_execution_service.py` を作成。ReconPipeline 実行切り出し後に本格移行予定のため、構造定義のみ。

### 手順8/8: 最終統合検証
- 全 master_conductor 関連テスト 166 tests 通過。
- 外部 import 互換確認: `from src.core.engine.master_conductor import MasterConductor` を含む 12 箇所の import パスを確認、すべて正常。
- 新しい service module import 確認: 全 6 モジュールが正常に import 可能。

## 2. 達成効果

| 指標 | 分割前 | 分割後 | 効果 |
|---|---|---|---|
| `master_conductor.py` 行数 | 9777 | 8317 | -1460 行 (-15%) |
| `_create_attack_tasks_from_recon` 行数 | 1327 | 35 (thin wrapper) | -1292 行 |
| HITL 関連メソッド行数 | ~240 | ~75 (thin wrappers) | -165 行 |
| 新規作成ファイル | 0 | 6 | +1811 行 (他ファイルへ移行) |
| テスト | 80 | 166 | 全通過、回帰なし |

## 3. 懸念点と対策

### 達成済み
- [x] import 互換: 平置き `master_conductor_*.py` で既存 import path を保護。
- [x] shared state 所有権: `task_queue` / `context` / `phase_gate` / `event_bus` / `_state_lock` / `pending_hitl` / `project_manager` を facade に固定。
- [x] 循環 import 禁止: `master_conductor.py -> service -> helper` の一方向のみ。
- [x] planner の queue mutation 排除: `list[Task]` を返し、queue mutation は facade 側の `_add_tasks` に維持。
- [x] session 互換: `apply_restored_session_state` で resume 動作を helper 化。
- [x] log/event 契約: 既存ログキー維持。service の開始/終了/失敗は facade 側で一元管理。

### 残課題 (deferred_tasks)

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0264-D01
    title: "継続監視: MasterConductor 分割後の回帰監視"
    reason: "分割後も dispatch / session / HITL / recon planning の挙動監視が必要"
    impact: medium
    tracking_task_id: SGK-2026-0280
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"

  - deferred_id: SGK-2026-0264-D02
    title: "dispatch service 本格実装"
    reason: "scope guard / worker / swarm / recon / AgentFactory を含むため、先に safety character tests を厚くする必要がある"
    impact: high
    tracking_task_id: SGK-2026-0280
    recommended_next_action: "dispatch 専用 character tests を追加後、master_conductor_dispatch_service.py に _dispatch ロジックを移行する"

  - deferred_id: SGK-2026-0264-D03
    title: "recon execution service 本格実装"
    reason: "ReconPipeline 実行と PhaseGate 反映の順序制約を整理後、master_conductor_recon_execution_service.py に移行する"
    impact: medium
    tracking_task_id: SGK-2026-0280
    recommended_next_action: "recon pipeline の isolated thread/loop 互換をテストで固定後、移行する"

  - deferred_id: SGK-2026-0264-D04
    title: "execute_with_replan の service 分割"
    reason: "並列実行、checkpoint、precheck、summary が絡むため、最後に寄せる方針。旧ロジックの二重実装確認が必要"
    impact: high
    tracking_task_id: SGK-2026-0280
    recommended_next_action: "phase 1-5 完了後に execution loop 分割を実施する"
```

## 4. 検証結果

```
$ pytest tests/core/engine/test_master_conductor*.py tests/test_session_persistence.py tests/test_session_resume.py tests/test_integration.py -q
166 passed, 1 warning in 10.56s
```

- 全 166 tests 通過
- import 互換 12 箇所すべて正常
- 新規 module import 6 件すべて正常

## 5. 判断理由とリスク

- **dispatch / recon execution の skeleton 化**: 計画の安全境界要件（safety character tests の事前追加）を満たしていないため、本格実装は deferred として残した。現状の skeleton は他開発者が拡張するための構造的準備として機能する。
- **遅延初期化 (`_get_hitl_service`)**: テストが `__new__` で `__init__` をバイパスするパターンに対応するため。サービス非存在時は fallback 値で初期化。
- **`_ensure_pending_hitl_store` の簡略化**: `__init__` で常に `self.pending_hitl = []` が保証されるため、`getattr` + 再初期化の防御コードを削除。

## 6. 参照ルール

本タスクで参照したルールファイル:
- `rules/task-ledger.md` - タスク台帳ワークフロー
- `rules/shigoku-docs.md` - SHIGOKU ドキュメント規則
- `rules/codingrules.md` - コーディング規約
