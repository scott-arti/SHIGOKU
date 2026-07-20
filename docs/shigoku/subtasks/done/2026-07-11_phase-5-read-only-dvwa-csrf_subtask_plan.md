---
task_id: SGK-2026-0356
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0314
related_docs:
- docs/shigoku/subtasks/done/2026-06-26_swarm-phase-5-read-only-outer-task-parallelism_subtask_plan.md
title: 'Phase 5: read_only並列化有効化とDVWA CSRF安全性評価'
created_at: '2026-07-11'
updated_at: '2026-07-21'
tags:
- shigoku
target: config/shigoku.yaml, .env, src/config.py
---

# 実装計画書：Phase 5: read_only並列化有効化とDVWA CSRF安全性評価

## 1. 達成したいゴール（ユーザー視点）
- [x] Phase 5 (SGK-2026-0314) で実装された read_only 並列ゲートを本番有効化すること。
- [x] DVWA Vulntest の並列化安全性（CSRFトークン競合リスク）を評価すること。
- [x] その他並列化に伴うリスクを包括的に評価し、安全なロールアウト戦略を確立すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `config/shigoku.yaml`: parallelism セクション追加（YAML正本）
  - `.env`: `SHIGOKU_PARALLELISM__ENABLED=true` 追加（レガシーSettings用）
  - `src/config.py`: `ParallelismSettings` 定義（変更なし）
  - `src/core/config/settings.py`: `ParallelismSettings` 定義（変更なし）
- **データの流れ / 依存関係:**
  - YAML → `src/core/config/settings`（新Settings）＋ `.env` → `src/config.py`（レガシーSettings）
  - `master_conductor.py` → `force_serial` 判定 → `ParallelOrchestrator.execute_parallel()` or `_execute_single_task_full_flow()`

## 3. 具体的な仕様と制約条件
- **制約・ルール:**
  - `read_only` + `parallel_safe=true` タスクのみ並列実行
  - `stateful_read` / `mutating` / `aggressive_exclusive` / `injection` は逐次実行のまま
  - `lane_workers: {read_only: 4}` で最大4並列
  - `per_origin_budget.max_inflight: 2` で同一オリジン同時接続を制限
  - kill switch (`parallelism.kill_switch: true`) で即座に逐次復帰可能

## 4. 実装ステップ
- [x] ステップ1: `config/shigoku.yaml` に `parallelism` セクションを追加（`enabled: true`）
- [x] ステップ2: `.env` に `SHIGOKU_PARALLELISM__ENABLED=true` を追加（レガシーSettings用）
- [x] ステップ3: Phase 5 テスト全101件パス確認
- [x] ステップ4: レガシーSettingsの `parallelism.enabled` が `True` になることを検証
- [x] ステップ5: DVWA CSRFトークン安全性分析と包括的リスク評価を実施

## 5. 既知のリスクと次回の申し送り
- [x] [重要度:中] LLM APIレート制限（R5） — 最大4並列タスクが同時にLLMを呼ぶと `max_concurrency: 4` を枯渇させる可能性。モニタリング要。
- [x] [重要度:低] 共有ステート競合（FU-1, FU-2） — `_observe_and_rethink` のカウンタ競合。Phase 7で対処予定。
- [x] [重要度:低] 単一ClientSession共有（R4） — aiohttpコネクタプール次第でボトルネック化の可能性。

### 5.1 deferred_tasks
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0356-D01
    title: "継続監視: read_only並列化の実行時KPI"
    reason: "本番有効化後のタスク完了速度、Finding parity、LLM消費量の監視が必要"
    impact: medium
    tracking_task_id: SGK-2026-0356
    recommended_next_action: "実稼働中に tasks/minute, LLM requests/minute, エラーレート を計測し、serial baseline と比較"
  - deferred_id: SGK-2026-0356-D02
    title: "継続監視: DVWA security=medium/high のCSRFトークン安全性検証"
    reason: "security=lowでは安全だが、medium/highでは未検証"
    impact: low
    tracking_task_id: SGK-2026-0356
    recommended_next_action: "medium/high環境で並列実行テストを実施し、トークン競合の有無を確認"
```
