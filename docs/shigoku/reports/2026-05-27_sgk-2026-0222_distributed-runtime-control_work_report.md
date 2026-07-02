---
task_id: SGK-2026-0222
doc_type: work_report
status: done
parent_task_id: null
related_docs:
- docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md
- docs/shigoku/worklogs/2026-05-26_sgk-2026-0222_runtime-control-backend-implementation_work_log.md
- docs/shigoku/manuals/2026-05-26_runtime-control-fail-open-guard_runbook.md
created_at: '2026-05-27'
updated_at: '2026-07-02'
---

# 作業報告書: 分散ランタイム制御共通基盤化（SGK-2026-0222）

## 概要

SGK-2026-0222 の計画に基づき、runtime control の backend 化、fail-safe/影響分類の仕様固定、release governance の CI 強制、承認正本照合、証跡真正性検証まで実装した。  
本タスクは実装・検証・運用導線の観点で完了条件を満たしたため `done` とする。

## 実装・反映内容

1. Runtime Control 制御面の実装
- `src/core/agents/swarm/discovery/graphql.py`
  - backend unavailable 時の fail-safe 未検査扱い (`not_tested_runtime_control_fail_safe`) を固定
  - policy/shadow diff の構造化イベント契約を実装
- `src/core/agents/swarm/runtime_control_backend.py`
  - backend 抽象と導入経路を整備

2. Release Gate / 統治の実装
- `src/reporting/runtime_control_release_gate.py`
  - 6ゲート必須、fail→hold、critical waived 禁止の検証
- `scripts/shigoku_ops_cli.py`
  - `runtime-control gate` を追加
  - gate証跡検証、integrity hash照合、approval evidence照合、branch protection 条件評価を実装
- `scripts/generate_runtime_control_approval_evidence.py`
  - GitHub PR Review API + branch protection 正本から承認証跡を生成
- `scripts/generate_runtime_control_gate_evidence.py`
  - approval証跡を入力に gate証跡 + integrity manifest を自動生成
- `scripts/check_runtime_control_required_check.py`
  - branch protection required checks に `runtime-control-governance` が含まれることを検証

3. CI/運用導線の実装
- `.github/workflows/test.yml`
  - `runtime-control-governance` ジョブを PR で必須実行
  - required check 検証、approval証跡生成、gate証跡生成、runtime-control gate 実行を連結
- `docs/shigoku/manuals/2026-05-26_runtime-control-fail-open-guard_runbook.md`
  - API一時障害時の再実行基準（回数・待機・エスカレーション）を明文化

## 検証結果

- `.venv/bin/pytest tests/unit/scripts/test_check_runtime_control_required_check.py tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/reporting/test_runtime_control_release_gate.py -q`
  - 31 passed
- `python3 scripts/shigoku_ops_cli.py --json runtime-control gate --evidence-file ... --integrity-manifest ... --approval-evidence-file ...`
  - `status=pass`, `decision=proceed` を確認済み

## 完了判定

- 計画書で定義した runtime-control governance の実装方針（backend化、gate強制、承認正本照合、証跡真正性、運用runbook）を満たしたため、SGK-2026-0222 を `done` とする。

## 残課題 / deferred_tasks

```yaml
deferred_tasks:
  - task: "GitHub branch protection required check 名変更時の運用周知"
    reason: "CI側は `${{ github.job }}` で追従するが、組織運用手順側の周知は別途必要"
    tracked_by: "運用改善バックログ"
```
