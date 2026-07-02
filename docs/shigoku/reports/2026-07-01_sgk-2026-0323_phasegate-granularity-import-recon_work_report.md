---
task_id: SGK-2026-0323-WR
doc_type: work_report
status: done
parent_task_id: SGK-2026-0320
related_docs:
  - docs/shigoku/subtasks/done/2026-06-29_sgk-2026-0323_phasegate-granularity-import-recon_subtask_plan.md
  - docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
  - docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
title: 'SGK-2026-0323 P2b 実装完了報告: PhaseGate細粒度化＋過去Recon成果物再利用'
created_at: '2026-07-01'
updated_at: '2026-07-02'
---

# SGK-2026-0323 P2b 実装完了報告

## 実施サマリ

P2b（過去Recon成果物の安全な取り込み + PhaseGate 細粒度 Attack 解放）を完了した。
Recipe score 選抜（Phase C）および P3/Neo4j/UI は未着手。

## 実装ユニット

| Unit | 内容 | ファイル |
|------|------|----------|
| 1 | recon_importer データ契約 | `src/core/engine/recon_importer.py` (新設) |
| 2 | load_imported_recon_dir() 読み込み・正規化 | 同上 |
| 3 | freshness/provenance (compute_freshness_score 再利用) | 同上 |
| 4 | CLI --import-recon + messages.py + interactive_bridge 接続 | `src/main.py`, `src/cli/messages.py`, `src/core/conductor/interactive_bridge.py` |
| 5 | MasterConductor への import bundle 接続・merge | `src/core/engine/master_conductor.py` |
| 6 | PhaseGate 細粒度判定 (PhaseData 拡張, can_create_attack_task) | `src/core/engine/phase_gate.py` |
| 7 | 段階的 Attack 解放 (_create_attack_tasks_from_recon 改修) | `src/core/engine/master_conductor.py` |
| 8 | テスト | 4ファイル新設 (43 tests) |

## 検証結果

- targeted tests: 43 passed
- engine regression: 574 passed (0 breakage)
- recon regression: 89 passed
- SHIGOKU docs validation: 0 issues

## 修正済み不具合（レビュー指摘反映）

| Priority | Issue | 修正 |
|----------|-------|------|
| High | Budget exhaustion が全 Attack category を拒否 | budget 判定を metadata 明示指定時のみに制限 |
| High | --recon パスが import_recon_dir 未伝搬 | args.recon 分岐に import_recon_dir 追加 |
| Medium | provenance key 不統一 | _provenance → _import_provenance に統一 |
| Low | accepted_artifacts が fail-closed artifact を含む | FAIL_CLOSED_REASON_CODES 全件フィルタ |

## deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0323-D01
    title: 'freshness しきい値の運用チューニング'
    reason: 'compute_freshness_score は takeover candidate 用に設計されており、recon_state.json の mtime 代用は精度限界あり'
    impact: medium
    tracking_task_id: SGK-2026-0320
    recommended_next_action: '複数ターゲットで freshness スコア分布を計測し既定値を見直す'

  - deferred_id: SGK-2026-0323-D02
    title: 'Phase C: Recipe score 選抜の本実装'
    reason: 'P2b ではスコープ外。match_recipes_to_context() は依然全件返し'
    impact: high
    tracking_task_id: SGK-2026-0320
    recommended_next_action: 'Phase C 計画書に基づき score-based top-N 選抜を実装'

  - deferred_id: SGK-2026-0323-D03
    title: '実 import dir での運用テスト'
    reason: 'テストは tempdir + モックデータのみ。実ターゲットの *_subs.txt / httpx.json で確認必要'
    impact: medium
    tracking_task_id: SGK-2026-0320
    recommended_next_action: '実ターゲットの recon export で --import-recon を動作確認'
```
