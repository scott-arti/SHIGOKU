---
task_id: SGK-2026-0431
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0430
related_docs:
- docs/shigoku/reports/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_report.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
created_at: '2026-08-08'
updated_at: '2026-08-08'
tags:
- shigoku
- vdp
- deferred
target: src/core/engine/master_conductor.py,tests/core/engine
---

# SGK-2026-0431: 並列 executor（execute_parallel）における VDP follow-up drain 合流点の再配線

SGK-2026-0430 の独立検証中に特定した latent gap を、独立した追跡タスクとして起票する。**0430 の完了契約（Q1 attempts>0 / Q2 fail-open closed）は VDP が使うシリアル経路で充足済み**であり、本件は現行 runtime 経路の阻害ではない（deferred_followup）。

## 背景 / 観測

- 0430 F1 で、`master_conductor.execute_parallel` 内の `task_executor` クロージャに置かれていた
  `_drain_vdp_pending_follow_up_injections()` を削除した。この callsite は scheduler により
  **off-main thread** で実行され、drain の PCR-P1 main-thread assert を必ず発火させていた
  （＝並列＋VDP follow-up は従来「確実クラッシュ」だった）。削除自体は正当。
- ただし削除後、`execute_parallel` は末尾が `await scheduler.run(task_executor)` → `return summary`
  のみで、**deferred VDP injection buffer を main thread で drain する合流点が存在しない**。
- `_apply_post_batch_feedback`（drain ホスト, master_conductor.py:6686→6702）は**シリアルバッチ経路
  （7354/7391）からのみ**呼ばれる。したがって並列 executor で VDP follow-up を回すと、
  deferred buffer が drain されず滞留し得る。
- 現行の VDP m3a runtime は `parallelism.default_executor: serial` を使うため、この経路は
  0430 では未行使。run#2（serial, `session_20260807_153606`）は attempts=3 で正常 drain を実証済み。

## 完了条件（着手時に確定する）

1. `execute_parallel` 経由で VDP follow-up が enqueue される条件を確定する（そもそも到達し得るか）。
2. 到達し得る場合、次のいずれかを実装する:
   - (A) `execute_parallel` の scheduler.run 完了後に **main thread で** deferred injection を drain する
     合流点を追加する（PCR-P1 main-thread 契約を維持）。
   - (B) VDP follow-up が有効なとき並列 executor を **serial に強制**する明示ガードを入れ、
     設定・コードで並列＋VDP を fail-closed に拒否する。
3. 選んだ方針に対する回帰テストを追加する（並列経路で deferred injection が drain される、
   または serial 強制が発火することを self-checking で検証）。
4. PCR-P1 assert は無改変（drain は main thread のみ）。

## NOT in scope

- PCR-P1 assert の削除・条件緩和。
- シリアル経路の drain 再設計（0426/0430 で実証済み・無改変）。
- 0430 で確定した Q1/Q2 の再検証（別artifactで確認済み）。

## 参照

- `src/core/engine/master_conductor.py`: `execute_parallel`（~15256）、`_apply_post_batch_feedback`（6686/6702）、`_drain_vdp_pending_follow_up_injections`（11714）。
- 0430 work_report（F1 の記述）。
