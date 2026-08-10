---
task_id: SGK-2026-0431
doc_type: plan
status: done
parent_task_id: SGK-2026-0430
related_docs:
- docs/shigoku/reports/2026-08-07_sgk-2026-0430_sealed-live-rerun-verification_work_report.md
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
- docs/shigoku/reports/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_work_report.md
created_at: '2026-08-08'
updated_at: '2026-08-10'
tags:
- shigoku
- vdp
target: src/core/engine/master_conductor.py,tests/core/engine
---

# SGK-2026-0431: task 実行経路における off-main VDP follow-up drain の main-thread 化（scope 拡大）

当初は「execute_parallel の drain 合流点」の latent gap として起票したが、**SGK-2026-0437 の封印ライブ run
（session_20260809_212541）で実害が実証された**ため、scope を task 実行経路全般の off-main drain へ拡大し active 化する。

## 背景 / 観測（0437 で実証）

- 0437 run_stdout で **recon_master（task_002）が critical failure**:
  `_execute_single_task_full_flow`（master_conductor.py:**7667**）が
  `_drain_vdp_pending_follow_up_injections()` を **main-thread ガード無し**で呼び出し、
  当該メソッドが `_run_async_safe`（recon のバックグラウンド event loop スレッド）経由で **off-main 実行**
  → drain の PCR-P1 assert（11724）発火 → task_002 critical failure → **recon が truncate**。
- 直前に `ReconPipeline execution error: PCR-P1: task_queue mutation must be on main thread` も記録
  （recon background thread からの task_queue mutation）。
- 対照的に callsite **11695 は `if threading.current_thread() is threading.main_thread():` ガード済み**で安全
  （off-main 時は drain せず buffer に残し、次の main-thread drain=`_apply_post_batch_feedback`(6702) へ委譲）。
- 影響: この critical failure が **breadth を直接制約**（0437 は followed_up 5 / attempted 1・scenario coverage 1/12）。
  つまり本件は「並列限定の latent gap」ではなく、**通常 recon 経路で発火する correctness 欠陥かつ breadth 主因の一つ**。

## 完了条件（着手時に確定する）

1. **全 drain callsite を棚卸し**（6702 / 7667 / 11695 / 旧 execute_parallel 系ほか）し、off-main で実行され得るものを特定する。
2. off-main で実行され得る callsite は **11695 と同じ main-thread ガードに統一**する:
   off-main のときは drain せず buffer に残し、**次の main-thread 合流点（`_apply_post_batch_feedback` 6702）で必ず drain される**ことを保証する（PCR-P1 契約維持・injection の取りこぼし 0）。
3. off-main task 実行後に buffered injection が確実に main-thread drain される合流点が常に存在することを保証
   （無ければ main-thread の合流点を追加。injection 滞留・喪失を作らない）。
4. **回帰テスト（self-checking）**: (a) off-main から drain callsite を呼んでも assert で落ちず buffer に残る／
   (b) その後 main-thread drain で確実に反映される／(c) recon 経路（`_run_async_safe`）で task が critical failure しない。
5. 可能なら 0437 相当の封印 run で **recon が critical failure せず breadth が回復**することを実測（confirmed 件数は指標にしない）。
6. PCR-P1 assert（task_queue.py・drain 11724）は無改変。

## NOT in scope

- PCR-P1 assert の削除・条件緩和（修正は「off-main では drain せず main-thread へ委譲」方向のみ）。
- シリアル経路の drain 再設計（0426/0430 で実証済み・無改変）。
- breadth 改善そのもの（hypothesis/recon の広さ拡大）は別軸（本件は「クラッシュで breadth を削る欠陥」の除去に限定）。

## 参照

- `src/core/engine/master_conductor.py`: `_execute_single_task_full_flow`(7667・**未ガード**)、
  `_apply_post_batch_feedback`(6686/6702)、11695(**ガード済み参照実装**)、`_drain_vdp_pending_follow_up_injections`(11714/assert 11724)、`_run_async_safe`(1284)。
- SGK-2026-0437 work_report / run_stdout（task_002 critical failure の実証）。
- SGK-2026-0430 work_report（F1 の経緯）。
