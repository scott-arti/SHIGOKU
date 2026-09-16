---
task_id: SGK-2026-0506
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0506_blind-sqli-autonomous-wiring.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0506_blind-sqli-autonomous-wiring_work_log.md
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0504_autonomous-detection-wiring.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- autonomous-integration
- blind-sqli
created_at: '2026-09-16'
updated_at: '2026-09-17'
---

# SGK-2026-0506 作業完了報告 — blind_sqli を自律走行へ配線（URL 駆動の汎用自己適応・非カーブフィット）

## 何をしたか / なぜ

SGK-2026-0504 の配線土台（`hunter_registry`）に、次の1本として `smart_blind_sqli` を載せた。
`SmartBlindSQLiHunter` の中核（真偽オラクルの自己導出・恒真恒偽差分・実データ抽出成立で確定/否なら
fail-close）は汎用で健全と確認済で、唯一の自走ギャップは入力適応（`mode/param/base_value` が
task ヒント頼み＝既定 path/id は SKF ラボ形状寄り）だった。これを **URL 駆動の自己適応**で埋めた。

## カーブフィッティング回避（本タスクの絶対条件・遵守）

- ラボ固有のヒント（特定 param 名・成功印・DB 種別）を**与えず・ハードコードせず**、対象 URL と
  実応答からのみ導出した。
- 真偽オラクルが自己校正できない／実データ抽出ができない対象は **fail-close**（偽◎を作らない）。
- 完了契約に「特定ラボで確定する」ことを含めていない（実対象の自走E2E◎認証は deferred）。

## 実装（最小差分・追加中心・凍結5ファイル無変更）

- `smart_blind_sqli.py`: `_effective_target(task)` 新設 →（1）`blind_sqli_mode` 明示時は従来通り
  （2）未明示かつ URL にクエリ有り → `query` モード＋先頭 param＋その現在値を URL から導出
  （3）クエリ無し → `path`/`id`/`1`（不変）。`_build_url`/`_probe` の mode/param/base_value 解決を
  `_effective_target` に一本化（重複除去）。module 関数 `build_blind_sqli_url`/`build_blind_sqli_value`
  （封印再現と共有）は無変更。
- `hunter_registry.py`: `blind_sqli` の HunterSpec を追加。
- `unknown_hypotheses.py`: sqli 面かつクエリ param があるとき `blind_sqli` 仮説を併走。
- 新規テスト `test_blind_sqli_autonomous_wiring.py`（8件）。
- 能力マップ(0465) SQLi 行に自走配線を追記。

## 結果（独立検証・Claude が実測）

- 新規テスト: `test_blind_sqli_autonomous_wiring`(8) ＋ `test_registry_hunter_wiring`(10) → **18 passed**。
- 自己適応の実測: `?id=7&q=x` → `(query, id, "7")`／注入は `id` へ・`q=x` 保持；`/home/5` →
  `(path, id, "1")`；明示 `blind_sqli_mode=path` → path（後方互換）。
- 回帰: injection スイート **910 passed, 1 failed**。唯一の失敗 `test_t3_hybrid_wiring.py::
  TestT6BudgetExhaustion::test_needs_more_still_no_f5_emit` は本変更前(HEAD)でも同一に失敗＝**既存の失敗**。
  既存 `blind_sqli` テスト（`test_blind_sqli_finding`・`test_sealed_reproduction_blind_sqli`）は pass
  ＝後方互換（明示 `blind_sqli_mode=path` を保持）。
- docs: `validate_shigoku_docs.py` → `REGISTRY_ISSUES=0`/`BROKEN_LINKS=0`/`DEFERRED_LINK_ISSUES=0`
  （既存の無関係 FM 1件のみ）。`graphify update .` 実行済。

## 完了条件の充足

- CB-1（登録→routing→汎用 dispatch）／CB-2（URL 駆動自己適応）／CB-3（後方互換）／
  CB-4（injection 回帰なし・唯一の失敗は既存）／CB-5（マップ更新＋validate 0エラー）: すべて満たす。

`in_scope_blocker` は0件。完了契約を全て満たすため本タスクを `done` とする。

## 参考にしたルール

- `rules/codingrules.md`・`rules/python-tests.md`・`rules/lessons.md`、`CLAUDE.md` §11〜§19
- メモリ [[no-capability-minimization]]（カーブフィット禁止）・[[detection-capability-wiring-map]]

## deferred / 別件（非阻害・honest boundary）

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0506-D01
    title: "blind_sqli の実対象フル自走E2E◎認証"
    reason: "機構は単体テストで実証済。実確定は target 依存。"
    impact: medium
    tracking_task_id: SGK-2026-0506
    recommended_next_action: "実 blind-sqli 対象を起動し自走で真偽オラクル校正→抽出→確定まで目視確認する追跡タスクを起票する"
  - deferred_id: SGK-2026-0506-D02
    title: "文字列文脈(quote 推定)・複数 DB 抽出への一般化"
    reason: "現状は数値文脈・sqlite 既定で、非該当は fail-close(honest boundary)。"
    impact: medium
    tracking_task_id: SGK-2026-0506
    recommended_next_action: "quote 両文脈の校正試行と DB 別 version 関数の自動選択を扱う追跡タスクを起票する"
  - deferred_id: SGK-2026-0506-D03
    title: "残り13ハンターの配線・第2 dispatch(vuln_type)・OOB 受信器の自走統合"
    reason: "フェーズB の後続範囲。"
    impact: high
    tracking_task_id: SGK-2026-0504
    recommended_next_action: "各ハンターの自走適応と第2 dispatch 汎用化を1本ずつ追跡タスク化する"
```
