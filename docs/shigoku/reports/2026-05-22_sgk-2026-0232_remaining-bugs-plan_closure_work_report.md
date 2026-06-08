---
task_id: SGK-2026-0232
doc_type: work_report
status: done
parent_task_id: SGK-2026-0215
related_docs:
  - docs/shigoku/plans/remaining_bugs_plan.md
  - docs/shigoku/specs/2026-05-22_should_observe_observation_policy_spec.md
created_at: '2026-05-22'
updated_at: '2026-05-22'
---

# SGK-2026-0215 クローズ作業報告

## 実装内容
- ReAct観察の実行判定を `_should_observe` 経由へ統一し、判定理由を enum ベースで集約。
- `master_conductor_*` を含む回帰テストを再実行し、最終回帰を確認。
- `_should_observe` の別紙 spec を実装準拠へ更新（判定順序・reason code・可観測性項目）。
- Bug #6 計画を実装実体へ同期（`safe_run_async` 名称統一、対象ファイル更新）。
- `src/core` 内の `asyncio.run()` 実呼び出しを `safe_run_async` へ置換。

## 判断理由
- コスト爆発対策（Bug #1）は、回数制御・低価値除外・サンプリング・breaker/queue制御で先に実効性を確保。
- token budget は制限値設計の難易度が高く、誤設定時の検知品質劣化リスクがあるため現時点では見送り。
- Bug #6 は plan と実コードの乖離を解消し、運用判断可能な状態へ整備。

## リスク
- token budget 未導入のため、長文応答時のコスト制御は回数制御依存。
- `src/core` 以外には `asyncio.run()` が残存しており、将来の呼び出し拡大時に再監査が必要。

## deferred_tasks
- deferred_task_id: SGK-2026-0215-D01
  title: 全repo async呼び出し統一（`safe_run_async` への段階置換）
  reason: 現フェーズは `src/core` を優先して安全化。CLI/commands/tools 全体適用は影響範囲が広く別フェーズ管理が妥当。
  owner_role: Architect/SRE
  target_doc: docs/shigoku/plans/remaining_bugs_plan.md
  due_hint: '2026-Q2'
- deferred_task_id: SGK-2026-0215-D02
  title: 長文応答監視 KPI（平均/95p token）追加
  reason: token budget を導入しない方針の代替として、コスト劣化の早期検知KPIを運用で担保する必要がある。
  owner_role: PM/SRE
  target_doc: docs/shigoku/plans/remaining_bugs_plan.md
  due_hint: '2026-Q2'

