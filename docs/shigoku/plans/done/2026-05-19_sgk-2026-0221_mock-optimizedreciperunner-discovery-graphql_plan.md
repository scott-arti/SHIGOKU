---
task_id: SGK-2026-0221
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
- docs/shigoku/specs/2026-02-11_PHASE2_MANAGER_ARCH.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s01_groupa_execution-path_subtask_plan.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s02_groupb_discovery-graphql_subtask_plan.md
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s03_groupc_regression-observability_subtask_plan.md
- docs/shigoku/subtasks/2026-05-31_sgk-2026-0250_graphql-slo_subtask_plan.md
title: 'Mock除去優先: OptimizedRecipeRunner と Discovery GraphQL 本実装接続'
created_at: '2026-05-19'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/engine/optimized_runner.py, src/core/agents/swarm/discovery/graphql.py
---

# Mock除去優先: OptimizedRecipeRunner と Discovery GraphQL 本実装接続 Plan

## Goal
- 検出実行経路に残存するモック/スケルトンを本実装へ置換し、以下2系統の「見かけ成功」を排除する。
- `OptimizedRecipeRunner` の `_mock_execute` 依存を解消し、Recipe実行を実ツール実行へ接続する。
- `DiscoveryManager -> GraphQLNavigator` 経路を実HTTPベース検査へ接続し、URL文字列判定の擬似検出を廃止する。

## Scope
- In scope:
  - `src/core/engine/optimized_runner.py` の実行ロジックを Dispatcher/既存Agent実行に接続する。
  - `src/core/engine/master_conductor.py` の `run_recipe` 経路で、実行結果の成否・エラー伝播を厳格化する。
  - `src/core/agents/swarm/discovery/graphql.py` をスケルトン実装から実検査実装へ置換する。
  - `src/core/agents/swarm/discovery/manager.py` の GraphQL委譲経路を、上記本実装に整合させる。
  - GraphQL 検出の結果構造（`introspection_enabled` 等）を既存利用側と互換に保つ。
  - 既存テスト拡張（unit/integration）と最低1件の実行経路検証。
- Out of scope:
  - AuthManager の OAuth/MFA 本実装統合（別タスク）。
  - AutoReauth のトークンリフレッシュ本実装（別タスク）。
  - `src/core/agents/specialized/graphql_navigator.py` の全面統廃合（本計画では接続優先）。
  - レシピ体系の全面リデザイン（DAG最適化戦略の刷新など）。

## Current Gaps (Mock / Unimplemented)
1. `OptimizedRecipeRunner` が `_mock_execute` を呼んでおり、実スキャンが未接続。
2. `Discovery GraphQL` が URL 文字列判定による擬似結果返却（Skeleton）。
3. `run_recipe` 経路で成功扱いされても、実際の検査保証が弱い（成否基準が曖昧）。
4. ドキュメント（稼働中表現）と実行経路の実態に乖離がある。

## Subtask Grouping (Dependency / Risk Based)
### Group A: 実行基盤の確定（高影響・先行必須）
- 対象:
  - `optimized_runner.py`
  - `master_conductor.py`（`run_recipe` 分岐）
- 理由:
  - Recipe実行基盤がモックのままだと、GraphQL側を本実装化しても全体で擬似成功が残る。
  - 実行成否・エラー伝播が不明確だと、後続テストの真偽が崩れる。
- 主要実装:
  - `step.action` を既存Dispatcher/Agent実行にマッピング。
  - `_mock_execute` を削除または非本番限定へ隔離。
  - 失敗時を握り潰さず、`step_id` 単位の失敗理由を返却。
  - キャッシュキーと再実行時挙動を見直し（誤キャッシュ防止）。

### Group B: Discovery GraphQL 本実装接続（高リスク・A完了後）
- 対象:
  - `src/core/agents/swarm/discovery/graphql.py`
  - `src/core/agents/swarm/discovery/manager.py`
- 理由:
  - 現在の Skeleton 実装は誤検出リスクが高い。
  - Group A の成否基盤が固まってから接続しないと、検証が不安定化する。
- 主要実装:
  - HTTPベースで Introspection / GraphiQL / Field Suggestion を実検査。
  - 既存 `GraphQLAnalyzer`（`src/core/attack/graphql_analyzer.py`）活用を第一選択。
  - 返却スキーマを `manager` 側互換に統一。
  - タイムアウト・接続エラー時の挙動を deterministic に定義。

### Group C: 回帰防止と可観測性（中影響・A/B完了後）
- 対象:
  - `tests/core/engine/*`
  - `tests/core/agents/swarm/discovery/*`（必要に応じ新規）
  - 関連ドキュメント更新（稼働中/未実装表現）
- 理由:
  - モック除去は既存テストの前提を壊しやすく、回帰ガードが必須。
  - 実行ログ/失敗理由の可視化不足は運用で再発を招く。
- 主要実装:
  - Recipe実行テストで「実経路が呼ばれたこと」を検証。
  - GraphQLテストで「URL文字列依存でない検出」を保証。
  - docs の表現を実態に合わせる（別報告書でも可）。

## Implementation Order (Strict)
1. Group A-1: `optimized_runner.py` 実行アダプタ導入（最小接続）。
2. Group A-2: `master_conductor.py` `run_recipe` 成否・エラー伝播の厳格化。
3. Group A-3: `_mock_execute` の本番経路除外（削除/DEV限定隔離）。
4. Group B-1: `discovery/graphql.py` を `GraphQLAnalyzer` ベースへ置換。
5. Group B-2: `discovery/manager.py` 結果整形・ログ・例外処理整合。
6. Group C-1: ユニットテスト更新（A/Bの主要分岐）。
7. Group C-2: 統合テストと実行サンプル検証。
8. Group C-3: ドキュメント更新（実装状況、制約、既知リスク）。

## Risk Register
1. 実行基盤変更で既存Recipe互換が壊れる。
   - 対策: Actionマッピング互換層を先に作る。未対応Actionは明示エラーで fail-fast。
2. GraphQL検査でタイムアウト増加・誤検知。
   - 対策: タイムアウトを段階化（通常/大規模スキーマ）。判定を複数シグナル化。
3. テストが旧モック前提で破綻。
   - 対策: 旧モック依存テストを分離し、実経路検証テストへ置換。
4. 変更範囲が大きくレビュー困難。
   - 対策: Group単位でPR相当の論理分割（A→B→C）で進行。

## Acceptance Criteria
1. `run_recipe` 実行時に `_mock_execute` が呼ばれない。
2. Recipe step は実行結果（成功/失敗/理由）を `step_id` ごとに返す。
3. `DiscoveryManager.run_graphql_navigator` が Skeleton 判定を使わず、実検査結果を返す。
4. GraphQL の `introspection_enabled/graphiql_enabled/field_suggestions_enabled` が実レスポンス起点で判定される。
5. 主要テストが通り、既知の未対応は明示された状態で完了報告できる。

## Tasks
1. Group A: Recipe実行基盤を本実装接続し、モック経路を排除する。
2. Group B: Discovery GraphQL を実HTTP検査へ置換し、Manager経路を整合させる。
3. Group C: 回帰防止テストとドキュメント整備を実施する。

## Deliverables
- Plan doc (this file)
- Group A subtask plan (`SGK-2026-0221-S01`)
- Group B subtask plan (`SGK-2026-0221-S02`)
- Group C subtask plan (`SGK-2026-0221-S03`)
- Work report (`doc_type: work_report`)
- Work log (`doc_type: work_log`)

## Validation
- Targeted:
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_graphql.py -q`
  - `.venv/bin/pytest tests/core/agents/swarm/injection/test_graphql_integration.py -q`
  - `.venv/bin/pytest tests/core/engine -q`
- Broader (targeted pass後):
  - `.venv/bin/pytest tests/core/agents/swarm tests/core/engine -q`
- Docs integrity:
  - `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`
