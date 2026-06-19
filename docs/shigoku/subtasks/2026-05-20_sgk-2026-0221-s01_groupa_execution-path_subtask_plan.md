---
task_id: SGK-2026-0221-S01
doc_type: subtask_plan
doc_usage: execution_plan
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/plans/2026-05-19_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/specs/2026-02-11_PHASE2_MANAGER_ARCH.md
- docs/shigoku/reports/2026-05-21_sgk-2026-0221-s01_groupa_work_report.md
title: 'GroupA: 実行経路のモック除去（OptimizedRecipeRunner / run_recipe）'
created_at: '2026-05-20'
updated_at: '2026-05-20'
tags:
- shigoku
- group-a
- execution-path
---

# GroupA Subtask Plan (Integrated)

## Goal
- `OptimizedRecipeRunner` のモック実行依存を除去し、`run_recipe` を本番実行経路へ統合する。
- Recon 起点の `ssrf_candidate` から検出までを、response-only 偏重から `response + blind/oob/dns` の相関型へ拡張し、攻撃成功率と再現性を両立する。
- 実行基盤の結合度を下げ、将来のレシピ追加・ツールチェーン統合時に破綻しない設計へ移行する。

## Success Definition
1. `run_recipe` 実行で `_mock_execute` が呼ばれない。
2. Recipe step の結果が `step_result` 契約に準拠して返る。
3. SSRF は 2 レーン（Fast/Blind）で実行され、`blind_correlation` 契約を満たす。
4. 同時実行制御・再試行制御・バックプレッシャーが明示設定され、暴走しない。
5. タグ語彙・Action・Recipe選定の契約が単一化され、統合テストで守られる。

## Scope
- `src/core/engine/optimized_runner.py`
- `src/core/engine/master_conductor.py`
- `src/core/engine/recipe_loader.py`
- `src/core/engine/swarm_dispatcher.py`
- `src/recon/pipeline.py`
- `src/core/agents/swarm/injection/manager.py`
- `src/core/agents/swarm/injection/smart_ssrf.py`
- `config/tagging_rules.yaml`
- 関連テスト群（engine/recon/injection）

## Out of Scope
- OAuth/MFA の本実装統合。
- Discovery GraphQL 本実装接続の全面実装（GroupBで実施）。
- レシピ仕様の全面刷新（DSL再設計など）。

## Unified Design Principles
1. 攻撃成功率: 防御指紋・到達性確認・段階的エスカレーションを必須化。
2. 品質保証: 失敗を分類可能にし、再試行条件を固定し、判定をブレさせない。
3. 効率最適化: スコアリング駆動、早期停止、非同期制御を採用する。
4. 規模耐性: 同時実行予算、重複抑止、バックプレッシャーを最初から設計に入れる。
5. 設計保全: タグ語彙・Action・Task契約を単一化し、二重経路を削減する。

## Data/Contract Definitions
### Step Result Contract
- `status`: `success|failed|blocked|skipped`
- `error_code`: `BLOCKED_SCOPE|UNSUPPORTED_ACTION|TOOL_TIMEOUT|TOOL_ERROR|DEPENDENCY_FAILED|UNKNOWN_ERROR`
- `reason`: 非空文字列
- `retryable`: `TOOL_TIMEOUT|TOOL_ERROR` のみ `true`

### Recipe Final Verdict
- 重大失敗（`BLOCKED_SCOPE|UNSUPPORTED_ACTION`）が1件でもあれば `success=false`
- 重大失敗なしでも `failed_ratio > 0.3` かつ `step_count >= 5` で `success=false`

### SSRF Evidence Contract
- `ssrf_score`: 0-100
- `score_breakdown`: ルール別スコア詳細
- `blind_correlation`:
  - `time_based.confirmed`
  - `oob.confirmed`
  - `dns.confirmed`
  - `correlated`（2-of-3）
  - `verdict`: `confirmed|tentative|none`

## Integrated Implementation Tasks
### PM Execution Strategy
1. 先に「価値が早く出る変更」を入れて攻撃成功率と品質を上げる。
2. 次に「誤検知/見逃しと暴走リスク」を抑える。
3. 最後に「アーキテクチャ整理」を実施し、長期保守性を確保する。

### Wave A: Core Execution Stabilization (最優先)
1. `OptimizedRecipeRunner` から `_mock_execute` を除去し、実行アダプタを導入する。
2. `run_recipe` を通常の実行チェーンと整合する結果契約で返却する。
3. `master_conductor` 側 `run_recipe` 分岐の成功判定を契約準拠へ変更する。
4. `action` の許可セットを列挙管理し、未対応は `UNSUPPORTED_ACTION` で即失敗させる。

### Wave A Gate
1. `_mock_execute` 呼び出しが 0 件である。
2. `step_result` 契約の必須キー欠落が 0 件である。

### Wave B: Hit-Rate Quick Wins (攻撃成功率の即効改善)
5. レシピ先頭にパラメータ到達性ゲートを追加し、未到達対象を除外する。
6. `tagging_rules.yaml` と `recon pipeline` を拡張し、JSON nested / GraphQL variables / header文脈を採点対象に含める。
7. `ssrf_score` と `score_breakdown` を `_context.url_evidence_by_url` へ保存する。
8. Lane-1: `ssrf_score >= 40` を `SmartSSRFHunter` に投入する。

### Wave B Gate
1. 到達性ゲートが無効化されず実行される。
2. SSRF 採点情報（score/breakdown）が出力に含まれる。

### Wave C: Deep Detection + Safety Baseline
9. Lane-2: `Lane-1陰性 AND (score>=65 OR risk_override=true)` を `cmd_ssrf` へ昇格する。
10. DNS rebinding を Lane-2 で必須有効化し、`blind_correlation` を 2-of-3 相関で確定する。
11. `global semaphore + host semaphore` を導入し、同時実行予算を設定化する。
12. retry 戦略（回数/backoff/jitter/circuit breaker）を固定し、再試行ストームを防止する。
13. 重複抑止キー（target+param+payload_class）を導入し、多重送信を防止する。

### Wave C Gate
1. Lane-2 昇格条件がテストで再現できる。
2. `blind_correlation.verdict` が常に設定される。
3. 同時実行予算の上限超過が発生しない。

### Wave D: Recipe Hardening and Operability
14. `match_recipes_to_context` をスコアリング化し、上位実行制限を導入する。
15. 防御指紋ステップ（WAF/CDN/Auth/RateLimit）を導入し、レシピ戦術を切替する。
16. レシピを `probe -> adaptive -> evasive` の3段に分割し、段階実行する。
17. 成功定義を `PoC成立 -> 影響確認 -> 再現確認` の3段へ変更する。
18. OOB/DNS 依存障害時の隔離フォールバック（Lane-2 degrade）を導入する。
19. ログ高カーディナリティを抑制し、メトリクス集約キーを定義する。
20. `skip_reason` 別件数を `execution_log.phase1_summary` に集計出力する（`url_results` 由来）。
21. Dashboard API の metrics で `skip_reason_counts` を返却し、UI 連携可能な形で公開する。
22. `skip_reason` の語彙管理を固定し、未知値は `other` に集約する。

### Wave D Gate
1. スコアリング選定で上位Nのみが実行される。
2. 成功定義が3段すべて満たされたケースのみ confirmed 扱いになる。
3. `skip_reason_counts` が API レスポンスに含まれ、セッション横断で集計される。

### Wave E: Architecture Decoupling and Toolchain Integration
20. タグ語彙を `Tag Taxonomy Registry` に一本化し、`pipeline/dispatcher/manager` で共有する。
21. `run_recipe` 特別経路を縮小し、Recipe step を first-class task として統合する。
22. 死蔵/二重経路（`RecipeLoader.to_tasks`、deprecated runner/cli）を整理し、正規統合点を明示する。
23. `TaskSchema` と `ActionSchema` の契約テストを追加し、互換性をCIで強制する。

### Wave E Gate
1. タグ語彙の重複定義が存在しない。
2. 主要実行経路が単一路であることを契約テストで証明できる。

## Critical Risks and Countermeasures
1. 互換崩れ: Action列挙と契約テストで防止。
2. 攻撃成功率低下: 到達性ゲートと段階実行で緩和。
3. FP/FN増加: `verdict` 導入と再検証キューで緩和。
4. 実行暴走: 同時実行予算・retry制御・重複抑止で防止。
5. 統合破綻: タグ語彙正本化と単一路実行で防止。

## Acceptance Criteria
1. `_mock_execute` 未使用（検索で 0 hit）。
2. `step_result` と `blind_correlation` が全出力で契約準拠。
3. `UNKNOWN_ERROR` 比率が閾値以下（運用KPI設定値）。
4. Lane-2 昇格が規定条件で発火し、`verdict` が設定される。
5. タグ語彙の重複定義が解消され、契約テストが通過する。

## Validation
- `.venv/bin/pytest tests/core/engine -q`
- `.venv/bin/pytest tests/core/engine -k recipe -q`
- `.venv/bin/pytest tests/core/attack/test_ssrf_tester.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_smart_ssrf.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/test_smart_cmd_ssrf.py -q`
- `.venv/bin/pytest tests/core/agents/swarm/injection/test_ssrf_pipeline.py -q`
- `.venv/bin/pytest tests/recon/test_step3b_hybrid_url.py -q`
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`

## Mandatory Edge Test Cases
1. JSON nested parameter が `ssrf_candidate` として採点される。
2. GraphQL variables 内 URL が採点される。
3. Lane-1 陰性 + 高スコアで Lane-2 昇格が発火する。
4. DNS rebinding 実行で `blind_correlation.dns` が更新される。
5. OOB hit で `verdict` が `confirmed|tentative` に遷移する。
6. `failed_ratio` 判定が `step_count < 5` では fail-close しない。
7. 重複抑止キーにより同一 target/param/payload_class が多重送信されない。
8. タグ語彙契約テストで `pipeline/dispatcher/manager` の不一致が検知される。

## Wave C Pre-Start Review (Threshold and Lane-2 Promotion)

### Review Conclusion
- Wave C は着手可能と判断する。
- ただし、着手前に「閾値の初期値」と「Lane-2昇格条件」を固定し、事前検証 Gate を通過してから実装を開始する。

### Current State (Code-confirmed)
- Lane-1 `ssrf_score` 閾値は稼働中（`ssrf_candidate` で `ssrf_score < 40` は skip）。
- Phase2（実質 Lane-2）昇格は `high_risk_requires_phase2` / `phase2_forced_by_risk` で制御される。
- リスク強制時の実行予算 cap（`phase2_max_seconds_risk_forced`）は稼働中。
- blind signal 判定は `time_based/oob/correlated` を参照するが、DNS 軸の判定統合は Wave C で追加実装が必要。

### Threshold Policy to Fix Before Wave C
1. Lane-1 投入条件: `ssrf_score >= 40`（現状維持）。
2. Lane-2 昇格条件: `Lane-1陰性` かつ `ssrf_score >= 65`。
3. 例外昇格: `risk_override=true` の場合は `score<65` でも Lane-2 昇格可。
4. `phase2_on_empty_phase1` はデフォルト `false` を維持。
5. 予算上限: `phase2_max_seconds_risk_forced=120`, `phase2_max_seconds=240` を初期値とする。

### Pre-Verification Gate (Required Before Starting Wave C)
1. `score=64` + Lane-1陰性 + overrideなし: Lane-2 昇格しない。
2. `score=65` + Lane-1陰性 + overrideなし: Lane-2 昇格する。
3. `score<65` + `risk_override=true`: Lane-2 昇格する。
4. `tool_error=true` の場合、risk-forced 昇格が暴発しない。
5. `blind_correlation` が空でも処理失敗しない。
6. `phase2` 予算が cap を超過しない（risk-forced/normal 両方）。

### Multi-Persona Assessment
- PM: 合格。Wave A/B成果を維持したまま Wave Cへ進む条件が明文化された。
- SRE/Infra: 合格。同時実行抑制・予算 cap 前提で負荷暴走リスクが管理可能。
- Software Architect: 条件付き合格。Lane定義と昇格ルールの定数化で保守性を高めること。
- Bug Hunter: 条件付き合格。`time/oob/dns` の 2-of-3 相関確定を Wave C 完了条件にすること。

## Wave D Progress Update (Dashboard Visualization / Timeline)

### Implemented
1. `execution_log.phase1_summary.skip_reason_counts` 集計を InjectionManager 側で実装。
2. Dashboard metrics API で `skip_reason_counts` を返却する契約を実装。
3. Dashboard metrics API で `skip_reason_timeline`（task順の `delta/cumulative`）を返却する契約を実装。
4. フロント型 `SessionMetrics` に `skip_reason_counts` / `skip_reason_timeline` を反映。
5. Metrics Card UI に以下を追加:
   - `skip_reason` 別件数の可視化（件数＋比率バー）
   - task順の時系列表示（累積件数＋delta要約）

### Validation Result

## Completion Note (2026-05-21)
- GroupA (`SGK-2026-0221-S01`) は完了としてクローズ。
- 実行経路のモック除去、本実装経路への統合、Wave D/E/F 範囲の可観測性強化を反映済み。
- 親タスク `SGK-2026-0221` は GroupB/GroupC が残っているため `active` 維持。
1. `.venv/bin/pytest -q tests/unit/dashboard/test_skip_reason_metrics.py` : `2 passed`
2. `cd src/dashboard/frontend && npm run build` : `passed`（front build green）
3. TypeScriptエラー修正完了:
   - `src/App.tsx`: 未使用 import 削除
   - `src/components/VulnerabilityScoreCard.tsx`: 未使用関数削除
   - `src/vite-env.d.ts`: Vite `ImportMeta.env` 型定義追加

### Remaining Action
1. `low_ssrf_score` の `score_breakdown` を skip_reason集計/UIにも展開し、改善ループの粒度を上げる。

## Wave E Progress Update (Contract Test -> Path Integration -> Deprecated Cleanup)

### Implemented
1. 契約テストを追加:
   - `tests/unit/engine/test_recipe_contracts.py`
   - `tests/core/engine/test_master_conductor_recipe_contracts.py`
2. Action語彙の正本化:
   - `src/core/engine/recipe_contracts.py` を追加し、`validate_action_schema` / `validate_task_schema` を提供。
   - `OptimizedRecipeRunner.ALLOWED_ACTIONS` は契約モジュールの `ALLOWED_RECIPE_STEP_ACTIONS` を参照する形へ統合。
3. 経路統合:
   - `MasterConductor` の `run_recipe` 実行ロジックを `_execute_recipe_task` に集約。
   - `_load_recipe_tasks` で注入する recipe task に `TaskSchema` 検証を追加し、契約不正タスクを注入しない。
4. deprecated整理:
   - 未参照だった `RecipeLoader.to_tasks` を削除（二重経路の解消）。

### Validation Result
1. `.venv/bin/pytest -q tests/unit/engine/test_recipe_contracts.py tests/core/engine/test_master_conductor_recipe_contracts.py` : `5 passed`
2. `.venv/bin/pytest -q tests/unit/engine/test_optimized_runner.py` : `3 passed`
3. `.venv/bin/pytest -q tests/core/engine/test_worker_integration.py` : `2 passed`

## Wave E Progress Update (Tag Taxonomy Registry Unification)

### Implemented
1. `src/core/engine/tag_taxonomy_registry.py` を追加し、カテゴリ語彙・カテゴリ→タグ・タグ→Swarm の正本を一本化。
2. `ReconPipeline` 側:
   - 履歴seedカテゴリ列挙を `PIPELINE_HISTORY_CANDIDATE_CATEGORIES` 参照へ変更。
   - `_map_tagged_category_to_tags()` を `tags_for_category()` 経由へ変更。
3. `SwarmDispatcher` 側:
   - `SUBDOMAIN_TAG_TO_SWARM` / `URL_TAG_TO_SWARM` / `TAG_TO_SWARM` をレジストリ参照へ変更。
4. `InjectionManager` 側:
   - `ssrf_candidate` 等の主要カテゴリ判定をレジストリ定数参照へ変更。

### Validation Result
1. `.venv/bin/pytest -q tests/unit/engine/test_swarm_dispatcher_close.py tests/core/agents/swarm/injection/test_manager_p1_metadata.py tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py` : `14 passed`
2. `.venv/bin/pytest -q tests/recon/test_step3b_hybrid_url.py` : `14 passed`
3. `.venv/bin/pytest -q tests/recon/test_tagged_uncategorized_promotion.py` : `25 passed`

## Immediate Execution Plan (Start Now)

### Objective
1. `low_ssrf_score` の内訳（`score_breakdown`）を API/ダッシュボードで直接可視化し、攻撃改善ループを即時化する。

### Implementation Tasks
1. InjectionManager:
   - `skip_reason == low_ssrf_score` の件数に加え、`score_breakdown` の不足特徴を集計する `skip_reason_breakdown` を `execution_log.phase1_summary` へ追加。
2. Dashboard API:
   - metrics に `skip_reason_breakdown` / `low_ssrf_score_breakdown` を追加し、セッション横断集計を返却。
3. Dashboard UI:
   - MetricsCard に「low_ssrf_score 内訳（不足特徴 TOP N）」を追加。
4. Tests:
   - 集計ロジックの unit test 追加（summary優先、fallback復元、未知キー `other` 集約）。

### Immediate Gate
1. `low_ssrf_score` の内訳が API レスポンスで確認できる。
2. UI で不足特徴の件数表示が確認できる。
3. 既存 `skip_reason_counts/timeline` の挙動が回帰しない。

## Wave F Plan (Stabilization and Operability)

### Wave F-1: Contract Hardening
1. `tag_taxonomy_registry` を単一正本として運用ルール化（更新窓口固定）。
2. カテゴリ/タグ/Swarm の契約テストを追加:
   - `category -> tags` 完全性
   - `tag -> swarm` ルーティング整合性
   - 未知カテゴリ/未知タグのフォールバック一貫性
3. 型拘束の段階導入（Enum/TypedDict もしくは定数検証テスト）で破壊変更をCIで検知。

### Wave F-2: Observability and Alerting
1. `skip_reason` と `other` 比率の時系列監視指標を追加。
2. `low_ssrf_score_breakdown` の上位特徴推移をダッシュボード時系列に追加。
3. アラート条件を定義:
   - `other` 比率急増
   - `low_ssrf_score` の特定特徴偏重が継続

### Wave F-3: Operational Guardrails
1. taxonomy更新時の運用チェックリストを追加（docs/manual更新、契約テスト更新、互換確認）。
2. 変更影響の自動レポート（影響カテゴリ/タグ/Swarm一覧）をCIログへ出力。

### Wave F Gate
1. taxonomy関連契約テストがCIで常時グリーン。
2. `other` 比率・`low_ssrf_score` 内訳の監視が稼働。
3. 更新手順と影響確認手順が文書化され、再現可能。

### Wave F Scope Split (Implement vs Deferred)
1. Implement Now (Low Risk):
   - taxonomy契約テスト強化（`category -> tags`, `tag -> swarm`, unknown fallback一貫性）。
   - 監視用派生指標の追加（`skip_reason_other_ratio`, `low_ssrf_top_missing_feature`）。
   - ダッシュボードへの軽量表示追加（既存MetricsCard内）。
2. Deferred (High Risk / Cross-cutting):
   - taxonomy変更影響の自動レポート生成をCIログへ統合（CI設計/運用調整の影響が大きい）。
   - Enum/TypedDict の全面導入（横断的な型変更で既存モジュール影響が広い）。
   - 本番監視基盤（外部ダッシュボード/アラート配線）への完全接続（環境依存・運用手順調整が必要）。

## Multi-Persona Review and Plan Update

### PM Review
1. 指摘: 改善価値が高い `low_ssrf_score` 分解を後回しにすると学習サイクルが鈍化。
2. 反映: Immediate Execution を Wave F から分離して先行実施。

### SRE/Infra Review
1. 指摘: `other` 増加を検知できないと語彙崩れを運用で見逃す。
2. 反映: Wave F-2 に `other` 比率監視とアラートを追加。

### Software Architect Review
1. 指摘: 正本化だけでは不十分で、契約テストと型拘束が必要。
2. 反映: Wave F-1 に契約テスト拡張と型拘束導入を追加。

### Bug Hunter Review
1. 指摘: 攻撃失敗理由の粒度不足はヒット率改善を遅延させる。
2. 反映: Immediateで `low_ssrf_score_breakdown` をAPI/UIへ展開。

### CTO Review
1. 指摘: 技術負債を増やさず効果を早く出すには「即効施策→基盤強化」の2段構えが最適。
2. 反映: Immediate（可視化即効）→ Wave F（契約/運用基盤）へ順序最適化。

## Immediate Execution Progress Update (low_ssrf_score_breakdown API/UI)

### Implemented
1. InjectionManager:
   - `low_ssrf_score` の不足特徴を集計する `_summarize_low_ssrf_score_breakdown()` を追加。
   - `execution_log.phase1_summary` に `low_ssrf_score_breakdown` を出力。
2. Dashboard API:
   - `SessionMetrics` に `low_ssrf_score_breakdown` を追加。
   - `_aggregate_low_ssrf_score_breakdown()` を追加し、summary優先 + url_results fallback で集計。
3. Dashboard UI:
   - MetricsCard に `low_ssrf_score 内訳（不足特徴 TOP）` セクションを追加。
4. Tests:
   - `tests/unit/dashboard/test_skip_reason_metrics.py` に breakdown集計テストを追加。
   - `tests/core/agents/swarm/injection/test_manager_p1_metadata.py` に不足特徴集計テストを追加。

### Validation Result
1. `.venv/bin/pytest -q tests/core/agents/swarm/injection/test_manager_p1_metadata.py tests/unit/dashboard/test_skip_reason_metrics.py` : `12 passed`
2. `.venv/bin/pytest -q tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py` : `4 passed`
3. `cd src/dashboard/frontend && npm run build` : `passed`

## Wave F Execution Update (Implemented vs Deferred)

### Implemented (This Iteration)
1. Contract Hardening:
   - taxonomy契約テストを追加（`tests/unit/engine/test_tag_taxonomy_registry_contracts.py`）。
   - unknown category fallback（空タグ）と core tag->swarm 整合を固定化。
2. Observability (Lightweight):
   - Dashboard metrics に `skip_reason_other_ratio` を追加。
   - Dashboard metrics に `low_ssrf_top_missing_feature` を追加。
   - MetricsCard に上記2指標を表示。
3. Validation:
   - `.venv/bin/pytest -q tests/unit/engine/test_tag_taxonomy_registry_contracts.py tests/unit/dashboard/test_skip_reason_metrics.py` : `11 passed`
   - `.venv/bin/pytest -q tests/core/agents/swarm/injection/test_manager_p1_metadata.py tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py` : `12 passed`
   - `cd src/dashboard/frontend && npm run build` : `passed`

### Deferred (High Risk / Cross-cutting)
1. taxonomy変更影響の自動レポートをCIログへ統合（CI運用設計の変更影響が大きい）。
2. Enum/TypedDict の全面導入（横断的変更が大きく、段階導入が安全）。
3. 本番監視基盤への外部ダッシュボード/アラート完全接続（環境依存作業が必要）。
