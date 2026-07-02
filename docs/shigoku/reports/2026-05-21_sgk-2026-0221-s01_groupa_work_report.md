---
task_id: SGK-2026-0221-S01
doc_type: work_report
status: done
parent_task_id: SGK-2026-0221
related_docs:
- docs/shigoku/subtasks/2026-05-20_sgk-2026-0221-s01_groupa_execution-path_subtask_plan.md
- docs/shigoku/plans/2026-05-19_sgk-2026-0221_mock-optimizedreciperunner-discovery-graphql_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
created_at: '2026-05-21'
updated_at: '2026-07-02'
---

# Work Report: SGK-2026-0221-S01 GroupA 実行経路モック除去

## 実装内容
- `OptimizedRecipeRunner` / `run_recipe` の実行経路を本実装へ統合し、モック依存を除去。
- Recipe契約（action/step_result）を共通化し、`MasterConductor` 経路と整合。
- SSRF Lane運用で Phase1/Phase2 の観測を強化:
  - `skip_reason_counts`
  - `skip_reason_unknown_counts`
  - `low_ssrf_score_breakdown`
- `phase2_timeout` 経路でも上記メトリクスを欠落なく返すよう修正。
- Tag taxonomy を `tag_taxonomy_registry` に一本化し、重複タグの不整合を fail-fast 化。
- Dashboard API/UI を更新:
  - `skip_reason_other_ratio`
  - `low_ssrf_top_missing_feature`
  - `skip_reason_unknown_alert`（unknown急増アラート）

## 主要な設計判断
- 無音劣化回避を優先し、`TAG_TO_SWARM` は衝突時に起動失敗（fail-fast）を採用。
- `skip_reason` 正規化は過剰吸収を避けるため、限定エイリアス + 最小ルールに留めた。
- unknown急増アラートは誤検知抑制のため二段閾値（件数 + 比率）で判定。

## 検証結果
- 実行コア/観測/契約テスト:
  - `.venv/bin/pytest -q tests/unit/engine/test_skip_reason_registry.py tests/unit/engine/test_tag_taxonomy_registry_contracts.py tests/unit/dashboard/test_skip_reason_metrics.py tests/core/agents/swarm/injection/test_manager_p1_metadata.py tests/core/agents/swarm/injection/test_manager_phase2_lane2_integration.py`
  - 結果: `37 passed`
- フロントビルド:
  - `cd src/dashboard/frontend && npm run build`
  - 結果: build green（Tailwind ESM warning は継続、失敗なし）

## リスク評価
- 解消済み
  - `phase2_timeout` 経路での skipメトリクス欠落
  - `other` 集約過多による原因不透明化（unknown内訳導入）
  - taxonomy重複時の無音上書き
- 残リスク
  - unknown語彙は運用データに応じて alias 追加が必要
  - unknown急増アラート閾値は実データで再調整余地あり

## deferred_tasks
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0221-D01
    title: unknown skip_reason 正規化辞書の運用拡張
    reason: 実データの分布観測後に追加する方が安全なため
    impact: medium
    recommended_next_action: 1週間分の実セッションを観測し、上位unknown語彙のみ段階追加
  - deferred_id: SGK-2026-0221-D02
    title: unknown急増アラート閾値の本番最適化
    reason: 現在は初期閾値（count>=5 かつ ratio>=0.20）で暫定運用
    impact: medium
    recommended_next_action: false positive/false negative をレビューし閾値を再設定
  - deferred_id: SGK-2026-0221-D03
    title: GroupB Discovery GraphQL 本実装接続
    reason: サブタスク分割により GroupA 範囲外
    impact: high
    recommended_next_action: SGK-2026-0221-S02 を active 化して着手
  - deferred_id: SGK-2026-0221-D04
    title: GroupC 回帰防止テスト/可観測性仕上げ
    reason: サブタスク分割により GroupA 範囲外
    impact: high
    recommended_next_action: SGK-2026-0221-S03 を GroupB完了後に着手
```
