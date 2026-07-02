---
task_id: SGK-2026-0307
doc_type: plan
status: active
created_at: '2026-06-25'
updated_at: '2026-07-02'
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/reports/2026-06-25_sgk-2026-0302_attack-path-markdown-neo4j-prep_work_report.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0302_attack-path-markdown-neo4j-prep_subtask_plan.md
title: '内部挙動可視化 S4 Phase 2 残タスク一括 + 継続監視'
---

# 内部挙動可視化 S4 Phase 2 残タスク + 継続監視

SGK-2026-0302 の deferred tasks D01-D05 を束ねた追跡タスク。

## 束ねた deferred tasks

| Deferred ID | 内容 | Phase |
|---|---|---|
| D01 | 5軸採点基準の実装 (asset_criticality, exploitability, preconditions, blast_radius) | Phase 2 |
| D02 | 2つの chain_builder の統合 (attack/ + intelligence/) | Phase 2 |
| D03 | Neo4j 実書き込みの実装 (JSON export → ingest batch) | Phase 2 |
| D04 | observed_at / inferred_after 時間軸の完全実装 | Phase 2 |
| D05 | Neo4j driver.py の graceful degradation 監視 | 継続監視 |

## 完了条件

- D01: 5軸スコアリングが `_rank_paths()` に統合され、ユニットテストが通ること
- D02: `attack/chain_builder.py` が非推奨化され、全チェーンが `intelligence/chain_builder.py` 経由になること
- D03: `attack_paths.json` → Neo4j 一括 ingest が動作すること
- D04: session findings の `timestamp` から `observed_at` を抽出可能であること
- D05: 実運用で Neo4j 不在時のレポート生成が安定していることを監視
