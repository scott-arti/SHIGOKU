---
task_id: SGK-2026-0302
doc_type: work_report
status: done
created_at: '2026-06-25'
updated_at: '2026-06-30'
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/plans/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0302_attack-path-markdown-neo4j-prep_subtask_plan.md
- docs/shigoku/worklogs/2026-06-25_sgk-2026-0302_attack-path-markdown-neo4j-prep_work_log.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: '作業報告書: 内部挙動可視化 S4 — 攻撃パスMarkdownグラフ・Neo4j連携準備'
---

# 作業報告書: 内部挙動可視化 S4

## 1. 完了したスコープ

### Phase 1 MVP（計画書の完了条件）+ Step 7/8 前倒し実装

計画書では Step 7 (`attack_paths.json` + Neo4j schema追記) と Step 8 (`shigoku-ops report attack-paths` CLI追加) を Phase 2（完了条件外）としていたが、実装効率の観点から Phase 1 内で前倒し実装した。実装スコープを完了条件と一致させるため、ここに明記する。

### 実装済みファイル

| ファイル | 変更内容 |
|---|---|
| `src/core/knowledge/models.py` | `AttackPathNode`, `AttackPathEdge`, `AttackPathGraph` dataclass 型定義 + `resolve_evidence_state()` 関数 |
| `src/reporting/attack_path_formatter.py` | 新規: Markdown + Mermaid 出力 + JSON エクスポート |
| `src/core/knowledge/schema.py` | AttackPath, Decision, Task, ToolRun の Neo4j constraint 追記 |
| `scripts/shigoku_ops_cli.py` | `report attack-paths` サブコマンド追加 + `VALIDATION_SUITES` 登録 |
| `config/shigoku.yaml` | `reporting.attack_paths` 設定セクション追加 (閾値) |
| `tests/unit/reporting/test_attack_path_formatter.py` | 53件のユニットテスト (全パス) |

### 達成したゴール

- [x] SHIGOKU実行結果から、成立済み/候補/未検証の攻撃パスをMarkdownで把握可能
- [x] Mermaidグラフで読みやすく可視化（凡例・バッジ・線種で状態識別）
- [x] Target ProfileやRun Narrativeと同じsession一次証跡から生成
- [x] `evidence_state` 単一語彙による状態統一（confirmed / candidate / blocked / backfill）
- [x] Neo4j接続不可時でもMarkdown/Mermaid出力は正常生成（graceful degradation）
- [x] 1ページ目だけで「今すぐ追うべき攻撃パス」「成立扱いしてはいけない推定」「次に検証すべき一手」を判断可能

### テストカバレッジ

- **ユニットテスト:** 53件 (全パス)
  - `resolve_evidence_state()` 全マッピングパターン (13件)
  - 欠損パターン網羅 (findings空、decision_trace空/None、confidence=0.0、target_url="" / "Multiple"、scenario_coverage不在、additional_info=None)
  - セクション構造・順序検証 (7件)
  - 30秒レビュープロトコル検証 (6件)
  - Mermaid出力検証 (4件)
  - Neo4jエクスポート契約検証 (3件)
- **回帰テスト:** 既存70件パス（ノーリグレッション）

### CLI インターフェース

```bash
shigoku-ops report attack-paths \
  --session <session.json> \
  --output attack_paths.md \
  --json-output          # 任意: attack_paths.json も出力
```

## 2. 判断事項

### 2.1 `evidence_state` マッピングの確定

| condition | evidence_state |
|---|---|
| `state == "confirmed"` AND `confidence >= 0.8` | `confirmed` |
| `state == "confirmed"` AND `confidence < 0.8` | `candidate` |
| `state in {blocked, draft}` | `blocked` |
| `decision_trace` が None / 空dict / 非dict | `backfill` |
| `source_origin == "proposal_engine"` | `backfill` |

`ExploitChain`（旧API、`additional_info` に `decision_trace` なし）は `backfill` に分類され、crash しない。

### 2.2 Neo4jスキーマ衝突確認

既存ノード/エッジとの命名・意味論の衝突なし。新規ノードタイプ `AttackPath`, `Decision`, `Task`, `ToolRun` は既存スキーマに非干渉。

### 2.3 Mermaid 縮約ルール

`config/shigoku.yaml` の `reporting.attack_paths` で上書き可能:
- `max_mermaid_nodes`: 25 (デフォルト)
- `max_mermaid_edges`: 40 (デフォルト)
- `max_top_paths`: 5 (デフォルト)

## 3. 未対応事項 (Deferred Tasks)

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0302-D01
    title: "Phase 2: High-value path 5軸採点基準の実装"
    reason: "Phase 1 MVP では evidence_state + severity + confidence による簡易ランキング。asset_criticality, exploitability, preconditions, blast_radius のフルスコアリングは Phase 2"
    impact: medium
    tracking_task_id: SGK-2026-0307
    recommended_next_action: "SGK-2026-0307 (Phase 2 bundle) の一部として実装"

  - deferred_id: SGK-2026-0302-D02
    title: "2つの chain_builder の統合"
    reason: "attack/chain_builder.py (ExploitChain) は旧API。intelligence/chain_builder.py (AttackChain) への統一・旧API非推奨化が必要"
    impact: high
    tracking_task_id: SGK-2026-0307
    recommended_next_action: "SGK-2026-0307 (Phase 2 bundle) の一部として実装"

  - deferred_id: SGK-2026-0302-D03
    title: "Neo4j 実書き込みの実装"
    reason: "Phase 1 では schema/export 契約の定義まで。実Neo4j書き込みは後続"
    impact: medium
    tracking_task_id: SGK-2026-0307
    recommended_next_action: "SGK-2026-0307 (Phase 2 bundle) の一部として実装"

  - deferred_id: SGK-2026-0302-D04
    title: "observed_at / inferred_after 時間軸の完全実装"
    reason: "dataclass と formatter にフィールドは実装済み。セッションJSONからの観測時刻抽出とフォールバックは Phase 2 で強化"
    impact: low
    tracking_task_id: SGK-2026-0307
    recommended_next_action: "SGK-2026-0307 (Phase 2 bundle) の一部として実装"

  - deferred_id: SGK-2026-0302-D05
    title: "継続監視: Neo4j接続不可時の graceful degradation"
    reason: "Markdown/Mermaid は Neo4j 不在でも正常生成するが、driver.py は依然として接続失敗時に raise する。attack_path_formatter は driver.py を参照しないため影響なし"
    impact: low
    tracking_task_id: SGK-2026-0307
    recommended_next_action: "SGK-2026-0307 で driver.py の graceful degradation 化を監視・対応"
```

## 4. バリデーション実行結果

```
$ python3 scripts/sync_shigoku_updated_at.py
  TARGETS=127  UPDATED=124  SKIPPED=3  DATE=2026-06-25

$ python3 scripts/validate_shigoku_docs.py
  MD_FILES=411  FRONT_MATTER_ISSUES=0  BROKEN_LINKS=0
  REGISTRY_ISSUES=0  DEFERRED_LINK_ISSUES=0
  REGISTRY_ENTRIES=317  REGISTRY_MD_COUNT=411

$ .venv/bin/pytest tests/unit/reporting/test_attack_path_formatter.py -v
  53 passed in 0.13s

$ .venv/bin/pytest tests/unit/reporting/ -v
  227 passed in 0.54s
```
