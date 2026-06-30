---
task_id: SGK-2026-0302
doc_type: work_log
status: done
created_at: '2026-06-25'
updated_at: '2026-06-30'
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0302_attack-path-markdown-neo4j-prep_subtask_plan.md
- docs/shigoku/reports/2026-06-25_sgk-2026-0302_attack-path-markdown-neo4j-prep_work_report.md
- docs/shigoku/plans/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
title: '作業ログ: 内部挙動可視化 S4 — 攻撃パスMarkdownグラフ・Neo4j連携準備'
---

# 作業ログ: SGK-2026-0302

## 実施日: 2026-06-25

### Phase 1: 棚卸し・設計 (ステップ1, 1.5, 2, 3, 5)

- explorer agent x3 で並列棚卸し
  - exp-1: intelligence/chain_builder.py (AttackChain, analyze_hybrid), attack/chain_builder.py (ExploitChain), knowledge/schema.py
  - exp-2: reporting/ ディレクトリ全フォーマッター、shigoku_ops_cli.py、config/shigoku.yaml
  - exp-3: Neo4j driver, session JSON artifacts, テストパターン
- 既存Neo4jスキーマと計画書Node/Edge contractの突合 → 衝突なし確認
- evidence_state マッピング規則を確定
- `models.py` に AttackPathNode, AttackPathEdge, AttackPathGraph の dataclass 型定義を実装
- `resolve_evidence_state()` 関数を models.py に実装（すべてのマッピングパターン対応）

### Phase 2: TDD実装 (ステップ6, 9)

- テストファイル `test_attack_path_formatter.py` (53件) を先行作成 (TDD)
- `attack_path_formatter.py` を実装:
  - format() メソッド (Markdown出力)
  - export_json() メソッド (Neo4j contract JSON)
  - _build_attack_path_graph() (内部グラフ構築)
  - _build_mermaid() (Mermaid graph TD 生成)
  - 7セクション (Executive Summary → Top Paths → Candidate/Blocked → Mermaid → Blockers → Next Validation → Legend)
  - 既存フォーマッターと同一のユーティリティパターン (_safe_get, _safe_list, _safe_dict, _safe_str)
  - すべての欠損パターンで crash しない (additional_info=None, decision_trace=None/空, confidence=0.0 等)
- 修正: decision_trace=None 時の backfill 判定ロジック
- 修正: 空セッション時の空グラフ返却

### Phase 3: CLI・Config・Schema (ステップ7, 8)

- `shigoku_ops_cli.py` に `report attack-paths` サブコマンド追加
  - --session, --report, --sessions-dir, --output, --output-dir, --json-output
  - `_resolve_session_from_args()` 再利用 (既存パターン準拠)
  - `_load_attack_paths_config()` で config 読み込み
  - `VALIDATION_SUITES["report"]` にテストパス登録
- `config/shigoku.yaml` に `reporting.attack_paths` セクション追加
- `schema.py` に新規ノードタイプ (AttackPath, Decision, Task, ToolRun) の constraint 追記

### Phase 4: 検証

- ユニットテスト 53件 全パス
- 回帰テスト 70件 全パス (ノーリグレッション)
- ops CLI validate 133件 パス (1件の既存失敗は無関係)
- 実セッションJSONでの疎通確認
- チェーン付きテストフィクスチャでの出力品質確認
- 30秒レビュープロトコル (3問即答可能) 確認

### 変更ファイル一覧

| ファイル | 操作 | 行数 |
|---|---|---|
| `src/core/knowledge/models.py` | 新規実装 | 233行 |
| `src/reporting/attack_path_formatter.py` | 新規実装 | 566行 |
| `tests/unit/reporting/test_attack_path_formatter.py` | 新規実装 | 940行 |
| `src/core/knowledge/schema.py` | 修正 (+4制約) | +4行 |
| `scripts/shigoku_ops_cli.py` | 修正 (+1ハンドラ, +1パーサ, +1スイート登録) | +100行 |
| `config/shigoku.yaml` | 修正 (+5行) | +5行 |

### 残課題

- SGK-2026-0302-D01: 5軸採点基準の実装 (Phase 2)
- SGK-2026-0302-D02: 2つのchain_builder統合
- SGK-2026-0302-D03: Neo4j実書き込み
- SGK-2026-0302-D04: observed_at/inferred_after 時間軸強化
- SGK-2026-0302-D05: driver.py の graceful degradation
