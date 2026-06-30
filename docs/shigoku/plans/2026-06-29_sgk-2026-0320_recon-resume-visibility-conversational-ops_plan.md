---
task_id: SGK-2026-0320
doc_type: plan
status: active
parent_task_id: null
related_docs:
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0293_vulnerability-management-review-trail_subtask_plan.md
- docs/shigoku/roadmaps/future_functions1.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0321_recon-step-state-resume-diff_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0323_phasegate-granularity-import-recon_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0324_neo4j-attack-path-ui-vuln-management_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0325_conversational-ops-chat-direction_subtask_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0326_flexible-report-generation-reinjection_subtask_plan.md
title: 'Recon途中再開・可視化・対話型オペレーション 統合ロードマップ'
created_at: '2026-06-29'
updated_at: '2026-06-30'
tags:
- shigoku
- roadmap
target: src/recon/, src/core/engine/, src/reporting/, src/cli/, scripts/shigoku_ops_cli.py
---

# 統合ロードマップ：Recon途中再開・可視化・対話型オペレーション

> 本書は、たたき台（ブラッシュアップ前提）の統合ロードマップである。個別計画書 SGK-2026-0321〜0326 はすべて本ロードママップの子タスクとする。

## 1. 達成したいゴール（ユーザー視点）
- 長い Recon が中断しても途中成果を活かし、任意の step/ポイントから再開できる。
- 「前回との差分」「どこまで何をしてどうだったか」が可視化され、再開やスキップの判断材料になる。
- 「2回目は API だけ Fuzz」「1回目のここから開始」「このワードリストで攻撃」をチャット/指示ベースで柔軟に進められる。
- 見つけたエンドポイント一覧や脆弱性一覧を自由な形式で出し、それを SHIGOKU に再投入して分析・攻撃できる。

## 2. 対応するユーザー要望と子タスク対応

| 要望群 | 子タスク | 概要 |
|--------|----------|------|
| **P0** 即効 | SGK-2026-0321 | Recon step状態の自動保存＋再開CLI＋前回差分可視化 |
| **P1** 基盤 | SGK-2026-0322 | ReconState完全化＋並行タスク途中保存＋判断ツリー可視化 |
| **P2** 運用 | SGK-2026-0323 | PhaseGate細粒度化＋過去Recon成果物再利用(`--import-recon`) |
| **P3** 発展 | SGK-2026-0324 | 攻撃パスNeo4j UI＋脆弱性管理システム |
| **A** 対話 | SGK-2026-0325 | 対話型オペレーション（チャットベース指揮 軽量版） |
| **B** レポート | SGK-2026-0326 | 自由形式レポート生成→SHIGOKU再投入 |

## 3. 優先度と依存関係

```
P0 (0321) ──┐
P1 (0322) ──┼─→ P2 (0323) ──→ P3 (0324)
            │
B (0326) ───┘  ← 可視化/抽出基盤が先行すると A でも再利用できる
A (0325) ───── 依存: P0/P1 の step resume CLI、B のクエリ基盤
```

- **P0/P1** が最優先。ReconState.save()/load() と start_step/end_step はすでにコードに存在し、統合するだけで価値が出る。
- **B** は基盤が近い（`inspect_session_findings` + フィルタ/射影 + JSON envelope が既存）。P0/P1 と並行可能。
- **A** は P0/P1 の「step resume CLI」と B の「クエリ/抽出基盤」に依存。軽量版（shigoku-ops ラッパー）は早期に一部可能。
- **P2** は P0/P1 の差分可視化が前提（freshness判定に差分が必要）。
- **P3** は SGK-2026-0307（攻撃パスPhase2）と SGK-2026-0293（脆弱性管理）の設計を引き継ぐ。

## 4. 現状の前提知識（実装踏まえた評価）

### 4.1 すでに存在する基盤
- `ReconPipeline.run(start_step, end_step)` が step レンジ指定をサポート（`src/recon/pipeline.py:3696`）。
- `ReconState.save()/load()` が存在するが本番で未呼び出し（同 `pipeline.py:80/97`）。
- Run Ledger / LLM Usage Summary / Run Narrative / Target Profile / Attack Path Markdown は SGK-2026-0298 系列で実装済み。
- `inspect_session_findings(detection_class, fields, preset, max)` と JSON envelope 出力が既存。
- `FindingsRepository`（SQLite `~/.shigoku/findings.db`）は存在するが CLI から未露出。

### 4.2 主なギャップ
- `ReconState.save()` のフィールド不足（`tech_stack`/`screenshots_count`/`results` 未保存）＋並行タスク途中状態未保存。
- 再開ポイント・差分の可視化がなく、前回結果との added/removed/modified 比較がない。
- PhaseGate がバイナリ（INIT/RECON 常時解放 → ATTACK 一括解放）。
- チャット/REPL インターフェースなし（旧 `src/cli/cli.py` は DEPRECATED）。実行中MCへのアドホックタスク注入はアーキテクチャ変更が必要。
- エンドポイント一覧抽出・テンプレート化・逆投入 CLI が未整備。

## 5. フェーズ分割と達成基準
- **Phase 1（P0+P1+B並行）**: Recon step resume 実用化、差分可視化、柔軟レポート抽出の基盤完成。
- **Phase 2（P2+A軽量）**: PhaseGate 細粒度化、import-recon、対話ラッパー（shigoku-ops 経由）。
- **Phase 3（P3+A重量）**: Neo4j UI、脆弱性管理、実行中MC動的注入（次期アーキテクチャ）。

達成基準（共通）: 各子タスクは単体テスト＋可能なら実 session/report artifact で検証すること。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] artifact reuse を急ぐと古い成果物混入で誤判定する。freshness/provenance を P2 で先設計（P0の差分基盤を利用）。
- [ ] [重要度:高] 実行中MCへの動的タスク注入はアーキテクチャ変更を伴う。軽量版（外部エージェントが shigoku-ops を呼ぶ）を先行し、重量版は次期フェーズ。
- [ ] [重要度:中] チャット/レポート出力の機密値マスク。既存 redactor を再利用し、secret を出力に漏らさない。
- [ ] [重要度:中] ReconState の保存フォーマット後方互換。schema_version を付け、旧セッション reader を壊さない。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0320-D01
    title: "継続監視: 子タスク群の進捗と依存整合"
    reason: "本ロードマップはたたき台であり、子タスクの設計変更に追随が必要"
    impact: medium
    tracking_task_id: SGK-2026-0320
    recommended_next_action: "各子タスク計画書のブラッシュアップ時に本 related_docs を更新する"
```
