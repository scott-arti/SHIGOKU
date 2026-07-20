---
task_id: SGK-2026-0341
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/reports/2026-07-03_sgk-2026-0341_auto-report-bundle-followup_work_report.md
- docs/shigoku/worklogs/2026-07-03_sgk-2026-0341_auto-report-bundle-followup_work_log.md
- docs/shigoku/subtasks/done/2026-07-03_auto-report-bundle-cli-tail_subtask_plan.md
- docs/shigoku/reports/2026-07-03_sgk-2026-0340_auto-report-bundle-cli-tail_work_report.md
title: 自動レポートbundleのtimestamp化と差分可視化追補
created_at: '2026-07-03'
updated_at: '2026-07-21'
tags:
- shigoku
target: reporting/cli
---

# 実装計画書：自動レポートbundleのtimestamp化と差分可視化追補

## 1. 達成したいゴール（ユーザー視点）
- [ ] 通常実行後に `run_narrative_*.md` と `target_profile_*.md` が上書きされず時刻付きで蓄積されること。
- [ ] CLI の最後で Markdown だけでなく JSON 系成果物 (`session_*.json`, `haddix_gate_*.json`, 必要時 `haddix_deferred_*.json`) の場所も分かること。
- [ ] `target_profile_*.md` を開くと、前回版と比べて差分があるか、あるならどのセクション近辺か分かること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: 修正。auto report bundle の保存命名、Target Profile 比較サマリー、JSON path summary を拡張する。
  - `tests/unit/main/test_main_auto_report_bundle.py`: 修正。timestamp 命名、履歴保持、差分サマリー、JSON path 表示を回帰テスト化する。
  - `docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md`: 修正。auto flow での timestamped 命名を補足する。
  - `docs/shigoku/manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md`: 修正。生成物一覧と末尾ログ表示を新仕様へ更新する。
- **データの流れ / 依存関係:**
  - latest `session_*.json` -> auto bundle helper -> timestamped Markdown / Haddix JSON -> `reports/`
  - latest `target_profile_*.md` + new profile content -> diff summary block -> new `target_profile_*.md`
  - generated paths -> CLI tail summary

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** latest session (`session_*.json`), previous target profile markdown (optional)
- **出力/結果 (Output):** `run_narrative_*.md`, `target_profile_*.md`, `haddix_report_*.md`, `haddix_gate_*.json`, optional `haddix_deferred_*.json`, CLI末尾 path summary
- **制約・ルール:**
  - 前回差分比較では、生成日時などのノイズだけで毎回差分ありにならないようにする。
  - 既存の Haddix report / gate / deferred 生成互換は維持する。
  - 過去成果物を破壊せず additive に増やす。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: auto bundle helper を timestamped 命名に変え、JSON path も bundle summary に載せる。
- [x] ステップ2: Target Profile に前回版比較サマリーを埋め込み、差分なし時も明示する。
- [x] ステップ3: 対象テスト・実在 report consistency・docs validation で最終確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] Target Profile の差分サマリーは行番号/見出し近辺の要約までで、本文 inline highlighting まではしていない - 必要なら別タスクで richer diff 表示を検討する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0341-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
