---
task_id: SGK-2026-0300
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0298
related_docs:
- docs/shigoku/plans/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/specs/visibility_and_metrics.md
title: '内部挙動可視化 S2: Run Narrative・Target Profile Markdown出力'
created_at: '2026-06-24'
updated_at: '2026-06-30'
tags:
- shigoku
target: shigoku-ops report narrative, target_profile.md
---

# 実装計画書：内部挙動可視化 S2: Run Narrative・Target Profile Markdown出力

## 1. 達成したいゴール（ユーザー視点）
- [ ] `session_*.json` から、SHIGOKUの判断と行動の流れを日本語の `run_narrative.md` として読めること。
- [ ] 同じsessionから、ターゲット理解と次回シナリオ設計に使える `target_profile.md` を生成できること。
- [ ] どちらのMarkdownも、一次証跡のevent/task/finding/session参照を残し、推定とraw evidenceを区別すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `scripts/shigoku_ops_cli.py`: 修正。`report narrative` と `report target-profile` を追加する。
  - `src/reporting/run_narrative_formatter.py`: 新規。run ledgerを時系列の日本語説明へ変換する。
  - `src/reporting/target_profile_formatter.py`: 新規。target_info、findings、coverage、URL/APIメタ情報をMarkdownへ整形する。
  - `src/reporting/report_session_consistency.py`: 確認。report path指定時のsession解決ルールと衝突させない。
  - `tests/unit/reporting/`: 新規。formatter snapshot/contractテストを追加する。
- **データの流れ / 依存関係:**
  - `session_*.json.run_ledger` -> narrative formatter -> `workspace/projects/<target>/reports/run_narrative_*.md`
  - `session_*.json.context.target_info` + findings + scenario_coverage + task records -> target profile formatter -> `target_profile_*.md`
  - report path指定時は consistency checker -> resolved session -> formatter の順にする。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - session path、または report pathから解決したsession path
  - run_ledger, completed_tasks, task_execution_records, decision_traces, findings, context.target_info, scenario_coverage
- **出力/結果 (Output):**
  - `run_narrative.md`: 実行概要、LLM使用量、時系列、判断根拠、Swarm/ツール実行、失敗/再試行、Finding、次判断、未完了事項
  - `target_profile.md`: 概要、機能、技術、認証、URL/API/page counts、攻撃面、Finding/仮説、次回推奨シナリオ、未検証領域
- **制約・ルール:**
  - Markdownは日本語を基本にするが、提出用英語レポートとは混ぜない。
  - raw evidenceがない項目は `推定` または `backfill` と明記する。
  - report path指定時は `verify_report_session_consistency.py --report <path>` 相当を先に通す。
  - 機密値はマスクし、URLやパラメータも必要に応じて短縮表示する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `run_narrative.md` と `target_profile.md` のMarkdown構成をfixtureで固定する。
- [ ] ステップ2: `run_narrative_formatter.py` を実装し、S1のrun ledgerがない旧sessionではgraceful fallbackする。
- [ ] ステップ3: `target_profile_formatter.py` を実装し、URL/API/page数、Finding、coverage、next scenariosを出力する。
- [ ] ステップ4: `shigoku-ops report narrative` / `report target-profile` を追加する。
- [ ] ステップ5: unit testsと、可能なら実session artifactで生成確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] Narrativeが「それっぽい物語」になり一次証跡から離れる。 - event_id/task_id/finding_idを各段落に残す。
- [ ] [重要度:中] Target Profileのページ数/URL数が収集元によって揺れる。 - sourceと集計方法を明記する。
- [ ] [重要度:中] 旧sessionでは情報不足になる。 - 欠損セクションは `No data in source session` と明示する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0300-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
