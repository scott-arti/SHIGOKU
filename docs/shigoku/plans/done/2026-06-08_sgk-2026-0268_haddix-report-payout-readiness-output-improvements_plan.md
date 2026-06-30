---
task_id: SGK-2026-0268
doc_type: plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
- docs/shigoku/reports/REPORT_OUTPUTS.md
title: Haddix report payout-readiness output improvements
created_at: '2026-06-08'
updated_at: '2026-06-24'
tags:
- shigoku
target: Haddix report output
---

# 実装計画書：Haddix report payout-readiness output improvements

## 1. 達成したいゴール（ユーザー視点）
- [ ] `--report --format haddix` で生成される Markdown に、提出に必要な response 本文、baseline vs attack 比較、対象固有 impact、submission-ready / hold-back の境界が明示されること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/haddix_formatter.py`: 修正。提出品質を上げる Markdown セクションと補助ヘルパーを追加する。
  - `tests/unit/reporting/test_haddix_formatter_kpi.py`: 修正。response evidence、baseline/attack 比較、対象固有 impact、candidate 分離の回帰を固定する。
  - `tests/unit/reporting/test_haddix_formatter_quality.py`: 確認対象。既存品質フィルタとの非衝突を検証する。
- **データの流れ / 依存関係:**
  - `findings/additional_info` -> `HaddixFormatter.add_finding_from_dict()` -> `format_markdown()` -> `haddix_report_*.md`
  - `authz_differential` / `poc_request` / `poc_response` -> formatter helper -> comparison table / response evidence / impact sentence

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - finding 辞書の `poc_request`, `poc_response`, `summary`, `impact`, `target_url`
  - `additional_info.authz_differential` の `baseline_status`, `test_status`, `original_id`, `test_id`, `auth_body_length`, `test_body_length`, `body_length_delta`, `body_length_delta_ratio`, `signals`
- **出力/結果 (Output):**
  - Confirmed finding 本文に `Response Evidence` ブロックを追加する。
  - differential がある finding に `Baseline vs Attack Comparison` テーブルを追加する。
  - 影響分析に `対象固有の影響` を追加する。
  - findings 要約に `Submission Readiness` を追加し、candidate を non-submission appendix へ隔離する。
- **制約・ルール:**
  - 既存 schema は壊さず、Markdown 表示を追加する方向で最小差分に留める。
  - Confirmed / Candidate 判定ロジック自体は変更しない。
  - 既存 gate / consistency parser への影響を観測し、影響があれば明示する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `tests/unit/reporting/test_haddix_formatter_kpi.py` に 4 要件の failing test を追加し、Red を確認する。
- [x] ステップ2: `src/reporting/haddix_formatter.py` に response evidence 表示、baseline vs attack 比較、対象固有 impact、submission appendix を最小実装する。
- [x] ステップ3: formatter 系 targeted test を Green にし、関連 main test の影響有無を確認する。
- [x] ステップ4: 作業報告書 / 作業ログを作成し、台帳整合チェックを完了する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] `test_main_report_haddix_includes_authz_and_timeout_kpi` は synthetic session に `scenario_coverage` が無く、既存 consistency gate で blocked になる。今回差分の主対象外として切り分け、必要なら別タスクで fixture 整備または gate 期待値調整を行う。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0268-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
