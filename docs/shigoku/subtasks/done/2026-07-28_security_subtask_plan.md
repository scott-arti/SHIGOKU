---
task_id: SGK-2026-0400
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_dvwa-high_subtask_plan.md
- docs/shigoku/reports/2026-07-28_sgk-2026-0400_security-baseline-separation_work_report.md
- docs/shigoku/worklogs/2026-07-28_sgk-2026-0400_security-baseline-separation_work_log.md
title: Securityレベル別レポート基準線の分離
created_at: '2026-07-28'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/reporting;tests/unit/reporting
---

# 実装計画書：Securityレベル別レポート基準線の分離

## 1. 達成したいゴール（ユーザー視点）
- [x] 同じ保存ディレクトリでLow/Medium/Highのreport gateを再評価しても、異なるSecurityレベルの基準線を比較に使わず、古い基準線による誤った`regression_confirmed_drop`を表示しないこと。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/initial_release_gate.py`: 保存済み基準線と現在sessionのSecurityレベルをCookie由来で照合し、異なる場合は比較対象から除外する。
  - `tests/unit/reporting/test_initial_release_gate.py`: Low基準線がHigh評価に再利用されない回帰テストを固定する。
- **データの流れ / 依存関係:**
  - report -> consistencyで解決したsessionのCookie -> 基準線sessionのCookieと同一レベル照合 -> 同一レベルだけ差分ゲートへ渡す

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 現在report/session、`quality_baseline_lock.json`のbaseline report/session。
- **出力/結果 (Output):** Securityレベルが一致する基準線だけで差分を評価し、不一致または不明なら現在report/sessionを自己基準線として評価する。
- **制約・ルール:**
  - Securityレベルはsession中の`cookie`/`cookies`値だけから読む。レスポンス本文やreport本文は判定に使わない。
  - 既存の基準線ファイル形式を変更せず、異なるレベルでは安全側に比較を停止する。
  - report/session consistencyが`consistent`でなければ、従来どおりfail-closedにする。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 基準線を読み込む経路に、現在sessionとbaseline sessionのSecurityレベル照合を追加した。
- [x] ステップ2: Lowの基準線をHighに再利用しない回帰テストを追加し、Cookie以外の文字列検索を共通抽出器に置き換えた。
- [x] ステップ3: 対象pytestと実High report/sessionの整合性・gate再評価を実行し、`candidate_above_maximum`だけが残ることを確認した。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:低/中/高] [懸念内容] - [次回対応方針]

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0400-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
