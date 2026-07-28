---
task_id: SGK-2026-0399
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/subtasks/done/2026-07-28_high-security_subtask_plan.md
- docs/shigoku/reports/2026-07-28_sgk-2026-0399_generic-capability-evaluation_work_report.md
- docs/shigoku/worklogs/2026-07-28_sgk-2026-0399_generic-capability-evaluation_work_log.md
title: 全Securityレベルの汎用検出能力評価基準
created_at: '2026-07-28'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/reporting;config;tests/unit/reporting
---

# 実装計画書：全Securityレベルの汎用検出能力評価基準

## 1. 達成したいゴール（ユーザー視点）
- [x] Low / Medium / High の一貫した report/session に対して `report expected-detections` を実行すると、DVWA固有の脆弱性一覧を正解として要求せず、探索範囲・confirmed証拠・候補保留理由の三観点による汎用評価結果を返すこと。
- [x] 脆弱性が存在しないアプリを不合格にせず、発見数ではなく「観測した結果を証拠に応じてconfirmed/candidateへ正しく分けたか」を評価すること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/expected_detection_matrix.py`: 全Securityレベル用の汎用能力評価を追加し、Low専用のパス一致matrixを明示的なDVWA回帰プロファイルとして分離する。
  - `scripts/shigoku_ops_cli.py`: 既存の`report expected-detections`から一貫したsessionを渡し、既定では汎用評価、明示的なprofile指定時だけDVWA回帰評価をJSONで返す。
  - `tests/unit/reporting/test_expected_detection_matrix.py`: High評価の成功・不足・候補reason code欠損を固定する。
  - `tests/unit/scripts/test_shigoku_ops_expected_detection_cli.py`: High report/sessionに対するCLIの終了コードとJSON契約を固定する。
- **データの流れ / 依存関係:**
  - consistent report -> source session -> generic capability assessment -> CLI JSON
  - explicit `dvwa-low-regression` profile -> Low専用の既存path一致matrix -> 回帰比較JSON

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** source sessionのsecurity cookie、coverage/family gate、canonical extractorによるraw finding、evidence-quality verdict。
- **出力/結果 (Output):** `status=ok`と以下のdimensionを返す。失敗したdimensionはreason codeを返すが、脆弱性の未発見をreason codeにしない。
  - `coverage_integrity`: family coverageがPASSであり、sessionのscenario coverageが保存されていること。
  - `confirmed_evidence_integrity`: confirmedとして扱うfindingがevidence-quality validatorでconfirmedとなること。
  - `candidate_holdback_integrity`: candidateとして扱うfindingに少なくとも一つのreason codeがあること。
  - `observed_security_signals`: confirmed/candidateの件数を参考情報として表示するだけで、0件を失格にしないこと。
- **制約・ルール:**
  - 既定評価ではDVWAのURL、固定payload、既知の脆弱性名をrequired detectionとして使わない。
  - `DEFAULT_DVWA_LOW_EXPECTED_DETECTIONS`は削除せず、`dvwa-low-regression`を明示した回帰評価だけで使う。これはDVWAの実装変更を検知するためのfixtureであり、実戦能力の合否には使わない。
  - report/session consistencyが`consistent`でなければ既存どおりblockedにする。
  - セッションCookieや認証情報を出力しない。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: Low/Medium/Highで異なるmatrix選択経路、session coverage、evidence-quality verdictを確認し、既定の汎用評価と明示的DVWA回帰評価の失敗テストを追加した。
- [x] ステップ2: `expected_detection_matrix.py`に全Securityレベル共通のgeneric capability assessmentを実装し、Lowのパス一致matrixから分離した。
- [x] ステップ3: CLIの既定を汎用評価に接続し、`--profile dvwa-low-regression`でのみ既存Low matrixを実行するようにした。
- [x] ステップ4: targeted pytest、CLI test、実Low/Medium/High report/sessionの整合性と評価コマンドで検証した。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] 実アプリ横断の外部ベンチマーク - 本タスクの評価は汎用契約だが、複数の許可済みアプリで妥当性を検証する別タスクを起票する。
- [ ] [重要度:低] Highの脆弱性有無そのものの完全性判定 - 脆弱性が存在しない正常アプリを不合格にしないため、本タスクでは判定対象外とする。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0399-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
