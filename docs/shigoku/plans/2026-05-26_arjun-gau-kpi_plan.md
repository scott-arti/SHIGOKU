---
task_id: SGK-2026-0245
doc_type: plan
status: done
parent_task_id: SGK-2026-0239
related_docs:
- docs/shigoku/plans/external_tool_migration_plan.md
- docs/shigoku/manuals/2026-05-26_arjun-gau-threshold-recalibration_runbook.md
- docs/shigoku/manuals/2026-05-26_arjun-gau-failure-drill_runbook.md
title: Arjun/GAU 運用KPI・ガバナンス充足化実装計画
created_at: '2026-05-26'
updated_at: '2026-05-26'
tags:
- shigoku
target: external-tool-observability-governance
---

# Arjun/GAU 運用KPI・ガバナンス充足化実装計画 Plan

## Goal
- CTO確認点5件を運用可能な状態で充足する。
- 既存の Arjun/GAU 実装を維持しつつ、経営判断に使える KPI・運用統制・監査性を確立する。

## Scope
- In scope:
  - Arjun/GAU KPI の外部永続化（再起動耐性）
  - 品質KPI（confirmed/fp/reproducibility）の定義固定と算出実装
  - テレメトリのデータガバナンス（PII/機密情報制御）
  - 監視基盤障害時のフォールバック運用（Runbook + 演習）
  - ロールバック副作用の判定基準と監査ログ
- Out of scope:
  - 新規検出ロジックの追加
  - 既存スキャンアルゴリズムの性能改善
  - 外部監視基盤の製品選定見直し

## Tasks
1. KPI因果性の強化
   - `arjun_scan_failure_total.reason.*` と `native_fallback_total.trigger_reason.*` に相関軸を追加する。
   - 相関軸は固定列挙に限定する（カテゴリ/実行モード/対象種別）。
   - 自由文字列ラベルは禁止する。
2. 品質KPI信頼性の固定
   - `confirmed_rate`, `fp_rate`, `reproducibility_rate` の算出式を単一正本化する。
   - 算出元データ（session/report/raw findings）を明示し、混在優先順位を固定する。
   - `scripts/check_initial_release_gate.py` の判定に品質KPI閾値を追加する。
3. ガバナンス実効化
   - メトリクス/ログ出力の allow-list を定義し、PII/機密値の出力を禁止する。
   - マスキング必須経路をテストで固定する。
   - 保持期間・閲覧権限・監査ログ保存を運用文書に追加する。
4. 障害時フォールバック運用
   - 監視基盤障害時の劣化運用手順を Runbook 化する。
   - 手順には「ローカル蓄積」「再送」「手動Go/No-Go判定」「復旧後整合確認」を含める。
   - 演習シナリオ（timeout急増 / provider_error連発 / 監視基盤停止）を定例実施する。
5. ロールバック副作用管理
   - ロールバック条件式を KPI に紐づけて固定する。
   - ロールバック前後で `confirmed_rate/fp_rate/reproducibility_rate` を比較し、品質劣化を監査ログへ記録する。
   - 判断者・承認者・通知先を RACI で明文化する。

## Fixed Numeric Targets & Operational Conditions

### 1) KPI閾値（運用KPI）
- 集計窓:
  - 短期窓: 5分
  - 中期窓: 1時間
- `arjun_failure_rate = arjun_scan_failure_total / arjun_scan_total`
  - Warning: `> 0.08` が 5分窓で2連続
  - Critical: `> 0.15` が 5分窓で3連続
- `native_fallback_rate = native_fallback_total / arjun_scan_total`
  - Warning: `> 0.20` が 5分窓で2連続
  - Critical: `> 0.35` が 5分窓で3連続
- `arjun_empty_success_rate = arjun_scan_empty_success_total / arjun_scan_total`
  - Warning: `> 0.12` が 1時間窓で継続
  - Critical: `> 0.20` が 1時間窓で継続
- 分母ゼロ時:
  - 判定値は `N/A`。アラート評価対象外。

### 2) 品質KPI算出式とゲート条件
- 算出元優先順位（単一正本）:
  1. session raw findings
  2. report structured findings_summary
  3. report text parse（フォールバック）
- `confirmed_rate = confirmed_count / (confirmed_count + candidate_count)`（分母0はN/A）
- `fp_rate = false_positive_count / (false_positive_count + confirmed_count)`（分母0はN/A）
- `reproducibility_rate = reproducible_confirmed_count / confirmed_count`（分母0はN/A）
- Gate条件:
  - `confirmed_rate >= 0.25`
  - `fp_rate <= 0.20`
  - `reproducibility_rate >= 0.80`
  - かつ、各値が直近安定ベースラインより悪化していない（閾値: ±0.05）

### 3) テレメトリガバナンス固定値
- メトリクス許可キー（allow-list）:
  - `metric_name`, `metric_value`, `reason`, `trigger_reason`, `scan_category`, `execution_mode`, `target_kind`, `timestamp`, `run_id`
- 禁止データ:
  - URL生値、query/body生値、header生値、token/API key、メールアドレス等PII
- 保持期間:
  - 外部監視基盤: 180日
  - ローカルスプール: 7日
  - 監査ログ: 365日
- アクセス権限:
  - 書き込み: SRE/Platform runtime service account
  - 閲覧: Security Eng / SRE On-call / CTO read-only
  - 監査ログ閲覧: Security Manager + SRE Manager

### 4) 監視基盤障害時フォールバック運用
- 障害検知条件:
  - 監視送信 heartbeat 欠損が 5分継続
- 劣化運用:
  - `workspace/observability/spool/*.jsonl` へローカル蓄積
  - flush間隔: 30秒
  - 最大バッファ: 10000 events または 50MB（先到達でローテート）
  - backoff再送: 5s → 15s → 30s → 60s（最大60s）
- 復旧条件:
  - heartbeat復帰後、スプール再送成功率 `>= 99%`
  - 未送信残量 `<= 100 events`
- 手動Go/No-Go:
  - 障害中は「品質KPI + 直近1時間の手動確認メモ」が揃うまで Go 禁止

### 5) ロールバック副作用管理
- ロールバック実行条件（いずれか）:
  - `arjun_failure_rate > 0.20` が 15分継続
  - `native_fallback_rate > 0.50` が 15分継続
  - `reproducibility_rate < 0.70` が 3連続run
- ロールバック後の復帰条件:
  - 24時間で `confirmed_rate` がロールバック前比 -0.05 以内
  - 24時間で `fp_rate` がロールバック前比 +0.05 以内
  - `reproducibility_rate >= 0.80`
- 監査記録必須項目:
  - 発動条件、比較メトリクス値、影響範囲、承認者、復帰判定時刻

### RACI（運用責任）
- Responsible: Platform On-call（一次対応）
- Accountable: Security Engineering Manager（最終判断）
- Consulted: AppSec Lead / SRE Lead
- Informed: CTO / Product Security Stakeholders

## Deliverables
- 計画書（本書）
- 運用Runbook（`docs/shigoku/manuals/` 配下）
- KPI仕様書（`docs/shigoku/specs/` もしくは `manuals/` 配下）
- 作業報告書（`doc_type: work_report`）
- 作業ログ（`doc_type: work_log`）

## Acceptance Criteria (Go/No-Go)
1. KPI永続化
   - 再起動後も KPI が欠損せずに外部基盤で時系列追跡できる。
2. 品質KPI固定
   - `confirmed_rate/fp_rate/reproducibility_rate` が gate 判定に実装済みで、算出元が一意に説明可能。
3. ガバナンス
   - allow-list 未登録の機密項目は出力されないことをテストで証明できる。
4. 障害時運用
   - 監視基盤障害演習を1回以上実施し、Runbook更新履歴が残る。
5. ロールバック統制
   - ロールバック判断ログに「条件」「影響評価」「承認者」が必須記録される。
6. 閾値再校正（追加完了条件）
   - 本番相当データを最低14日収集し、初期閾値との差分レビューを1回以上実施済み。
   - 再校正結果（維持/変更）と根拠が Runbook に記録され、承認者が記名されている。
7. 演習証跡（追加完了条件）
   - `timeout急増` / `provider_error連発` / `監視基盤停止` の3演習を実施済み。
   - 各演習の証跡（時刻、検知、一次対応、復旧判定、改善点）が運用Runbookに記録されている。

## Validation
- `.venv/bin/pytest` で以下を最低実行:
  - Arjun/GAUメトリクス分類・二重加算防止
  - 品質KPI算出の一貫性
  - PII/allow-list準拠
- `python3 scripts/check_initial_release_gate.py --report <report-path>` で gate 判定確認
- `python3 scripts/sync_shigoku_updated_at.py`
- `python3 scripts/validate_shigoku_docs.py`

## Risk & Mitigation
- リスク: KPI最適化が検出品質劣化を隠す
  - 対策: 運用KPI単独ではなく品質KPI同時ゲートを必須化
- リスク: 監視基盤障害で意思決定不能
  - 対策: 手動判定Runbook + ローカル蓄積/再送の二段構え
- リスク: ロールバック乱発で改善停滞
  - 対策: ロールバック後の根因分析・再発防止アクションを必須化
