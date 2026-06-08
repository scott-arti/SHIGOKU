---
task_id: SGK-2026-0255
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0251
related_docs:
- docs/shigoku/plans/2026-06-01_task_plan.md
- docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md
- docs/shigoku/manuals/2026-06-03_degrade-operations_runbook.md
- docs/shigoku/reports/2026-06-03_sgk-2026-0255_degrade-runbook_work_report.md
- docs/shigoku/worklogs/2026-06-03_sgk-2026-0255_degrade-runbook_work_log.md
title: 脆弱性チェーン degrade 設計と運用Runbook 整備
created_at: '2026-06-02'
updated_at: '2026-06-03'
tags:
- shigoku
target: chain-operations
---

# 実装計画書：脆弱性チェーン degrade 設計と運用Runbook 整備

## 1. 達成したいゴール（ユーザー視点）
- [x] 一部コンポーネント障害や運用イベントが起きても、degrade 先へ安全に落とし込み、停止・復旧・再開手順が文書化されていること。
- [x] component ごとの degrade 開始条件・解除条件・TTL・rollback 条件と、`continue` / `defer` / `blocked` の判定根拠がコード・テスト・Runbook で一致していること。
- [x] degrade 中でも `AuditLogger` / `DecisionTracer` から復旧判断まで追跡でき、`report_adapter` 劣化時の提出保留と復旧後 replay 手順が明文化されていること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: （修正）component degradation 境界の明確化
  - `docs/shigoku/plans/2026-06-01_task_plan.md`: （参照）Phase2 の既存 degrade 実装と運用差分
  - `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md`: （新規）Step 7 で使う drill 証跡テンプレート
  - `docs/shigoku/manuals/` 配下: （新規または修正）停止/復旧/再開/エスカレーション手順
  - `tests/core/intelligence/test_phase2_risk_clearance_checklist.py`: （修正）degrade 動作の補強テスト
- **データの流れ / 依存関係:**
  - component failure / alert -> degrade decision -> fallback path -> audit / runbook / recovery action
- **責務境界:**
  - `src/core/engine/master_conductor.py`: component health から `continue` / `defer` / `blocked` と fallback を決める正本
  - `docs/shigoku/manuals/` 配下の Runbook: 発動条件、監視項目、rollback、replay、No-Go 判定の運用正本
  - `tests/core/intelligence/test_phase2_risk_clearance_checklist.py`: component contract と failure mode 回帰を固定する正本
  - `AuditLogger` / `DecisionTracer`: degrade 開始から復旧判断までの観測証跡の正本

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** failure signal, alert context, component boundary, fallback policy
- **出力/結果 (Output):** degrade decision, documented recovery path, escalation criteria
- **component contract 表で最低限固定する項目:** `component`, `health_state`, `allowed_fallback`, `forbidden_transition`, `recovery_precondition`, `ttl`, `rollback_trigger`
- **degrade 開始/解除ルールで最低限固定する項目:** `signal_source`, `threshold`, `evaluation_window`, `auto_recovery_condition`, `manual_recovery_condition`, `no_go_condition`
- **観測・監査で最低限固定する項目:** `correlation_id`, `component_before`, `component_after`, `selected_fallback`, `policy_version`, `decision_reason`, `recovery_reason`, `recovery_outcome`
- **drill / tabletop 証跡で最低限固定する項目:** `scenario_id`, `triggered_component`, `expected_state`, `observed_state`, `submit_blocked`, `replay_verdict`, `followup_action`
- **制約・ルール:**
  - 既存 `resolve_component_degradation()` の公開挙動を壊さない
  - Runbook は `AuditLogger` / `DecisionTracer` の観測項目と整合する
  - scope 逸脱や WAF 反応時の停止条件を明文化する
  - `scope_violation` と繰り返し WAF 反応は `blocked` または `stop` 相当として扱い、degrade 継続を許可しない
  - 依存障害で `report_adapter` や復旧判断が不完全な場合は `defer` を優先し、platform 提出は実行しない
  - `report_adapter=degraded` 時は `canonical_report_payload` 保存と復旧後 replay のみ許可し、提出先 adapter 実行は復旧完了まで保留する
  - 本 subtask では unknown component は現行 `best_effort` 互換を維持し、fail-closed 方向への仕様変更は行わない。将来変更する場合は feature flag と回帰テストを必須にする
  - Runbook の正本配置は `docs/shigoku/manuals/` とし、`master_conductor`・tests・manuals 間で対象 component 名を一致させる

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `src/core/engine/master_conductor.py`、`tests/core/intelligence/test_phase2_risk_clearance_checklist.py`、親計画 Step 23/25/27、既存 `docs/shigoku/manuals/` を照合し、現行の component 一覧、fallback、failure mode、非目標を棚卸しする。
- [x] ステップ1A: `program_memory` / `audit_logger` / `report_adapter` / unknown component を対象に、`component`, `health_state`, `allowed_fallback`, `forbidden_transition`, `recovery_precondition`, `ttl`, `rollback_trigger` を持つ component contract 表を計画書へ固定する。この subtask では unknown component を `best_effort` 維持と明示し、挙動変更をスコープ外に置く。
- [x] ステップ2: component ごとの failure mode table を定義し、`signal_source`, `threshold`, `evaluation_window`, `continue` / `defer` / `blocked`, `auto_recovery_condition`, `manual_recovery_condition`, `no_go_condition` を先に固定する。
- [x] ステップ2A: `scope_violation`、WAF 反応、依存障害、`report_adapter=degraded` を横断する運用ルールを整理し、どの条件で degrade 継続を禁止し、どの条件で replay 保留へ切り替えるかを明文化する。
- [x] ステップ3: `AuditLogger` / `DecisionTracer` に残す必須項目として `correlation_id`, `component_before`, `component_after`, `selected_fallback`, `policy_version`, `decision_reason`, `recovery_reason`, `recovery_outcome` を固定し、監視項目・アラート条件・監査観点を仕様へ対応付ける。
- [x] ステップ4: `tests/core/intelligence/test_phase2_risk_clearance_checklist.py` に、(a) isolated degradation、(b) multi-component degradation、(c) unknown component、(d) WAF + dependency collision、(e) `report_adapter` degraded での提出保留、(f) TTL 超過後の recovery / rollback、を先に追加して期待挙動を固定する。
- [x] ステップ5: `src/core/engine/master_conductor.py` の degrade decision 契約を component contract 表と failure mode table に合わせて補強し、既存 `resolve_component_degradation()` の公開挙動を壊さない範囲で fallback と state 遷移を明示化する。
- [x] ステップ6: `docs/shigoku/manuals/` 配下に Runbook / playbook を整備し、発動条件、監視項目、TTL、rollback、No-Go 判定、platform 提出保留、復旧後 replay、エスカレーション手順をコード契約と同じ用語で記述する。
- [x] ステップ7: alert -> degrade -> recovery -> replay の tabletop / drill 観点を Runbook に組み込み、障害注入パターン、期待ログ、期待 state 遷移、復旧判断の根拠を手順化する。drill 結果は `docs/shigoku/manuals/2026-06-03_degrade-drill-evidence_template.md` の形式を使い、`work_report` または Runbook 付録へ必ず残す。
- [x] ステップ8: `AuditLogger` / `DecisionTracer` の証跡から Runbook の復旧判断まで追えることを確認し、実装・テスト・運用文書の差分があれば component contract 表と failure mode table を正本として解消する。
- [x] ステップ9: 親計画 Step 23/25/27 と本 subtask の成果を突き合わせ、残課題があれば `deferred_tasks` に切り出す条件と追跡方針を記録する。親計画または `work_report` には、unknown component 方針、drill 結果要約、`report_adapter=degraded` 時に submit が block された証跡を最終要約として反映する。

## 4.1 Done条件
- [x] `tests/core/intelligence/test_phase2_risk_clearance_checklist.py` の targeted tests で isolated / multi / unknown / collision / replay 保留 / rollback の少なくとも 6 ケースが通り、`report_adapter=degraded` ケースで submit が実行されないこと。
- [x] component contract 表、failure mode table、Runbook の component 名・state 名・fallback 名が一致していること。
- [x] `AuditLogger` / `DecisionTracer` から復旧判断まで必要証跡を追跡できること。
- [x] `report_adapter=degraded` 時の提出保留と復旧後 replay 手順が manuals に記録されていること。
- [x] 少なくとも 1 つの tabletop / drill 実施結果が `work_report` または Runbook 付録に残り、`expected_state` と `observed_state` の一致/差分、`submit_blocked`、`replay_verdict` が確認できること。
- [x] 親計画 Step 23/25/27 との差分が解消されるか、別 task として追跡条件が明記されていること。

## 5. 懸念点と対策
- [x] **SRE/インフラ**【発生確率:高 / 影響度:大】degrade 開始条件・解除条件が曖昧なままだと、障害時の判断が人依存になり継続/停止がぶれる懸念がある。  
  **対策:** ステップ2で component ごとの `signal_source`、`threshold`、`evaluation_window`、`continue` / `defer` / `blocked` を failure mode table として固定する。
- [x] **SRE/インフラ**【発生確率:高 / 影響度:大】degraded mode の TTL と rollback 条件が未定義だと、silent degradation が長引く懸念がある。  
  **対策:** ステップ1A とステップ6で `ttl`、`rollback_trigger`、`auto_recovery_condition`、`manual_recovery_condition` を component contract 表と Runbook の両方へ明記する。
- [x] **SRE/インフラ**【発生確率:中 / 影響度:大】監視項目とアラート条件が計画段階で固定されないと、degrade 中の悪化を見逃す懸念がある。  
  **対策:** ステップ3で `correlation_id`、state 遷移、fallback 選択、recovery outcome に対応する監視項目とアラート条件を定義し、ステップ6で Runbook へ反映する。
- [x] **ソフトウェアアーキテクト**【発生確率:高 / 影響度:大】component boundary の正本がないと、コード・テスト・Runbook で別々の解釈が生まれる懸念がある。  
  **対策:** ステップ1Aで component contract 表を先に固定し、ステップ5・6・8 でその表を正本にして差分を解消する。
- [x] **ソフトウェアアーキテクト**【発生確率:中 / 影響度:大】`resolve_component_degradation()` の入力/出力契約と unknown component の扱いが曖昧だと、将来の変更で互換性を壊す懸念がある。  
  **対策:** ステップ4で unknown component 回帰を先に固定し、ステップ5で `best_effort` 互換維持または feature flag 付き変更のどちらかに明示的に寄せる。
- [x] **ソフトウェアアーキテクト**【発生確率:高 / 影響度:中】計画書が `docs/shigoku/runbooks/` を指したままだと、既存の `docs/shigoku/manuals/` と正本配置がズレる懸念がある。  
  **対策:** 本計画書で Runbook の canonical location を `docs/shigoku/manuals/` に修正し、ステップ6で manuals 配下へ統一する。
- [x] **デバッガー**【発生確率:高 / 影響度:大】複合障害や TTL 超過後の復旧がテスト化されないと、実運用で再現できないまま不具合が残る懸念がある。  
  **対策:** ステップ4で isolated / multi / unknown / collision / replay 保留 / rollback のケースを先に追加し、期待 state を1ケース1期待値で固定する。
- [x] **デバッガー**【発生確率:高 / 影響度:中】監査ログから復旧判断まで必要な証跡が曖昧だと、障害解析で「なぜその fallback を選んだか」を追えない懸念がある。  
  **対策:** ステップ3で `component_before` / `component_after` / `selected_fallback` / `policy_version` / `decision_reason` / `recovery_reason` / `recovery_outcome` を必須項目として固定する。
- [x] **デバッガー**【発生確率:中 / 影響度:大】tabletop / 障害注入シナリオがないと、Runbook が紙だけで終わる懸念がある。  
  **対策:** ステップ7で alert -> degrade -> recovery -> replay を通しで確認する drill を組み込み、障害注入パターンと期待ログを Runbook に追加する。
- [x] **CTO**【発生確率:高 / 影響度:大】どこまで degraded continue を許容するかの経営ガードレールがないと、scope 逸脱や監査欠損のまま継続する懸念がある。  
  **対策:** ステップ2Aで `scope_violation`、繰り返し WAF、監査欠損、`report_adapter` 不完全時の No-Go 条件を固定し、ステップ6で運用判断へ落とし込む。
- [x] **CTO**【発生確率:高 / 影響度:中】subtask の完了条件が弱いと、Runbook や証跡の整合が未完でも完了扱いになる懸念がある。  
  **対策:** `## 4.1 Done条件` を追加し、tests、contract 一致、証跡追跡、提出保留/replay、親計画差分解消を完了判定へ組み込む。
- [x] **CTO**【発生確率:中 / 影響度:大】`report_adapter` が degraded のまま提出先 adapter を通すと、提出品質や監査整合を壊す懸念がある。  
  **対策:** ステップ2Aとステップ6で `report_adapter=degraded` 時は `canonical_report_payload` 保存と復旧後 replay のみ許可し、platform 提出は保留する方針を明文化する。
- [x] **CTO**【発生確率:中 / 影響度:中】継続監視や追加対策をどの条件で別 task に切り出すかが曖昧だと、完了後の追跡が抜ける懸念がある。  
  **対策:** ステップ9で親計画 Step 23/25/27 との差分確認と `deferred_tasks` 切り出し条件を定義し、別 task に分離すべき項目を残せるようにする。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:中] 実装と運用文書がずれると障害時に判断が割れる - テスト観点と Runbook を同じ task 配下で更新する。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0255-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
