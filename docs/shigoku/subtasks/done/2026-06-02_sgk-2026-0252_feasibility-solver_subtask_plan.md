---
task_id: SGK-2026-0252
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0251
related_docs:
- docs/shigoku/plans/2026-06-01_sgk-2026-0251_task_plan.md
- docs/shigoku/reports/2026-06-02_sgk-2026-0252_feasibility-solver_work_report.md
- docs/shigoku/worklogs/2026-06-02_sgk-2026-0252_feasibility-solver_work_log.md
title: 脆弱性チェーン基盤分割と feasibility solver 実装
created_at: '2026-06-02'
updated_at: '2026-07-02'
tags:
- shigoku
target: chain-builder-core
---

# 実装計画書：脆弱性チェーン基盤分割と feasibility solver 実装

## 1. 達成したいゴール（ユーザー視点）
- [x] チェーン候補を評価すると、等価経路は統合されつつ、前提条件制約を満たすチェーンだけが成立候補として残ること。

### 1.1 受け入れ条件（Done 条件）
- [x] 既存 canonical chain の回帰を発生させないこと。
- [x] 既知の infeasible chain corpus は制約違反として除外されること。
- [x] heuristic 候補と AI 候補で同一入力に対して同一の feasibility verdict を返すこと。
- [x] feasibility 判定導入後も、探索予算超過時は既存 heuristic ベースの結果を返し、ゼロ件化しないこと。
- [x] feasibility 判定の処理時間増分は targeted benchmark で観測し、既存フローに対する劣化が説明可能であること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/intelligence/chain_builder.py`: （修正）`primitive_transition_graph` と feasibility 判定の接続
  - `src/core/intelligence/chain_proposal.py`: （必要に応じて修正）AI候補にも feasibility 判定を適用
  - `tests/core/intelligence/test_chain_builder.py`: （修正）canonicalization 後の feasibility 検証
  - `tests/core/intelligence/test_phase0_risk_clearance_checklist.py`: （修正）Step 5 の残要件検証
- **データの流れ / 依存関係:**
  - findings / rule path -> canonicalization -> primitive transition graph -> feasibility solver -> chain candidate

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** chain candidate (`list[Finding]`), rule transitions (`list[dict]`), preconditions / temporal constraints
- **出力/結果 (Output):** feasibility pass 済み chain candidate, 失敗時は `excluded_reasons` に制約違反理由を残す
- **制約・ルール:**
  - 既存 `chain_key` canonicalization の公開挙動を壊さない
  - AI候補・ルール候補の両方に同じ feasibility 判定を適用する
  - `auth`, `same_origin`, `token_lifetime`, `session_generation` などの制約を拡張可能な形で扱う

### 3.1 制約入力スキーマ
- `auth`: `Finding.additional_info.auth_level` を参照し、`unauth` / `user` / `admin` のみを有効値とする。
- `same_origin`: `Finding.additional_info.same_origin` を参照し、bool のみを有効値とする。
- `primitive`: `Finding.additional_info.primitive` を参照し、`read` / `write` / `exec` / `pivot` を有効値とする。
- `asset_scope`: `Finding.additional_info.asset_scope` を参照し、`in_scope` 以外は feasibility 評価対象外とする。
- `token_lifetime`, `session_generation` など未実装制約は schema 上は受理してよいが、未評価時は `feasibility:constraint_data_missing` または `feasibility:constraint_not_supported` を返せるようにする。
- unknown / 欠損値の扱いは制約ごとに明示し、silent pass は禁止する。
- `constraint_schema_version` と `decision_trace_version` を保持し、将来の制約追加時も互換性を追跡できるようにする。

### 3.1.1 制約エラー時の状態遷移
- `feasibility:constraint_data_missing` は原則として `blocked` 相当の扱いとし、`actionable` へは昇格させない。
- `feasibility:constraint_not_supported` は `draft` 止まりとし、サポート追加または明示的な policy 更新なしに `confirmed` / `actionable` へ進めない。
- fail-open / fail-close の判断は制約ごとに文書化し、実装時の暗黙解釈を禁止する。

### 3.2 feasibility evaluator 契約
- 候補正規化後に `evaluate_feasibility(candidate, findings, constraints)` 相当の単一 evaluator を必ず通す。
- heuristic 候補と AI 候補は evaluator の前段だけを分離し、判定ロジック本体は共有実装に集約する。
- evaluator は `verdict`, `failed_constraints`, `excluded_reasons`, `decision_trace.feasibility` を返し、観測根拠を残す。
- evaluator 入力前に、`chain_key` 生成元と整合する canonicalized finding set / signal path / objective material を構築する。

### 3.3 探索予算とフォールバック
- feasibility solver には `max_nodes`, `max_edges`, `timeout_ms` の探索上限を設ける。
- 予算超過時は fail-close で全除外せず、既存 heuristic ベースの候補を返しつつ `used_fallback=true` と `fallback_reason` を必須記録する。
- targeted benchmark では、通常ケースと予算超過ケースの両方を固定入力で再現できるようにする。
- `used_fallback_count`, `solver_timeout_count`, `avg_solver_latency_ms`, `p95_solver_latency_ms` を benchmark と decision trace に残す。

### 3.4 除外理由とトレース
- `excluded_reasons` は `feasibility:*` と `promotion:*` の namespace を分ける。
- `decision_trace.feasibility` には少なくとも `selected_rule_id`, `failed_constraints`, `evidence_source`, `verdict`, `used_fallback`, `fallback_reason` を残す。
- `failed_constraints` は配列とし、各要素に `constraint`, `observed_value`, `expected_value`, `evidence_source` を含める。
- feasibility 判定失敗と replay / falsification 不足は別原因として切り分け可能にする。

## 4. 懸念点と対策

### 4.1 SRE / インフラ観点
- 【発生確率:高】【影響度:大】探索コストが入力サイズに応じて増加し、feasibility solver が連鎖評価のボトルネックになる。  
  対策: `max_nodes`, `max_edges`, `timeout_ms` を実装し、`used_fallback_count`, `solver_timeout_count`, `avg_solver_latency_ms`, `p95_solver_latency_ms` を benchmark と decision trace に記録する。
- 【発生確率:高】【影響度:中】`verify_chaining_flow` の固定 sleep に依存した検証は flaky になりやすく、CI やローカル再現性を下げる。  
  対策: 主検証は targeted unit/integration test に寄せ、`verify_chaining_flow` は補助確認に限定する。condition-based wait または同期的検証へ段階置換する。
- 【発生確率:中】【影響度:大】フォールバック時に silently 品質劣化し、下流で solver 不達が見えない。  
  対策: 返却 candidate と decision trace に `used_fallback=true` と `fallback_reason` を必須付与し、fallback 発生率を benchmark で確認する。

### 4.2 ソフトウェアアーキテクト観点
- 【発生確率:高】【影響度:大】heuristic 候補と AI 候補が別経路のまま実装されると、同一入力でも feasibility verdict が分岐する。  
  対策: 候補正規化後に `evaluate_feasibility(candidate, findings, constraints)` の単一 evaluator を通し、判定本体を共有実装へ集約する。
- 【発生確率:中】【影響度:大】`chain_key` 生成材料と evaluator 入力材料がずれると、同一 chain の dedupe と判定が不整合になる。  
  対策: evaluator 入力前に `chain_key` と整合する canonicalized finding set / signal path / objective material を構築する。
- 【発生確率:中】【影響度:大】制約入力 schema が曖昧なままだと、unknown / 欠損値の扱いが実装者依存になる。  
  対策: `auth`, `same_origin`, `primitive`, `asset_scope`, `token_lifetime`, `session_generation` の参照元、許容値、未設定時挙動を固定し、`constraint_schema_version` を付与する。
- 【発生確率:低】【影響度:大】将来の制約追加で trace や互換性が崩れる可能性がある。  
  対策: `decision_trace_version` を保持し、制約追加時の後方互換ポリシーを維持する。

### 4.3 デバッガー観点
- 【発生確率:高】【影響度:中】`excluded_reasons` に feasibility と promotion の失敗理由が混在すると、原因切り分けが難しい。  
  対策: `excluded_reasons` を `feasibility:*` と `promotion:*` に namespace 分離し、`decision_trace.feasibility` に観測根拠を残す。
- 【発生確率:高】【影響度:中】複数制約違反時に単一の `failed_constraint` だけでは再現と診断が弱い。  
  対策: `failed_constraints` を配列化し、各要素に `constraint`, `observed_value`, `expected_value`, `evidence_source` を保持する。
- 【発生確率:中】【影響度:中】最小再現 fixture がないと、不具合時に benchmark と unit test の往復が重くなる。  
  対策: 各制約ごとに 1 制約 1 失敗理由で再現できる最小 fixture を追加し、unit test から直接再現できるようにする。

### 4.4 CTO 観点
- 【発生確率:中】【影響度:大】制約を入れすぎると既存 benchmark の成立チェーンまで落とし、回帰の影響範囲が読めなくなる。  
  対策: synthetic / integration / benchmark の 3 層で回帰確認し、既知 canonical chain と infeasible corpus を分けて検証する。
- 【発生確率:中】【影響度:大】unsupported / missing constraint の扱いが曖昧だと、実運用で誤昇格または過剰抑止が起こる。  
  対策: `constraint_data_missing` と `constraint_not_supported` の状態遷移規則を明文化し、`actionable` への昇格条件から除外する。
- 【発生確率:中】【影響度:大】一度に enforcement まで有効化すると、回帰時に原因分離が難しい。  
  対策: 初回は shadow verdict を記録する read-only モードを先に実装し、既存判定との差分を確認後に enforcement を有効化する。

## 5. Tasks
- [x] ステップ1: `auth`, `same_origin`, `primitive`, `asset_scope`, `token_lifetime`, `session_generation` の constraint schema と `constraint_schema_version` / `decision_trace_version` を定義し、unknown / 欠損値・unsupported constraint の状態遷移規則を文書とテスト前提に固定する。
- [x] ステップ2: `chain_key` と整合する canonicalized finding set / signal path / objective material を明文化し、heuristic 候補・AI 候補の両方が同じ前処理結果を evaluator 入力に使うよう API 境界を定める。
- [x] ステップ3: `primitive_transition_graph` と `evaluate_feasibility(candidate, findings, constraints)` の最小APIを実装し、shadow verdict を返せる read-only モードで `chain_builder.py` に接続する。
- [x] ステップ4: `excluded_reasons` の `feasibility:*` / `promotion:*` namespace、`failed_constraints` 配列、`decision_trace.feasibility` の `verdict` / `evidence_source` / `used_fallback` / `fallback_reason` を実装する。
- [x] ステップ5: 各制約ごとの最小再現 fixture を用意し、canonicalization 後の graph 判定、unknown / 欠損入力、unsupported constraint、複数制約違反を targeted unit test で TDD 固定する。
- [x] ステップ6: AI 候補・heuristic 候補に対して同一入力なら同一 feasibility verdict になること、`constraint_data_missing` / `constraint_not_supported` が `actionable` へ昇格しないことを integration test で固定する。
- [x] ステップ7: `analyze_with_budget` 相当の予算制御を実装し、`max_nodes`, `max_edges`, `timeout_ms`, `used_fallback=true`, `fallback_reason` を返却 candidate と trace に反映する。
- [x] ステップ8: targeted benchmark で通常ケース・予算超過ケース・既知 infeasible corpus を固定入力で再現し、`used_fallback_count`, `solver_timeout_count`, `avg_solver_latency_ms`, `p95_solver_latency_ms` を記録する。
- [x] ステップ9: targeted unit/integration test を主検証、`verify_chaining_flow` を補助確認として運用し、condition-based wait への置換方針を確認しながら既存成立チェーンを壊さず不成立チェーンだけを除外できることを確認する。
- [x] ステップ10: shadow verdict と既存判定との差分を確認し、差分が説明可能であることを benchmark / trace で確認した後に enforcement を有効化する。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 制約を入れすぎると既存 benchmark の成立チェーンまで落とす可能性 - synthetic / E2E の両方で回帰確認する。
- [ ] [重要度:中] `verify_chaining_flow` は固定 sleep を含むため、feasibility 判定の主検証に使うと flaky になる可能性 - condition-based wait か同期的テストへ段階的に置換する。
- [ ] [重要度:中] 未実装制約を silent pass すると heuristic / AI で判定差分が出る可能性 - `constraint_not_supported` を返す方針を維持する。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0252-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
