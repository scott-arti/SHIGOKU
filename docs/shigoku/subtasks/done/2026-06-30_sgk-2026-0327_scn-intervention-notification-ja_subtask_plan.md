---
task_id: SGK-2026-0327
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0288_discord-notification-ja_subtask_plan.md
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0297_discord-all-finding-detail-notification_subtask_plan.md
- docs/shigoku/worklogs/2026-05-11_log_scn07-12_discord_notification_v1.md
- docs/shigoku/reports/2026-06-30_SGK-2026-0327_work_report.md
- docs/shigoku/worklogs/2026-06-30_SGK-2026-0327_work_log.md
title: SCN介入通知日本語化（最小差分）計画
created_at: '2026-06-30'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/engine/master_conductor.py, tests/core/engine/test_master_conductor_intervention_gate.py
---

# 実装計画書：SCN介入通知日本語化（最小差分）計画

## 0. 状態メモ
- 2026-06-30 に計画書へ懸念点と対策を追記し、TDD 前提の手順へ更新した。
- `tests/core/engine/test_master_conductor_intervention_gate.py` で RED を確認した後、`src/core/engine/master_conductor.py` の SCN 介入通知文面を最小差分で日本語化した。
- targeted test が green になったため、subtask は `done` に移行する。

## 1. 達成したいゴール（ユーザー視点）
- [ ] Discord に届く `SCN08` から `SCN11` の介入通知が、日本語で自然に読めること。
- [ ] 主対象は `SCN08-11` としつつ、実装関数が `SCN07-12` 共通である都合を明示したうえで、共通文面を最小差分で更新すること。
- [ ] すでに日本語化済みの Finding 詳細通知とは別系統のまま、SCN 介入通知だけを最小差分で日本語化すること。
- [ ] 通知の判断ロジックや `manual_deferred` / `SCN11` 例外実行ポリシーは変更せず、文面のみを対象にすること。
- [ ] 運用判断に必要な 1) シナリオ 2) 対象 3) 判定理由 4) 次アクション が一読で分かること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: `_notify_scn07_12_intervention()` で SCN07-12 の Discord 通知本文を組み立てている。今回の主変更点。
  - `tests/core/engine/test_master_conductor_intervention_gate.py`: 介入通知の文面と既存ポリシーを確認する回帰テスト。
- **データの流れ / 依存関係:**
  - `InterventionPolicy` の判定結果 -> `MasterConductor._notify_scn07_12_intervention()` -> `get_notifier().notify(..., bulk=True)` -> Discord。
  - Finding 詳細通知の `JapaneseBodyBuilder` 経路とは分離されており、今回はこちらへ混ぜない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `decision.scenario_id`, `decision.route`, `decision.confidence`, `decision.reasons`, `decision.matched_signals`, `task.name`, `task.params.target(s)`
- **出力/結果 (Output):** 日本語化された SCN 介入通知本文、既存どおりの `bulk=True` 送信、既存どおりの非致命 notification failure ログ
- **制約・ルール:**
  - 変更対象は通知本文のラベル・説明文を中心とし、介入判定ロジック・送信条件・dedupe key は変えない。
  - `SCN11` は Ver.1 方針どおり自律実行を維持するため、通知日本語化の影響で `_is_manual_defer_target_v1()` や precheck 挙動を崩さない。
  - 既存の machine-readable 情報として `scenario_id`、`route`、`gate_mode`、対象 URL/タスク名は英語値のまま残し、表示ラベルのみを日本語化する。
  - 追加実装は `master_conductor.py` と対象テストの最小差分を優先し、新規 formatter 抽象化はこのタスクでは行わない。
  - 許可する構造変更は、同一関数内のラベル文字列とシナリオ名辞書の日本語化、および同ファイル内の小さな定数整理までとする。新規モジュール追加や cross-file 抽象化は行わない。
  - `notify_action_required()`、Finding 通知、CLI ログ、日本語化済みの別テンプレートは非スコープとする。
  - 本文はプレーンテキスト互換を維持し、絵文字・全角日本語を使っても既存英語版と同等以下の行数・長さに収める。
  - 通知失敗時の既存 debug ログメッセージと fail-open/非致命挙動は変更しない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `tests/core/engine/test_master_conductor_intervention_gate.py` に、日本語ラベル前提の期待文面テストを先に追加する。見出し、Scenario、Target、Task、Route/Gate、Confidence、Signals、Why、Required Action を期待値として固定する。
- [ ] ステップ2: ステップ1の対象 pytest を実行し、追加テストが英語文面のまま正しく失敗することを確認する。必要に応じて `reasons` / `matched_signals` が文字列・空配列・未指定でも文面が壊れないケースを追加する。
- [ ] ステップ3: `src/core/engine/master_conductor.py` の `_notify_scn07_12_intervention()` を最小差分で更新し、日本語ラベル化を実装する。`scenario_id`、`route`、`gate_mode` はそのまま残す。
- [ ] ステップ4: 対象 pytest を再実行し、通知文面テストに加えて既存の route / `manual_deferred` / dedupe / `SCN11` 実行許可テストが green であることを確認する。`__new__` ベースの `MasterConductor` テスト経路で lazy attribute と dedupe が維持されることを確認する。
- [ ] ステップ5: notifier モックまたは dry-run 前提で、`bulk=True`、provider 未指定、既存 debug ログ維持の前提が崩れていないことを確認する。
- [ ] ステップ6: 実装完了後、作業報告書・作業ログ・台帳の必要更新を行い、docs validation で計画と成果物の整合を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] SCN07-12 通知だけ `MasterConductor` 直書きの文面組み立てが残るため、Finding 通知より i18n の責務が分散したままになる。 - 将来の通知テンプレート共通化タスクで formatter へ集約を検討する。
- [ ] [重要度:低] 今回は `SCN08-11` を優先対象とするが、実装関数は `SCN07-12` 共通のため周辺シナリオの文面も同時に変わる。 - 回帰テストで想定範囲を固定し、必要なら後続でシナリオ別微調整を行う。
- [ ] [重要度:低] Discord 以外の provider でも同じ本文が送られるため、Markdown 表示差分は残る。 - provider 非依存の表現に留め、表示最適化は別タスクで扱う。

## 6. 懸念点と対策

### 6.1 SRE / インフラエンジニア観点
- [ ] [発生確率:中][影響度:中] 文面変更後の送達性確認がテスト観点から漏れやすい。  
  対策: notifier モックまたは dry-run 相当の前提で、`bulk=True`・provider 未指定・通知呼び出し回数を検証するテストを維持する。
- [ ] [発生確率:中][影響度:大] Discord 以外の provider でも同じ本文が送られるため、文字種や改行で表示崩れが起きる可能性がある。  
  対策: プレーンテキスト互換と既存同等以下の長さを制約として明記し、ラベル変更だけで済ませる。
- [ ] [発生確率:低][影響度:中] 通知失敗時の既存 debug ログが変わると運用上の調査導線が分断される。  
  対策: 通知失敗時のログ文言と非致命挙動は不変とし、計画内の検証対象へ明記する。

### 6.2 ソフトウェアアーキテクト観点
- [ ] [発生確率:高][影響度:中] ゴールが `SCN08-11` でも実装関数は `SCN07-12` 共通であり、対象境界の誤解が起きやすい。  
  対策: 主対象と共通実装の関係をゴールで明示し、変更理由を計画書本文に残す。
- [ ] [発生確率:中][影響度:中] 最小差分のつもりで局所的な抽象化が増え、責務が中途半端に分散する可能性がある。  
  対策: 許可する構造変更を「同一関数内の定数整理まで」に限定し、新規モジュール追加を禁止する。
- [ ] [発生確率:中][影響度:小] `route` や `gate_mode` まで翻訳すると機械検索性が下がる。  
  対策: 英語値を保持し、表示ラベルのみ日本語化する制約を採用する。

### 6.3 デバッガー観点
- [ ] [発生確率:高][影響度:大] 文面テストが一部ラベルだけの確認に留まると、英語残りや崩れを見逃しやすい。  
  対策: 見出しから Required Action まで主要ラベルを期待値として固定する。
- [ ] [発生確率:中][影響度:中] `reasons` / `matched_signals` の入力揺れにより、日本語化後に境界ケースだけ崩れる可能性がある。  
  対策: 文字列・空配列・未指定のケースを追加し、通知文面が壊れないことをテストする。
- [ ] [発生確率:中][影響度:中] `MasterConductor.__new__` 経路の lazy attribute 初期化や dedupe が文面変更のついでに壊れる可能性がある。  
  対策: 既存の dedupe / SCN11 実行許可テストを必須回帰として再実行し、`_notified_scn07_12_keys` の挙動を守る。

### 6.4 CTO観点
- [ ] [発生確率:中][影響度:大] 「自然に読める」だけでは成功判定が主観的で、レビュー観点がぶれる。  
  対策: 運用判断に必要な 4 要素（シナリオ・対象・判定理由・次アクション）を明示的な達成条件にする。
- [ ] [発生確率:中][影響度:中] 非スコープが曖昧だと、周辺通知まで手を広げて差分が膨らむ。  
  対策: Finding 通知、`notify_action_required()`、CLI ログは非スコープと明記する。
- [ ] [発生確率:低][影響度:中] 継続監視の `tracking_task_id` を未起票のまま残すと、work_report 作成時に docs ルール違反へつながる。  
  対策: `deferred_tasks` の例には「追跡タスク起票後に実IDへ置換必須」と注記し、未起票のまま転記しない。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0327-D01
    title: "継続監視: SCN介入通知テンプレート共通化"
    reason: "今回は最小差分で本文だけを日本語化し、通知整形責務の分離までは行わない"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN  # work_report へ転記する前に、起票済みの実タスクIDへ必ず置換する
    recommended_next_action: "SCN07-12 介入通知を formatter 化する独立タスクを起票し、Finding 通知との共通化範囲を整理する"
```
