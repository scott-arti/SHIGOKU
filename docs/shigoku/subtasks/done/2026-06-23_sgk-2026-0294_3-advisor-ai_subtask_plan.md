---
task_id: SGK-2026-0294
doc_type: subtask_plan
status: backlog
parent_task_id: SGK-2026-0293
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0293_vulnerability-management-review-trail_subtask_plan.md
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0287_task-queue-pruning-policy_subtask_plan.md
- docs/shigoku/subtasks/2026-06-21_sgk-2026-0286_agentic-rag-hypothesis-advisor_subtask_plan.md
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0292_ollama-removal-llm-config-unification_subtask_plan.md
- docs/shigoku/plans/2026-06-24_sgk-2026-0304_active_plan.md
title: 3判断器再設計とAdvisor AI戦略レビュー化 議論計画
created_at: '2026-06-23'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/engine/strategy_optimizer.py, src/core/intelligence/self_reflection.py,
  src/core/intelligence/task_prioritizer.py, src/core/engine/master_conductor.py,
  src/core/intelligence/
---

# 実装計画書：3判断器再設計とAdvisor AI戦略レビュー化 議論計画

> 2026-06-24 統合メモ: `SGK-2026-0304` で独立 `active` から外し、`SGK-2026-0293` の後段議題へ吸収した。`TargetSystemProfile` / `AttackReviewTrail` の正本設計が固まるまでは、本計画を単独 execution unit として扱わない。

## 1. 達成したいゴール（ユーザー視点）
- [ ] StrategyOptimizer / SelfReflection / TaskPrioritizer をばらばらの小さな判断器として扱うのではなく、ターゲット理解を参照する Advisor AI 型の戦略レビュー機構へ作り直す方針を議論できること。
- [ ] Advisor AI が定期的にタスクキューとターゲット理解をレビューし、タスクの間引き、優先度ブースト、シナリオ追加、タスク追加、MC の判断ミス指摘を行える設計にすること。
- [ ] ただし、実装は `TargetSystemProfile` / `AttackReviewTrail` などの脆弱性管理・ターゲット情報一元化がまとまった後に開始すること。
- [ ] ユーザーが「なぜ Advisor AI がその指摘・追加・間引きをしたのか」をレビューできること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/strategy_optimizer.py`: 現状のルールベース pruning / boosting を Advisor AI の戦略レビュー結果へ寄せる候補。
  - `src/core/intelligence/self_reflection.py`: 実行履歴の統計的省察を、AttackReviewTrail に書き込む人間可読の学習・反省へ寄せる候補。
  - `src/core/intelligence/task_prioritizer.py`: 粗い bandit 方式のタスク選択を、TargetSystemProfile / ScenarioCandidate 参照の補助スコアへ寄せる候補。
  - `src/core/engine/master_conductor.py`: Advisor AI の定期発火、提案採用/棄却、キュー操作、シナリオ追加、MC判断レビューの接続点。
  - `src/core/intelligence/`（新規候補）: `advisor_ai.py`, `strategic_review.py`, `advisor_models.py` などの集約先候補。
- **データの流れ / 依存関係:**
  - TaskResult / Finding / Swarm observation / decision trace -> TargetSystemProfile / AttackReviewTrail 更新。
  - TargetSystemProfile / AttackReviewTrail / TaskQueue snapshot / ScenarioCandidate -> Advisor AI review。
  - Advisor AI review -> prune candidates / priority boosts / scenario candidates / task drafts / MC critique。
  - 採用・棄却・保留の結果 -> AttackReviewTrail と session artifact に保存し、ユーザーが後から読めるようにする。

## 2.1 現状認識
- [ ] StrategyOptimizer は実装はあるが、実態はキーワード、静的拡張子、KG風 attack surface を見たルールベースの間引き・ブーストで、受け取っている LLM client は使っていない。
- [ ] SelfReflection は成功/失敗/blocked を記録し、成功率・繰り返しエラー・遅いタスクなどの洞察を作るが、ターゲットシステム理解や次シナリオ設計には十分つながっていない。
- [ ] TaskPrioritizer は `agent_type::vuln_hint` 単位の単純な ROI 学習であり、Finding が出たカテゴリを優先しやすくする補助としては使えるが、文脈理解は薄い。
- [ ] 3つとも「独自の小さな記憶やヒューリスティック」を持つため、ターゲット全体の理解、攻撃シナリオ、MC の判断レビューが分散している。

## 2.2 実装開始の前提条件
- [ ] `SGK-2026-0293` で議論する脆弱性管理・実行後レビュー設計がまとまり、少なくとも TargetSystemProfile / AttackReviewTrail の最小スキーマが決まっていること。
- [ ] Advisor AI が参照する正本は、時系列ログそのものではなく、ユーザーも読めるターゲット理解・機能理解・攻撃面・シナリオ候補であること。
- [ ] LLMモデル選択は `SGK-2026-0292` の LLM設定統一方針に従い、Advisor AI 用モデルを設定ファイルから選べるようにすること。
- [ ] 初期実装は shadow mode を持ち、Advisor AI の提案をいきなり実キューに反映せず、妥当性を観測できること。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** TargetSystemProfile、AttackReviewTrail、TaskQueue snapshot、ScenarioCandidate、Finding、recent failures、budget/scope/rate limit 状態、MC decision trace。
- **出力/結果 (Output):** AdvisorReview、PruneProposal、BoostProposal、ScenarioProposal、TaskDraft、MCCritique、採用/棄却理由。
- **制約・ルール:**
  - Advisor AI は MC を置き換える司令塔ではなく、MC のレビュー役・参謀役から始める。
  - 実キュー変更は初期状態では shadow mode。採用する場合も reason code と evidence を必須にする。
  - coverage guard、manual verification、scope validation、evidence collection は削除保護対象とする。
  - MC の判断ミス指摘は、批判だけではなく「根拠」「代替案」「次に検証すべきこと」をセットで出す。
  - AIの内部思考全文ではなく、観測、仮説、判断、提案、採用/棄却、結果を保存する。

## 3.1 議論したい設計論点
- [ ] Advisor AI の発火条件: Nタスクごと、Finding発生時、失敗連続時、TargetSystemProfile更新時、キュー肥大化時、MCが高リスク判断をした時。
- [ ] Advisor AI の権限: 提案のみ、shadow queue操作、低リスクboostのみ自動、pruneは手動承認、など段階をどう分けるか。
- [ ] 3判断器の扱い: 既存を薄いadapterとして残すか、Advisor AI の下位機能に統合するか、廃止して新規実装するか。
- [ ] レビュー粒度: タスク単位、シナリオ単位、ターゲット機能単位、攻撃チェイン単位のどれを主軸にするか。
- [ ] MCの判断ミス指摘: 見落とし、過剰実行、重複、低ROI継続、スコープ/証跡不足、仮説の偏りをどう検出するか。
- [ ] 人間向け表示: `advisor_review.md`、session JSON、Discord通知、CLIログのどこにどの粒度で出すか。

## 3.2 Advisor AI の想定ロール
- [ ] タスク間引き: 重複、不要化、低ROI、既に別シナリオで代替済みの未処理タスクを候補化する。
- [ ] 優先度ブースト: ターゲット理解上、重要機能・認証境界・入力点・高価値Findingに近いタスクを上げる。
- [ ] シナリオ追加: TargetSystemProfile から未検証の攻撃シナリオを提案する。
- [ ] タスク追加: シナリオを実行可能な TaskDraft に落とす。ただし最初はMCが採用判断する。
- [ ] MCレビュー: MCが見落としていそうな仮説、証跡不足、過剰な同一方向探索、危険な自動判断を指摘する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 議論フェーズ。3判断器の現状、残す機能、捨てる機能、Advisor AI に統合する機能を分類する。
- [ ] ステップ2: 依存フェーズ。`SGK-2026-0293` の TargetSystemProfile / AttackReviewTrail の最小スキーマを確定する。
- [ ] ステップ3: 契約設計。AdvisorReview、Proposal、MCCritique、TaskDraft のデータ構造と採用/棄却フローを決める。
- [ ] ステップ4: shadow mode 実装案を決める。まずは提案を保存・表示するだけにし、実キュー変更はしない。
- [ ] ステップ5: 段階的移行案を決める。StrategyOptimizer -> pruning/boost proposal、SelfReflection -> review trail insight、TaskPrioritizer -> profile-aware ranking 補助へ寄せる。
- [ ] ステップ6: 実装判断。脆弱性管理の一元化が完了してから、別実装タスクとして着手する。

## 4.1 完了条件
- [ ] Advisor AI が何を正本として読むかが決まっている。
- [ ] 3判断器を残す/統合する/廃止する方針が決まっている。
- [ ] Advisor AI の発火条件、出力、権限、shadow mode の扱いが決まっている。
- [ ] 脆弱性管理一元化が完了するまで実装を開始しない依存関係が明記されている。
- [ ] 次の実装タスクへ分割できる粒度のサブプラン候補が出ている。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 脆弱性管理の正本がないまま Advisor AI を作ると、また判断材料が散る - `SGK-2026-0293` の完了後に実装する。
- [ ] [重要度:高] Advisor AI が強すぎると MC の判断を壊す - 初期は shadow mode と提案保存に限定する。
- [ ] [重要度:中] 3判断器を急に消すと既存の挙動が変わる - adapter化または互換層を置いて段階的に移行する。
- [ ] [重要度:中] LLMコストが増える - 発火条件、要約済みprofile入力、安価モデル設定、review interval を設計する。
- [ ] [重要度:中] ユーザーが読めないレビューになる - `advisor_review.md` のような人間可読artifactを初期から完了条件に入れる。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0294-D01
    title: "継続監視: Advisor AI 提案の妥当性レビュー"
    reason: "初期実装では shadow mode で提案のみ保存し、実キュー変更の自動化は後続判断に回す"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "実セッションで advisor_review.md を確認し、prune/boost/task追加の自動化範囲を決める"
```
