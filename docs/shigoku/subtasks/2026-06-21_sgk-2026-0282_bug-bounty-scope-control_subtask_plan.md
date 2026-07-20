---
task_id: SGK-2026-0282
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/subtasks/done/2026-06-21_sgk-2026-0284_phasegate-fine-grained_subtask_plan.md
- docs/shigoku/subtasks/2026-06-20_sgk-2026-0281_recon-resume-recipe-phasegate_subtask_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: Bug Bounty向けScope・PhaseGate実行制御統合計画
created_at: '2026-06-21'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/security/, src/core/engine/phase_gate.py,
  src/core/engine/master_conductor.py, src/core/engine/recipe_loader.py,
  src/commands/
---

# 実装計画書：Bug Bounty向けScope・PhaseGate実行制御統合計画

> 2026-07-17 統合メモ: `SGK-2026-0284` を独立 `active` から外し、本計画を Bug Bounty 向け scope policy と PhaseGate 細粒度制御の正本計画に統合した。`EthicsGuard` の fail-closed 判定と `MasterConductor` の段階的 task 解放を同じ execution unit として設計する。

## 1. 達成したいゴール（ユーザー視点）
- Bug Bounty モードで scope を読み込むと、どこまで調査・攻撃してよいかが実行前に明確になる。
- `in/out of scope` だけでなく、`post-exploit可否`、`host横断可否`、`攻撃種別制限`、`auth要否`、`予算制限` を MC が判断材料として扱える。
- Recon 完了後に Attack をまとめて全開放するのではなく、得られた signal に応じて必要なタスクだけ順に解放できる。
- scope 逸脱、予算超過、critical finding、HITL pending が起きたら、危険なタスクだけ止めて安全に report 側へ退避できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/security/ethics_guard.py`: 現在の URL / path / rate limit ガード。本計画では action policy 拡張の中心
  - `src/core/security/scope_parser.py`: YAML / text から `ScopeDefinition` を構築する入口
  - `src/core/engine/phase_gate.py`: 現在は coarse-grained な unlock 判定が中心。今後は capability gate と runtime stop reason の集約先
  - `src/core/engine/master_conductor.py`: task 生成・post exploit 起動・段階的解放・停止判断の最終責任者
  - `src/core/engine/recipe_loader.py`: Recon / recipe 選抜と gate 解放条件を接続する候補
  - `src/commands/recon.py`, `src/commands/hunt.py`: scope 読み込みの CLI 入口
  - `src/core/reporting/evidence_collector.py`: 証拠採取時の scope 強度と整合を取る接続候補
- **データの流れ / 依存関係:**
  - `scope.yaml / program text` -> `ScopeParser` -> `ScopeDefinition`
  - `ScopeDefinition` -> `EthicsGuard` で URL / path / rate limit / action policy 判定
  - Recon 結果 (`assets`, `tech_stack`, `classified_files`) + `ScopeDefinition` + task metadata -> `PhaseGate`
  - `PhaseGate verdict` + runtime budget / auth / HITL / critical finding -> `MasterConductor` で dispatch / defer / route-to-report 決定
  - 判定結果 -> audit / report / operator 通知

## 3. 具体的な仕様と制約条件
- **現状整理:**
  - 現在の `EthicsGuard` は `in_scope_domains / out_of_scope_domains / out_of_scope_paths / max_requests_per_minute / allow_post_exploit` を扱える。
  - `MasterConductor._trigger_post_exploit()` は Bug Bounty モードかつ `allow_post_exploit=False` のとき post exploit 系 task を止める。
  - `PhaseGate.can_create_task()` は実質 `phase が unlocked か` しか見ておらず、`MasterConductor` は Recon 成果が1つでもあれば `ATTACK` を unlock し得る。
  - まだ `host横断`, `攻撃種別`, `auth要否`, `予算`, `phase/capability` 単位の制御は構造化されていない。
- **入力情報 (Input):**
  - プログラムスコープ文面または YAML
  - 実行モード、request budget、time budget
  - Recon の分類結果 / tech / assets
  - task 属性: target host, auth要否, attack class, post exploit性, risk
  - runtime signals: `scope_violation`, `budget_exceeded`, `critical finding`, `pending_hitl`
- **出力/結果 (Output):**
  - `allow / block / requires_hitl / degrade_to_report / defer / lock_phase / unlock_subset`
  - reason code (`out_of_scope`, `cross_host_blocked`, `attack_class_denied`, `budget_exceeded`, `critical_finding`, `pending_hitl` など)
  - 監査・通知向け decision trace
- **制約・ルール:**
  - MC中心設計を維持し、Swarm 側で独自に scope policy を拡張解釈しない
  - MC中心設計を維持し、Swarm 間で勝手に unlock / lock を決めない
  - Bug Bounty モードでは判定不能時に fail-open しない
  - `PhaseGate` は司令塔の代替ではなく、司令塔の判断材料と停止機構として使う
  - `allow_post_exploit` だけでなく「何をどこまで止めるか」を task metadata と capability gate で表現できるようにする
  - phase を増やしすぎず、まずは `ATTACK` 内サブレベルまたは capability gate で表現する
  - 既存の `EthicsGuard.check_scope()` 利用箇所との後方互換を保つ

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `ScopeDefinition`、Recon 出力、task metadata、現行 `PhaseGate` の unlock 条件を棚卸しし、`host横断`, `attack_class`, `budget`, `phase/capability`, `auth_required`, `risk` の共通スキーマを定義する
- [ ] ステップ2: `ScopeParser` の出力、`EthicsGuard` の判定 API、`PhaseGate` の verdict をつなぐ共有 policy evaluator 案を作り、URL判定だけでなく task 可否と gate reason を返せる契約を定義する
- [ ] ステップ3: `Attack 全開放` をやめ、`public_attack`, `auth_attack`, `high_risk_attack`, `report_priority` などの細粒度 gate を定義し、`unlock_subset`, `defer`, `lock_phase`, `route_to_report` の意味を固定する
- [ ] ステップ4: `MasterConductor` の task 追加・post exploit 起動・report退避条件へ policy evaluator / PhaseGate を接続し、`scope_violation`, `budget_exceeded`, `critical finding`, `pending_hitl` の状態遷移表を作る
- [ ] ステップ5: Bug Bounty 向け優先ルールと検証観点を固定する。例: `post exploit禁止`, `cross-host pivot禁止`, `高リスク action は HITL`, `budget超過で report移行`, `critical finding で report優先`

## 4.1 統合後にこの計画で扱うもの
- `ScopePolicy` 相当の構造化ルール
- task metadata / recon signal / gate verdict の共通契約
- `block / allow / requires_hitl / degrade / defer / unlock_subset` の状態遷移表
- Bug Bounty 用デフォルトポリシーと PhaseGate capability 定義
- `SGK-2026-0335` / `SGK-2026-0336` のような実装寄り子タスクをぶら下げる親計画

## 4.2 これで何ができるようになるか
- いまは `URLがscope内か` と `post exploit丸ごと可否`、Recon 後の coarse unlock が中心だが、将来は「同一ホスト内の read-only 確認だけ許可」「他ホスト pivot は禁止」「認証が揃うまで auth attack を defer」のような粒度の細かい制御ができる
- 高リスクの action だけ止めて Recon / 報告作成を継続できる
- report に「なぜ止めたか」「どの gate で止めたか」を一貫した reason code で残せる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] policy を細かくしすぎると operator が理解しづらい - Bug Bounty 用プリセットを先に作る
- [ ] [重要度:高] task metadata が薄いままだと判定精度も gate 精度も出ない - MC / Swarm 間 task schema 整理を前提条件にする
- [ ] [重要度:中] `EthicsGuard` と `PhaseGate` の責務が曖昧だと二重判定になる - `scopeは可否`, `gateは進行制御` の線引きを明文化する
- [ ] [重要度:中] `EthicsGuard` と report 側の evidence scope が別々に進化すると説明が食い違う - reason code と audit 項目を共通化する
- [ ] [重要度:中] Recipe / pruning / gate を別々に先行実装すると境界が再び分散する - `SGK-2026-0281` / `SGK-2026-0287` との接続順を先に固定する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0282-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
