---
task_id: SGK-2026-0282
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/specs/bug_bounty_enhancements.md
- docs/shigoku/roadmaps/bug_bounty_enhancements_2026.md
title: Bug Bounty向けScope制御高度化計画
created_at: '2026-06-21'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/security/, src/core/engine/master_conductor.py, src/commands/
---

# 実装計画書：Bug Bounty向けScope制御高度化計画

## 1. 達成したいゴール（ユーザー視点）
- Bug Bounty モードで scope を読み込むと、どこまで調査・攻撃してよいかが実行前に明確になる。
- `in/out of scope` だけでなく、`post-exploit可否`、`host横断可否`、`攻撃種別制限`、`予算制限` を MC が判断材料として扱える。
- 実行中に scope 逸脱や予算超過が起きたら、危険なタスクだけ止めて安全に report 側へ退避できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/security/ethics_guard.py`: 現在の URL / path / rate limit ガード。本計画では action policy 拡張の中心
  - `src/core/security/scope_parser.py`: YAML / text から `ScopeDefinition` を構築する入口
  - `src/core/engine/master_conductor.py`: task 生成・post exploit 起動・停止判断の最終責任者
  - `src/commands/recon.py`, `src/commands/hunt.py`: scope 読み込みの CLI 入口
  - `src/core/reporting/evidence_collector.py`: 証拠採取時の scope 強度と整合を取る接続候補
- **データの流れ / 依存関係:**
  - `scope.yaml / program text` -> `ScopeParser` -> `ScopeDefinition`
  - `ScopeDefinition` -> `EthicsGuard` で URL / path / rate limit 判定
  - `ScopeDefinition + runtime budget + task metadata` -> `MasterConductor` で dispatch 可否決定
  - 判定結果 -> audit / report / operator 通知

## 3. 具体的な仕様と制約条件
- **現状整理:**
  - 現在の `EthicsGuard` は `in_scope_domains / out_of_scope_domains / out_of_scope_paths / max_requests_per_minute / allow_post_exploit` を扱える。
  - `MasterConductor._trigger_post_exploit()` は Bug Bounty モードかつ `allow_post_exploit=False` のとき post exploit 系 task を止める。
  - まだ `host横断`, `攻撃種別`, `予算`, `phase` 単位の制御は構造化されていない。
- **入力情報 (Input):**
  - プログラムスコープ文面または YAML
  - 実行モード、request budget、time budget
  - task 属性: target host, auth要否, attack class, post exploit性
- **出力/結果 (Output):**
  - `allow / block / requires_hitl / degrade_to_report`
  - reason code (`out_of_scope`, `cross_host_blocked`, `attack_class_denied`, `budget_exceeded` など)
  - 監査・通知向け decision trace
- **制約・ルール:**
  - MC中心設計を維持し、Swarm 側で独自に scope policy を拡張解釈しない
  - Bug Bounty モードでは判定不能時に fail-open しない
  - `allow_post_exploit` だけでなく「何をどこまで止めるか」を task metadata で表現できるようにする
  - 既存の `EthicsGuard.check_scope()` 利用箇所との後方互換を保つ

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `ScopeDefinition` と task metadata の棚卸しを行い、`host横断`, `attack_class`, `budget`, `phase`, `auth_required` の表現スキーマを定義する
- [ ] ステップ2: `ScopeParser` の出力と `EthicsGuard` の判定 API を拡張し、URL判定だけでなく task 可否も返せる policy evaluator 案を作る
- [ ] ステップ3: `MasterConductor` の task 追加・post exploit 起動・report退避条件へ policy evaluator を接続する設計をまとめる
- [ ] ステップ4: Bug Bounty 向け優先ルールを固定する。例: `post exploit禁止`, `cross-host pivot禁止`, `高リスク action は HITL`, `budget超過で report移行`
- [ ] ステップ5: unit test / integration test / dry-run 検証観点を列挙する

## 4.1 この計画で作るもの
- `ScopePolicy` 相当の構造化ルール
- task metadata と policy の照合仕様
- `block / allow / requires_hitl / degrade` の状態遷移表
- Bug Bounty 用デフォルトポリシー

## 4.2 これで何ができるようになるか
- いまは `URLがscope内か` と `post exploit丸ごと可否` が中心だが、将来は「同一ホスト内の read-only 確認だけ許可」「他ホスト pivot は禁止」など粒度の細かい制御ができる
- 高リスクの action だけ止めて Recon / 報告作成を継続できる
- report に「なぜ止めたか」を一貫した reason code で残せる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] policy を細かくしすぎると operator が理解しづらい - Bug Bounty 用プリセットを先に作る
- [ ] [重要度:中] task metadata が薄いままだと判定精度が出ない - MC / Swarm 間 task schema 整理を前提条件にする
- [ ] [重要度:中] `EthicsGuard` と report 側の evidence scope が別々に進化すると説明が食い違う - reason code と audit 項目を共通化する

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
