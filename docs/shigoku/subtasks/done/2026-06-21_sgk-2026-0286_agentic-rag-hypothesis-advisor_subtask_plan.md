---
task_id: SGK-2026-0286
doc_type: subtask_plan
status: backlog
parent_task_id: SGK-2026-0262
related_docs:
- docs/shigoku/subtasks/2026-06-03_sgk-2026-0262_obsidian-rag-kg-recipe_subtask_plan.md
- docs/shigoku/roadmaps/2026-06-03_continuous-learning-architecture-reference.md
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/plans/2026-06-24_sgk-2026-0304_active_plan.md
title: Agentic RAG hypothesis advisor 組み込み計画
created_at: '2026-06-21'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/intelligence/agentic_rag.py, src/core/engine/master_conductor.py,
  src/core/intelligence/chain_builder.py, src/core/rag_module/
---

# 実装計画書：Agentic RAG hypothesis advisor 組み込み計画

> 2026-06-24 統合メモ: `SGK-2026-0304` で独立 `active` から外し、`SGK-2026-0262` execution bundle の後段設計付録として扱うことにした。`RAG/KG/Recipe` の責務整理完了前は本計画を単独着手しない。

## 1. 達成したいゴール（ユーザー視点）
- MC が runtime facts から本命仮説を作りつつ、RAG が探索漏れや既知パターンを補助する形で安全に仮説を広げられる。
- RAG が司令塔にならず、MC が `chain state` と `hypothesis set` を持ったままサブエージェントへ検証タスクを配分できる。
- `現在のタスクにない方法を試す` を、無秩序な寄り道ではなく `alternative hypothesis lane` として管理できる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/intelligence/agentic_rag.py`: RAG retrieve loop を `hypothesis advisor` 専用の出力へ再設計
  - `src/core/engine/master_conductor.py`: `chain state` / `hypothesis set` / lane 管理の正本
  - `src/core/intelligence/chain_builder.py`: runtime findings から chain / belief state を供給
  - `src/core/rag_module/`: RAG backend API 契約の統一対象
  - `tests/core/engine/`, `tests/core/intelligence/`: lane 制御、bias guard、fallback の回帰対象
- **データの流れ / 依存関係:**
  - Recon / Swarm findings -> `chain_builder` -> `belief_state` / chain candidates
  - `belief_state + current task + KG context` -> MC -> primary hypothesis 作成
  - MC query contract -> Agentic RAG -> `RAGHint[]` / `alternative hypotheses` / provenance
  - MC -> `hypothesis set` を優先度付きで管理 -> sub-agent へ検証タスク化
  - 検証結果 -> KG / LearningRepository / MC state に戻して hypothesis を昇格・降格・破棄

## 2.1 この計画の基本思想
- **司令塔は MC のまま**:
  - RAG やサブエージェントは「提案」や「検証」はするが、最終的に何を進めるかは MC が決める
- **RAG は仮説補助に限定**:
  - `RAG に出てきたから実行` を禁止し、`MC がすでに見えている chain / task を補強または補完する` 用途へ寄せる
- **探索レーンを分ける**:
  - `primary lane`: MC が runtime facts と chain state から作る本命仮説
  - `alternative lane`: RAG や AI proposal が補助的に出す別仮説
  - `counter-example lane`: 本命仮説を壊すための反証タスク

## 2.2 MC が持つべき state の具体像
- **chain state**
  - `goal`: 何を狙っているか。例: `auth bypass -> IDOR -> secret exposure`
  - `confirmed_steps`: 確認済みの前提や foothold
  - `missing_links`: 次に埋めるべき欠損
  - `belief_state`: `chain_builder` が返す runtime belief
  - `phase_constraints`: scope / auth / budget / HITL など
- **hypothesis set**
  - `hypothesis_id`
  - `lane_type`: `primary | alternative | counter_example`
  - `source`: `mc_runtime | rag_hint | chain_builder_ai | human_override`
  - `statement`: 仮説本文
  - `required_evidence`
  - `recommended_probe`
  - `priority`
  - `ttl`
  - `status`: `draft | queued | running | supported | disproved | parked`

## 2.3 いまの実装との差分
- `MasterConductor` は `current_attack_chain` と chain inference の芽を持つが、仮説集合を構造化してはいない
- `AgenticRAGFeedbackLoop` は現在 `retrieve -> 自己採点 -> query改善` が中心で、MC へ返す出力契約が薄い
- `_dispatch` 付近の Agentic RAG 呼び出しは `initial context` 寄りで、lane 制御や hypothesis 管理に接続されていない
- つまり今は `RAGを呼ぶ` はあるが、`RAGの知見を司令塔がどう使うか` が未設計

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - runtime findings / KG context / current task / chain_builder belief state
  - RAG corpus（Obsidian / writeups / notes）
  - scope / auth / budget / HITL 制約
- **出力/結果 (Output):**
  - `RAGHint[]`: `checklist`, `similar_case`, `caution`, `strategy`, `alternative_hypothesis`
  - `HypothesisSet`: lane 付き仮説集合
  - `TaskDraft[]`: MC が実際に sub-agent へ渡す検証タスク
  - provenance / decision trace / suppression reason
- **制約・ルール:**
  - RAG は runtime fact の正本にならない
  - RAG は gating しない。`RAG に根拠がないから却下` を禁止する
  - `alternative lane` は常に `primary lane` より低優先で、scope / budget に余力があるときだけ走らせる
  - `counter-example lane` を必ず残し、本命仮説への過信を防ぐ
  - raw chunk をそのまま sub-agent に渡さず、MC が正規化した hint と provenance だけを渡す

## 3.1 Agentic RAG の新しい返却契約
- `RAGHint`
  - `hint_type`: `checklist | similar_case | caution | strategy | alternative_hypothesis`
  - `summary`
  - `reason`
  - `confidence`
  - `query_lineage`
  - `provenance`
- `HypothesisExpansion`
  - `statement`
  - `why_now`
  - `required_evidence`
  - `recommended_probe`
  - `expected_cost`
  - `lane_type=alternative`
- `BiasGuardNote`
  - `fp_risk`
  - `known_failure_mode`
  - `do_not_overfit_reason`

## 3.2 MC に入れるべき制御ロジック
- **Trigger**
  - primary hypothesis だけでは次の一手が弱い
  - chain builder が `missing_evidence` を返した
  - 同じカテゴリで失敗が続き、別観点が必要
  - auth / workflow / multi-step 系で blind spot が多い
- **Do not trigger**
  - scope / budget が逼迫
  - critical finding 発生で report 優先
  - task が deterministic verification フェーズに入っている
- **Task synthesis**
  - MC が `primary lane tasks` をまず生成
  - その後に `alternative lane tasks` を 1-2 件だけ追加
  - `counter-example lane` で本命仮説の破綻確認も混ぜる

## 3.3 具体例
- 例1: OAuth callback が見えた
  - primary lane: callback validation, state check, redirect_uri strictness
  - alternative lane: token exchange trust boundary, fragment leakage, mobile deep-link abuse
  - counter-example lane: callback only で token exchange は無関係という仮説の検証
- 例2: IDOR っぽい numeric object が見えた
  - primary lane: object A/B access diff
  - alternative lane: bulk endpoint, export API, secondary identifier, cached object view
  - counter-example lane: 単なる listing bug で object ownership enforcement は効いている仮説

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `agentic_rag.py`, `master_conductor.py`, `chain_builder.py`, `rag_module` の API 契約差を整理し、`retrieve/query` と返却型を一本化する
- [ ] ステップ2: `RAGHint`, `HypothesisExpansion`, `BiasGuardNote`, `HypothesisSet` のデータ構造を定義する
- [ ] ステップ3: MC に `chain state` / `hypothesis set` / `lane manager` を追加し、`primary / alternative / counter-example` の優先順位制御を設計する
- [ ] ステップ4: Agentic RAG の出力を `initial context` ではなく `hypothesis expansion` として返すよう再設計する
- [ ] ステップ5: sub-agent への handoff 契約を定義し、`task + hypothesis + required_evidence + provenance` を渡す形式へ整える
- [ ] ステップ6: fallback / bias guard / budget guard の回帰テスト観点を固定する

## 4.1 実装順の推奨
- Phase A: 契約統一
  - `retrieve` / `query` 差分解消
  - RAG 返却型の正規化
- Phase B: MC state 化
  - hypothesis registry
  - lane priority
  - state transition
- Phase C: task synthesis
  - hypothesis -> task draft
  - counter-example lane
- Phase D: guardrails
  - budget cap
  - novelty budget
  - false-positive caution

## 4.2 この計画で何ができるようになるか
- 「今の task にない方法も試す」が、ただの寄り道ではなく管理された別レーンになる
- MC が一連の攻撃意図を失わず、同時に探索漏れを減らせる
- RAG が本命仮説を乗っ取らず、補助的に発想を広げるだけの安全な位置に収まる

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `retrieve` / `query` API 契約差が残ると組み込み以前に壊れやすい - Phase A で最優先解消する
- [ ] [重要度:高] RAG を task 生成の主役にすると writeup bias が強くなる - `primary lane` の正本は runtime facts に固定する
- [ ] [重要度:中] hypothesis set を増やしすぎると MC が過負荷になる - lane ごとの上限件数と TTL を入れる
- [ ] [重要度:中] counter-example lane を省くと「それっぽい仮説」に引っ張られる - 反証タスクを最低1本入れる運用にする

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0286-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
