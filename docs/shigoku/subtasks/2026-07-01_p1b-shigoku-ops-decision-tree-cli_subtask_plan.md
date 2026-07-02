---
task_id: SGK-2026-0334
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/plans/2026-06-29_sgk-2026-0320_recon-resume-visibility-conversational-ops_plan.md
- docs/shigoku/subtasks/2026-06-29_sgk-2026-0322_reconstate-completion-parallel-checkpoint-decision-tree_subtask_plan.md
- docs/shigoku/plans/done/2026-06-24_sgk-2026-0298_internal-behavior-visibility-governance_plan.md
- docs/shigoku/subtasks/done/2026-06-24_sgk-2026-0300_run-narrative-target-profile-markdown_subtask_plan.md
title: 'P1b: 判断ツリー可視化＋shigoku-ops decision-tree CLI'
created_at: '2026-07-01'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/reporting/, scripts/shigoku_ops_cli.py
---

# 実装計画書：P1b: 判断ツリー可視化＋shigoku-ops decision-tree CLI

## 1. 達成したいゴール（ユーザー視点）
- [ ] `shigoku-ops report decision-tree --session <path>` を実行すると、Recon→MC→Swarm入口→Report の判断と結果が、一次証拠由来の Markdown / Mermaid ツリーとして読める。
- [ ] 運用者が失敗ノード、重要判断、再開判断だけを絞り込んで見られ、中断後の再実行判断に使える。
- [ ] 巨大 session や親子リンク欠落があっても壊れず、縮約表示や degrade 表示で「読めるが推測しない」出力になる。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/decision_tree_formatter.py`: `run_ledger` / `decision_traces` / `task_execution_records` から判断ツリーを構築する formatter。
  - `src/reporting/`: 必要なら既存 reporting helper を再利用し、一次証拠抽出と redaction を共有する。
  - `scripts/shigoku_ops_cli.py`: `report decision-tree` サブコマンドと表示オプション。
- **データの流れ / 依存関係:**
  - `session_*.json` の `run_ledger` + `decision_traces` + `task_execution_records` -> formatter が親子関係を構築 -> Markdown / Mermaid と要約を生成
  - `shigoku-ops report decision-tree` -> session 読み込み -> formatter -> `decision_tree.md` または stdout 表示

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** session artifact (`run_ledger`, `decision_traces`, `task_execution_records`), 必要に応じて SGK-2026-0322 の checkpoint metadata
- **出力/結果 (Output):**
  - `decision_tree.md`（Mermaid `graph TD` + Markdown summary）
  - `--phase` / `--actor` / `--only-failures` などで絞り込んだ CLI 出力
  - 親子リンク欠落や情報不足時の degrade 表示（推定は `estimated` 明記）
- **制約・ルール:**
  - 一次証拠（session/ledger）由来のみを表示し、推定は `estimated` を明記する。
  - secret/PII は既存 redactor 後の値だけを出力する。
  - 巨大 session では phase/actor 畳み込みとノード上限で既定表示を抑制し、全文展開を既定にしない。
  - Swarm 内部の think ループ詳細までは扱わず、対象は `Recon→MC→Swarm入口→Report` の判断に限定する。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 判断ツリーの入力契約を整理し、`run_ledger` / `decision_traces` / `task_execution_records` のうち利用する必須フィールド、親子リンク規則、`estimated` 表記条件、ノード上限、退避表現を定義する。
- [ ] ステップ2: `decision_tree_formatter.py` を実装し、phase/actor グルーピング、親子関係（`parent_event_id` / `source_refs`）からのツリー構築、失敗ノード・重要判断・再開判断の優先表示を追加する。
- [ ] ステップ3: `scripts/shigoku_ops_cli.py` に `report decision-tree --session <path>` サブコマンドを追加し、`--phase`, `--actor`, `--only-failures`, `--max-nodes` の絞り込みと degrade 表示を接続する。
- [ ] ステップ4: targeted tests を追加し、正常系だけでなく親子リンク欠落、巨大 session の縮約、secret/PII redaction、`estimated` 表記、絞り込みオプションを検証する。
- [ ] ステップ5: 実 session artifact を使って `decision_tree.md` と CLI 出力を検証し、運用者が再実行判断に使える粒度で読めることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] 巨大 session はツリー全展開だと読めなくなる。phase/actor 畳み込みと `--only-failures` を既定運用に寄せる。
- [ ] [重要度:中] 親子リンクが不完全な古い session では、一部ノードが孤立表示になる。リンク補完は推測せず `estimated` / `unlinked` として退避する。
- [ ] [重要度:中] Swarm 内部の thought/action 詳細統合は本タスク外。詳細統合は SGK-2026-0293 系の設計に委ねる。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0334-D01
    title: "継続監視: Swarm内部判断ログの decision tree 統合"
    reason: "本タスクは Recon→MC→Swarm入口→Report に限定し、Swarm内部詳細は対象外"
    impact: medium
    tracking_task_id: SGK-2026-0293
    recommended_next_action: "SGK-2026-0293 系で execution trace の粒度と decision tree 連携契約を設計する"
```
