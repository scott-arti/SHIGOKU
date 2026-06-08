---
task_id: SGK-2026-0257
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0253
related_docs:
- docs/shigoku/subtasks/2026-06-02_program-overrides_subtask_plan.md
- docs/shigoku/reports/2026-06-03_sgk-2026-0253_program-overrides_work_report.md
title: SGK-2026-0253 技術的負債追跡（sample rules / schema test）
created_at: '2026-06-03'
updated_at: '2026-06-03'
tags:
- shigoku
target: attack-chain-rules-maintainability
---

# 実装計画書：SGK-2026-0253 技術的負債追跡（sample rules / schema test）

## 1. 達成したいゴール（ユーザー視点）
- [ ] `attack_chain_rules` に新しい rule や override を追加しても、schema 不整合や fallback 崩れを回帰テストで即座に検知できること。
- [ ] sample rules と schema test により、`chain_builder` / `master_conductor` の期待契約を変更前に検証できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `data/attack_chain_rules.json`: sample rules と schema 対象の正本
  - `src/core/intelligence/chain_builder.py`: rule / workflow / tactical policy 解決の互換維持対象
  - `src/core/engine/master_conductor.py`: runtime policy / rollout 判定の契約維持対象
  - `tests/core/intelligence/test_chain_builder.py`: schema mismatch / fallback / sample rule 検証
  - `tests/core/engine/test_master_conductor_phase1_step14.py`: precedence / rollout 契約の回帰検証
- **データの流れ / 依存関係:**
  - `attack_chain_rules` 更新 -> sample rules / schema test 実行 -> rule 解決 / policy 解決の回帰検知 -> 必要時は修正タスクへ分離

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `attack_chain_rules` の JSON データ、industry-specific rule、workflow template、program override、既存回帰テスト結果
- **出力/結果 (Output):** sample rules 定義、schema test、回帰検知結果、必要時の追加修正判断
- **制約・ルール:**
  - `SGK-2026-0253` の precedence と safety gate 契約は変更しない
  - 旧 JSON 形式互換と common fallback の挙動を壊さない
  - sample rules は common / industry / workflow / override の最小代表ケースを含む
  - schema test は required key 欠落、型不一致、unknown industry fallback、invalid override を最低限含む

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `data/attack_chain_rules.json` と既存テストを照合し、sample rules に含める common / industry / workflow / override の代表ケースと schema test の必須観点を固定する。
- [ ] ステップ2: `tests/core/intelligence/test_chain_builder.py` に sample rules / schema test を追加し、required key 欠落、型不一致、unknown industry fallback、invalid override、old-format compatibility を常設検証へ組み込む。
- [ ] ステップ3: `tests/core/engine/test_master_conductor_phase1_step14.py` と関連統合テストで、sample rules 変更後も precedence / rollout / audit 契約が維持されることを確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] sample rules の代表ケースが不足すると、実データ追加時の schema drift を取り逃す - common / industry / workflow / override の4系統を最低限維持し、追加 rule 導入時に代表ケースを見直す。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0257-D01
    title: "技術的負債追跡: sample rules / schema test"
    reason: "program overrides 本体は完了したが、保守性向上の追跡タスクが別途必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "sample rules と schema test の対象範囲を固定し、回帰テストへ段階追加する"
```
