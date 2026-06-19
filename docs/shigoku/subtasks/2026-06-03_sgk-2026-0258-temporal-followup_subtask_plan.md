---
task_id: SGK-2026-0258
doc_type: subtask_plan
doc_usage: execution_plan
status: active
parent_task_id: SGK-2026-0254
related_docs:
- docs/shigoku/subtasks/2026-06-02_task_subtask_plan.md
- docs/shigoku/reports/2026-06-03_sgk-2026-0254_temporal-state_work_report.md
title: SGK-2026-0258 継続監視（temporal metadata / benchmark / reason code 安定化）
created_at: '2026-06-03'
updated_at: '2026-06-03'
tags:
- shigoku
target: chain-temporal-followup
---

# 実装計画書：SGK-2026-0258 継続監視（temporal metadata / benchmark / reason code 安定化）

## 1. 達成したいゴール（ユーザー視点）
- [ ] temporal 制約導入後も metadata 欠損率、representative session 回帰、reason code 分類が継続的に観測され、説明不能な劣化を早期検知できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `docs/shigoku/reports/2026-06-03_sgk-2026-0254_temporal-state_work_report.md`: 完了時点の基準値と deferred task の起点
  - `docs/shigoku/subtasks/2026-06-02_task_subtask_plan.md`: temporal 制約の正本仕様
  - `src/core/intelligence/chain_builder.py`: temporal metadata 判定と reason code 分類の観測対象
  - `src/core/engine/master_conductor.py`: shadow metric / audit record / stale version 制御の観測対象
- **データの流れ / 依存関係:**
  - benchmark/session review -> metadata/reason/audit 観測 -> 継続監視レビュー -> 追加修正要否判定

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** metadata 欠損率、`draft` / `blocked` 降格率、representative session 回帰結果、reason code 分布、audit 完全性
- **出力/結果 (Output):** 継続監視レビュー結果、追加修正要否、別修正タスク起票要否
- **制約・ルール:**
  - `SGK-2026-0254` の実装済み public behavior は巻き戻さず、監視結果に応じて別タスクで修正判断する
  - `deferred_tasks` に記録した4項目は、このタスクで集約管理する
  - 新規の修正が必要な場合は、本監視タスク配下で追加タスクを分離起票する

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: metadata 欠損率と `draft` / `blocked` 降格率の継続観測方法を固定し、基準値との差分レビューを記録する。
- [ ] ステップ2: representative session / benchmark 回帰セットを定期確認し、再現性が弱いケースを棚卸しする。
- [ ] ステップ3: temporal reason code の分類粒度を監視し、切り分けに不足があれば別修正タスクを起票する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:中] metadata 欠損率が入力ソース依存で変動する場合、`draft` 比率だけでは品質解釈が難しい。
- [ ] [重要度:中] representative session にしか出ない temporal 差分は通常 benchmark では捉えにくい。
- [ ] [重要度:中] reason code が増えると集計軸が粗いままでは説明可能性が下がる。

