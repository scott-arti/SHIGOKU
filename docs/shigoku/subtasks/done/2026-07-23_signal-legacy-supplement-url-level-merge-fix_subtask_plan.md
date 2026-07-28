---
task_id: SGK-2026-0378
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0377
related_docs:
- docs/shigoku/subtasks/done/2026-07-23_sgk-2026-0377_signal-legacy-supplement-vulntest-guard.md
- docs/shigoku/reports/2026-07-23_sgk-2026-0378_signal-legacy-supplement-url-level-merge-fix_work_report.md
- docs/shigoku/worklogs/2026-07-23_sgk-2026-0378_signal-legacy-supplement-url-level-merge-fix_work_log.md
title: Signal legacy supplement URL-level merge fix
created_at: '2026-07-23'
updated_at: '2026-07-28'
tags:
- shigoku
target: src/core/engine/master_conductor.py
---

# 実装計画書：Signal legacy supplement URL-level merge fix

## 1. 達成したいゴール（ユーザー視点）
- [x] DVWA low のように signal-first が一部URLだけを拾う実行でも、同じカテゴリの `tagged_*` に残る未実行URLを攻撃タスクとして補強する。
- [x] 既に signal-first で実行済みのURLは重複タスク化しない。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/master_conductor.py`: signal-first 後の legacy tagged 補強をカテゴリ単位からURL単位へ変更。
  - `tests/core/engine/test_master_conductor_signal_recipe_routing.py`: 同カテゴリ内の漏れURLを再現する回帰テストを追加。
- **データの流れ / 依存関係:**
  - `_signal_bundle._endpoint_signals` -> 実行済みURLをカテゴリ別に記録 -> `tagged_*` JSONL読込時に実行済みURLだけ除外 -> 残URLを `master_conductor.recon.*` タスクとして補強。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `recon_results` (`dict`), `_signal_bundle` (`dict`), `tagged_*` JSONL (`file`)
- **出力/結果 (Output):** signal-first タスクに加えて、同カテゴリ内の未実行URLだけ legacy supplement タスクとして追加される。
- **制約・ルール:**
  - signal-first の重複抑止は維持する。
  - カテゴリ単位で legacy を丸ごと捨てない。
  - 実行済みURLは補強対象から除外し、同じURLの二重実行を避ける。
  - `vulntest` 実行は bugbounty compiled guard の判定に流さない既存方針を維持する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 2026-07-23 03:23:28 の report/session 整合性を確認し、49件の内訳を調査する。
- [x] ステップ2: signal-first 済みカテゴリで `tagged_*` の別URLが消える回帰テストを追加し、REDを確認する。
- [x] ステップ3: `MasterConductor._create_attack_tasks_from_recon()` で URL 単位の legacy supplement merge を実装する。
- [x] ステップ4: 対象テストと重複所有テストを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 83件時代との差分には、localhost/127.0.0.1 のalias重複や aggregate task の有無も含まれる。今回の修正は「同カテゴリの漏れURL復元」に限定し、完全に83件へ戻すことは目的外とする。
- [ ] [重要度:中] `tests/core/engine/test_master_conductor_scenario_probes.py` は既存の bugbounty guard 前提差分で複数失敗する。今回のURL補強修正とは別件として扱う。
