---
task_id: SGK-2026-0267
doc_type: plan
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/dynamic_recon_attack.md
title: '巨大ファイル分割計画 4/4: ReconPipeline 分割'
created_at: '2026-06-05'
updated_at: '2026-06-30'
tags:
- shigoku
target: src/recon/pipeline.py
---

# 実装計画書：巨大ファイル分割計画 4/4: ReconPipeline 分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] この文書が「4件中の4件目」であることが明確であり、`src/recon/pipeline.py` の分割優先順が整理されていること。
- [ ] `ReconState` と step 実行順を維持したまま、step orchestration と重い処理ロジックを分離できること。
- [ ] URL discovery、tagged file promotion、task generation、MC handoff を別責務へ移し、step 単位で変更しやすい構造にできること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/recon/pipeline.py`: （修正）step orchestration 本体。最終的に pipeline coordinator のみに縮小する対象。
  - `src/recon/steps/url_discovery.py`: （新規）`step3b_hybrid_url_discovery` と周辺 helper を保持する分割先候補。
  - `src/recon/tagged_candidate_promotion.py`: （新規）uncategorized promotion、history replay seed、candidate scoring を保持する分割先候補。
  - `src/recon/task_generation.py`: （新規）`_generate_tasks_for_tagged_urls` と category-to-task mapping を保持する分割先候補。
  - `src/recon/mc_handoff.py`: （新規）step8 handoff と phase-gate 向け payload 変換を保持する分割先候補。
- **データの流れ / 依存関係:**
  - target / live_subs -> step modules -> tagged files / classified artifacts -> task generation / MC handoff -> project artifacts / attack queue

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** target、`ReconState`、live subdomains、tagged/history files、MasterConductor context
- **出力/結果 (Output):** `ReconState` 更新、step artifacts、tagged candidate tasks、MC handoff payload
- **制約・ルール:**
  - `run(target, start_step, end_step)` の公開挙動と `ReconState` の保存形式は互換維持を優先する。
  - step 間で共有する I/O パス命名規則は変えず、分割後も既存 artifact reader を壊さない。
  - `master_conductor` 連携は adapter 境界に閉じ込め、pipeline 本体から MC 実装詳細を減らす。

## 4. 実装ステップ（AIに指示する手順）
- [ ] 手順1/4: step ごとの責務を整理し、`step3b_hybrid_url_discovery`、promotion、task generation、MC handoff を最優先分割対象として固定する。
- [ ] 手順2/4: URL discovery と tagged candidate promotion を `steps/url_discovery.py` と `tagged_candidate_promotion.py` へ切り出し、artifact 形式と件数差分を確認する。
- [ ] 手順3/4: task generation と MC handoff を `task_generation.py` / `mc_handoff.py` へ分け、pipeline は step orchestration と state 更新に限定する。
- [ ] 手順4/4: `tests/recon/test_tagged_uncategorized_promotion.py` と recon 関連 focused 回帰を実行し、step 範囲指定と tagged output の互換を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] pipeline は file artifact と state 更新が強く結び付いており、抽出順を誤ると途中再開が壊れやすい。 - `ReconState` と file naming を先に固定する。
- [ ] [重要度:中] task generation の category mapping は MC 側と暗黙結合している。 - handoff adapter を挟んで結合点を一箇所にする。
- [ ] [重要度:中] step3b の外部ツール連携は I/O と parsing が混在している。 - discovery module で parse 層と exec 層を分ける。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0267-D01
    title: "継続監視: ReconPipeline 分割後の artifact 互換監視"
    reason: "分割後も step artifact と task handoff の互換監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
