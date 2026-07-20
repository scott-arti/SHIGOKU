---
task_id: SGK-2026-0340
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0320
related_docs:
- docs/shigoku/reports/2026-07-03_sgk-2026-0340_auto-report-bundle-cli-tail_work_report.md
- docs/shigoku/worklogs/2026-07-03_sgk-2026-0340_auto-report-bundle-cli-tail_work_log.md
- docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md
- docs/shigoku/manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md
title: 実行完了時の標準レポート自動生成とCLI末尾パス表示
created_at: '2026-07-03'
updated_at: '2026-07-21'
tags:
- shigoku
target: reporting/cli
---

# 実装計画書：実行完了時の標準レポート自動生成とCLI末尾パス表示

## 1. 達成したいゴール（ユーザー視点）
- [ ] `--target` / `--recon` / `--crawl` / `--analyze` / interactive bridge 経由の `--log` 実行が終わると、`reports/` 配下に `run_narrative.md`・`target_profile.md`・`haddix_report_*.md` が自動生成されること。
- [ ] CLI の末尾で、プロジェクトフォルダーと上記レポートの絶対パスが確認できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: 修正。session から標準レポート3点を束ねて生成する helper と、通常実行末尾の表示導線を追加する。
  - `tests/unit/main/test_main_auto_report_bundle.py`: 新規。自動生成 bundle と末尾表示の回帰テスト。
  - `tests/unit/main/test_main_report_haddix.py`: 修正。現在の gate 挙動に合わせて assertion を調整する。
  - `docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md`: 修正。手動 CLI は再生成/再確認用途であることを補足する。
  - `docs/shigoku/manuals/2026-07-02_sgk-2026-0338_operator-user-manual.md`: 修正。通常実行で自動生成される成果物と末尾ログ表示を追記する。
- **データの流れ / 依存関係:**
  - `latest session_*.json` -> formatter / Haddix generator / gate -> `workspace/projects/<target>/reports/`
  - `generated artifact paths` -> `print_step()` -> CLI 最終ログ

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** project target (`str`), latest saved session (`session_*.json`)
- **出力/結果 (Output):** `run_narrative.md`, `target_profile.md`, `haddix_report_*.md`, CLI末尾の絶対パス表示
- **制約・ルール:**
  - 既存の手動 `--report --format haddix` 挙動は壊さない。
  - 保存先は既存 project reports directory を使い、命名互換を保つ。
  - セッションが見つからない場合は自動生成を黙って偽装せず、skip/failure をログへ残す。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `src/main.py` に session -> report bundle helper を追加し、通常実行の後段から呼び出す。
- [x] ステップ2: `run_narrative.md` / `target_profile.md` / `haddix_report_*.md` が生成されるテストを追加する。
- [x] ステップ3: マニュアルを更新し、関連 pytest と実在 report consistency を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] 自動生成対象は現時点で標準3点のみ - `attack_paths.md/json` まで bundle 化する場合は別タスクで導線を拡張する

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0340-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
