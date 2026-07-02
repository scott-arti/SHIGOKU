---
task_id: SGK-2026-0337
doc_type: plan
status: done
parent_task_id: SGK-2026-0001
related_docs:
- docs/shigoku/README.md
- docs/shigoku/manuals/REFERENCE.md
- docs/shigoku/manuals/USER_MANUAL.md
- docs/shigoku/manuals/QUICK_START.md
- docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md
- docs/shigoku/reports/2026-07-02_sgk-2026-0337_work_report.md
- docs/shigoku/worklogs/2026-07-02_sgk-2026-0337_work_log.md
title: SHIGOKU 詳細コマンドリファレンス整備
created_at: '2026-07-02'
updated_at: '2026-07-02'
tags:
- shigoku
target: shigoku-ops / src.main CLI
---

# 実装計画書：SHIGOKU 詳細コマンドリファレンス整備

## 1. 達成したいゴール（ユーザー視点）
- [ ] `shigoku-ops` と `src.main` のどちらを使うべきかが迷わず判断できること。
- [ ] report / session / validate / recon state の運用コマンドを、実装に存在する引数名のまま参照できること。
- [ ] 旧 `REFERENCE.md` / `USER_MANUAL.md` / `QUICK_START.md` から詳細版へ辿れること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `scripts/shigoku_ops_cli.py`: （参照）`shigoku-ops` の正本 CLI 定義。
  - `src/main.py`: （参照）実行系 CLI の正本エントリポイント。
  - `docs/shigoku/manuals/2026-07-02_sgk-2026-0337_detailed-command-reference.md`: （新規）詳細版コマンドリファレンス。
  - `docs/shigoku/manuals/REFERENCE.md`: （修正）詳細版への導線追加。
  - `docs/shigoku/manuals/USER_MANUAL.md`: （修正）CLI 節から詳細版への誘導。
  - `docs/shigoku/manuals/QUICK_START.md`: （修正）次のステップへ詳細版を追加。
- **データの流れ / 依存関係:**
  - `scripts/shigoku_ops_cli.py` / `src/main.py` -> help / argparse 定義確認 -> 詳細版 manual へ集約 -> 既存 manual からリンク。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `shigoku-ops --help` 群、`python -m src.main --help`、既存 manuals。
- **出力/結果 (Output):** `docs/shigoku/manuals/` 配下の詳細版 command reference と既存 manual からの導線。
- **制約・ルール:**
  - SHIGOKU ドキュメントは `docs/shigoku/` 配下に作成する。
  - report / session / validate 系は `shigoku-ops` を優先し、旧 CLI と混同しない記述にする。
  - 実装に存在しないコマンドや引数名を創作せず、`argparse` 定義と `--help` 出力で照合する。
  - 最後に `sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` を実行する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: 既存 manual、`scripts/shigoku_ops_cli.py`、`src/main.py` を確認して対象コマンド群を棚卸しする。
- [x] ステップ2: `docs/shigoku/manuals/` に詳細版コマンドリファレンスを新規作成し、`shigoku-ops` と `src.main` の使い分けを整理する。
- [x] ステップ3: `REFERENCE.md`、`USER_MANUAL.md`、`QUICK_START.md` に詳細版への導線を追加する。
- [x] ステップ4: `work_report` / `work_log` を作成し、plan クローズと台帳更新を行う。
- [x] ステップ5: `sync_shigoku_updated_at.py` と `validate_shigoku_docs.py` を実行し、整合性を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:中] `src.main` のヘルプ項目数が多く、今後追加コマンドが増えると manual の手同期コストが上がる。将来的には help 生成物から docs を半自動生成する余地がある。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0337-D01
    title: "CLI help 生成物からの command reference 半自動更新"
    reason: "手書き manual は CLI 追加時に乖離しやすい"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "`argparse` help を収集して docs へ流し込む補助スクリプトを検討する"
```
