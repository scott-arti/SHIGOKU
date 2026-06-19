---
task_id: SGK-2026-0305
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0266
related_docs:
- docs/shigoku/plans/2026-06-05_cli-entrypoint-split-plan_plan.md
- docs/shigoku/specs/adr/001-entry-point-unification.md
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
title: 'CLI Entrypoint 追加分割計画: report/replay/quality-loop cluster'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/main.py
---

# 実装計画書：CLI Entrypoint 追加分割計画: report/replay/quality-loop cluster

## 1. 達成したいゴール（ユーザー視点）
- [x] `src/main.py` の CLI 入口互換を維持したまま、report / replay / deferred / focus-tests / quality-loop の残存 cluster を handler 単位へ外出しできること。
- [x] 既存の subcommand / option / help / exit code / JSON payload を変えず、`main()` を薄化して影響範囲を狭められること。
- [x] 現在 3,483 行の `src/main.py` を、最終的に 1,000 行未満、可能なら 900 行前後まで縮小し、分割先各ファイルも 1,000 行未満へ収めること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: （修正）互換 entrypoint。最終的に parser / preflight / dispatch のみに寄せる。
  - `src/cli/handlers/`: （新規 directory）report / replay / quality-loop / focus-tests / deferred checklist 系 handler の配置先。
  - `src/cli/handlers/report_haddix.py`: （新規）scenario catalog、coverage、heuristic findings、evidence artifact materialize を含む report 生成 cluster の分割先候補。
  - `src/cli/handlers/report_replay.py`: （新規）replay command build、session artifact selection、retry_failed / replay 系の分割先候補。
  - `src/cli/handlers/quality_loop.py`: （新規）quality loop command build、precheck artifact 書き込みの分割先候補。
  - `src/cli/handlers/focus_tests.py`: （新規）focus test path 解決、runtime path 解決、focused pytest 実行の分割先候補。
  - `src/cli/handlers/deferred_backlog.py`: （新規）deferred scenario resolve、status summarize、checklist markdown 生成の分割先候補。
  - `src/cli/commands.py`: （参照のみ）interactive CLI command registry であり、今回の `src/main.py` 分割とは混ぜない。
  - `tests/unit/main/test_main_report_haddix.py`: （既存）report haddix cluster の主要回帰。
  - `tests/unit/main/test_main_report_replay.py`: （既存）replay 系の主要回帰。
  - `tests/unit/main/test_main_focus_tests.py`: （既存）focus test / pytest invocation の主要回帰。
  - `tests/core/test_entry_points.py`: （既存）entrypoint 互換確認。
  - `tests/core/test_phase4_regression.py`: （既存）広めの CLI/phase4 退行確認。
- **データの流れ / 依存関係:**
  - CLI argv -> `main()` の parser / dispatch -> handler module -> report/session/filesystem/test runner -> stdout / JSON / artifact。

## 2.1 分割境界の基本方針
- `src/cli/handlers/` は新設してよいが、`src/main.py` 自体は削除せず互換 entrypoint として残す。
- top-level helper 群は実際の cluster に沿って外出しする。具体的には `focus-tests`、`quality-loop`、`report/haddix`、`replay/retry_failed`、`deferred/checklist` を第一候補とする。
- parser 定義の全面再設計は今回の主対象ではない。handler 抽出で `main()` を薄くすることを優先する。
- `src/cli/commands.py` の interactive command registry とは別文脈なので、今回の差分に混ぜない。
- shared helper が必要なら `src/cli/handlers/_shared.py` のような薄い補助を検討してよいが、最初から抽象化しすぎない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `argparse.Namespace`、report/session/file path、focus test group、custom tests、retry/replay 対象、quality-loop mode など CLI 引数一式
- **出力/結果 (Output):** 既存どおりの console output、JSON payload、artifact file、subprocess 実行、exit code
- **制約・ルール:**
  - 既存 subcommand、flag 名、help 文言、exit code、JSON field は互換維持を優先する。
  - `main()` は引き続き正規 entrypoint として残し、`python -m src.main` の利用を壊さないこと。
  - report/session/deferred path 選択ロジックは handler ごとに閉じ込めるが、primary source of truth の扱いは既存と同じにする。
  - focus test / quality loop の subprocess command 生成は変えすぎない。まずは外出しのみを目的とする。
  - 目安サイズ:
    - `src/main.py`: 900 行前後、遅くとも 1,000 行未満
    - `report_haddix.py`: 500-900 行
    - `report_replay.py`: 250-600 行
    - `quality_loop.py`: 150-350 行
    - `focus_tests.py`: 150-300 行
    - `deferred_backlog.py`: 200-450 行

## 3.1 先に固定する回帰観点
- report/haddix 回帰:
  - scenario coverage、heuristic findings merge、evidence artifact materialize。
- replay / retry_failed 回帰:
  - replay command build、artifact ordering、latest selection。
- focus-tests / quality-loop 回帰:
  - selected tests 解決、runtime path 解決、pytest command build、precheck artifact 生成。
- deferred backlog 回帰:
  - deferred scenario resolve、status normalize、checklist markdown 出力。
- entrypoint 回帰:
  - `main()` の引数 dispatch と exit code。

## 3.2 DeepSeek 向け実装ルール
- `main.py` の helper を cluster ごとに外へ出し、最初から parser 大改造や DTO 導入まで広げない。
- 追加 helper 名は既存関数名をなるべく維持し、git blame とテスト追跡性を落とさない。
- `main()` 本体の薄化は段階的に行い、1 patch で複数 cluster を同時に移しすぎない。
- report 系は artifact 選択ロジックが多いので、unit test を先に固定してから移す。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `src/main.py` の top-level helper と `main()` 内ブロックを棚卸しし、`focus-tests`、`quality-loop`、`report/haddix`、`replay`、`deferred/checklist` の5 cluster に分類する。
- [x] ステップ2: `tests/unit/main/test_main_report_haddix.py`、`tests/unit/main/test_main_report_replay.py`、`tests/unit/main/test_main_focus_tests.py`、`tests/core/test_entry_points.py` を確認し、cluster 抽出前に必要な characterization case が足りているかを判断する。
- [x] ステップ3: `_dedupe_keep_order`、focus test path 解決、focused pytest 実行 helper を `src/cli/handlers/focus_tests.py` へ抽出する。
- [x] ステップ4: quality loop command build と precheck artifact helper を `src/cli/handlers/quality_loop.py` へ抽出する。
- [x] ステップ5: scenario catalog、coverage build、heuristic findings merge、evidence artifact materialize など report/haddix cluster を `src/cli/handlers/report_haddix.py` へ抽出する。
- [x] ステップ6: replay command build、artifact order、latest session/report resolve など replay cluster を `src/cli/handlers/report_replay.py` へ抽出する。
- [x] ステップ7: deferred scenario resolve、status summarize、checklist markdown build を `src/cli/handlers/deferred_backlog.py` へ抽出する。
- [x] ステップ8: `main()` を parser / preflight / dispatch 中心に薄化し、`src/main.py` を 1,000 行未満へ縮小する。必要なら shared helper を最小限だけ追加する。
- [x] ステップ9: targeted tests と entrypoint tests を再実行し、help/JSON/exit code の互換が保たれていることを確認する。

## 4.1 推奨検証コマンド
```bash
.venv/bin/pytest tests/unit/main/test_main_report_haddix.py tests/unit/main/test_main_report_replay.py tests/unit/main/test_main_focus_tests.py tests/core/test_entry_points.py tests/core/test_phase4_regression.py -q
.venv/bin/python -m compileall src/main.py src/cli/handlers
```

## 4.2 完了条件
- `src/main.py` が 1,000 行未満まで縮小され、entrypoint と dispatch 中心の構成になっている。
- report / replay / focus-tests / quality-loop / deferred cluster が handler 単位へ外出しされている。
- 既存 subcommand / flag / help / exit code / JSON payload の互換が targeted tests で確認されている。
- `src/cli/commands.py` など今回対象外の interactive CLI へ不用意な変更が入っていない。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `main()` は artifact 選択と出力組み立ての暗黙依存が多く、handler 抽出時に subtle な差分が出やすい - report/replay 系の unit test を先に固定する。
- [ ] [重要度:中] `src/cli/handlers/` 新設により共有 helper の置き場所がぶれやすい - 初回は cluster 単位で素直に分け、抽象化は後回しにする。
- [ ] [重要度:中] parser 定義まで同時に大きく触ると差分が大きくなりすぎる - 今回は handler 抽出を主目的とし、parser 再設計は follow-up に回す。
- [ ] [重要度:中] `report_haddix.py` だけで再び 1,000 行近くまで膨らむ可能性がある - 必要なら後続で evidence helper と coverage helper に二段分割する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0305-D01
    title: "継続監視: CLI handler 分割後の help/JSON/exit code 互換"
    reason: "entrypoint を薄化しても CLI surface の回帰監視が継続して必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "代表 subcommand の smoke task を active で起票し、handler 追加時の回帰監視を継続する"
```
