---
task_id: SGK-2026-0266
doc_type: plan
status: active
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/ARCHITECTURE.md
- docs/shigoku/specs/adr/001-entry-point-unification.md
title: '巨大ファイル分割計画 3/4: CLI Entrypoint 分割'
created_at: '2026-06-05'
updated_at: '2026-06-08'
tags:
- shigoku
target: src/main.py
---

# 実装計画書：巨大ファイル分割計画 3/4: CLI Entrypoint 分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] この文書が「4件中の3件目」であることが明確であり、`src/main.py` の分岐過密を崩す順序が共有されていること。
- [ ] `python -m src.main` の入口互換を維持したまま、parser 構築と handler 実装を分離できること。
- [ ] deferred / HITL / report / mission 実行系を別 handler に逃がし、CLI 変更時の副作用範囲を縮小できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/main.py`: （修正）互換エントリポイント。最終的に parser 初期化と dispatch だけに縮小する対象。
  - `src/cli/parser.py`: （新規）argument parser と group 定義を保持する分割先候補。
  - `src/cli/handlers/reporting.py`: （新規）report / replay / deferred backlog 系 handler を保持する分割先候補。
  - `src/cli/handlers/hitl.py`: （新規）HITL / resume / session 選択系 handler を保持する分割先候補。
  - `src/cli/handlers/mission.py`: （新規）target / recon / log / interactive の通常実行 handler を保持する分割先候補。
- **データの流れ / 依存関係:**
  - CLI argv -> parser builder -> selected handler -> project/session/report services -> stdout / JSON output

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `argparse.Namespace`、CLI flags、target/scope/session/report path
- **出力/結果 (Output):** 既存と同じ CLI exit path、console output、JSON payload、report artifact selection
- **制約・ルール:**
  - 既存オプション名、help text、JSON 出力形式、終了コードは互換維持を優先する。
  - `src/main.py` は削除せず、既存 import / 実行パスの shim として残す。
  - file/session/report の選択ロジックは handler ごとに閉じ込め、cross-cutting helper は `src/cli/` 配下へ寄せる。

## 4. 実装ステップ（AIに指示する手順）
- [ ] 手順1/4: `main()` の責務を parser 構築、preflight、handler dispatch に分類し、引数群と handler 群の切断面を決める。
- [ ] 手順2/4: parser 定義を `src/cli/parser.py` へ抽出し、既存の flag 名と help の互換性を壊さないように移設する。
- [ ] 手順3/4: deferred / HITL / report / mission 実行ブロックを handler へ移し、`src/main.py` は handler dispatch だけに縮小する。
- [ ] 手順4/4: `tests/unit/main/test_main_report_haddix.py`、`tests/core/test_main_hitl_session_selection.py`、focused CLI 回帰を実行し、出力互換と target selection を確認する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- [ ] [重要度:高] `main.py` は report/session/path 選択の暗黙依存が多く、handler 分割時に出力差分が発生しやすい。 - 互換テストを先に固定する。
- [ ] [重要度:中] `argparse.Namespace` をそのまま横流しすると handler 境界が曖昧なまま残る。 - handler 入力 DTO を後続タスクで検討する。
- [ ] [重要度:中] parser と business logic の両方が `settings` を直接見る箇所が残ると再肥大化しやすい。 - preflight helper へ寄せる。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0266-D01
    title: "継続監視: CLI 分割後の出力互換監視"
    reason: "分割後も help / JSON / session selection の互換監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
