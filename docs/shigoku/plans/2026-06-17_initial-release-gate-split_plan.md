---
task_id: SGK-2026-0304
doc_type: plan
doc_usage: implementation_plan
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/roadmaps/IMPLEMENTATION_ROADMAP.md
- docs/shigoku/specs/2026-05-31_sgk-2026-0219_non-scn-evaluation-spec.md
- docs/shigoku/plans/superpowers/2026-05-14-required-class-hybrid-gate.md
title: '巨大ファイル分割計画: Initial Release Gate 分割'
created_at: '2026-06-17'
updated_at: '2026-06-18'
tags:
- shigoku
target: src/reporting/initial_release_gate.py
---

# 実装計画書：巨大ファイル分割計画: Initial Release Gate 分割

## 1. 達成したいゴール（ユーザー視点）
- [ ] `src/reporting/initial_release_gate.py` の公開 API と CLI 入口を維持したまま、policy / session summary / baseline / actions の責務を分割できること。
- [ ] `evaluate_initial_release_gate()`、`set_locked_baseline()`、`DEFAULT_ALLOWED_MISSING_SCENARIOS`、`DEFAULT_REQUIRED_CONFIRMED_CLASSES` の公開挙動を変えず、`scripts/shigoku_ops_cli.py` や `report_loop` 系からの利用を壊さないこと。
- [ ] 現在 1,632 行の file を、facade 300-500 行、分割先 200-700 行目安に整理し、report/session consistency と gate 判定を今後個別に変更しやすくすること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/reporting/initial_release_gate.py`: （修正）公開 API と orchestration を保持する facade。
  - `src/reporting/initial_release_gate_policy.py`: （新規）allowed-missing、required class、schema severity など policy 正規化・note 生成を保持する候補。
  - `src/reporting/initial_release_gate_session.py`: （新規）session coverage、findings summary、detection class、schema severity summary を保持する候補。
  - `src/reporting/initial_release_gate_baseline.py`: （新規）baseline lock、baseline diff、finding class diff を保持する候補。
  - `src/reporting/initial_release_gate_actions.py`: （新規）recommended actions、deferred scenarios、human-readable note 生成を保持する候補。
  - `src/reporting/report_session_consistency.py`: （参照のみ）consistency checker は既存の primary source of truth を維持する前提で利用する。
  - `src/reporting/report_loop_orchestrator.py`: （参照のみ）gate 呼び出し元の互換確認対象。
  - `scripts/shigoku_ops_cli.py`: （参照のみ）`report consistency` / `report gate` サブコマンドの入口互換確認対象。
  - `tests/unit/reporting/test_initial_release_gate.py`: （既存）主要な gate 回帰テスト群。
  - `tests/unit/reporting/test_report_session_consistency.py`: （既存）consistency checker の前提を固定するテスト群。
  - `tests/unit/reporting/test_haddix_formatter_kpi.py`: （既存）formatter 側から見た gate section の回帰確認。
  - `tests/unit/scripts/test_shigoku_ops_cli.py`: （既存）CLI surface の回帰確認。
- **データの流れ / 依存関係:**
  - report path / optional session path -> consistency checker -> session/report summaries + baseline diff + policy evaluation -> gate verdict / actions / CLI payload。

## 2.1 分割境界の基本方針
- `initial_release_gate.py` は公開 API と orchestrator に留め、pure helper を sibling module に平置きで移す。
- session/report の読み出し・正規化と、人間向け action 文章生成を同じファイルに置かない。
- baseline lock と diff 計算は独立 module に寄せ、gate 判定ロジック本体から切り離す。
- consistency checker 自体は `src/reporting/report_session_consistency.py` を正本とし、今回のタスクで再実装しない。
- CLI routing は `shigoku-ops` / `scripts/shigoku_ops_cli.py` を正本とし、`initial_release_gate.py` 側で CLI 仕様を持ち込まない。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** `haddix_report_*.md` path、optional `session_*.json` path、allowed missing list、required detection classes、schema severity policy、optional baseline report/session path
- **出力/結果 (Output):** pass/fail verdict、report metrics、required class evaluation、baseline context/diff、recommended actions、CLI-friendly payload
- **制約・ルール:**
  - `evaluate_initial_release_gate()` と `set_locked_baseline()` は引き続き `src.reporting.initial_release_gate` から import できること。
  - report path はその turn の primary source of truth とし、consistency checker の利用順序を変えないこと。
  - report-only backfill と raw session evidence を混同しないこと。既存の required class / raw summary 判定は維持する。
  - `scripts/shigoku_ops_cli.py` の `report consistency`、`report gate`、`report loop` 入口の引数仕様を壊さないこと。
  - 実アーティファクト検証が可能な場合は、unit test だけでなく consistency checker と gate 実行もセットで行うこと。
  - 目安サイズ:
    - `initial_release_gate.py`: 300-500 行
    - `initial_release_gate_policy.py`: 150-300 行
    - `initial_release_gate_session.py`: 250-500 行
    - `initial_release_gate_baseline.py`: 200-400 行
    - `initial_release_gate_actions.py`: 250-450 行

## 3.1 先に固定する回帰観点
- import / CLI 回帰:
  - `scripts/shigoku_ops_cli.py` からの constants / function import。
  - `report_loop_orchestrator.py` 経由の gate 実行。
- logic 回帰:
  - required detection class 判定。
  - session raw findings summary を使う threshold 判定。
  - schema severity enforcement mode。
  - baseline lock / baseline diff。
  - recommended actions と deferred scenarios の生成。
- artifact consistency 回帰:
  - 実 report がある場合は `verify_report_session_consistency` の verdict を変えず、その後に gate を評価できること。

## 3.2 DeepSeek 向け実装ルール
- `tests/unit/reporting/test_initial_release_gate.py` を RED/GREEN の主軸にし、helper 抽出だけで logic を変えない。
- real report path が用意できる場合は、unit test の後に `shigoku-ops report consistency` と `shigoku-ops report gate` で実アーティファクト確認を行う。
- policy / session / baseline / actions を 1ファイルずつ抽出し、1 patch で複数責務をまたがない。
- consistency checker は別 file を正本として維持し、今回の分割で `initial_release_gate.py` 内に複製を増やさない。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: `initial_release_gate.py` の top-level helper を棚卸しし、policy、session summary、baseline、actions の4 clusterへ分類する。公開 API と constants を facade に残す前提を明確化する。
- [ ] ステップ2: `tests/unit/reporting/test_initial_release_gate.py`、`tests/unit/reporting/test_report_session_consistency.py`、`tests/unit/reporting/test_haddix_formatter_kpi.py`、`tests/unit/scripts/test_shigoku_ops_cli.py` の relevant case を確認し、不足する import/CLI parity があれば最小追加する。
- [ ] ステップ3: `_normalize_tokens`、required class 系、policy note 系 helper を `initial_release_gate_policy.py` へ抽出し、`DEFAULT_*` constants と併せて facade から再公開する。
- [ ] ステップ4: session coverage / findings / detection class / schema severity summary helper を `initial_release_gate_session.py` へ抽出し、session 由来の raw data 取り扱いを一箇所へ寄せる。
- [ ] ステップ5: baseline lock / load / write / diff helper を `initial_release_gate_baseline.py` へ抽出し、`set_locked_baseline()` と `evaluate_initial_release_gate()` から利用する。
- [ ] ステップ6: `_build_recommended_actions` と deferred scenario 生成を `initial_release_gate_actions.py` へ抽出し、人間向け message 生成の責務をまとめる。
- [ ] ステップ7: `initial_release_gate.py` を orchestrator 中心に薄化し、公開 API / constants / re-export だけが残る形へ整理する。
- [ ] ステップ8: unit tests を再実行し、実 report path があれば consistency -> gate の順で実アーティファクト検証を行う。

## 4.1 推奨検証コマンド
```bash
.venv/bin/pytest tests/unit/reporting/test_initial_release_gate.py tests/unit/reporting/test_report_session_consistency.py tests/unit/reporting/test_haddix_formatter_kpi.py tests/unit/scripts/test_shigoku_ops_cli.py -q
.venv/bin/shigoku-ops report consistency --report <absolute-report-path>
.venv/bin/shigoku-ops report gate --report <absolute-report-path>
```

`shigoku-ops` 解決が難しい場合の fallback:
```bash
python3 scripts/shigoku_ops_cli.py report consistency --report <absolute-report-path>
python3 scripts/shigoku_ops_cli.py report gate --report <absolute-report-path>
```

## 4.2 完了条件
- `initial_release_gate.py` が公開 API と orchestration 中心に縮小され、1,632 行から 300-500 行程度まで薄くなっている。
- `evaluate_initial_release_gate()`、`set_locked_baseline()`、`DEFAULT_*` constants の import path が維持されている。
- gate 関連 unit tests と CLI unit tests が通る。
- 実 report path がある場合、consistency checker と gate evaluation の両方で分割前後の verdict が一致している。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] report/session consistency と gate logic の境界が近く、責務分離のつもりで判定差分を入れてしまう危険がある - real artifact を使った consistency -> gate の実行順を固定する。
- [ ] [重要度:高] `scripts/shigoku_ops_cli.py` から constants と function を直接 import しているため、移設時の re-export 漏れで CLI が即死しやすい - import parity を unit test と compile で先に固定する。
- [ ] [重要度:中] recommended actions は文章組み立てが多く、純粋な helper 分割でも出力文言差分が出る可能性がある - formatter / CLI tests で文字列回帰を確認する。
- [ ] [重要度:中] baseline lock は file I/O を含むため、helper 抽出時に path 依存の subtle bug が入りやすい - baseline 専用 helper に閉じ込めて責務を明確化する。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0304-D01
    title: "継続監視: report consistency と gate verdict の実アーティファクト回帰"
    reason: "分割後も report/session primary source of truth の取り扱いに回帰が入りやすい"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "代表 report を固定した回帰 task を active で起票し、consistency -> gate の順で継続監視する"
```
