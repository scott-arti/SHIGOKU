---
task_id: SGK-2026-0290
doc_type: work_report
status: done
parent_task_id: SGK-2026-0266
related_docs:
  - docs/shigoku/subtasks/2026-06-22_sgk-2026-0290_cli-japanese-localization_subtask_plan.md
  - docs/shigoku/plans/2026-06-05_sgk-2026-0266_cli-entrypoint-split-plan_plan.md
title: CLI日本語化 作業完了報告書
created_at: '2026-06-22'
updated_at: '2026-06-30'
tags:
  - shigoku
  - localization
  - cli
---

# 作業完了報告書：CLI日本語化設計計画 (SGK-2026-0290)

## 1. 実装概要
CLIのユーザー向け表示を日本語化するため、`src/cli/messages.py` をメッセージ集約の正本として作成し、既存の全ユーザー向け文面（~400箇所）を `msg()` 呼び出しに一元化した。

### 実装したファイル
| ファイル | 変更内容 | msg()呼び出し数 |
|---|---|---|
| `src/cli/messages.py` | **新規作成**: 390キーの日本語メッセージカタログ | — |
| `src/main.py` | argparse help/error、print系出力をmsg()化 | 175 |
| `src/cli/cli.py` | REPLインターフェース（welcome/error/goodbye） | 10 |
| `src/cli/commands.py` | 18コマンドハンドラーの文面をmsg()化 | 159 |
| `src/cli/graph.py` | 実行グラフ表示の文面をmsg()化 | 10 |
| `src/cli/monitoring_dashboard.py` | ダッシュボード表/パネルをmsg()化 | 36 |
| `src/core/logger.py` | `show_tree()` デフォルトタイトルのみ変更 | 1 |
| `tests/test_cli_localization.py` | **新規作成**: 20件の focused test | — |

**合計:** ~390 メッセージキー、~390 箇所の `msg()` 呼び出し

### メッセージキー命名規約
```
module.category.specific_id
例: argparse.log.help, cmd.dalfox.vulns_found, dashboard.semaphore_title
```

## 2. 完了条件（DoD）達成状況

| 完了条件 | 状態 |
|---|---|
| `--help` の主要説明文と主要オプション help が日本語で読める | ✅ 全70オプション日本語化 |
| interactive CLI の `/help`, `/mode`, `/sessions`, `/resume` など主要案内が日本語 | ✅ 全18コマンド日本語化 |
| 主要な標準出力メッセージ（成功、失敗、注意、次の操作ヒント）が日本語化 | ✅ print_step/print_result/print 全175箇所を置換 |
| JSON出力モードでキー構造を壊さず、機械処理互換を維持 | ✅ JSONキーは未変更 |
| focused test が追加される | ✅ 20件追加 |
| `--translate-logs` を使わなくてもCLI日本語化が成立 | ✅ 本実装は同オプション非依存 |
| 内部 logger の英語ログ、event key、log level が変わらず | ✅ stdlib logging は未改変 |
| `--help`、interactive `/help`、主要エラーパス、deferred/HITL/resume案内で日本語化対象が確認 | ✅ 確認済み |
| 80-100桁程度の端末幅でも主要status/panel/tableタイトルが過度に崩れない | ✅ Richマークアップは既存のまま、日本語文面は端末幅を考慮した短さ |
| 主要フローで初見ユーザーが次の操作を判断できる案内文 | ✅ `/help` 出力やヒント文を維持 |

## 3. Phase GO/NO-GO 判定

### Phase 1 GO 条件（達成）
- ✅ message resolver経由への集約方針成立
- ✅ `--help` の日本語化完了
- ✅ JSON非汚染
- ✅ 内部logger互換維持
- ✅ 主要識別子（オプション名、パス、task_id等）の英数字保持

### Phase 2 GO 条件（達成）
- ✅ interactive `/help` と主要エラーパスが presentation 層のみの変更で日本語化
- ✅ 文面直書きの再増殖なし
- ✅ focused test で回帰切り分け可能

## 4. テスト結果

```
tests/test_cli.py:                  6 passed, 4 failed (pre-existing readline issue)
tests/test_cli_localization.py:    20 passed
─────────────────────────────────────────
Total:                             26 passed, 4 failed (all pre-existing)
```

### 新規テストの内訳
- メッセージカタログ整合性（6件）: 全キーの解決、重複なし、必須キー存在確認
- 日本語コンテンツ検証（1件）: 主要キーに日本語文字が含まれること
- --help出力統合テスト（2件）: 実サブプロセスによる日本語出力確認
- JSON非汚染（2件）: メッセージキーとJSONキーの分離確認
- 内部ロガー互換性（2件）: stdlib logging への日本語混入がないこと
- パーサーエラーメッセージ（2件）: 日本語化されたエラーメッセージ確認
- メッセージフォーマット機能（5件）: フォーマット引数処理、欠落キーハンドリング

## 5. 既知のリスクと判断理由

| リスク | 判断 |
|---|---|
| `src/main.py` は巨大ファイルのまま | 親タスク SGK-2026-0266 の分割計画と競合しないよう、文言置換のみに留めた |
| 将来的な `ja/en` 切替 | メッセージキー命名規約を先に固定し、`_MESSAGES_EN` 辞書の追加で対応可能 |
| Rich装飾つき文面の翻訳品質 | 各翻訳は元のRichマークアップを保持し、装飾崩れを防止 |
| 通知文面の日本語化 | スコープ外と明示。別タスクで `src/core/notifications/` 側を扱う |

## 6. deferred_tasks

```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0290-D01
    title: "継続監視: CLI多言語化の本格対応 (ja/en切替)"
    reason: "初期スコープでは日本語正本の提供を優先し、ja/en切替や message catalog 化は後続で進める"
    impact: medium
    recommended_next_action: "日本語化完了後に言語切替方式と未対応メッセージの棚卸しを行い、追跡サブタスクを起票する"

  - deferred_id: SGK-2026-0290-D02
    title: "継続監視: 通知文面の日本語化"
    reason: "本タスクスコープ外。src/core/notifications/ 側の日本語化は別タスク"
    impact: low
    recommended_next_action: "Discord通知日本語化タスク (SGK-2026-0286) との連携を検討"

  - deferred_id: SGK-2026-0290-D03
    title: "継続監視: master_conductor.py 内の summary_table 文面"
    reason: "Phase 3 スコープ外（ドメインロジックファイルへの翻訳分岐持ち込みを回避するため）。logger.py 自体の変更は完了"
    impact: medium
    recommended_next_action: "SGK-2026-0266（CLI分割）完了後、handler 側で msg() 経由にする"
```

## 7. 変更ファイル一覧

```
新規:
  src/cli/messages.py
  tests/test_cli_localization.py

修正:
  src/main.py
  src/cli/cli.py
  src/cli/commands.py
  src/cli/graph.py
  src/cli/monitoring_dashboard.py
  src/core/logger.py
```
