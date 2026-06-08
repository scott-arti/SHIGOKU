---
task_id: SGK-2026-0063
doc_type: work_report
status: done
parent_task_id: SGK-2026-0065
related_docs:
- docs/shigoku/plans/2026-05-14_ssti_docs/shigoku/plans/file_upload_implementation_plan_legacy.md
- docs/shigoku/worklogs/2026-05-14_log_codex_chat_summary.md
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# REPORT Outputs Reference

`python -m src.main --report` の出力内容を、運用時に確認しやすいように整理したページです。

---

## 1. 基本コマンド

```bash
# 直近セッションのテキストサマリー
python -m src.main --report

# プロジェクト指定（有効な最新セッションを自動選択）
python -m src.main --report --target <project_name>

# Haddix markdown レポート生成
python -m src.main --report --format haddix --target <project_name>

# HTML レポート生成
python -m src.main --report --format html --target <project_name>
```

---

## 2. 出力フォーマット別の要点

| `--format` | 出力先 | 主な用途 |
| :-- | :-- | :-- |
| 未指定（text） | コンソール | 実行結果の短い振り返り |
| `haddix` | `workspace/projects/<project>/reports/haddix_report_*.md` | 提出・共有用 Markdown |
| `html` | HTML ファイル（生成後にパス表示） | ブラウザ確認用 |

---

## 3. Text サマリーで確認できる項目

`src/commands/report.py` の `ExecutionSummary` で、主に以下を表示します。

- タスク総数 / 成功 / 失敗
- タスク単位の Action と Result 概要
- Injection 系の補足メモ（存在時）
  - `tested_params`
  - `blind_correlation` 要約
  - `AuthZ differential` 要約
  - `Timeout KPI` 要約

> 注: 長い `result.data` は表示幅の都合で短縮されますが、補足メモ行は優先して残る設計です。

---

## 4. Haddix レポートで確認できる項目

`--format haddix` は `src/reporting/haddix_formatter.py` を通して Markdown を生成します。

### Finding 単位

- 脆弱性サマリー（severity / vuln_type / 対象URL）
- Blind evidence（time-based / OOB）
- AuthZ differential（存在時）
  - `scenario`
  - `confidence`
  - `signals`
  - 再現手順向け `original_id` / `test_id`
  - `baseline_status` / `test_status`

### Injection Execution Notes

- 実行ログ由来の URL 別メモ
- セッション KPI（集計）
  - `total`
  - `completed`
  - `timeout`
  - `error`
  - `timeout_rate`
  - `avg_retry`

---

## 5. 期待値チェック（運用向け）

最小確認として、以下 2 点が出力されるかを見ると回帰を検知しやすくなります。

1. AuthZ differential の行に `scenario` と `signals` が出る
2. KPI 行に `avg_retry` を含む

この 2 点は現在、ユニットテストでも固定化されています。
