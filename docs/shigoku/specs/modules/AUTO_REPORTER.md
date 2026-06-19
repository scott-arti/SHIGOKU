---
task_id: SGK-2026-0032
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# AutoReporter

**現行モジュールパス**

- `src/core/reports/auto_reporter.py`

## 概要

AutoReporter は `Finding` 群から Markdown ベースの報告書を生成するレポートモジュールです。主に Hybrid Hunt とデモ系コマンドで使われます。

## 現行の主要 API

- `class AutoReporter`
- `get_auto_reporter()`
- `generate_report_from_finding()`
- `export_findings_json()`

## 現行仕様

- `Finding` オブジェクトからレポート本文を組み立てる
- JSON エクスポートを提供する
- `src/core/reporting/` 配下の platform integration とは別レイヤー
- Haddix 形式の運用は主に `src/cli/handlers/report_haddix.py` 側が担当する

## 主な呼び出し元

- `src/commands/hunt.py`
- `src/commands/demo.py`
- `src/commands/watch.py`

## 注意点

- 旧仕様書にあった「重複チェック将来実装」などの計画記述は本仕様から除外
- 現行コードでは AutoReporter 単体が Bugcrowd/HackerOne API 送信を担うわけではない
