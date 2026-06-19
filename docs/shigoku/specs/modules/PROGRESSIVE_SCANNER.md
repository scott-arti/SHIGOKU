---
task_id: SGK-2026-0041
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# ProgressiveScanner

**現行モジュールパス**

- `src/core/wordlist/progressive_scanner.py`

## 概要

ProgressiveScanner は `small -> medium -> high` の順にワードリストサイズを切り替えながら、発見率で継続可否を判断する段階的スキャナです。

## 現行の主要構成

- `ScanResult`
- `ProgressiveScanConfig`
- `ProgressiveScanner`
- `create_progressive_scanner()`

## 現行仕様

- `WordlistManager.select()` でサイズ別ワードリストを選ぶ
- 現在の実ツール実装は主に `FfufTool` を前提にしている
- discovery rate を見て early termination を判断する

## 主要メソッド

- `scan()`
- `_select_wordlist()`
- `_execute_scan()`
- `_parse_ffuf_output()`
- `_should_continue()`

## 注意点

- 旧仕様書にあった HeadlessCrawler 連携説明は現行 spec から外した
- 現在は「段階的 wordlist scan helper」であり、統合 orchestrator ではない
