---
task_id: SGK-2026-0039
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# HeadlessCrawler

**現行状態**

- `src/core/intel/headless_crawler.py` は存在しない

## 概要

旧ドキュメントでは standalone の HeadlessCrawler モジュールを前提にしていたが、現行コードベースには対応実装ファイルがない。

## 現行仕様

- 専用モジュールとしての公開 API は存在しない
- `src/core/tool_registry.py` と `src/core/engine/mode_manager.py` には `headless_crawler` 名の登録が残っている
- ただし、実ファイル不在のため、この spec で旧機能詳細を canonical 仕様として扱わない

## 注意点

- この文書は「現時点で standalone 実装がない」ことを示すために残している
- 旧仕様書にあった headless browse / Playwright 連携の詳細は削除した
