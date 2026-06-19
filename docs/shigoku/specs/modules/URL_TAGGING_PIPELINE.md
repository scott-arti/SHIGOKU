---
task_id: SGK-2026-0044
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# URL Tagging Pipeline

**現行モジュールパス**

- `src/core/intel/tagging_filter.py`
- 設定: `config/tagging_rules.yaml`

## 概要

URL Tagging Pipeline は HTTP entry をルールベースで分類し、認証コンテキストや evidence を抽出するフィルタ層です。

## 現行の主要構成

- `TaggingRule`
- `TaggingFilter`
- `main()`

## 現行仕様

- `config/tagging_rules.yaml` を必須入力として読む
- path / query / body / response body / headers / response headers を対象にタグ付けする
- 静的ファイル判定、URL 正規化、重複排除、auth header 抽出を行う
- pipeline の中心実装は `TaggingFilter` であり、旧文書の大規模 phase 図は canonical 仕様から外す

## 主な関連モジュール

- `src/tools/custom/caido_importer.py`
- `src/tools/custom/process_caido_logs.py`

## 注意点

- 旧仕様書にあった Katana / GAU / Httpx を含む「広義の URL discovery 全体像」は、このファイル単体の責務ではない
- 現行 spec では tagging 部分を中心に扱う
