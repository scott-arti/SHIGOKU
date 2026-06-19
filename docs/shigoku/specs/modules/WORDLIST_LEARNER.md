---
task_id: SGK-2026-0046
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# WordlistLearner

**現行モジュールパス**

- `src/core/wordlist/wordlist_learner.py`

## 概要

WordlistLearner は発見済み URL から path / subdomain / query parameter を収集し、`wordlists/custom/` に再利用用ファイルを書き出す学習モジュールです。

## 現行の主要構成

- `WordlistLearner`
- `get_wordlist_learner()`

## 現行仕様

- `add_url()` と `add_urls()` で収集する
- 数値のみ、UUID 風、長い hex などを `_is_dynamic()` で除外する
- 保存先は `discovered_paths.txt` `discovered_subdomains.txt` `discovered_params.txt`
- 既存ファイルと統合して重複排除する

## 主要メソッド

- `add_url()`
- `add_urls()`
- `save_wordlist()`
- `save_all()`
- `get_stats()`
- `clear()`

## 注意点

- 旧仕様書にあった HeadlessCrawler 連携説明は削除した
- 現在の責務は「収集済み URL からの軽量学習」に限定される
