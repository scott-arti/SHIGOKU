---
task_id: SGK-2026-0047
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# WordlistManager

**現行モジュールパス**

- `src/core/wordlist/wordlist_manager.py`

## 概要

WordlistManager は metadata ベースでワードリスト群を管理し、purpose / mode / strategy / source を使って適切な候補を返すモジュールです。

## 現行の主要構成

- `WordlistInfo`
- `WordlistManager`
- `get_wordlist_manager()`

## 現行仕様

- `wordlists/<purpose>/metadata.yaml` を読む
- `purpose` `mode` `strategy` `sources` `tech_stack` によって候補を絞る
- strategy は `quick / standard / deep` を想定
- `learn_params()` で学習済みパラメータも保持できる

## 主要メソッド

- `select()`
- `list_available()`
- `get_summary()`
- `learn_params()`
- `get_fuzzing_wordlist()`

## 注意点

- 旧仕様書にあった外部ソース比較表は実装保証ではないため省略
- 現在は metadata 依存の selector として理解するのが正確
