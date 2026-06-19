---
task_id: SGK-2026-0035
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# CommitWatcher

**現行モジュールパス**

- `src/core/intel/commit_watcher.py`

## 概要

CommitWatcher は GitHub リポジトリ差分から secret / token / credential らしき情報を検出する intel モジュールです。

## 現行の主要構成

- `SecretPattern`
- `CommitInfo`
- `SecretFinding`
- `CommitWatcher`
- `get_commit_watcher()`

## 現行仕様

- GitHub API 経由で commit や diff を収集する
- secret pattern を評価して `Finding` 相当へ落とし込む
- tool registry と mode manager に登録されている
- デモ / watch コマンドから参照される

## 主な呼び出し元

- `src/commands/demo.py`
- `src/commands/watch.py`
- `src/core/tool_registry.py`

## 注意点

- 現行 `src/main.py` には `--watch` の実行分岐がない
- そのためモジュール自体は存在するが、標準 CLI 運用の主線にはいない
