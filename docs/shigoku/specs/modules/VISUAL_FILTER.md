---
task_id: SGK-2026-0045
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# VisualFilter

**現行状態**

- `src/core/intel/visual_filter.py` は存在しない

## 概要

旧ドキュメントでは OCR ベースの VisualFilter を想定していたが、現行コードベースには対応する standalone 実装ファイルがない。

## 現行仕様

- 専用モジュールとしての公開 API は存在しない
- `src/core/tool_registry.py` と `src/core/engine/mode_manager.py` には `visual_filter` 名の登録が残っている
- 旧仕様にあった OCR / entropy / page classifier の詳細は現行コードの canonical 仕様ではない

## 注意点

- この文書は「現行コードには standalone module がない」ことを示すために最小限残している
- 画像系の近縁実装としては `src/core/agents/specialized/visual_recon.py` があるが、旧 VisualFilter の直接置き換えとは見なさない
