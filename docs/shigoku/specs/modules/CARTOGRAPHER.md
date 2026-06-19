---
task_id: SGK-2026-0034
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# Cartographer

**現行モジュールパス**

- `src/core/intel/cartographer.py`

## 概要

Cartographer はサイトマップ生成と URL 発見を担当する偵察モジュールです。Knowledge Graph と Master Conductor の両方から参照されます。

## 現行の主要構成

- `SiteNode`
- `SiteMap`
- `Cartographer`

## 現行仕様

- URL を辿ってサイト構造を収集する
- `src/commands/recon.py` から直接利用できる
- `src/core/infra/knowledge_graph.py` で `SiteNode` を取り込む
- Master Conductor dispatch service からも呼び出し対象になる

## 主な呼び出し元

- `src/commands/recon.py`
- `src/core/engine/master_conductor_dispatch_service.py`
- `src/core/infra/knowledge_graph.py`

## 注意点

- 旧仕様書にあった BFS/DFS の詳細設計は、現行コードの公開仕様としては保証しない
- 現在の CLI 主入口は `src/main.py` であり、単独 recon コマンドは補助的立ち位置
