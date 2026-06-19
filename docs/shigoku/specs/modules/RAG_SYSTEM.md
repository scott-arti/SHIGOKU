---
task_id: SGK-2026-0043
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# RAG System

**現行モジュールパス**

- facade: `src/core/rag_module/rag.py`
- 実装分割:
  - `src/core/rag_module/rag_types.py`
  - `src/core/rag_module/rag_pdf_ingester.py`
  - `src/core/rag_module/rag_ingester.py`
  - `src/core/rag_module/rag_switch.py`
  - `src/core/rag_module/rag_policy.py`
  - `src/core/rag_module/rag_feedback.py`

## 概要

RAG System は Markdown / PDF を取り込み、ChromaDB ベースの検索と利用ポリシー制御を行うナレッジ層です。

## 現行の主要構成

- `RAGDocument`
- `RAGResult`
- `PDFIngester`
- `KnowledgeIngester`
- `RAGSwitch`
- `get_rag_switch()`
- `init_rag()`
- `RAGUsageDecision`
- `check_rag_usage_budget()`

## 現行仕様

- `src/core/rag_module/rag.py` 自体は facade
- CLI 入口は `src/commands/rag.py`
- PDF 取り込み、query、stats、switch、usage policy が分離済み
- RAG feedback / provenance / budget 系型が追加されている

## 主な呼び出し元

- `src/commands/rag.py`
- `src/commands/hunt.py`

## 注意点

- 旧仕様書の `src/core/rag.py` 前提は現行コードと一致しない
- 現在は split module 構成が canonical
