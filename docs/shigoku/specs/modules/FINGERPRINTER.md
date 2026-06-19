---
task_id: SGK-2026-0037
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# Fingerprinter

**現行モジュールパス**

- `src/core/intel/fingerprinter.py`

## 概要

Fingerprinter はレスポンス本文やヘッダーから技術スタックを推定する偵察モジュールです。

## 現行の主要構成

- `TechInfo`
- `Fingerprinter`

## 現行仕様

- `src/commands/recon.py` で利用される
- `ScopeParserAgent` や Master Conductor dispatch service からも参照される
- `TechInfo` は Knowledge Graph 側で型として利用される

## 主な呼び出し元

- `src/commands/recon.py`
- `src/core/agents/specialized/scope_parser.py`
- `src/core/engine/master_conductor_dispatch_service.py`
- `src/core/infra/knowledge_graph.py`

## 注意点

- 旧仕様書にある「検出精度表」は参考情報であり、現行公開仕様としては固定しない
- 現在は recon / planning 文脈へ技術タグを供給する役割が中心
