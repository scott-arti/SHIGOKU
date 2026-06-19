---
task_id: SGK-2026-0040
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# KnowledgeGraph

**現行モジュールパス**

- `src/core/infra/knowledge_graph.py`

## 概要

KnowledgeGraph は Neo4j ベースの長期記憶レイヤーです。Recon / planning / finding enrichment の補助として使われます。

## 現行の主要構成

- `KnowledgeGraph`

## 現行仕様

- Recon や intel の結果をグラフ化して保持する
- Master Conductor facade から query 対象として参照される
- dashboard API や swarm agent からも読み出される

## 主な呼び出し元

- `src/commands/recon.py`
- `src/core/engine/master_conductor_facade.py`
- `src/core/engine/attack_planner.py`
- `src/dashboard/api/main.py`

## 注意点

- 旧仕様書にあったノード/エッジ完全一覧は現行の保守対象として固定しない
- 現在の canonical な利用面は「queryable context store」
