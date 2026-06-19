---
task_id: SGK-2026-0033
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# BizLogicHunter

**現行モジュールパス**

- `src/core/agents/swarm/biz_logic_hunter.py`
- `src/agents/swarm/biz_logic_hunter.py` は legacy shim

## 概要

BizLogicHunter は IDOR / 権限昇格 / hidden parameter abuse などのビジネスロジック寄り検証を担う swarm agent です。

## 現行の主要構成

- `VerifyResult`
- `VerifyContext`
- `CriticConfig`
- `BizLogicHunter`
- `create_bizlogic_hunter()`

## 現行仕様

- `ProxyLogAnalyzer` の候補や手動文脈を受けて検証を行う
- 複数セッションを使う cross-session 系テストと接続できる
- Knowledge Graph や report 系と連携して finding を返す
- `src/core/tool_registry.py` と mode manager から有効化対象として参照される

## 主な呼び出し元

- `src/commands/hunt.py`
- `src/core/agents/swarm/logic/llm_specialists.py`
- `src/core/tool_registry.py`

## 注意点

- 旧仕様書にある個別メソッド一覧は現行巨大クラス構成とズレるため省略
- 実際の責務は「単体テスター」より「business-logic swarm agent」に近い
