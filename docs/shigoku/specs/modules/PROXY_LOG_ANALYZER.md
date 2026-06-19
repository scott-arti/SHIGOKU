---
task_id: SGK-2026-0042
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-06-19'
---

# ProxyLogAnalyzer

**現行モジュールパス**

- `src/intelligence/proxy_log_analyzer.py`

## 概要

ProxyLogAnalyzer は Caido などの proxy log から smell を抽出し、攻撃候補と agent routing 情報へ変換する分析モジュールです。

## 現行の主要構成

- `SmellType`
- `HttpEntry`
- `FindingCandidate`
- `AttackPlan`
- `ProxyLogAnalyzer`
- `analyze_and_dispatch()`
- `get_proxy_analyzer()`

## 現行仕様

- proxy log を読んで auth / idor / injection などの候補を抽出する
- Hybrid Hunt の初期プラン生成に使われる
- BizLogicHunter や security cross-test 系からも型を参照される

## 主な呼び出し元

- `src/commands/hunt.py`
- `src/core/security/idor_cross_tester.py`
- `src/core/agents/swarm/biz_logic_hunter.py`

## 注意点

- 旧仕様書の smell ルール詳細は将来変更されうるため、この文書では固定しない
- 現行の canonical 仕様は「log -> candidate/plan 変換器」
