---
task_id: SGK-2026-0126
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Spec: Fix SmartXSSHunter Logic and Prompts

## 概要 (Overview)
`SmartXSSHunter` の実装において、内部プロンプトやロジックの一部が SQL インジェクション用の記述（コピペミスと思われる）になっており、LLM の推論が XSS 検出から逸脱する可能性がある問題を修正します。

## 変更範囲 (Scope)
- `src/core/agents/swarm/injection/smart_xss.py`

## 挙動 (Behavior)

### 1. プロンプトの修正
- `SYSTEM_PROMPT` 内の "SQL Penetration Tester" を "XSS Penetration Tester" に修正。
- `initial_prompt` および `decide` メソッド内のヒントテキストにおける "SQL injection" の記述をすべて "XSS" に置換・修正。

### 2. ロジックの整合性向上
- `decide` メソッド内での LLM への指示出しを XSS 特有の観点（反射の確認、コンテキスト解析など）に合わせた内容に変更。
- `max_turns` の設定に関するコメントとコードの不一致を解消。

### 3. 判定ロジックの精密化
- `act` メソッドでの「脆弱性あり」判定において、XSS 特有のキーワードや状態を考慮するように調整。

## 制約 (Constraints)
- `ThoughtLoop` (Observe-Think-Act) の基本アルゴリズムは変更せず、内容의 純化に留める。
- 既存の `src/core/infra/smart_request.py` 等の通信基盤との高い親和性を維持する。
- 全てのコミュニケーションとドキュメントは日本語とする。

## Implementation Order
1.  `src/core/agents/swarm/injection/smart_xss.py` の修正。
2.  `tests/core/agents/swarm/injection/test_smart_xss_logic.py` による検証。
