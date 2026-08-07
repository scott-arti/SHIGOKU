---
task_id: SGK-2026-0429
doc_type: plan
status: deferred
parent_task_id: SGK-2026-0426
related_docs:
- docs/shigoku/reports/2026-08-06_sgk-2026-0426_vdp-product-independent-improvement_work_report.md
created_at: '2026-08-07'
updated_at: '2026-08-07'
tags:
- shigoku
- test-hygiene
- deferred
target: tests,tests/conftest.py,tests/e2e
---

# SGK-2026-0429: LLM API キー依存テストの隔離（キー無し環境での fail 回避）

SGK-2026-0426 の裏取り（広域 engine/reporting 回帰）中に観測された既存 baseline 失敗を、独立した追跡タスクとして起票する。**0426 の変更が原因ではない**。

## 背景 / 観測

- 広域回帰で **20 件**が失敗。
- 失敗シグネチャ: `Authentication Fails, api key invalid` — テスト環境に有効な LLM(DeepSeek) API キーが無いため、実 API を叩くテストが認証で落ちる。
- 由来: 環境依存（テスト env に `api_key_env` で参照するキーが未設定）。**製品コードのバグではない**。ただし「キー未設定でも回帰が green であるべき」というテスト衛生上の課題。
- 主な入口: `tests/e2e/test_swarm_llm.py` ほか、`LLMClient(...)` を実呼び出しするテスト群。

## 完了条件（着手時に確定する）

1. 20 件の失敗テストの正確な node id を確定し、「実 API 必須（e2e）」と「本来 mock で済むもの」に分類する。
2. 本来 mock すべきものは LLM クライアントを stub/mock 化してキー非依存で green 化する。
3. 実 API 必須のものは `requires_llm` 等のマーカーを付け、キー未設定時は skip（fail ではなく）にする。
4. 回帰: キー未設定環境で対象テストが green もしくは skip となり、fail が 0 になる。

## NOT in scope

- LLM 設定正本（`config/shigoku.yaml` の `llm:` ブロック）や role 定義の変更。
- SGK-2026-0428（bundle preflight テスト baseline）— 別タスク。
- API キーの生値をリポジトリへ格納すること（禁止・`api_key_env` 経由のみ）。

## 再現

```
.venv/bin/pytest tests/e2e/test_swarm_llm.py -q   # キー未設定環境で認証失敗を確認
```
