---
task_id: SGK-2026-0081
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-09'
updated_at: '2026-07-02'
---

# Specification: Hybrid Intelligence Architecture Refactoring (Phase 8.1 - 8.2)

## 📌 概要

Bug Bounty における「人間のホワイトハッカーの思考プロセス」を模倣するために、現在の「単発実行型（ToolExecutor一辺倒）」のアーキテクチャを、**「Robot（定型）とBrain（思考ループ）のハイブリッド型」** にアップグレードする。

具体的には、`InjectionSwarm` 内の LLM Specialist を「ステートフルな思考ループを持つエージェント」に書き換え、発見された脆弱性候補に対して AI が試行錯誤（仮説→実験→修正）を行えるようにする。

---

## 🎯 Scope (対応するRoadmap項目)

- **Phase 8.1**: Swarm Architecture Refactoring (Logic Separation)
  - `ThoughtLoop` 基底クラスの実装
  - `SmartRequest` ラッパー機能の実装
- **Phase 8.2**: Stateful Specialist Implementation (Brain)
  - `SmartSQLiHunter` の実装 (LLMSQLiHunterの置換)

---

## 🛠️ Changes (変更内容)

### 1. New Core Component: `ThoughtLoop`

**File**: `src/core/agents/swarm/thought_loop.py` (New)

LLM が試行錯誤するための共通基底クラス。

- **機能**:
  - `History`: 思考と実行結果の履歴管理（最大ターン数制限付き）。
  - `Observe`: ツールの実行結果を解析し、要約して LLM に渡す。
  - `Decide`: 次のアクション（ツール実行 or 終了）を決定する。
  - `Act`: 決定されたアクションを実行する（ToolExecutor連携）。

### 2. Enhanced Network Client: `SmartRequest`

**File**: `src/core/infra/smart_request.py` (New)

Swarm が「賢くリクエストする」ためのラッパー。

- **機能**:
  - **WAF Detection**: 403/406 エラー時に自動で「WAF検知」フラグを立てる。
  - **Diff Analysis**: 正常系レスポンスとの差分（Diff）を計算し、AI に「何が変わったか」だけを伝える（コンテキスト節約）。
  - **Retry/Backoff**: レート制限時の自動待機。

### 3. Smart SQLi Hunter

**File**: `src/core/agents/swarm/injection/smart_sqli.py` (New)
**File**: `src/core/agents/swarm/injection/llm_specialists.py` (Modify/Deprecate)

既存の `LLMSQLiHunter` を置き換える、ループ思考型エージェント。

- **Behavior**:
  - **Turn 1**: パラメータの型推定と基本的な Fuzzing (`'`, `"`)。
  - **Turn 2-3**: エラー内容に基づく攻撃手法の特定（MySQL Error-based, Time-based 等）。
  - **Turn 4-5**: 特定された手法での Exploitation（DB名取得、バージョン取得）。
  - **Finish**: 成功/失敗の確定とレポート生成。

---

## ✅ Verification (完了条件)

### 1. Unit Tests (DONE)

- [x] `ThoughtLoop` が指定されたターン数だけループし、LLM の指示通りにツールを呼び出せること。
- [x] `SmartRequest` が差分（Diff）を正しく計算できること。

### 2. Integration Tests (Simulated) (DONE)

- [x] ローカルの Mock Server（脆弱性あり）に対して `SmartSQLiHunter` を実行し、以下の挙動を確認する：
  1.  最初はエラーが出る（探り）。
  2.  次に正しいペイロード（`UNION SELECT`）を投げる。
  3.  最終的に「脆弱性あり」と判定して終了する。

### 3. E2E Verification

- `DVWA` (Localhost) の SQLi ページに対して実行し、実際に脆弱性を検知・攻略できることを確認する。
