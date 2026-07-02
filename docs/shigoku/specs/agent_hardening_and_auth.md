---
task_id: SGK-2026-0104
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Agent Hardening & Authentication Integration Specification

## 概要

ReconBotおよび関連エージェントの信頼性と安全性を向上させるため、以下の3点を実装する。

1.  **権限適正化 (Hardening)**: 汎用シェル実行権限 (`linux_cmd`) を剥奪し、専用ラッパーツールの使用を強制する。
2.  **認証連携 (Auth Integration)**: `MasterConductor` が保持するセッションクッキーをツール実行時に自動注入し、認証済みスキャンを実現する。
3.  **堅牢性向上 (Robustness)**: ツール実行エラーや結果空のケースを適切にハンドリングし、サイレント失敗を防ぐ。

## 変更範囲

### 1. エージェント設定 (`src/core/engine/agent_registry.py`)

- **変更点**:
  - `ReconBot`, `VulnScanner` などの脆弱性診断系エージェントのタグ設定または許可ツールリストから `linux_cmd`, `bash` を削除。
  - 代わりに `NucleiTool`, `HttpxTool` などのラッパーツールを明示的に許可。

### 2. ツールラッパー (`src/tools/custom/nuclei.py`, `src/tools/wrappers/httpx_wrapper.py`)

- **変更点**:
  - `NucleiTool`: プロファイル機能 (`ToolProfileManager`) と連携し、デフォルトヘッダーとしてCookieを受け取れるように拡張。
  - `HttpxTool`: 同様にCookie注入に対応。
  - docstringを強化し、エージェントが「tool use」として正しく認識できるようにする。

### 3. エージェント基底 (`src/core/agents/base.py`)

- **変更点**:
  - `execute_tool_with_guardrail` または `run_tool` 相当のメソッドにおいて、`SharedWorkspace` または `ExecutionContext` から自動的に `Cookie` ヘッダーを取得し、ツール引数 (`headers` や `extra_args`) にマージするロジックを追加。

### 4. システムプロンプト (各エージェント定義)

- **変更点**:
  - "Do not use shell commands. Use provided verified tools only." という趣旨の強力な制約をSystem Promptに追加。

## 挙動 (Input/Output)

### Before

- User: "スキャンして"
- Agent: `linux_cmd("nuclei -u target ...")` -> **Blocked by EthicsGuard**
- Agent: Result `[]` -> Crash `IndexError` or Silent Skip

### After

- User: "スキャンして"
- Agent: `NucleiTool(target="...", profile="standard")`
- BaseAgent: `Cookie: PHPSESSID=...` を自動付加して実行
- Tool: 正しいパスで `nuclei` を実行し、JSON結果を返す
- Agent: 結果を解析し、レポート生成

## 制約事項

- **EthicsGuard**: ラッパー経由であっても、ターゲットスコープ外へのアクセスは引き続きブロックされる必要がある（既存の仕組みを利用）。
- **Performance**: ツール実行は非同期で行い、メインスレッドをブロックしない。

## 検証計画

1.  `linux_cmd` を使おうとしてエラーになること（またはそもそも選択肢に出ないこと）を確認。
2.  `nuclei` 実行時に `debug` ログでCookieが付与されていることを確認。
3.  意図的にツールをアンインストールした状態で、エラーが適切に報告されることを確認。
