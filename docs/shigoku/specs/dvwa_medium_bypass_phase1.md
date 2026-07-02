---
task_id: SGK-2026-0112
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Spec: DVWA Medium Bypasses (Phase 1)

## 概要 (Overview)

SHIGOKUのペネトレーションテスト能力を向上させ、DVWAの「Medium」セキュリティレベルにおける各種脆弱性（SQL Injection, XSS, Command Injection, File Inclusion）を自律的に突破できるようにします。現在のSHIGOKUは単純なエスケープやフィルタリングに阻まれているため、各Injection SpecialistのLLMプロンプトおよびペイロードジェネレータを強化し、バイパス手法を標準装備させます。

## 変更範囲 (Scope)

以下のファイルが変更の対象となります：

1. `src/core/agents/swarm/injection/smart_sqli.py`
2. `src/core/agents/swarm/injection/smart_xss.py`
3. `src/core/agents/swarm/injection/smart_cmd_ssrf.py`
4. `src/core/attack/lfi_tester.py`

## 挙動 (Behavior)

### 1. SmartSQLiHunter (`smart_sqli.py`)

- **変更内容**: `SYSTEM_PROMPT` のガイドラインに「Mediumレベルの防御（`mysql_real_escape_string` 等）を回避するため、文字列（シングルクォート）に依存しない数値ベースの注入（例：`1 OR 1=1`）を優先的に試行する」という指示を追加。
- **期待される結果**: クォートがエスケープされる環境でも、数値型パラメータと推測される場所でBoolean-basedな推論を確実に試みる。

### 2. SmartXSSHunter (`smart_xss.py`)

- **変更内容**: `SYSTEM_PROMPT` のガイドラインに「`<script>`タグそのものがフィルタリングされる防御を想定し、`<svg onload="...">` や `onerror`, `onmouseover` 等のHTML属性・イベントハンドラを活用したペイロードを試行する」という指示を追加。
- **期待される結果**: プレーンなスクリプトタグが使えない状況でもXSSを発火・検知できる。

### 3. SmartCmdSSRFHunter (`smart_cmd_ssrf.py`)

- **変更内容**: `SYSTEM_PROMPT` に「`;` (セミコロン) や `&&` (論理積) がフィルタされている場合は、コマンドの連結にパイプ `|` や論理和 `||` を用いること」という指示を追加。
- **期待される結果**: 最も基本的なコマンドセパレータが使用不可能なシステムにおいてもOSコマンドインジェクションを確立する。

### 4. LFITester (`lfi_tester.py`)

- **変更内容**: `generate_smart_payloads` メソッドにおいて、標準パイプラインとして以下のLFIペイロードを必ず生成するように機能拡張する。
  - Double Traversal: `....//....//....//etc/passwd` (1回の置換処理をバイパス)
  - Absolute Path: `/etc/passwd` (相対パス探索を前提としたフィルタのバイパス)
- **期待される結果**: LLMの推論を待たずに（あるいはフェーズ1として）確実かつ低遅延でMediumレベルのディレクトリトラバーサル制約を突破する。

## 制約 (Constraints)

- **EthicsGuardとの整合性**: 破壊的なコマンド（`rm`, `reboot` など）を使用しないという既存の `BLOCKED_COMMANDS` ポリシーを維持します。XSSでの検証時も安全な `alert()` や `console.log()` を引き続き利用します。
- **既存アーキテクチャの維持**: LLMによるThoughtLoop処理（思考・推論・行動）のフレームワークは変更せず、LLMへの誘導（プロンプト）の改善によって精度を上げます。
