---
task_id: SGK-2026-0152
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# Phase 3.6: Scanner Swarm Specification

**作成日:** 2026/01/26
**対象:** Scanner Swarm

## 1. 概要

Scanner Swarm は、既存のセキュリティツール (`Nuclei`, `Nmap`) を統合し、既知の脆弱性 (CVE) や構成ミス、ポート開放状況を効率的にスキャンするためのエージェント群です。

## 2. アーキテクチャ

### 2.1. ディレクトリ構造

- `src/core/agents/swarm/scanner/`: Swarm Manager & Specialists
- `src/tools/scanners/`: Tool Wrappers

### 2.2. Components

#### A. ScannerSwarm (Manager)

- タスクのタグに基づいて適切な Specialist にディスパッチします。
- **Tags**: `scanner`, `cve`, `port_open`, `ssl`, `service`

#### B. PortScanSpecialist

- **Role**: ポートスキャンとサービス特定。
- **Tool**: `NmapWrapper` (or Native Socket Scanner if nmap missing).
- **Behavior**:
  - Tag `port_open` または `service` で起動。
  - Top 100 ports をスキャン（デフォルト）。
  - 結果を `Service` 形式で Evidence に保存。

#### C. VulnScanSpecialist (Nuclei)

- **Role**: 既知の脆弱性 (CVE) スキャン。
- **Tool**: `NucleiWrapper`.
- **Behavior**:
  - Tag `cve` または `vuln` で起動。
  - **Safety**: 破壊的なテンプレートは除外 (`-tags cve,auth,config` 等に限定)。
  - 重複実行を避ける（ハッシュチェック）。

#### D. SSLScanSpecialist

- **Role**: SSL/TLS 設定診断。
- **Tool**: `SSLScanner` (Native Python `ssl` module).
- **Behavior**:
  - Tag `ssl`, `tls`, `certificate` で起動。
  - 証明書の有効期限、弱暗号化スイートの検出。

## 3. インターフェース

### 3.1. Tool Wrappers

- `src/tools/scanners/nuclei_wrapper.py`:
  - `run(target, templates=...)`
  - Output: JSON parsing
- `src/tools/scanners/ssl_scanner.py`:
  - `scan(host, port)`

### 3.2. Integration

- `SwarmDispatcher` に `scanner` タグをマッピング。

## 4. 制約事項 (Safety & Performance)

- **Nuclei**: 大量のHTTPリクエストが発生するため、`rate-limit` オプションを必ず設定する。
- **Nmap**: Root権限がない環境では `connect` スキャン (`-sT`) を使用する。
- **EthicsGuard**: スキャン対象がスコープ内であることを常に確認する。
