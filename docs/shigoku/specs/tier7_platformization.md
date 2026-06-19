---
name: tier7-platformization
description: Tier 7 プラットフォーム化の実装仕様
task_id: SGK-2026-0165
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Tier 7: プラットフォーム化実装仕様 (Platformization Spec)

## 概要

本仕様書は、SHIGOKUの「Tier 7: プラットフォーム化 (UI/API)」の実装に関する要件を定義します。開発者が使いやすく、外部のバグバウンティプラットフォームともシームレスに連携できる洗練されたシステム基盤を構築します。

## 変更範囲

以下のファイル群が影響を受け、あるいは新規作成されます。

- **ロガーの一元化とEventBus統合**:
  - `src/core/logger.py` (改修)
  - 各種エージェントおよびツールのログ出力部分 (改修)
- **WAFモデリングの完全化**:
  - `src/core/attack/waf_mutator.py` (改修/拡充)
  - `src/core/infra/network_client.py` (改修: 自動WAFバイパス再送ロジックの追加)
- **HackerOne / Bugcrowd API 同期**:
  - `src/core/export/platform_sync.py` (新規追加: H1/Bugcrowd連携)
- **グラフUI / ダッシュボード (Web & CLI)**:
  - `src/dashboard/api/main.py` (改修: WebSocketログ配信の追加)
  - `src/core/ui/live_dashboard.py` (改修: アタックツリー/グラフの可視化強化)

## 挙動・実装詳細

### 1. ロガーの一元化 (Centralized Logging)

- **Input/Output**: すべてのモジュールは標準の `logging.getLogger` 経由でログを出力しますが、配下で `ShigokuLogger` が一元的に処理します。
- **実装内容**:
  - 既存の `ShigokuLogger` をシングルトンとして整理し、コンソール出力(Rich)とファイル出力(JSON化)を強制します。
  - すべての重要ログ（INFO・WARN・ERROR）を `EventBus` へ転送し、ダッシュボードやUI側でリアルタイムに拾えるように連携させます。

### 2. WAFモデリングの完全化 (Enhanced WAF Modeling)

- **Input/Output**: `AsyncNetworkClient` が 403 (Forbidden) や WAF 特有のブロックレスポンスを受け取った際。
- **実装内容**:
  - 通信エラーハンドリング（特に 403 や 406 など）時に `WAFPayloadMutator` を呼び出し、自動的にペイロードを難読化・変異させてリトライするロジックを `AsyncNetworkClient.request` 内に組み込みます。
  - WAF検知時に `EventBus` に通知を飛ばし、「WAF Bypass試行中」などのメッセージをダッシュボードに表示します。

### 3. HackerOne / Bugcrowd API 同期 (Bug Bounty API Sync)

- **Input/Output**: `Finding` オブジェクトを外部バグバウンティプラットフォームへと送信。
- **実装内容**:
  - `PlatformSyncClient` を新規作成し、提供されたAPIキー（環境変数 `H1_API_KEY` 等）を利用してレポートの自動作成 (Draft状態) を行います。
  - 対象: HackerOne (Report API), Bugcrowd (Crowdcontrol API)。
  - `EthicsGuard` によって承認された確定 Findings のみを送信の対象とします。

### 4. グラフUI / ダッシュボード機能 (Dashboard Integration)

- **Input/Output**: `EventBus` 経由でのイベントストリームをダッシュボードに反映。
- **実装内容**:
  - FastAPIバックエンド (`src/dashboard/api/main.py`) にWebSocketエンドポイント (`/api/ws/logs`) を追加し、フロントエンドにリアルタイムログを配信します。
  - CLI側の `LiveDashboard` に、脆弱性チェーン（`ExploitChain`）をグラフ形式・ツリー形式で出力するパネルを追加します。

## 制約

- **EthicsGuard遵守**: 外部プラットフォーム（HackerOne/Bugcrowd）への自動送付は、`EthicsGuard` で承認・確定済みの脆弱性（Findings）に対してのみ実行許可（またはDry-Run許可）するものとします。
- **パフォーマンスと安定性**: WebSocketの接続増加によるイベントループのブロックを防ぐため、FastAPI側の非同期処理を適切に保護します。自動WAFバイパスは無限ループを回避するため、リトライ上限（Max Retries）と遅延（Backoff）を厳守します。
