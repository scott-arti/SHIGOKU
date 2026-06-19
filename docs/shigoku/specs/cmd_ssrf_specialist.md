---
task_id: SGK-2026-0109
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Command Injection & SSRF Specialist Feature Specification

## 概要

Bug Bounty において Critical (最高深刻度) に直結する **Command Injection (OSコマンドインジェクション)** と **SSRF (Server-Side Request Forgery)** を専門に探知・攻撃する自律型エージェント `SmartCmdSSRFHunter` を実装します。
さらに、特定のテクノロジーやバージョンを検知した際に、外部の脅威インテリジェンス（Exa Search）を用いて最新の PoC (Proof of Concept) を動的に取得・適用する仕組みを統合します。

## 変更範囲

- `docs/specs/cmd_ssrf_specialist.md` (本ファイル)
- `src/core/agents/swarm/injection/smart_cmd_ssrf.py` (新規作成)
  - `SmartCmdSSRFHunter` エージェントの実装
  - Command Injection および SSRF の検査ロジック
- `src/core/agents/swarm/injection/manager.py` (修正)
  - `InjectionManagerAgent` へ Specialist を登録
  - `analyze_parameters` におけるターゲットパラメータのルーティング強化
- `src/core/infra/mcp_client.py` (既存連携があれば修正/拡張)
  - Exa MCP サーバーへの問い合わせツールの統合

## 挙動 (Input / Output)

### 1. 共通フロー

- **Input**: インジェクションの可能性が高いと判定された URL、パラメータ名、および現在のセッション情報（Cookies, Headers）。
- **Process**: LLM が ThoughtLoop を回し、パラメータ名（`?ip=`, `?url=`, `?dest=` 等）や文脈から、試行すべき攻撃ベクトル（コマンドインジェクションか SSRF か）を決定します。

### 2. Command Injection テストフロー

- **対象パラメータ**: `ip`, `host`, `ping`, `cmd`, `daemon`, `exec` 等。
- **Process**:
  1. LLM がベースラインリクエストと、インジェクションペイロード（`; id`, `| whoami`, `` `id` ``, `$(id)`）を用いたリクエストを生成。
  2. レスポンス内にコマンド実行結果（`uid=0(root)` 等）が含まれているかを検査（Verbsose/Reflected）。
  3. **Blind Command Injection**: 結果が表示されない場合、時間差攻撃（`sleep 5`, `ping -c 5 127.0.0.1`）を実行し、レスポンス遅延時間から脆弱性を推論。
- **Output**: 脆弱性詳細とエビデンス（コマンド実行結果 または レスポンスタイム遅延の証拠）。

### 3. SSRF テストフロー

- **対象パラメータ**: `url`, `target`, `dest`, `next`, `redirect`, `path` 等。
- **Process**:
  1. 内部ネットワークへのアクセス試行: `http://localhost`, `http://127.0.0.1`, `http://[::1]` などによるポートスキャン（22, 80, 443, 6379, 3306）。
  2. クラウドメタデータエンドポイントの攻撃: AWS (`169.254.169.254/latest/meta-data/`), GCP (`metadata.google.internal`), Azure などの機密情報取得を試行。
  3. プロトコルスマッシング: `file:///etc/passwd`, `dict://`, `gopher://` へのプロトコル変更によるアクセス試行。
- **Output**: 脆弱性詳細と取得できた内部データ（メタデータ等）。

### 4. Exa Web Search 連携 (脆弱性PoCの動的取得)

- **条件**: コマンド実行の足がかりになりそうな特定のミドルウェアやアプリケーションのバージョン情報（例: `Apache ActiveMQ 5.15.0` または特定のエラーメッセージ）を発見した場合。
- **Process**:
  1. `SmartCmdSSRFHunter` が `search_exploit` アクションをトリガー。
  2. Exa MCP サーバーを用いて Web 検索を実行。「`Apache ActiveMQ 5.15.0 RCE exploit PoC github`」等のクエリで最新の悪用手法を収集。
  3. LLM が検索結果を解析し、SHIGOKU から送信可能なペイロード形式に翻訳してテストを実行。
- **トグル制御 (ON/OFF)**: ローカルでのターゲットテスト（DVWA等）において Exa API を無駄に消費しないよう、Agent の config に `enable_exa_search: bool` (デフォルト `False`) を実装し、有効な場合のみ MCP 呼び出しを行う。

## 制約・セキュリティガイドライン (Constraints)

1. **EthicsGuardの遵守**:
   - リクエストはすべて `ethics_guard.check_scope(url)` を通過すること。
2. **破壊的操作の禁止**:
   - Command Injection 時にシステムを破壊するコマンド（`rm`, `reboot`, `shutdown` 等）は絶対に実行しない。情報取得（`id`, `whoami`, `uname -a`, `cat /etc/passwd`）または安全な時間遅延（`sleep`）に限定する。
3. **Exa API の利用制限**:
   - Exa API はレートリミットおよび課金対象となる可能性があるため、無意味な検索を繰り返さないよう ThoughtLoop 内での過度な呼び出しを制限する設計（キャッシュ機構の導入や呼び出し回数上限）とする。
4. **WAF への配慮**:
   - SSRF における SSRF 回避テクニック（`http://2130706433/` [127.0.0.1 の整数表現] や URL/DNS Rebinding 用ドメイン）を LLM のプロンプト知識として組み込んでおく。
