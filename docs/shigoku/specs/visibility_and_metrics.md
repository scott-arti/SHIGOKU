---
task_id: SGK-2026-0166
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Visibility & Metrics 仕様書

## 概要

SHIGOKUのペネトレーションテスト実行における進行状況・成果・エラー情報を、ユーザーが直感的かつ構造的に把握できるようにするための機能強化。

## 変更範囲

1. **CLI出力ロジック**: `src/core/utils/logger.py` などのロギング機構（新規・拡張）
2. **エラーハンドリング**: `src/core/models/error.py` (新規作成)
3. **セッションメトリクス**: `src/core/engine/` 配下の進行管理機構
4. **ダッシュボードAPI**: `src/dashboard/api/main.py`
5. **ダッシュボードUI**: `src/dashboard/frontend/src/`

## 挙動

### 1. CLIの可視性向上 (richライブラリの活用)

- **アイコンと日本語プレフィックス**: ログ出力時にAIのアクションを可視化。
  - 例: `[🔍 偵察] GitHubから情報を収集しています...`
  - 例: `[🧠 思考] Task: SQLi_Scan を InjectionManager に割り当てます。`
  - 例: `[🚨 発見] Critical: OS_COMMAND_INJECTION detected`
- **ツリー構造の可視化**: ReconからTaskのアサイン、Agentの実行結果までの流れをディレクトリ構造のようなツリー表示でターミナルに出力。
- **最終サマリー**: 実行完了時に、脆弱性の発見件数（Severity別）と、発生したエラーのサマリー（原因別）を表形式(`rich.table`)で表示。

### 2. エラー分類の厳格化

- `ErrorCode` Enum と `SHIGOKUError` データクラス（またはPydanticモデル）を定義。
- エラーの種類（API制限、タイムアウト、設定ミス、実行失敗、コンテキスト長超過など）を明確に分割。
- `try-except` で捕捉した例外を自動分類し、再試行可能なものかどうか（`retryable`）をフラグ化。結果の集計に使用。

### 3. メトリクスのダッシュボード表示

- 各フェーズ（Recon, Planning, Executionなど）ごとの「所要時間」「ステータス」「コスト（トークン使用推計など）」を算出し、セッションデータ(`session.json`)等に記録。
- FastAPIバックエンドにメトリクス取得用のエンドポイント `/api/metrics/{session_id}` を新設。
- Webダッシュボード（React）上に、フェーズ進行状況バーや、コスト内訳などのメトリクスを可視化するUI・コンポーネントを追加。

## 制約

- **アーキテクチャの維持**: 大幅な変更は控え、既存のMaster Conductor等のベースアーキテクチャや責務を破壊しない。
- **Web UIの簡素化**: フロントエンドは過度に複雑にせず、シンプルにメトリクスの把握ができる必要十分な内容とする。
- **Safety First**: 実装時にログへ機密情報が流出しないように注意する。
