---
task_id: SGK-2026-0132
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# 仕様書: I/Oパフォーマンスとディスクアクセスの最適化

## 1. 概要
SHIGOKUのパフォーマンスを最大化するため、同期的なファイルI/Oから非同期（Async）I/Oへの移行、およびフラットファイルからSQLiteデータベースへのデータ集約を行います。これにより、大規模スキャン時におけるイベントループのブロッキングを防ぎ、データの検索性を向上させます。

## 2. 目的
- イベントループのブロッキング解消（「画面が固まる」現象の防止）
- ディスクI/O待ちによるCPUリソースのアイドル時間を削減
- 数万件規模のデータに対する高速な検索・フィルタリングの実現
- **人間による可読性（Recon結果のファイル出力）の維持**

## 3. 変更範囲
- `src/core/workspace/shared_workspace.py`: 非同期インターフェースへの変更とDB連携。
- `src/core/logger.py`: 非同期ロギングへの移行（`QueueHandler` または `aiologger` 相当の仕組み）。
- `src/core/infra/async_writer.py`: `SharedWorkspace` からの呼び出しを受け入れるための機能拡張。
- `src/core/learning/findings_repository.py`: 真実のソース（Source of Truth）としての役割強化。

## 4. 挙動の詳細
### 4.1. SharedWorkspace の非同期化
- `save_finding`, `save_intel`, `save_artifact` 等を `async` メソッドに変更。
- 内部で `AsyncDatabaseWriter` を使用して、DBへのバッチ書き込みを実行。
- **Reconデータ (Intel)** については、DBへの保存と並行して、従来通り `workspace/intel/*.json` への非同期ファイル出力も継続する。

### 4.2. 非同期ロギング
- ロギング操作をブロッキングせず、バックグラウンドスレッド/タスクでファイル書き込みを行う。
- `ShigokuLogger.finding` 等の重い処理を非同期化。

## 5. 制約事項
- **EthicsGuardの遵守**: ログ出力やデータ保存において、PII（個人情報）や機密情報のマスク処理が正常に機能することを保証すること。
- **後方互換性**: 各Agent（`BaseAgent`）の `workspace` プロパティ経由でのアクセスを壊さないよう、段階的に移行するか、ラッパーを提供する。
- **データ移行**: 既存のJSONファイルからSQLiteへの自動インポートスクリプトを用意する（オプショナル、または初回起動時に実施）。
