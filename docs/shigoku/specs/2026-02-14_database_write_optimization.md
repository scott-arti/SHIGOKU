---
task_id: SGK-2026-0086
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-02-14'
updated_at: '2026-05-19'
---

# Spec: データベース書き込み最適化 (Hybrid Batch Architecture)

## 1. 概要

SHIGOKUエンジンのデータベース（SQLite/Neo4j）への書き込みパフォーマンスを向上させ、同時にデータ損失のリスクを最小限に抑えるための最適化。

## 2. 変更内容

### Core Components

- **`AsyncDatabaseWriter` (`src/core/infra/async_writer.py`)**:
  - **Severity-Based Routing**: 深刻度（Critical/High）に応じて即時書き込みとバッチ書き込みを動的に振り分け。
  - **Write-Ahead Logging (WAL)**: 書き込み前にローカルJSONLファイルに記録し、クラッシュ時の復旧を可能に。
  - **Graceful Shutdown**: SIGINT/SIGTERM 時に未処理のキューをフラッシュ。
  - **L1 Cache**: 書き込み中/待ちのデータをメモリに保持し、Read-After-Writeの一貫性を確保。
- **`FindingsRepository` (`src/core/learning/findings_repository.py`)**:
  - SQLiteの `WAL (Write-Ahead Logging)` モードを有効化。
  - `save_batch` メソッドの実装による一括挿入。
- **`KnowledgeGraph` (`src/core/infra/knowledge_graph.py`)**:
  - Neo4jの `UNWIND` を使用した `save_pages_batch` メソッドを実装。
  - 起動時のインデックス作成（`Page(url)`, `Domain(name)`）の保証。

### Engine Integration

- **`MasterConductor`**:
  - `AsyncDatabaseWriter` の初期化とライフサイクル管理（`start`/`stop`）。
  - `save_finding`, `get_finding`, `save_sitemap` インターフェースの追加。
  - `handle_finding` における書き込みロジックの統合。

## 3. 実装のメリット

- **パフォーマンス**: 大量のリクエストログや情報収集結果を一括処理することでIO負荷を激減。
- **安全性**: クリティカルな脆弱性は即時保存され、バッチ待ちのデータもWALにより保護される。
- **一貫性**: キャッシュ機能により、非同期書き込み中であっても最新のデータを即座に参照可能。

## 4. 検証結果

- `tests/unit/infra/test_async_writer.py` により、重要度ルーティング、バッチング、WAL、キャッシュの動作を確認済み。
