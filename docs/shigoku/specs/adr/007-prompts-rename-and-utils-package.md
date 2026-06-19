---
task_id: SGK-2026-0020
doc_type: spec
doc_usage: historical_completion_spec
status: done
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 007. プロンプトモジュールのリネームとユーティリティパッケージの導入

> 2026-06-19 注記: この ADR は実装完了後の履歴資料です。本文で述べる `src/prompts/__init__.py` の互換レイヤー、`src/core/utils/json_utils.py`、`MultiAccountSessionManager._load_from_env()` に対応する現行実装があります。

**Date:** 2026-01-05
**Status:** Accepted

## Context (背景)

SHIGOKU プロジェクトの開発において、以下の 3 つの技術的課題が浮上した。

1.  **インポート名の競合 (Namespace Shadowing)**:
    `src/prompts.py` (レガシーファイル) と `src/prompts/` (新パッケージ) が同一名称で存在していた。Python のインポート仕様上、ディレクトリパッケージが優先されるため、ファイル側の `get_agent_prompt` 関数が参照不能となり、`ImportError` が発生していた。

2.  **共通機能の欠如**:
    JSON パース時のエラーハンドリング (`try-except json.JSONDecodeError`) がコードベースの各所に散在しており、DRY (Don't Repeat Yourself) 原則に違反していた。

3.  **環境設定の柔軟性欠如**:
    `MultiAccountSessionManager` が設定ファイル (`sessions.json`) のみに依存しており、CI/CD 環境やコンテナ環境（Kubernetes 等）で推奨される「環境変数による設定注入 (Twelve-Factor App)」に対応していなかった。

## Decision (決定)

これらの課題を解決するため、以下のアーキテクチャ変更を決定した。

### 1. プロンプトモジュールのリネームと互換レイヤー

- **リネーム**: 旧 `src/prompts.py` を `src/legacy_prompts.py` にリネームし、名前空間の競合を物理的に解消する。
- **互換レイヤー**: `src/prompts/__init__.py` 内にハイブリッドラッパーを実装する。
  - `get_agent_prompt` 関数を定義し、内部で新しい `PromptRenderer` を試行、失敗時は `legacy_prompts` にフォールバックする。
  - `src/legacy_prompts` から全ての定数（`SECURITY_AGENT_PROMPT` 等）を再エクスポートし、既存コードからの `from src.prompts import ...` が維持されるようにする。

### 2. ユーティリティパッケージの新設

- `src/core/utils/` パッケージを作成する。
- 最初のモジュールとして `json_utils.py` を配置し、安全な JSON パース関数 `safe_json_loads` を提供する。
- 今後の共通関数はここに集約する。

### 3. セッション管理の環境変数対応

- `MultiAccountSessionManager` に `_load_from_env()` メソッドを追加する。
- ファイル読み込みよりも環境変数 (`SHIGOKU_ATTACKER_COOKIE` 等) を優先するロジックに変更する。

## Consequences (結果)

### メリット

- **安全性**: Python の標準的なインポート解決ルールに準拠し、隠蔽（Shadowing）による予期せぬエラーを排除した。
- **互換性**: 既存の呼び出し元コード（`factory.py` 等）を一切変更することなく、内部構造を整理できた。
- **保守性**: 共通処理が `src/core/utils` に集約され、将来的な変更容易性が向上した。
- **運用性**: 環境変数によるクレデンシャル注入が可能になり、セキュアなデプロイが容易になった。

### デメリット・リスク

- `src/prompts/__init__.py` がやや複雑化した（新旧共存のため）。これは将来的に `legacy_prompts.py` を廃止するフェーズで削除可能である。
