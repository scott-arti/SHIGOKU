---
task_id: SGK-2026-0110
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 仕様書: 設定管理のリファクタリング (Pydantic Settings 移行)

## 概要

現状の `ConfigManager` (独自実装) を `pydantic-settings` ベースの構成に刷新し、型安全性、自動バリデーション、および環境変数による柔軟な上書き機能を導入します。

## 背景

- 現在の `dataclasses` + `yaml.safe_load` による手動マッピングは、型の強制力が弱く、大規模なプロジェクトでは設定ミスの原因になります。
- 環境変数の上書きロジックが独自実装であり、スケーラビリティに欠けます。

## 挙動

### 設定の優先順位

以下の順序で設定を適用します（下に行くほど優先されます）：

1. デフォルト値 (コード内定義)
2. YAML ファイル (`shigoku.yaml`)
3. 環境変数 (`SHIGOKU_` 接頭辞)
4. CLI 引数 (既存の `main.py` ロジック)

### 環境変数マッピング

- プレフィックス: `SHIGOKU_`
- ネストの区切り: `__` (アンダースコア2つ)
- 例: `SHIGOKU__SCAN__RATE_LIMIT=100` -> `config.scan.rate_limit = 100`

## 変更範囲

1. **[NEW]** `src/core/settings.py`: Pydantic `BaseSettings` を継承した新設定クラス。
2. **[MODIFY]** `src/core/config_manager.py`: 内部ロジックを Pydantic に差し替え。外部インターフェース (`get_config()`) は維持。
3. **[MODIFY]** `pyproject.toml`: 依存関係の正式な利用（既にあるが活用を強化）。

## 制約

- 既存の `shigoku.yaml` の構造を壊さないこと。
- `get_config()` を呼び出している既存コードに変更を強いないこと（互換レイヤーの提供）。
- `EthicsGuard` などセキュリティに直結する設定のバリデーションを厳格化する。
