---
task_id: SGK-2026-0013
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# ADR-001: エントリポイントの統一

## ステータス

承認済み (2026-01-05)

## コンテキスト

現在、SHIGOKU には 2 つのエントリポイントが存在する:

1. **`src/__main__.py`** (`python -m src` で起動)

   - `--legacy` フラグで旧 `Runner` クラスを呼び出す分岐がある
   - 環境変数 `DEFAULT_MODEL` の読み込みロジックを含む
   - デフォルトでは `MasterConductor` を起動

2. **`src/main.py`** (`python -m src.main` または直接実行)
   - argparse ベースの CLI ツール群
   - `--interactive` オプションで `MasterConductor` を呼び出す
   - 20 以上のコマンドオプションを持つ

### 問題点

- **二重管理**: 新機能を両方のファイルに追加する必要がある
- **ロジックの重複**: 環境変数読み込み、モード判定などが分散
- **テストの複雑化**: どちらの起動方法でも動作することを保証する必要がある
- **ユーザーの混乱**: `python -m src` と `python -m src.main` で挙動が異なる

## 決定

1. **`src/main.py` に統一**する
2. **`pyproject.toml`** に `shigoku` コマンドを定義し、`pip install -e .` 後に `shigoku` で起動可能にする
3. **`src/__main__.py`** は `main.py` へのシンプルなリダイレクトとして残す（`python -m src` の互換性維持）
4. **レガシー `Runner`** クラスは廃止し、`MasterConductor` に完全移行

## 結果

### メリット

- メンテナンス対象が半減
- 新機能追加が 1 箇所で完結
- `shigoku --help` で全機能にアクセス可能
- テストがシンプルになる

### デメリット

- `--legacy` オプションを使用していたユーザーへの影響（移行期間が必要）
- `Runner` クラスに依存するコードの修正が必要

## 参考

- 技術的負債検証レポート (2026-01-05)
- Phase 4 実装計画
