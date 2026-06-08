---
task_id: SGK-2026-0016
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ADR-003: 技術的負債解消 - FastAPI ブロッキング I/O と例外処理改善

## ステータス

承認済み (Accepted)

## 日付

2026-01-05

## コンテキスト

AI によるコードレビューで以下の技術的負債が指摘された：

1. **FastAPI ブロッキング I/O**: `dashboard/api/main.py`のエンドポイントが`async def`で定義されているにもかかわらず、同期的なファイル I/O（`open()`, `json.load()`, `Path.iterdir()`）を実行していた。これによりイベントループがブロックされ、並行リクエスト処理に悪影響。

2. **広範な例外処理**: `except Exception: pass`や`except Exception`が多用され、エラーの診断が困難。

3. **未使用インポート**: `main.py`に未使用の`os`, `time`, `datetime`等が残存。

## 決定

### 1. FastAPI 同期関数化

`async def` → `def` に変更。FastAPI は同期関数を自動的にスレッドプールで実行するため、イベントループをブロックしない。

**理由**:

- 変更が最小限
- 真の非同期 I/O（aiofiles）は依存追加が必要で過剰
- FastAPI の標準機能で十分対応可能

### 2. 例外の特化

`except Exception` → `except (json.JSONDecodeError, OSError)` に変更。

**理由**:

- 予期しない例外を早期に発見可能
- デバッグ時間の短縮

### 3. ログ改善

- サイレント例外処理に`logger.debug()`を追加
- f-string ログ → lazy %s 形式に変更（パフォーマンス向上）

## 影響

### 変更ファイル

| ファイル                              | 変更内容                                        |
| ------------------------------------- | ----------------------------------------------- |
| `src/dashboard/api/main.py`           | async def → def、例外特化、エンコーディング明示 |
| `src/core/engine/master_conductor.py` | RAG エラーログ追加                              |
| `src/main.py`                         | 未使用インポート削除、インデント修正            |

### 副作用

- なし（動作互換維持）

## 代替案

### FastAPI

| 案                    | 評価                          |
| --------------------- | ----------------------------- |
| A. 同期関数化（採用） | ✅ 最小変更、FastAPI 標準機能 |
| B. aiofiles 使用      | ❌ 依存追加、大幅書き換え     |
| C. run_in_executor    | ❌ ボイラープレート増加       |

### 例外処理

| 案                         | 評価                    |
| -------------------------- | ----------------------- |
| A. 特定例外 + ログ（採用） | ✅ 診断可能、安全       |
| B. Result 型パターン       | ❌ 大規模リファクタ必要 |

## 検証

```bash
# 構文チェック
python3 -m py_compile src/main.py src/dashboard/api/main.py
# → PASS

# E2E検証
python3 src/main.py --help  # → 正常
python3 src/main.py --projects  # → 正常
```

## 関連

- CHANGELOG.md: [Unreleased] → Fixed セクション
- テスト: `tests/test_tech_debt_fixes_2026_01_05.py`
