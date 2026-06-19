---
task_id: SGK-2026-0019
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# 006. バグ修正と例外処理方針の改善

日付: 2026-01-05

## ステータス

Accepted

## コンテキスト

包括的なバグ調査（Bug Analysis and Review）の結果、以下の問題が特定された。

1.  **Critical Bug**: `shared_workspace.py` において、NDJSON（改行区切り JSON）ファイルを読み込む際に `json.load(f)` を誤ってループ内で使用していた。これにより `search_intel()` 機能が完全に動作不能となっていた。
2.  **Bad Practice**: 複数のファイル（9 箇所）において、`except:` （bare except）が使用されており、`KeyboardInterrupt` や `SystemExit` などのシステム例外まで捕捉してしまう状態だった。これはデバッグを困難にし、予期せぬ挙動を引き起こすリスクがある。

## 決定

システムの信頼性と保守性を向上させるため、以下の修正と方針を適用する。

### 1. JSON 読み込み処理の適正化

NDJSON 形式（JSONL）のファイルを処理する場合、ファイルオブジェクト全体を `json.load()` に渡すのではなく、行ごとに `json.loads()` でパースする実装に修正する。

```python
# Before (Bug)
for line in f:
    data = json.load(f)  # ファイル全体を読もうとして失敗する

# After (Fix)
for line in f:
    if line.strip():
        data = json.loads(line)
```

### 2. 例外処理の厳密化

`except:` (bare except) の使用を原則禁止し、捕捉すべき具体的な例外型を指定する。

- **JSON 処理**: `except json.JSONDecodeError:` を使用し、パースエラーのみを捕捉してスキップする。
- **リソース解放/通信**: `docker.py` のコンテナクリーンアップや `auth_ninja.py` のネットワーク通信など、広範なエラーを捕捉する必要がある場合でも、最低限 `except Exception:` を使用し、システム例外（`BaseException`由来）を捕捉しないようにする。

## 影響

- **信頼性向上**: `shared_workspace` の機能が正常に動作するようになり、データの保存・検索の信頼性が回復した。
- **デバッグ効率向上**: 予期せぬエラーが隠蔽されなくなり、根本原因の特定が容易になった。
- **安全性**: プロセス中断（Ctrl+C）などが適切に機能するようになった。
