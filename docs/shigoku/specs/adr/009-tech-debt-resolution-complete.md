---
task_id: SGK-2026-0022
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# ADR-009: 技術的負債解消（Phase 0-4 完了）

## ステータス

**承認済み** (2026-01-05)

## コンテキスト

SHIGOKU プロジェクトには以下の技術的負債が蓄積していた：

1. **エントリポイント分断**: `src/main.py` と `src/__main__.py` が二重管理
2. **エージェントインターフェース不統一**: `execute()` と `process()` が混在
3. **Factory の複雑性**: if-elif ブロックによるハードコード
4. **設定のハードコード**: 脆弱性情報やツール設定がコード内に埋め込み
5. **レガシーコード**: `sys.path` ハック、非推奨 Runner クラス

## 決定

5 つの Phase に分けて段階的にリファクタリングを実施：

### Phase 0: 準備（ADR + テスト）

- ADR-001, ADR-002 を作成し設計判断を記録
- エントリポイントテストを追加（回帰防止）

### Phase 1: インターフェース統一

- `AgentProtocol` を `src/core/agents/protocol.py` に定義
- 全エージェントに `run()` メソッドを実装
- `create_run_result()` で戻り値フォーマット統一

### Phase 2: Factory リファクタリング

- `@register_agent` デコレータを導入
- `src/core/engine/agent_registry.py` でエージェント登録管理
- `AgentFactory` をレジストリベースに変更

### Phase 3: 設定一元化

- `config/vulnerabilities.yaml`: 脆弱性タイプ定義（11 種類）
- `config/tools.yaml`: ツールプロファイル定義
- `_load_yaml_cached()` で lru_cache によるキャッシング
- `auto_reporter.py` から 62 行の VULN_TYPE_INFO 辞書を削除

### Phase 4: レガシー削除

- `src/__main__.py` を 64 行 → 10 行に簡素化（リダイレクトのみ）
- `src/main.py` から `sys.path.insert()` を削除
- `Runner` と `CLI` クラスに `[DEPRECATED]` マーク追加

## 結果

### 定量的効果

| 指標                              | Before                  | After           | 改善       |
| --------------------------------- | ----------------------- | --------------- | ---------- |
| `__main__.py` 行数                | 64 行                   | 10 行           | -84%       |
| `auto_reporter.py` VULN_TYPE_INFO | 62 行                   | 0 行            | -100%      |
| エージェント追加時の修正箇所      | Factory の if-elif 追加 | デコレータ 1 行 | 大幅簡素化 |

### 作成・修正ファイル

**新規作成:**

- `src/core/agents/protocol.py` - AgentProtocol 定義
- `src/core/engine/agent_registry.py` - エージェントレジストリ
- `config/vulnerabilities.yaml` - 脆弱性定義
- `config/tools.yaml` - ツール設定
- `tests/core/test_phase4_regression.py` - 回帰テスト（14 件）
- `tests/core/test_factory_registry.py` - Factory テスト（5 件）
- `tests/core/test_config_yaml.py` - YAML テスト

**修正:**

- `src/core/agents/base.py` - `run()` メソッド追加
- `src/core/factory.py` - レジストリベースに変更
- `src/config.py` - YAML ローダー追加
- `src/core/reports/auto_reporter.py` - ハードコード削除
- `src/__main__.py` - リダイレクト化
- `src/main.py` - sys.path 削除

### テスト結果

```
tests/core/test_phase4_regression.py ... 14 passed
tests/core/test_factory_registry.py .... 5 passed
```

### 3 点チェック（インターフェース・ロジック・副作用）

✅ **インターフェース**: 外部 API 変更なし（shigoku コマンド動作維持）  
✅ **ロジック**: 条件分岐削除のみ（legacy モード廃止）  
✅ **副作用**: YAML ファイル読み込み追加（lru_cache でキャッシュ）

## 注意事項

1. `pip install -e .` または `PYTHONPATH` 設定が必要（sys.path 削除による）
2. `Runner` と `CLI` は非推奨化のみ、即削除せず（後方互換性維持）
3. `main.py` Line 299 に既存 Lint エラーあり（本件とは無関係）

## 関連 ADR

- ADR-001: エントリポイント統一
- ADR-002: エージェントインターフェースプロトコル
- ADR-008: Phase 1-3 技術的負債解消（本 ADR で完了）
