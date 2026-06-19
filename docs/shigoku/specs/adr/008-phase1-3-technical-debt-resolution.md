---
task_id: SGK-2026-0021
doc_type: spec
doc_usage: historical_completion_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ADR-008: Phase 1-3 技術的負債解消リファクタリング

> 2026-06-19 注記: この ADR は Phase 1-3 リファクタリング完了後の履歴資料です。本文の `pydantic-settings` 導入、`safe_subprocess`、`AgentRegistry`、`asset_loader` に対応する現行実装があり、後続の [ADR-009](009-tech-debt-resolution-complete.md) にも接続しています。

**日付**: 2026-01-05  
**ステータス**: Accepted  
**決定者**: AI Assistant + Human Review

---

## コンテキスト

SHIGOKU プロジェクトには以下の技術的負債が蓄積していた:

1. **セキュリティ問題**: ハードコードされた秘密情報、安全でない subprocess 呼び出し
2. **アーキテクチャ問題**: 分散したエージェント登録、`factory.py`と`agent_registry.py`の重複
3. **保守性問題**: エージェント内にハードコードされた Payload/定数

## 決定

3 フェーズに分けてリファクタリングを実施:

### Phase 1: Security Fixes

| 変更                   | ファイル                               |
| ---------------------- | -------------------------------------- |
| pydantic-settings 導入 | `src/config.py`                        |
| Jinja2 テンプレート化  | `src/templates/*.j2`                   |
| 安全な subprocess      | `src/core/security/safe_subprocess.py` |

### Phase 2: Architecture Unification

| 変更               | ファイル                            |
| ------------------ | ----------------------------------- |
| AgentRegistry 統合 | `src/core/engine/agent_registry.py` |
| AgentFactory 連携  | `src/core/factory.py`               |
| BaseAgent 標準化   | `src/agents/swarm/*.py`             |

### Phase 3: Data Decoupling

| 変更             | ファイル                                 |
| ---------------- | ---------------------------------------- |
| AssetLoader 実装 | `src/core/utils/asset_loader.py`         |
| Payload 外部化   | `src/assets/payloads/auth_payloads.yaml` |

## 結果

### ポジティブ

- 環境変数ベースの設定管理でセキュリティ向上
- `@register_agent`デコレータによる自動エージェント登録
- Payload の外部 YAML ファイル化で編集・拡張が容易に

### ネガティブ

- `AgentConfig`の必須フィールド追加による初期化コードの冗長化
- `BaseAgent.name`プロパティとの競合解消が必要だった

## 検証結果

```
pytest: 496 passed, 18 failed (既存問題)
E2E: exit code 0, RECON PHASE正常起動
```

## 関連 ADR

- [ADR-002: Agent Interface Protocol](002-agent-interface-protocol.md)
- [ADR-007: Prompts Rename and Utils Package](007-prompts-rename-and-utils-package.md)
