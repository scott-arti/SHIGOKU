---
task_id: SGK-2026-0204
doc_type: work_log
status: done
parent_task_id: null
related_docs: []
created_at: '2026-01-06'
updated_at: '2026-05-19'
---

# Work Log: 双方向 PII マスキング機能実装

**日時**: 2026-01-06
**担当**: AntiGravity

## 概要

AI API（OpenAI 等）へのコンテキスト送信前に PII/機密情報をマスクし、ツール実行時に復元する双方向マスキング機能を実装しました。

## 実装内容

### 新規作成

- `src/core/security/pii_masker.py` - PIIMasker クラス、トークン化方式によるマスク/復元
- `tests/test_pii_masker.py` - 26 件のユニットテスト

### 変更

- `src/core/agent.py` - `_execute_tool_wrapper()`に PII トークン復元処理追加
- `src/core/models/llm.py` - `generate()`/`agenerate()`に PII マスク処理追加
- `src/core/security/__init__.py` - PIIMasker 関連のエクスポート追加

### ドキュメント更新

- `CHANGELOG.md` - PII マスキング機能を Unreleased に追加
- `README.md` - コアインフラテーブルに PIIMasker 追加
- `docs/TECHNICAL_SPEC_JA.md` - security ディレクトリ構成に pii_masker.py 追加

## データフロー

```
ユーザー入力 → Agent → LLMClient.generate() → [PIIMasker.mask_messages()]
    → 外部AI (マスク済み) → Tool Call応答
    → Agent._execute_tool_wrapper() → [PIIMasker.unmask_dict()]
    → ツール実行 (生データ使用)
```

## 対応パターン

- API キー: OpenAI, AWS, GitHub, Slack, Stripe, Google, Discord
- 認証トークン: JWT, Bearer Token
- 個人情報: メール、電話番号(JP)、クレジットカード、IP アドレス、UUID
- 秘密鍵: RSA, EC, DSA, OpenSSH
- その他: マイナンバー

## テスト結果

26 テスト全てパス
