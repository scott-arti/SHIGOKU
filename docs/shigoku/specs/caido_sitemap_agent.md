---
task_id: SGK-2026-0107
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Specification: Caido Sitemap Parser Agent

## 概要

CaidoのSitemapデータを解析し、SHIGOKUの攻撃エージェントが利用可能なエンドポイントリスト（`RichUrlContext`）を抽出する専門エージェントを構築します。
これにより、KatanaやGAUなどの外部ツールが見逃した、JavaScriptによって動的に生成されたリクエストやAPIエンドポイントを捕捉可能にします。

## 挙動

1.  **接続**: `CaidoSettings` に設定された API Token と URL を使用して Caido の GraphQL API に接続します。
2.  **プロジェクト特定**: 実行中のプロジェクト、または設定されたプロジェクト ID を取得します。
3.  **Sitemap取得**: GraphQL クエリを使用して、指定されたドメインに一致する Sitemap エントリを網羅的に取得します。
4.  **構造化**: 取得した生データを `RichUrlContext` モデルに変換します。
5.  **タスク化**: 抽出されたエンドポイントを `MasterConductor` に返し、後続の脆弱性スキャンタスクとしてスケジューリング可能にします。

## 変更範囲

- `src/core/agents/specialized/caido_sitemap_agent.py`: 新規作成
- `src/core/config/settings.py`: (実装済み) Caido設定の追加

## データモデル

出力は以下の形式の `RichUrlContext` リストとなります：

- `url`: フルURL
- `method`: HTTPメソッド
- `headers`: オリジナルのリクエストヘッダーの一部（認証情報の抽出用）
- `source`: "caido"

## 制約

- **EthicsGuard**: 抽出されたURLは必ず `EthicsGuard.check_scope()` を通過させる必要があります。
- **Timeout**: Caido API へのリクエストは 30秒 以上のタイムアウトを設定します。

## ユーザー承認事項

- [ ] Caido API Token の設定方法（`.env` に `SHIGOKU_CAIDO__TOKEN` を記述）の周知
- [ ] GraphQL スキーマの差異に対する適応ロジックの導入
