---
task_id: SGK-2026-0131
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# 脆弱性連鎖（Vulnerability Chaining）の仕様書

## 概要

エージェントが脆弱性を発見した際、その情報を`EventBus`経由で`MasterConductor`が受け取り、関連する高度な検査タスクを自動的に生成・追加する仕組みを実装します。これにより、単発の検査に留まらず、多角的な自律攻撃を実現します。

## 変更範囲

- `src/core/engine/master_conductor.py`: `VULN_FOUND` イベントのリスナー実装とタスク追加ロジック。
- `src/core/models/finding.py`: チェイニングに必要な情報の追加（もし不足していれば）。

## 挙動 (Chaining Logic)

| 発見された脆弱性             | トリガーされるアクション     | 目的                                                   |
| :--------------------------- | :--------------------------- | :----------------------------------------------------- |
| IDOR (情報漏洩)              | `AuthEscalation` タスク      | 他のユーザーIDでも再現するか、権限昇格が可能かを確認   |
| 認証回避 (Auth Bypass)       | `PrivilegeEscalation` タスク | 管理機能へのアクセスが可能か確認                       |
| 機密情報の露出 (Secret Leak) | `Discovery` タスク           | 露出したキーを使用してさらなるエンドポイントを探索     |
| 重要なエンドポイント発見     | `Injection` / `Logic` タスク | 発見された高機微エンドポイントに対して全スキャンを実施 |

## 制約

- **無限ループ防止**: 同一ターゲット・同一脆弱性タイプに対する連鎖は1レベルまでとし、循環参照を防止する。
- **EthicsGuard**: 連鎖タスクもすべて `EthicsGuard` のスコープチェックを通過させる。

## 承認待ち

- どの程度の深さまで連鎖させるべきか？（初期段階では1段階のみを推奨）
