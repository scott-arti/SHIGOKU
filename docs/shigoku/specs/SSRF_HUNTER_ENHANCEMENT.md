---
task_id: SGK-2026-0099
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# SmartCmdSSRFHunter 強化仕様書

## 概要
`SmartCmdSSRFHunter` を SHIGOKU の「自律型高度 VAPT エージェント」として進化させます。
現在の基本的な SSRF 検知機能に加え、多様なエンコーディング、WAF バイパス、クラウド固有のメタデータエンドポイントの自動抽出、および AI によるコンテキストに応じたペイロード調整機能を統合します。

## 変更範囲
- `src/core/agents/swarm/smart_cmd_ssrf_hunter.py`: ロジックの刷新（高度な回避策の統合）
- `src/core/agents/base.py` (オプション): 必要に応じて、SSRF 以外のエージェントでも使える回避策の抽象化を確認（現状は既存機能で十分）
- `src/core/security/ethics_guard.py`: メタデータアクセスのスキャンにおける例外・安全策の再導入（内部ネットワークへの攻撃防止を維持しつつ）

## 挙動
1. **インテリジェント・リコン**: パラメータ名（url, link, src, etc.）から SSRF 可能性を自動検知。
2. **高度な回避策 (Evasion)**:
    - IP アドレスの各種エンコーディング（十進数、十六進数、省略形）。
    - DNS Rebinding 候補の自動生成。
    - WAF バイパス用の特殊文字注入。
3. **クラウド・メタデータ探索**: AWS, Azure, GCP, Kubernetes 等の内部非公開エンドポイントをターゲットに応じて自動選択。
4. **フィードバックループ**: OAST (Out-of-Band Application Security Testing) ツールの結果を `SharedWorkspace` 経由で受け取り、追加スキャンを自律実行。

## 制約
- **EthicsGuard 準拠**: スキャン対象のスコープ外、または禁止された内部 NW への直接攻撃は `ethics_guard.check_scope` によって厳格に制限される。
- **リソース制限**: `AdaptiveRateLimiter` を使用し、ターゲットサーバーへの負荷を最小限に抑える。

## テスト計画
- **Unit Test**: `pytest tests/agents/test_smart_cmd_ssrf_hunter.py` を作成し、各回避策のペイロード生成ロジックを検証。
- **Mock E2E**: ローカルの脆弱なエンドポイント（SSRF 脆弱性あり）に対してスキャンを実行し、検知能力を確認。
