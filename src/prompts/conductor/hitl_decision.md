以下のタスク実行結果について、ユーザーへの確認が必要か判定してください。

## タスク情報

- タスク名: {{ task_name }}
- エージェント: {{ agent_type }}
- アクション: {{ action }}

## 実行結果

{{ result | tojson(indent=2) }}

## 確認が必要なケース

1. HIGH/CRITICAL severity の脆弱性を発見した
2. 攻撃的なアクション（SQLi, 認証バイパス等）を実行しようとしている
3. スコープ外のリソースにアクセスしようとしている
4. 重要な方針変更が必要

## 出力

```json
{
  "requires_approval": true/false,
  "reason": "確認理由",
  "severity": "info/warning/critical",
  "summary": "ユーザーに表示するサマリー"
}
```
