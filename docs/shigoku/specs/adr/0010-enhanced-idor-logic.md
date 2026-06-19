---
task_id: SGK-2026-0014
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# ADR 0010: Enhanced IDOR Logic and Mass Assignment Testing

## ステータス

承認済み

## コンテキスト

SHIGOKU の IDOR (Insecure Direct Object Reference) 検知能力を強化するため、以下の課題に対応する必要があった：

1. **Mass Assignment (BOPLA) の欠如**: 特権プロパティ（`role`, `is_admin` 等）を注入して権限昇格を試みるテストが未実装であった。
2. **JSON 以外のボディフォーマット未対応**: `application/x-www-form-urlencoded` 等のボディに含まれる ID を操作できなかった。
3. **偽陽性（False Positive）のリスク**: 単にレスポンスに注入した値が含まれるだけでは（エコーバック）、実際に値が書き換わったか（永続化）を判断できず、誤検知の原因となっていた。

## 決定事項

以下の設計・実装を採用した：

### 1. `BodyMutator` ユーティリティの導入

ボディのパース、シリアライズ、ID抽出、値置換、プロパティ注入を行う独立したクラス `src/core/agents/swarm/logic/body_mutator.py` を作成した。

- JSON および `application/x-www-form-urlencoded` をサポート。
- ヘッダとボディの内容から Content-Type を自動推定するヒューリスティック機能を搭載。

### 2. Mass Assignment (BOPLA) テストの実装

`IdorHunterSpecialist` に `_test_mass_assignment` メソッドを追加した。

- **動的候補抽出**: Baseline GET レスポンスから、POST/PUT ボディには存在しないがリソースには存在するキーを「注入候補」として抽出。
- **Write-then-Read 検証**: 値を注入してリクエストした直後、GET リクエストを再実行して値が実際に保存されたかを比較検証。これによりエコーバックによる誤検知を完全に排除。

### 3. URLEncoded ID 操作のサポート

既存の ID Manipulation ロジックを `BodyMutator` 経由にリファクタリングし、URL-encoded ボディ内の ID 操作も可能にした。

### 4. ガードレールの遵守

- `safe_mode` および `user_approved` フラグを厳格にチェック。
- 破壊的な操作（POST/PUT等）は、ユーザーの明示的な承認がある場合のみ実行されるよう制御。

## 影響

- **検知率の向上**: API 固有の特権昇格脆弱性（BOPLA）を発見可能になった。
- **汎用性の向上**: レガシーな Web アプリや単純なフォーム送信 API に対しても IDOR テストが可能になった。
- **信頼性の向上**: Write-then-Read 検証により、確実性の高い（High Severity）発見のみを報告可能になった。

## 関連ファイル

- `src/core/agents/swarm/logic/body_mutator.py` (New)
- `src/core/agents/swarm/logic/idor.py` (Enhanced)
- `tests/core/agents/swarm/logic/test_body_mutator.py` (New)
- `tests/core/agents/swarm/logic/test_idor_mass_assignment.py` (New)
