---
task_id: SGK-2026-0129
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# IDOR Enhancement Phase 2 & 3: Mass Assignment & Body Parsing

## 概要

`IdorHunterSpecialist` を拡張し、以下の2つの高度な検証能力を追加する。

1. **Mass Assignment（BOPLA）検知**: リクエストBodyに特権プロパティを注入し、意図しない権限昇格・プロパティ変更が可能かをテスト
2. **Form/URLEncoded Body 対応**: JSON以外のBody形式（`application/x-www-form-urlencoded`）を正確にパース・改変する能力の統合

## 変更範囲

### 新規ファイル

- `src/core/agents/swarm/logic/body_mutator.py` — Body解析・改変ユーティリティ（JSON / URLEncoded / 将来のMultipart対応）

### 変更ファイル

- `src/core/agents/swarm/logic/idor.py` — Mass Assignment テストメソッド追加、BodyMutator統合
- `tests/core/agents/swarm/test_idor.py` — テストケース追加

---

## 設計

### 1. BodyMutator クラス（新規）

Body の解析・改変ロジックを `IdorHunterSpecialist` から分離する。

```python
class BodyMutator:
    """Content-Type に応じて Body を安全にパース・改変するユーティリティ"""

    @staticmethod
    def detect_content_type(headers: Dict, body: Optional[str]) -> str:
        """Content-Type を判定。ヘッダ優先、なければBody内容からヒューリスティック推定"""
        # 1. headers["content-type"] を確認
        # 2. なければ body が "{" で始まるなら json、"key=value" 形式なら urlencoded
        # 3. 判定不能なら "unknown"

    @staticmethod
    def parse(body: str, content_type: str) -> Dict[str, Any]:
        """Body を辞書型に変換"""

    @staticmethod
    def serialize(data: Dict[str, Any], content_type: str) -> str:
        """辞書型を Body 文字列に再変換"""

    @staticmethod
    def inject_properties(body: str, content_type: str, props: Dict[str, Any]) -> str:
        """既存Bodyにプロパティを注入した新しいBody文字列を返す"""

    @staticmethod
    def replace_value(body: str, content_type: str, key_pattern: str, old_val: str, new_val: str) -> str:
        """既存Bodyの特定キーの値を置換した新しいBody文字列を返す"""
```

**設計意図**: `IdorHunterSpecialist` は「何をテストするか」に集中し、`BodyMutator` は「Body をどう操作するか」に集中する。将来の Multipart 対応も `BodyMutator` にメソッドを追加するだけで済む。

### 2. Mass Assignment テストフロー

```
[元リクエスト (POST /api/users)]
    ↓
[特権プロパティ候補を決定]
    ├── ハードコードリスト: role, is_admin, admin, premium, group_id, plan, ...
    └── 動的抽出: ベースラインGETから「元Bodyに含まれないフィールド」を差分で検出
    ↓
[BodyMutator.inject_properties() で注入]
    ↓
[POST/PUT 送信]
    ↓
[Write-then-Read 2段階検証]
    ├── Step 1: レスポンスに注入プロパティが含まれるか（エコーバック確認）
    └── Step 2: 同じリソースを GET で再取得し、そこにも反映されているか
    ↓
[両方に反映 → Finding (HIGH/CRITICAL)]
[エコーバックのみ → 無視 (False Positive 回避)]
```

> **重要**: Write-then-Read は「注入後にGETで確認」するため、**対象リソースのGET URLが必要**。これは以下の方法で推定する：
>
> - `POST /api/users` → `GET /api/users/{returned_id}`（レスポンスの `id` フィールドを使用）
> - `PUT /api/users/123` → `GET /api/users/123`（同じURL、メソッドだけ変更）
> - 推定不可能な場合はStep 1（エコーバック確認）のみで `Severity.LOW` の Potential として報告

### 3. Content-Type の伝播経路

Caido → `CaidoSitemapAgent` → `SwarmDispatcher` → `IdorHunterSpecialist` の流れで、`params` に以下を含める：

```python
params = {
    "method": "POST",
    "headers": {"Content-Type": "application/x-www-form-urlencoded", ...},
    "body": "user_id=123&name=test",
    ...
}
```

`BodyMutator.detect_content_type()` は `params["headers"]` から Content-Type を読み取る。ヘッダが欠落している場合は Body 内容からヒューリスティックに推定する（`{` で始まる → JSON、`key=value&` パターン → URLEncoded）。

---

## テストシナリオ

### テスト1: Mass Assignment 成功（Write-then-Read 確認）

```
入力: POST /api/users, Body: {"name": "test"}
注入: {"name": "test", "role": "admin"}
期待: POST → 200, GET /api/users/{id} → Body に "role": "admin" が含まれる → Finding (HIGH)
```

### テスト2: Mass Assignment False Positive 回避

```
入力: POST /api/users, Body: {"name": "test"}
注入: {"name": "test", "is_admin": true}
期待: POST → 200 (エコーバックあり), GET /api/users/{id} → "is_admin" が含まれない → Finding なし
```

### テスト3: URLEncoded Body の IDOR（ID置換）

```
入力: POST /api/profile, Content-Type: x-www-form-urlencoded, Body: "user_id=123&name=test"
操作: user_id=456 に置換
期待: POST → 200, Secret検出 → Finding (HIGH)
```

### テスト4: URLEncoded Body の Mass Assignment

```
入力: PUT /api/settings, Content-Type: x-www-form-urlencoded, Body: "theme=dark"
注入: "theme=dark&role=admin"
期待: PUT → 200, GET /api/settings → role=admin が反映 → Finding (CRITICAL)
```

### テスト5: 動的プロパティ抽出

```
入力: GET /api/users/me → {"name": "test", "email": "a@b.com", "plan": "free", "credits": 0}
元POST Bodyのキー: ["name", "email"]
差分: ["plan", "credits"] → これらが Mass Assignment 候補に追加される
```

---

## 制約

- **RequestGuard 連携必須**: POST/PUT/PATCH のテストは `user_approved=True` または CTF モード時のみ実行
- **既存テストへの悪影響ゼロ**: 既存の `_test_id_manipulation` の JSON パーサーを `BodyMutator` に移行するが、振る舞いは変えない
- **BodyMutator はステートレス**: 全メソッドが `@staticmethod` で、外部状態に依存しない純粋関数として実装する
