---
task_id: SGK-2026-0033
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# BizLogicHunter - ビジネスロジック脆弱性検証エージェント

**モジュールパス**: `src/agents/swarm/biz_logic_hunter.py`

---

## 概要 (Overview)

**BizLogicHunter** は、ビジネスロジックに起因する脆弱性を検証するエージェントです。従来のスキャナーでは検出が困難な「アプリケーション固有の論理的欠陥」を発見することを目的としています。

**検出対象の脆弱性**:

- **IDOR (Insecure Direct Object Reference)**: 他ユーザーのリソースへの不正アクセス
- **権限昇格 (Privilege Escalation)**: 一般ユーザーから管理者への権限昇格
- **Hidden Parameter Abuse**: 隠しパラメータによる機能改ざん
- **強制ブラウジング**: 保護されていない管理画面へのアクセス

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        BizLogicHunter                                │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Verification Engine                         │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  │   │
│  │  │ verify_idor  │ │verify_hidden │ │ verify_admin_access  │  │   │
│  │  │              │ │   _param     │ │                      │  │   │
│  │  └──────────────┘ └──────────────┘ └──────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Supporting Layer                            │   │
│  │  - RAGSwitch (attack pattern retrieval)                      │   │
│  │  - EthicsGuard (scope enforcement)                           │   │
│  │  - RotatingSession (IP rotation for detection evasion)       │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 主要機能 (Key Features)

### 1. IDOR 検証 (verify_idor)

オブジェクト ID 参照の不正アクセスをテストします。

#### 攻撃パターン

| パターン           | 説明                      | 例                                                |
| :----------------- | :------------------------ | :------------------------------------------------ |
| **Sequential ID**  | 連番 ID の増減            | `/api/users/100` → `/api/users/1`                 |
| **UUID Swap**      | 他ユーザーの UUID に置換  | `/api/docs/{our-uuid}` → `/api/docs/{other-uuid}` |
| **JSON Body ID**   | JSON ボディ内の ID 改ざん | `{"user_id": 100}` → `{"user_id": 1}`             |
| **Path Traversal** | パスでの ID 操作          | `/me/orders` → `/users/1/orders`                  |

#### 検証ロジック

```python
def verify_idor(self, context: VerifyContext) -> VerifyResult:
    """
    IDOR脆弱性を検証します。

    Steps:
    1. 元のリクエストを送信し、正常レスポンスを記録
    2. IDパラメータを別の値（他ユーザーのID）に変更
    3. 変更後のリクエストを送信
    4. レスポンスを比較：
       - 200 OK + 異なるデータ → IDOR確定
       - 403/404 → セキュア（検証不要）
       - 200 OK + 同じデータ → さらにテストが必要
    """
```

#### 使用例

```python
from src.agents.swarm import BizLogicHunter, VerifyContext

hunter = BizLogicHunter(ethics_guard=guard, session=session)

context = VerifyContext(
    original_request={
        "method": "GET",
        "url": "https://api.target.com/users/123/profile",
        "headers": {"Authorization": "Bearer ..."}
    },
    id_param="123",           # 元のユーザーID
    test_ids=["1", "0", "admin"]  # テストするID
)

result = hunter.verify_idor(context)
if result.vulnerable:
    print(f"🎯 IDOR Found! Accessed user {result.details['accessed_id']}")
```

---

### 2. Hidden Parameter 検証 (verify_hidden_param)

サーバーサイドで処理されるが、UI には露出していない「隠しパラメータ」を検出・悪用します。

#### 攻撃パターン

```python
# 一般的な隠しパラメータ候補
HIDDEN_PARAMS = [
    {"name": "role", "values": ["admin", "superuser", "staff"]},
    {"name": "is_admin", "values": ["true", "1", "yes"]},
    {"name": "is_verified", "values": ["true", "1"]},
    {"name": "discount", "values": ["100", "99", "-1"]},
    {"name": "debug", "values": ["true", "1"]},
    {"name": "internal", "values": ["true", "1"]},
]
```

#### 検証ロジック

```python
def verify_hidden_param(self, context: VerifyContext) -> VerifyResult:
    """
    隠しパラメータによる権限昇格をテストします。

    Steps:
    1. 元のリクエストを送信
    2. 候補パラメータをボディに追加して再送信
    3. レスポンスの変化を検出：
       - ステータスコードの変化
       - レスポンスボディの拡張（新しいフィールド出現）
       - 権限の変化（管理者機能へのアクセス）
    """
```

---

### 3. 管理画面アクセス検証 (verify_admin_access)

保護されていない管理画面や API エンドポイントへの直接アクセスをテストします。

#### チェック対象パス

```python
ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator",
    "/wp-admin", "/wp-login.php",
    "/manager", "/manage", "/dashboard",
    "/api/admin", "/api/v1/admin",
    "/internal", "/debug", "/console",
    "/phpmyadmin", "/adminer",
]
```

#### 検証ロジック

```python
def verify_admin_access(self, base_url: str) -> List[VerifyResult]:
    """
    管理画面への直接アクセスをテストします。

    Steps:
    1. 管理画面候補パスにリクエストを送信
    2. レスポンスを分析：
       - 200 OK → アクセス可能（要詳細確認）
       - 302 Redirect to Login → 保護済み
       - 403 Forbidden → 保護済み
       - 404 Not Found → パス不存在
    """
```

---

## RAG 統合 (Knowledge Augmentation)

BizLogicHunter は、Obsidian RAG からビジネスロジック攻撃パターンを動的に取得します。

### Obsidian メモ例

```markdown
# IDOR Techniques

## Pattern: User Profile Endpoint

`/api/users/{id}/profile` 形式のエンドポイントで、{id}を他ユーザーの ID に変更。

## Pattern: Order History

注文履歴 API で `order_id` を連番で走査し、他ユーザーの注文を取得。

## Bypass Tips

- UUID が使われていても、最初の数文字だけでマッチすることがある
- GraphQL の `node(id: "...")` クエリは特に脆弱
```

---

## API リファレンス

### クラス: `BizLogicHunter`

#### `__init__(self, ethics_guard: EthicsGuard, session: RotatingSession = None, rag_switch: RAGSwitch = None)`

#### `verify_idor(self, context: VerifyContext) -> VerifyResult`

IDOR 脆弱性を検証します。

#### `verify_hidden_param(self, context: VerifyContext) -> VerifyResult`

隠しパラメータの悪用可能性を検証します。

#### `verify_admin_access(self, base_url: str) -> List[VerifyResult]`

管理画面への不正アクセスをテストします。

### データクラス

```python
@dataclass
class VerifyContext:
    original_request: dict   # 元のHTTPリクエスト
    id_param: str            # テスト対象のIDパラメータ
    test_ids: List[str]      # テストするID値のリスト

@dataclass
class VerifyResult:
    vulnerable: bool         # 脆弱性の有無
    details: dict            # 詳細情報
    finding: Finding = None  # 自動生成されたFinding（脆弱な場合）
```

---

## Finding 生成

脆弱性が確認されると、自動的に Finding オブジェクトが生成されます。

```python
Finding(
    title="IDOR in User Profile API",
    severity=Severity.HIGH,
    vuln_type=VulnType.IDOR,
    description="The endpoint /api/users/{id}/profile allows...",
    evidence=[
        Evidence(
            request="GET /api/users/1/profile",
            response="{'name': 'Admin User', 'email': 'admin@...'}",
            screenshot=None
        )
    ],
    affected_url="https://api.target.com/users/1/profile"
)
```

---

## トラブルシューティング

### 症状: 全ての IDOR テストで 403 Forbidden が返る

**原因**: 適切なアクセス制御が実装されている（セキュア）
**解決策**: これは正常。別のエンドポイントをテストするか、認証トークンを確認。

### 症状: 隠しパラメータテストで WAF にブロックされる

**原因**: パラメータ追加が WAF ルールをトリガー
**解決策**: `ProxyRotation` で IP を回転させ、リクエスト頻度を下げる。
