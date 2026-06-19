---
task_id: SGK-2026-0036
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# EthicsGuard - 倫理ガードレールシステム

**モジュールパス**: `src/core/security/ethics_guard.py`

---

## 概要 (Overview)

**EthicsGuard** は、SHIGOKU の全トラフィックを監視・制御する「安全装置」です。バグバウンティプログラムにおける最も重大なリスクの一つである「スコープ外への誤った攻撃」を物理的・論理的に防止します。

従来のペネトレーションテストツールでは、オペレーターがスコープを「意識して」操作する必要がありましたが、EthicsGuard はこれを「強制」します。設定されたスコープ外の URL へのリクエストは、ネットワークに到達する前にブロックされます。

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│                         SHIGOKU Agent                           │
│  (AuthNinja, BizLogicHunter, Cartographer, etc.)                │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTP Request
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                       EthicsGuard                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │ Scope Check │ →│ Rate Limit  │ →│ Disallowed Path Check   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
│         │                                     │                 │
│         ▼                                     ▼                 │
│    ┌─────────┐                          ┌─────────┐             │
│    │  ALLOW  │                          │  BLOCK  │             │
│    └────┬────┘                          └────┬────┘             │
│         │                                    │                  │
└─────────┼────────────────────────────────────┼──────────────────┘
          ▼                                    ▼
   ┌─────────────┐                      ┌─────────────────┐
   │   Network   │                      │ ScopeViolation  │
   │   Request   │                      │     Error       │
   └─────────────┘                      └─────────────────┘
```

---

## 主要機能 (Key Features)

### 1. スコープ強制 (Scope Enforcement)

すべての HTTP リクエストは、送信前にスコープ定義ファイル（`scope.yaml`）と照合されます。

**マッチングロジック**:

1. **Out of Scope チェック**: URL が `out_of_scope` リストにマッチするか確認。マッチすれば即時ブロック。
2. **In Scope チェック**: URL が `in_scope` リストにマッチするか確認。マッチしなければブロック（デフォルト・デナイ）。

**ワイルドカードサポート**:

- `*.example.com`: サブドメイン（例: `api.example.com`, `www.example.com`）にマッチ。
- `example.com`: ルートドメインのみにマッチ（サブドメインは含まない）。

```python
# 内部ロジック例
def is_in_scope(self, url: str) -> bool:
    parsed = urlparse(url)
    host = parsed.netloc

    # Step 1: Out of Scope check (ブラックリスト優先)
    if self._matches_patterns(host, self.out_of_scope_domains):
        return False

    # Step 2: In Scope check (ホワイトリスト)
    if self._matches_patterns(host, self.in_scope_domains):
        return True

    # Default deny
    return False
```

### 2. レートリミット (Rate Limiting)

ターゲットサーバーへの過負荷や、WAF/IDS による検知を避けるため、リクエスト頻度を制御します。

| 設定項目              | デフォルト値 | 説明                           |
| :-------------------- | :----------- | :----------------------------- |
| `requests_per_minute` | 60           | 1 分間あたりの最大リクエスト数 |
| `burst_limit`         | 120          | 短期間でのバースト許容数       |
| `cooldown_seconds`    | 10           | 制限超過時のスリープ時間       |

**実装詳細**:

- トークンバケットアルゴリズムを使用。
- ドメインごとに独立したバケットを管理。

### 3. 禁止パス (Disallowed Paths)

特定のパスへのアクセスを無条件でブロックします。これは、アクションを実行すると不可逆な影響を与える可能性があるエンドポイントを保護するためです。

**デフォルトの禁止パス**:

- `/logout`, `/signout`: セッション破棄
- `/delete/*`, `/remove/*`: データ削除
- `/unsubscribe/*`: 登録解除
- `/admin/shutdown`: サービス停止

```yaml
# scope.yaml での設定例
disallowed_paths:
  - "/api/v1/users/*/delete"
  - "/settings/deactivate"
```

---

## 設定ファイル (`scope.yaml`) の詳細

### 完全なスキーマ

```yaml
# ===== スコープ定義 =====
in_scope:
  # 許可するドメイン（ワイルドカード使用可）
  domains:
    - "api.target.com"
    - "*.staging.target.com"
  # 許可するIPアドレス
  ips:
    - "192.168.1.100"
  # 許可するCIDR
  cidrs:
    - "10.0.0.0/24"

out_of_scope:
  # 明示的に禁止するドメイン
  domains:
    - "auth.target.com"
    - "*.internal.target.com"
  # 禁止するIP
  ips:
    - "127.0.0.1"
  # 禁止するCIDR
  cidrs:
    - "172.16.0.0/12"

# ===== レートリミット =====
rate_limit:
  requests_per_minute: 120
  burst_limit: 200
  cooldown_seconds: 5

# ===== 禁止パス =====
disallowed_paths:
  - "/logout"
  - "/api/*/destroy"
```

---

## API リファレンス

### クラス: `EthicsGuard`

#### `__init__(self, scope_file: str = None)`

EthicsGuard インスタンスを初期化します。

**パラメータ**:

- `scope_file` (str, optional): スコープ定義 YAML ファイルのパス。指定しない場合、デフォルトで「全ブロック」モードで起動。

#### `is_allowed(self, url: str) -> bool`

指定された URL がスコープ内かどうかを判定します。

**戻り値**: `True` (許可) / `False` (ブロック)

#### `check_and_wait(self, domain: str) -> None`

レートリミットをチェックし、必要であればスリープします。

#### `load_scope(self, scope_file: str) -> None`

スコープ定義を（再）読み込みします。

#### `get_stats(self) -> dict`

EthicsGuard の統計情報を返します。

- `total_allowed`: 許可されたリクエスト数
- `total_blocked`: ブロックされたリクエスト数
- `blocked_reasons`: ブロック理由の内訳

---

## 使用例 (Usage Examples)

### 基本的な使用法

```python
from src.core.security import EthicsGuard

# EthicsGuardの初期化
guard = EthicsGuard(scope_file="scopes/example_program.yaml")

# URLをチェック
url = "https://api.target.com/users/1"
if guard.is_allowed(url):
    print(f"✅ ALLOWED: {url}")
    # リクエストを実行
else:
    print(f"❌ BLOCKED: {url}")
    # リクエストをスキップ
```

### エージェントとの統合

```python
from src.core.security import EthicsGuard
from src.agents.swarm import AuthNinja

# 共有のEthicsGuardインスタンス
guard = EthicsGuard(scope_file="scopes/target.yaml")

# エージェントにガードを注入
ninja = AuthNinja(ethics_guard=guard)

# 攻撃実行（内部でEthicsGuardがチェック）
result = ninja.execute("https://api.target.com/login", context)
```

---

## エラーハンドリング

### `ScopeViolationError`

スコープ外の URL へのアクセスがブロックされた際に発生します。

```python
from src.core.security import ScopeViolationError

try:
    session.get("https://google.com")  # スコープ外
except ScopeViolationError as e:
    print(f"Scope violation: {e.url}")
    print(f"Reason: {e.reason}")
```

---

## トラブルシューティング

### 症状: 全てのリクエストがブロックされる

**原因**: スコープファイルが見つからない、または破損している。
**解決策**: `scope.yaml` のパスを確認し、YAML 構文エラーがないかチェックしてください。

```bash
# YAML構文チェック
python -c "import yaml; yaml.safe_load(open('scopes/target.yaml'))"
```

### 症状: サブドメインがブロックされる

**原因**: `example.com` のみを指定しており、ワイルドカードを使っていない。
**解決策**: `*.example.com` と `example.com` の両方をスコープに追加してください。

---

## セキュリティ考慮事項

1. **フェイルセーフ**: スコープファイルの読み込みに失敗した場合、EthicsGuard は「**Deny All**」モードで起動します。これにより、設定ミスによるスコープ外攻撃を防ぎます。

2. **ログ記録**: すべてのブロックイベントは詳細なログとして記録されます。事後監査に使用できます。

3. **改ざん防止**: EthicsGuard は実行時にバイパスできません。エージェントは EthicsGuard を経由せずにネットワークにアクセスする手段を持ちません。
