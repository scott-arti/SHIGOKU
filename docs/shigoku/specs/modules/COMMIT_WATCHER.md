---
task_id: SGK-2026-0035
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# CommitWatcher - Git リポジトリ監視エージェント

**モジュールパス**: `src/core/intel/commit_watcher.py`

---

## 概要 (Overview)

**CommitWatcher** は、GitHub 上のパブリックリポジトリを監視し、コミットに含まれるシークレット（API キー、パスワード、トークンなど）を検出するエージェントです。

**ユースケース**:

- ターゲット企業の OSS リポジトリを監視し、誤ってコミットされた認証情報を発見
- 新規コミットをリアルタイムでスキャンし、「ゼロデイ」漏洩を検出
- 開発者の不注意による情報漏洩を迅速に報告

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         CommitWatcher                                │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   GitHub API Client                           │   │
│  │  - Fetch Commits (since last check)                          │   │
│  │  - Fetch Diffs / Patches                                     │   │
│  │  - Rate Limit Handling                                       │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Secret Scanner Engine                       │   │
│  │  ┌──────────────────────────────────────────────────────┐    │   │
│  │  │              Pattern Matching (Regex)                 │    │   │
│  │  │  - AWS Keys                - GCP/Azure Keys          │    │   │
│  │  │  - Private Keys (RSA/SSH)  - Database Credentials    │    │   │
│  │  │  - API Tokens (Stripe, Twilio, etc.)                 │    │   │
│  │  │  - JWT Secrets             - Generic Passwords       │    │   │
│  │  └──────────────────────────────────────────────────────┘    │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                   Finding Generator                           │   │
│  │  - Create Finding objects for each detected secret           │   │
│  │  - Attach evidence (commit SHA, file path, line number)      │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## シークレット検出パターン (Detection Patterns)

CommitWatcher は、以下のカテゴリのシークレットを検出するための正規表現パターンを内蔵しています。

### AWS 認証情報

| パターン名        | 正規表現                               | 例                          |
| :---------------- | :------------------------------------- | :-------------------------- |
| AWS Access Key ID | `AKIA[0-9A-Z]{16}`                     | `AKIAIOSFODNN7EXAMPLE`      |
| AWS Secret Key    | `[0-9a-zA-Z/+]{40}` (コンテキスト依存) | `wJalrXUtnFEMI/K7MDENG/...` |

### クラウドプロバイダ

| パターン名              | 検出対象                                |
| :---------------------- | :-------------------------------------- |
| GCP Service Account     | `"type": "service_account"` を含む JSON |
| Azure Connection String | `DefaultEndpointsProtocol=...`          |
| DigitalOcean Token      | `dop_v1_[a-z0-9]{64}`                   |

### API トークン

| サービス       | パターン                      |
| :------------- | :---------------------------- |
| Stripe API Key | `sk_live_[0-9a-zA-Z]{24}`     |
| Twilio API Key | `SK[0-9a-f]{32}`              |
| Slack Token    | `xox[baprs]-[0-9]{10,13}-...` |
| GitHub Token   | `ghp_[a-zA-Z0-9]{36}`         |
| GitLab Token   | `glpat-[a-zA-Z0-9\-]{20}`     |

### 秘密鍵

| 種類            | 検出パターン                            |
| :-------------- | :-------------------------------------- |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----`       |
| SSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----`   |
| PGP Private Key | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |

### データベース

| パターン名            | 検出対象                   |
| :-------------------- | :------------------------- |
| MySQL Connection      | `mysql://.*:.*@`           |
| PostgreSQL Connection | `postgres://.*:.*@`        |
| MongoDB URI           | `mongodb(\+srv)?://.*:.*@` |
| Redis URL             | `redis://.*:.*@`           |

### 汎用パターン

| パターン名       | 検出対象                              |
| :--------------- | :------------------------------------ |
| Generic Password | `password\s*[:=]\s*['"][^'"]{8,}['"]` |
| API Key Variable | `api_key\s*[:=]\s*['"][^'"]+['"]`     |
| Secret Variable  | `secret\s*[:=]\s*['"][^'"]+['"]`      |
| Bearer Token     | `Bearer [a-zA-Z0-9\-_.]+`             |

---

## 主要機能 (Key Features)

### 1. リポジトリ監視 (watch_repository)

指定されたリポジトリを継続的に監視し、新規コミットをスキャンします。

```python
def watch_repository(self, owner: str, repo: str,
                     interval_seconds: int = 300,
                     since: datetime = None) -> Generator[Finding, None, None]:
    """
    リポジトリを監視し、シークレットを検出したらFindingを生成します。

    Args:
        owner: リポジトリオーナー (例: "facebook")
        repo: リポジトリ名 (例: "react")
        interval_seconds: ポーリング間隔（秒）
        since: この日時以降のコミットをスキャン

    Yields:
        Finding: 検出されたシークレットごとにFinding
    """
```

### 2. コミットスキャン (scan_commit)

特定のコミットの差分（Diff）をスキャンします。

```python
def scan_commit(self, owner: str, repo: str, sha: str) -> List[Finding]:
    """
    単一コミットをスキャンします。

    Returns:
        検出されたシークレットのFindingリスト
    """
```

### 3. コンテンツスキャン (scan_content)

任意のテキストコンテンツをスキャンします（ファイル、ログなど）。

```python
def scan_content(self, content: str, source: str = "unknown") -> List[Finding]:
    """
    テキストコンテンツをスキャンします。

    Args:
        content: スキャン対象のテキスト
        source: ソース情報（ファイル名など）
    """
```

---

## API リファレンス

### クラス: `CommitWatcher`

#### `__init__(self, github_token: str = None)`

CommitWatcher を初期化します。

- `github_token`: GitHub API トークン（レート制限回避のため推奨）

#### `watch_repository(...)` → `Generator[Finding]`

リポジトリを継続監視します。

#### `scan_commit(...)` → `List[Finding]`

単一コミットをスキャンします。

#### `scan_content(...)` → `List[Finding]`

テキストコンテンツをスキャンします。

#### `get_recent_commits(owner, repo, since) -> List[dict]`

指定日時以降のコミット一覧を取得します。

---

## 使用例 (Usage Examples)

### 継続監視モード

```python
from src.core.intel import CommitWatcher
import os

watcher = CommitWatcher(github_token=os.getenv("GITHUB_TOKEN"))

# Facebook/Reactを監視（デモ用）
for finding in watcher.watch_repository("facebook", "react"):
    print(f"🚨 Secret Found!")
    print(f"   Type: {finding.vuln_type.name}")
    print(f"   Commit: {finding.evidence[0].metadata['commit_sha']}")
    print(f"   File: {finding.evidence[0].metadata['file_path']}")
```

### 単発スキャン

```python
# 特定のコミットをスキャン
findings = watcher.scan_commit(
    owner="target-corp",
    repo="api-server",
    sha="abc123def456..."
)

for finding in findings:
    print(f"Detected: {finding.title}")
```

### ローカルファイルのスキャン

```python
# ダウンロードしたソースコードをスキャン
with open("downloaded_code.py", "r") as f:
    content = f.read()

findings = watcher.scan_content(content, source="downloaded_code.py")
```

---

## Finding 生成

検出されたシークレットは、自動的に Finding オブジェクトに変換されます。

```python
Finding(
    title="Exposed AWS Access Key",
    severity=Severity.CRITICAL,
    vuln_type=VulnType.SECRET_LEAK,
    description="An AWS Access Key ID was found in a public commit...",
    evidence=[
        Evidence(
            request=None,
            response="AKIAIOSFODNN7EXAMPLE",
            metadata={
                "commit_sha": "abc123...",
                "file_path": "config/settings.py",
                "line_number": 42,
                "secret_type": "AWS_ACCESS_KEY"
            }
        )
    ],
    affected_url="https://github.com/target/repo/commit/abc123"
)
```

---

## GitHub API レート制限

### 制限値

| 認証状態         | 制限                |
| :--------------- | :------------------ |
| 未認証           | 60 requests/hour    |
| 認証済み (Token) | 5,000 requests/hour |

### 対策

```python
# 環境変数でトークンを設定
export GITHUB_TOKEN="ghp_your_token_here"

# またはコンストラクタで指定
watcher = CommitWatcher(github_token="ghp_...")
```

---

## トラブルシューティング

### 症状: `403 Forbidden` エラー

**原因**: GitHub API レート制限超過
**解決策**:

- `GITHUB_TOKEN` を設定
- ポーリング間隔を長くする

### 症状: シークレットが検出されない

**原因**:

- パターンが DB に存在しない
- シークレットがエンコードされている（Base64 等）

**解決策**:

- カスタムパターンを追加
- `scan_content` を直接使用して Base64 デコード後のコンテンツをスキャン

### 症状: 誤検知が多い

**原因**: 汎用パターンが過剰にマッチ
**解決策**:

- 検出結果の手動レビュー
- 特定のファイルパスを除外リストに追加
