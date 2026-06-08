---
task_id: SGK-2026-0032
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# AutoReporter - 脆弱性レポート自動生成エンジン

**モジュールパス**: `src/core/reports/auto_reporter.py`

---

## 概要 (Overview)

**AutoReporter** は、発見された脆弱性情報（Finding）から、バグバウンティプラットフォーム（HackerOne、Bugcrowd 等）に提出可能な形式のレポートを自動生成するモジュールです。

**主な機能**:

1. Finding オブジェクトからマークダウン形式のレポートを生成
2. 重大度に基づく CVSS スコアの自動付与
3. 脆弱性タイプに基づく CWE 番号の自動マッピング
4. 再現手順と修正案の自動生成
5. 重複チェック（将来実装予定）

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AutoReporter                                 │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Input: Finding Object                      │   │
│  │  - title, severity, vuln_type, description, evidence         │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Report Generator                           │   │
│  │  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐  │   │
│  │  │ CVSS Mapper  │ │ CWE Mapper   │ │ Remediation Gen      │  │   │
│  │  │              │ │              │ │ (RAG Optional)       │  │   │
│  │  └──────────────┘ └──────────────┘ └──────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Output: Markdown Report                    │   │
│  │  - HackerOne/Bugcrowd submission ready                       │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## レポートフォーマット (Report Format)

生成されるレポートは以下の構造を持ちます：

````markdown
# [Vulnerability Title]

## Summary

[脆弱性の概要と影響]

## Severity

- **Rating**: Critical / High / Medium / Low / Informational
- **CVSS Score**: X.X
- **CWE**: CWE-XXX (Vulnerability Name)

## Description

[脆弱性の詳細説明]

## Steps to Reproduce

1. [手順 1]
2. [手順 2]
3. [手順 3]

## Proof of Concept

```http
[リクエスト/レスポンス例]
```
````

## Impact

[脆弱性の影響範囲と潜在的な被害]

## Remediation

[修正方法の提案]

## References

- [関連する CVE、記事、ドキュメント]

````

---

## マッピングテーブル

### 重大度 → CVSS

| Severity | CVSS Score Range | 説明 |
| :--- | :--- | :--- |
| CRITICAL | 9.0 - 10.0 | 認証なしでのRCE、管理者権限奪取 |
| HIGH | 7.0 - 8.9 | 認証バイパス、重要データ漏洩 |
| MEDIUM | 4.0 - 6.9 | IDOR、CSRF、情報開示 |
| LOW | 0.1 - 3.9 | 軽微な情報漏洩、ベストプラクティス違反 |
| INFORMATIONAL | 0.0 | 付加情報、推奨事項 |

### 脆弱性タイプ → CWE

| VulnType | CWE | 説明 |
| :--- | :--- | :--- |
| JWT_ALG_NONE | CWE-327 | 壊れた暗号アルゴリズム |
| JWT_WEAK_SECRET | CWE-521 | 脆弱な認証情報 |
| OAUTH_REDIRECT_BYPASS | CWE-601 | オープンリダイレクト |
| OAUTH_PKCE_BYPASS | CWE-287 | 不適切な認証 |
| MFA_BYPASS | CWE-308 | 単一要素認証の使用 |
| IDOR | CWE-639 | 不適切な認可 |
| SECRET_LEAK | CWE-540 | ソースコード内の情報漏洩 |
| PRIVILEGE_ESCALATION | CWE-269 | 不適切な権限管理 |

---

## API リファレンス

### クラス: `AutoReporter`

#### `__init__(self, program_name: str = None, rag_switch: RAGSwitch = None)`
AutoReporterを初期化します。
- `program_name`: レポート内で使用するプログラム名
- `rag_switch`: 修正案のRAG拡張用

#### `generate_report(self, finding: Finding) -> str`
FindingオブジェクトからMarkdownレポートを生成します。

#### `save_report(self, finding: Finding, output_dir: str = "reports/") -> str`
レポートをファイルに保存し、ファイルパスを返します。

#### `batch_generate(self, findings: List[Finding]) -> List[str]`
複数のFindingを一括処理します。

#### `check_duplicate(self, finding: Finding) -> bool`
既存のレポートとの重複をチェックします（将来実装予定）。

---

## 使用例 (Usage Examples)

### 基本的な使用法

```python
from src.core.reports import AutoReporter
from src.core.models import Finding, Severity, VulnType, Evidence

# Findingオブジェクトを作成
finding = Finding(
    title="JWT Algorithm None Bypass",
    severity=Severity.CRITICAL,
    vuln_type=VulnType.JWT_ALG_NONE,
    description="The API accepts JWT tokens with 'alg': 'none'...",
    evidence=[
        Evidence(
            request="GET /api/me HTTP/1.1\nAuthorization: Bearer eyJ...",
            response="HTTP/1.1 200 OK\n{\"user\": \"admin\"}",
        )
    ],
    affected_url="https://api.target.com/me"
)

# レポート生成
reporter = AutoReporter(program_name="Target Inc. Bug Bounty")
report = reporter.generate_report(finding)
print(report)
````

### ファイルへの保存

```python
# reports/ ディレクトリに保存
file_path = reporter.save_report(finding)
print(f"Report saved to: {file_path}")
# Output: Report saved to: reports/2024-01-15_jwt_algorithm_none_bypass.md
```

### RAG 統合（修正案の拡張）

```python
from src.core.rag import get_rag_switch

rag = get_rag_switch()
reporter = AutoReporter(rag_switch=rag)

# RAGから関連する修正案を検索し、レポートに含める
report = reporter.generate_report(finding)
# Remediationセクションに、Obsidianノートからのベストプラクティスが追加される
```

---

## 出力ファイル命名規則

レポートファイルは以下の形式で命名されます：

```
reports/
├── 2024-01-15_jwt_algorithm_none_bypass.md
├── 2024-01-15_idor_user_profile_api.md
└── 2024-01-16_oauth_redirect_bypass.md
```

**形式**: `{YYYY-MM-DD}_{vulnerability_title_snake_case}.md`

---

## 修正案の生成 (Remediation Generation)

### デフォルト修正案

各脆弱性タイプにはデフォルトの修正案が用意されています：

```python
REMEDIATION_TEMPLATES = {
    VulnType.JWT_ALG_NONE: """
## Remediation
1. JWTライブラリで `alg: none` を明示的に拒否する設定を有効化
2. 署名検証を必須とし、アルゴリズムをホワイトリストで制限
3. 推奨アルゴリズム: RS256 (非対称鍵) または HS256 (対称鍵)
    """,
    VulnType.IDOR: """
## Remediation
1. すべてのオブジェクト参照に対して認可チェックを実装
2. 推測困難なID（UUID v4など）を使用
3. アクセス制御ロジックを集約したミドルウェアを導入
    """,
    # ... 他の脆弱性タイプ
}
```

### RAG による拡張

Obsidian ノートに修正案を記述しておくと、レポート生成時に自動的に参照されます：

````markdown
# JWT Security Best Practices

## alg=none 対策

- `jose` ライブラリの場合: `algorithms=['RS256']` を明示的に指定
- Spring Security JWT の場合: `DefaultJwtParser` のカスタマイズ

## 参考コード

```java
JwtParserBuilder builder = Jwts.parserBuilder()
    .setSigningKey(publicKey)
    .setAllowedClockSkewSeconds(60)
    .require("iss", "issuer");
```
````

```

---

## トラブルシューティング

### 症状: レポートにCWEが含まれない
**原因**: 対応するVulnTypeがマッピングテーブルにない
**解決策**: `VULN_TYPE_INFO` にエントリを追加

### 症状: 修正案が一般的すぎる
**原因**: RAGが無効、またはObsidianノートに詳細がない
**解決策**: RAGを有効化し、脆弱性タイプごとの詳細なノートを作成

### 症状: ファイル保存に失敗する
**原因**: `reports/` ディレクトリが存在しない
**解決策**: ディレクトリを作成するか、`save_report` が自動作成するよう設定
```
