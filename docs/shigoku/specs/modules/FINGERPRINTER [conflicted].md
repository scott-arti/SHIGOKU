---
task_id: SGK-2026-0037
doc_type: spec
doc_usage: reference_spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Fingerprinter - 技術スタック識別エンジン

**モジュールパス**: `src/core/intel/fingerprinter.py`

> [!WARNING] > **非推奨 (Deprecated)**: このモジュールは `ScopeParserAgent` に統合されました。
> 新規利用は `ScopeParserAgent.fingerprint()` メソッドを使用してください。
>
> **移行方法:**
>
> ```python
> # 旧 (非推奨)
> from src.core.agents.specialized.fingerprinter import FingerprinterAgent
> agent = FingerprinterAgent(model='gpt-4o-mini')
> result = agent.process(target_url)
>
> # 新 (推奨)
> from src.core.agents.specialized.scope_parser import ScopeParserAgent
> agent = ScopeParserAgent(model='gpt-4o-mini')
> result = agent.fingerprint(target_url)
> ```

---

## 概要 (Overview)

**Fingerprinter** は、ターゲット Web サイトで使用されている技術スタック（サーバー、フレームワーク、CMS、言語など）を識別するモジュールです。HTTP レスポンスヘッダーと HTML コンテンツを分析し、既知のパターン（シグネチャ）と照合することで、ターゲットの技術的構成を明らかにします。

**なぜ重要か**:

- 使用技術に基づいて既知の脆弱性（CVE）を効率的に調査できる
- フレームワーク固有の攻撃ベクターを優先的に試行できる
- CMS（WordPress、Drupal など）の管理画面やプラグインを特定できる

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────┐
│                       HTTP Response                              │
│  ┌──────────────────┐         ┌──────────────────────────┐      │
│  │   Headers        │         │       HTML Body          │      │
│  │ Server: nginx    │         │ <meta generator="WP">    │      │
│  │ X-Powered-By:PHP │         │ <script src="react.js">  │      │
│  └────────┬─────────┘         └────────────┬─────────────┘      │
│           │                                 │                    │
└───────────┼─────────────────────────────────┼────────────────────┘
            │                                 │
            ▼                                 ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Fingerprinter Engine                          │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  Signature Database                          │ │
│  │  - Server Patterns (nginx, Apache, IIS...)                  │ │
│  │  - Framework Patterns (Laravel, Django, Rails...)           │ │
│  │  - CMS Patterns (WordPress, Drupal, Joomla...)              │ │
│  │  - Frontend Patterns (React, Vue, Angular...)               │ │
│  │  - Language Patterns (PHP, Python, Ruby, .NET...)           │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                              │                                    │
│                              ▼                                    │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │                  Detection Results                           │ │
│  │  [Technology(name="nginx", version="1.18", category=SERVER)] │ │
│  │  [Technology(name="PHP", version="8.1", category=LANGUAGE)]  │ │
│  │  [Technology(name="WordPress", version="6.4", category=CMS)] │ │
│  └─────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

---

## シグネチャデータベース (Signature Database)

Fingerprinter は、以下のカテゴリに分類されたシグネチャを使用します：

### 検出カテゴリ

| カテゴリ      | 説明                         | 検出例                          |
| :------------ | :--------------------------- | :------------------------------ |
| **SERVER**    | Web サーバーソフトウェア     | nginx, Apache, IIS, Caddy       |
| **FRAMEWORK** | Web フレームワーク           | Laravel, Django, Rails, Express |
| **CMS**       | コンテンツ管理システム       | WordPress, Drupal, Joomla       |
| **LANGUAGE**  | プログラミング言語           | PHP, Python, Ruby, .NET         |
| **FRONTEND**  | フロントエンドフレームワーク | React, Vue, Angular, Next.js    |
| **CACHE**     | キャッシュ/CDN               | Varnish, Cloudflare, Fastly     |

### シグネチャ構造

各シグネチャは以下の形式で定義されています：

```python
@dataclass
class Signature:
    name: str              # 技術名 (例: "WordPress")
    category: Category     # カテゴリ (例: CMS)
    patterns: List[dict]   # マッチングパターン
    # パターン例:
    # {"type": "header", "name": "X-Powered-By", "regex": r"PHP/(\d+\.\d+)"}
    # {"type": "html", "regex": r'<meta name="generator" content="WordPress (\d+\.\d+)"'}
```

---

## 主要機能 (Key Features)

### 1. ヘッダー分析 (Header Analysis)

HTTP レスポンスヘッダーから情報を抽出します。

**分析対象ヘッダー**:

- `Server`: Web サーバー名とバージョン
- `X-Powered-By`: バックエンド言語/FW
- `X-Generator`: CMS 情報
- `Set-Cookie`: セッション管理の手がかり（セッション ID 名から FW を推測）
- `X-AspNet-Version`: ASP.NET バージョン

```
HTTP/1.1 200 OK
Server: nginx/1.18.0
X-Powered-By: PHP/8.1.12
Set-Cookie: PHPSESSID=abc123...
```

→ 検出結果: `nginx 1.18.0`, `PHP 8.1.12`

### 2. HTML 分析 (HTML Body Analysis)

HTML コンテンツからメタ情報やパターンを抽出します。

**分析対象**:

- `<meta name="generator">`: CMS やフレームワーク情報
- `<script src="...">`: JS フレームワーク（React, Vue 等）
- `<link href="...">`: CSS フレームワーク（Bootstrap 等）
- コメント内の情報: 開発者が残したバージョン情報

```html
<meta name="generator" content="WordPress 6.4.2" />
<script src="/static/js/react.production.min.js"></script>
```

→ 検出結果: `WordPress 6.4.2`, `React`

### 3. バージョン抽出 (Version Extraction)

可能な限りソフトウェアのバージョン情報を抽出し、CVE 調査に活用できるようにします。

```python
# バージョン抽出の精度
# - Exact: "nginx/1.18.0" → "1.18.0"
# - Major.Minor: "PHP/8.1" → "8.1"
# - Major Only: "WordPress 6" → "6"
# - Unknown: バージョン不明時は None
```

---

## API リファレンス

### クラス: `Fingerprinter`

#### `__init__(self, custom_signatures: List[Signature] = None)`

Fingerprinter を初期化します。カスタムシグネチャを追加可能。

#### `fingerprint(self, url: str, session: RotatingSession = None) -> List[Technology]`

指定された URL の技術スタックを識別します。

**戻り値**: `List[Technology]`

```python
@dataclass
class Technology:
    name: str           # 技術名
    version: str        # バージョン（不明時はNone）
    category: Category  # カテゴリ
    confidence: float   # 信頼度 (0.0-1.0)
```

#### `fingerprint_response(self, headers: dict, body: str) -> List[Technology]`

事前に取得済みのレスポンスを分析します（リクエストを送信しない）。

#### `add_signature(self, signature: Signature) -> None`

カスタムシグネチャを追加します。

---

## 使用例 (Usage Examples)

### 基本的な技術識別

```python
from src.core.intel import Fingerprinter

fp = Fingerprinter()

# URLから技術スタックを識別
technologies = fp.fingerprint("https://example.com")

for tech in technologies:
    print(f"[{tech.category.name}] {tech.name}", end="")
    if tech.version:
        print(f" v{tech.version}", end="")
    print(f" (confidence: {tech.confidence:.0%})")

# 出力例:
# [SERVER] nginx v1.18.0 (confidence: 95%)
# [LANGUAGE] PHP v8.1 (confidence: 90%)
# [CMS] WordPress v6.4 (confidence: 99%)
# [FRONTEND] React (confidence: 85%)
```

### カスタムシグネチャの追加

```python
from src.core.intel import Fingerprinter, Signature, Category

# カスタム企業内FWを検出
custom_sig = Signature(
    name="InternalFramework",
    category=Category.FRAMEWORK,
    patterns=[
        {"type": "header", "name": "X-Internal-Version", "regex": r"IF/(\d+\.\d+)"}
    ]
)

fp = Fingerprinter(custom_signatures=[custom_sig])
```

### ナレッジグラフへの保存

```python
from src.core.infra import KnowledgeGraph

kg = KnowledgeGraph()

for tech in technologies:
    kg.add_technology(page_url, tech)
    # (Page)-[:RUNS_ON]->(Technology) というリレーションが作成される
```

---

## 組み込みシグネチャ一覧 (Built-in Signatures)

### サーバー (SERVER)

| 名前      | 検出パターン              |
| :-------- | :------------------------ |
| nginx     | `Server: nginx/*`         |
| Apache    | `Server: Apache/*`        |
| IIS       | `Server: Microsoft-IIS/*` |
| Caddy     | `Server: Caddy`           |
| LiteSpeed | `Server: LiteSpeed`       |

### フレームワーク (FRAMEWORK)

| 名前    | 検出パターン                                                        |
| :------ | :------------------------------------------------------------------ |
| Laravel | `Set-Cookie: laravel_session`, `X-Powered-By: Laravel`              |
| Django  | `Set-Cookie: csrftoken`, `X-Frame-Options: SAMEORIGIN` (組み合わせ) |
| Rails   | `X-Powered-By: Phusion Passenger`, `Set-Cookie: _session_id`        |
| Express | `X-Powered-By: Express`                                             |
| Spring  | `Set-Cookie: JSESSIONID`                                            |

### CMS

| 名前      | 検出パターン                                                |
| :-------- | :---------------------------------------------------------- |
| WordPress | `<meta name="generator" content="WordPress`, `/wp-content/` |
| Drupal    | `X-Generator: Drupal`, `Drupal.settings`                    |
| Joomla    | `<meta name="generator" content="Joomla`                    |

### 言語 (LANGUAGE)

| 名前    | 検出パターン                                   |
| :------ | :--------------------------------------------- |
| PHP     | `X-Powered-By: PHP/*`, `Set-Cookie: PHPSESSID` |
| ASP.NET | `X-AspNet-Version`, `X-Powered-By: ASP.NET`    |
| Python  | `Server: gunicorn`, `Server: Waitress`         |

### フロントエンド (FRONTEND)

| 名前    | 検出パターン                                         |
| :------ | :--------------------------------------------------- |
| React   | `react.production.min.js`, `__NEXT_DATA__` (Next.js) |
| Vue     | `vue.runtime.esm.js`, `__VUE__`                      |
| Angular | `ng-version=`, `angular.min.js`                      |
| jQuery  | `jquery.min.js`, `jQuery`                            |

---

## 信頼度スコア (Confidence Score)

検出結果には信頼度スコア（0.0〜1.0）が付与されます。

| スコア  | 意味       | 例                               |
| :------ | :--------- | :------------------------------- |
| 0.9-1.0 | ほぼ確実   | `<meta generator="WordPress">`   |
| 0.7-0.9 | 高確率     | `Server: nginx` (バージョン付き) |
| 0.5-0.7 | 可能性あり | Cookie 名からの推測              |
| 0.3-0.5 | 推測       | ファイルパスからの推測           |

---

## トラブルシューティング

### 症状: 技術が検出されない

**原因**:

- ヘッダーが意図的に隠蔽されている（セキュリティ対策）
- シグネチャ DB にパターンが存在しない

**解決策**:

- カスタムシグネチャを追加
- レスポンスを手動で確認し、新しいパターンを発見

### 症状: バージョンが取得できない

**原因**: サーバー設定でバージョン露出が無効化されている

**解決策**: バージョンなしでも技術名は活用可能。バージョンは将来のスキャンで取得できることもある。
