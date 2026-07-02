---
task_id: SGK-2026-0047
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# WordlistManager - ワードリスト管理モジュール

## 概要

**WordlistManager** は、複数のワードリストソース（SecLists、JHaddix、AssetNote 等）を統合管理し、
AI がコンテキストに応じて最適なワードリストを自動選択するためのモジュールです。

---

## 主要機能

### 1. メタデータベース管理

- 各ワードリストの行数、用途、強みを定義
- YAML ファイルで設定

### 2. 自動選択エンジン

- モード（BugBounty/VulnTest/CTF）に応じた選択
- 技術スタック（Django/Rails/AWS 等）に応じた選択
- スキャン戦略（quick/standard/deep）に応じた選択

### 3. ソース情報管理

- SecLists: 汎用・安定
- JHaddix: BugBounty 特化
- AssetNote: 最新 HTTPArchive データ

---

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│              WordlistManager                     │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────────────────┐   │
│  │ Metadata    │  │ SelectionEngine         │   │
│  │ Loader      │  │ (mode/tech/strategy)    │   │
│  └─────────────┘  └─────────────────────────┘   │
│         │                   │                   │
│         └───────────────────┘                   │
│                   ▼                             │
│         ┌─────────────────────────┐             │
│         │ WordlistInfo            │             │
│         │ (name, path, size...)   │             │
│         └─────────────────────────┘             │
└─────────────────────────────────────────────────┘
```

---

## 使用方法

### 基本的な選択

```python
from src.core.wordlist import get_wordlist_manager

wm = get_wordlist_manager()

# サブドメイン列挙用ワードリスト選択
wordlist = wm.select(
    purpose="subdomain",
    mode="bugbounty",
    strategy="standard"
)

print(f"Selected: {wordlist.name} ({wordlist.lines} lines)")
# → dns-Jhaddix.txt (2171687 lines)
```

### 技術スタック指定

```python
# AWS環境向け
wordlist = wm.select(
    purpose="subdomain",
    tech_stack=["aws"],
    strategy="deep"
)
# → 2m-subdomains.txt (AssetNote)
```

### サマリー取得

```python
summary = wm.get_summary()
print(summary)
# {
#   'subdomain': {'count': 10, 'sources': ['SecLists', 'JHaddix', 'AssetNote']},
#   'directory': {'count': 6, 'sources': ['DirBuster', 'AssetNote']},
#   ...
# }
```

---

## メタデータ形式

### wordlists/subdomain/metadata.yaml

```yaml
base_path: /home/user/wordlists

files:
  - name: subdomains-top1million-5000.txt
    path: SecLists/Discovery/DNS/subdomains-top1million-5000.txt
    source: SecLists
    lines: 4989
    size: small
    strength: [general, stable, fast]
    best_for: [first_scan, quick, unknown_target]

selection_rules:
  mode_defaults:
    bugbounty:
      quick: subdomains-top1million-5000.txt
      standard: dns-Jhaddix.txt
      deep: bug-bounty-program-subdomains-trickest-inventory.txt
```

---

## 選択ルール

### サイズ分類

| サイズ  | 行数           | 用途             |
| ------- | -------------- | ---------------- |
| small   | ~5,000         | クイックスキャン |
| medium  | 5,000~30,000   | 標準スキャン     |
| high    | 30,000~500,000 | 詳細スキャン     |
| massive | 500,000+       | 徹底スキャン     |

### モード別デフォルト

| モード    | quick          | standard        | deep            |
| --------- | -------------- | --------------- | --------------- |
| BugBounty | SecLists small | JHaddix         | Trickest        |
| VulnTest  | SecLists small | SecLists medium | SecLists high   |
| CTF       | SecLists small | SecLists small  | SecLists medium |

---

## 関連モジュール

| モジュール                                   | 連携                     |
| -------------------------------------------- | ------------------------ |
| [WordlistLearner](WORDLIST_LEARNER.md)       | 発見パスの自動学習       |
| [GAUIntegrator](GAU_INTEGRATOR.md)           | GAU 結果からパターン抽出 |
| [ProgressiveScanner](PROGRESSIVE_SCANNER.md) | 段階的スキャン           |

---

## 設定ファイル

| ファイル                            | 説明           |
| ----------------------------------- | -------------- |
| `wordlists/subdomain/metadata.yaml` | サブドメイン用 |
| `wordlists/directory/metadata.yaml` | ディレクトリ用 |
| `wordlists/api/metadata.yaml`       | API 用         |
| `wordlists/params/metadata.yaml`    | パラメータ用   |
| `wordlists/graphql/metadata.yaml`   | GraphQL 用     |

---

## ベストプラクティス

1. **メタデータ更新**

   - 新しいワードリスト追加時は metadata.yaml を更新
   - 行数は`wc -l`で確認

2. **ソース別使い分け**

   - 初回スキャン: SecLists（安定）
   - 深掘り: JHaddix（BugBounty 実績）
   - 最新技術: AssetNote（2025 年データ）

3. **カスタムワードリスト**
   - `wordlists/custom/`に配置
   - WordlistLearner で自動生成可能
