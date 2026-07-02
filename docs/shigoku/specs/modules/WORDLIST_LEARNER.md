---
task_id: SGK-2026-0046
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# WordlistLearner - ワードリスト自動学習モジュール

## 概要

**WordlistLearner** は、ハンティング中に発見された URL からパス、サブドメイン、パラメータを
自動収集し、カスタムワードリストを生成するモジュールです。

---

## 主要機能

### 1. URL 解析・パターン抽出

- パスセグメント抽出
- サブドメイン抽出
- クエリパラメータ抽出

### 2. 動的値フィルタリング

- 数字のみのセグメントを除外
- UUID 形式を除外
- ハッシュ値を除外

### 3. カスタムワードリスト生成

- 既存ファイルとの統合
- 重複排除
- ソート済み出力

---

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│              WordlistLearner                     │
├─────────────────────────────────────────────────┤
│                                                 │
│  URL入力                                        │
│      ↓                                          │
│  ┌─────────────────────────────────────────┐    │
│  │ URL Parser (urlparse)                   │    │
│  └─────────────────────────────────────────┘    │
│      │          │           │                   │
│      ▼          ▼           ▼                   │
│  ┌────────┐ ┌────────┐ ┌────────────────┐       │
│  │ Paths  │ │Subdomain│ │ Parameters   │       │
│  │ Set    │ │ Set     │ │ Set          │       │
│  └────────┘ └────────┘ └────────────────┘       │
│      │          │           │                   │
│      └──────────┼───────────┘                   │
│                 ▼                               │
│  ┌─────────────────────────────────────────┐    │
│  │ wordlists/custom/*.txt                  │    │
│  └─────────────────────────────────────────┘    │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

## 使用方法

### 基本的な使用

```python
from src.core.wordlist import get_wordlist_learner

learner = get_wordlist_learner()

# URL追加
learner.add_url("https://api.example.com/v1/users?id=123")
learner.add_url("https://admin.example.com/dashboard")
learner.add_url("https://example.com/api/v2/internal")

# 統計確認
print(learner.get_stats())
# {'paths': 5, 'subdomains': 2, 'params': 1}

# カスタムワードリスト保存
learner.save_all()
# wordlists/custom/discovered_paths.txt
# wordlists/custom/discovered_subdomains.txt
# wordlists/custom/discovered_params.txt
```

### 複数 URL 一括学習

```python
urls = [
    "https://example.com/api/users",
    "https://example.com/api/orders",
    "https://example.com/admin/settings",
]
learner.add_urls(urls)
```

---

## 動的値フィルタリング

以下のパターンは自動的に除外されます：

| パターン | 例                  | 理由         |
| -------- | ------------------- | ------------ |
| 数字のみ | `/users/12345`      | ID 値        |
| UUID     | `a1b2c3d4-e5f6-...` | 一意識別子   |
| ハッシュ | `abc123def456...`   | セッション等 |
| 単一文字 | `/a/b/c`            | 意味なし     |

---

## 出力形式

### discovered_paths.txt

```
admin
api
dashboard
internal
settings
users
v1
v2
```

### discovered_subdomains.txt

```
admin
api
staging
www
```

### discovered_params.txt

```
id
page
search
sort
token
```

---

## 統合例

### GAU からの学習

```python
from src.core.wordlist import get_gau_integrator, get_wordlist_learner

gau = get_gau_integrator()
urls = gau.fetch_urls("example.com")

learner = get_wordlist_learner()
learner.add_urls(urls)
learner.save_all()
```

### スキャン結果からの学習

```python
# ffuf結果から学習
discovered_paths = ["api/users", "api/orders", "admin/login"]
for path in discovered_paths:
    learner.add_url(f"https://example.com/{path}")
```

---

## ベストプラクティス

1. **定期的な保存**

   - スキャン終了時に`save_all()`を呼び出す
   - 途中経過も保存可能

2. **既存ワードリストとの統合**

   - 自動的に既存ファイルに追記
   - 重複は自動排除

3. **ターゲット別管理**
   - プロジェクトごとに Learner インスタンスを作成
   - 混在を防ぐ

---

## 関連モジュール

| モジュール                             | 連携             |
| -------------------------------------- | ---------------- |
| [GAUIntegrator](GAU_INTEGRATOR.md)     | GAU 結果の取得   |
| [HeadlessCrawler](HEADLESS_CRAWLER.md) | 動的 URL 取得    |
| [WordlistManager](WORDLIST_MANAGER.md) | ワードリスト選択 |
