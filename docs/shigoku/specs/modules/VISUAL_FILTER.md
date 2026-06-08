---
task_id: SGK-2026-0045
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# VisualFilter - 画像解析・ページ分類エンジン

**モジュールパス**: `src/core/intel/visual_filter.py`

---

## 概要 (Overview)

**VisualFilter** は、Web ページのスクリーンショットを解析し、ページタイプを自動分類するモジュールです。OCR（光学文字認識）と画像解析を組み合わせて、ログインページ、管理画面、エラーページなどを識別します。

**ユースケース**:

- Cartographer が収集した大量の URL の中から、ログインページを自動検出
- 空白ページやエラーページを除外し、調査対象を絞り込む
- 管理画面の発見を自動化

---

## アーキテクチャ (Architecture)

```
┌─────────────────────────────────────────────────────────────────────┐
│                         VisualFilter                                 │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Image Loader                               │   │
│  │  - Load screenshot (PNG, JPG, WebP)                          │   │
│  │  - Convert to PIL Image object                               │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Analysis Pipeline                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │   │
│  │  │ Entropy Calc │  │ OCR Extract  │  │ Keyword Match │        │   │
│  │  │ (Blankness)  │  │ (Tesseract)  │  │ (Page Type)   │        │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘        │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                              │                                       │
│                              ▼                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Classification Result                      │   │
│  │  - PageType: LOGIN | ADMIN | ERROR | BLANK | CONTENT | UNKNOWN│   │
│  │  - Confidence Score                                          │   │
│  │  - Extracted Text                                            │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ページタイプ分類 (Page Classification)

### 分類カテゴリ

| PageType    | 説明                     | 検出キーワード例                                                 |
| :---------- | :----------------------- | :--------------------------------------------------------------- |
| **LOGIN**   | ログイン/認証ページ      | "login", "sign in", "password", "username", "email"              |
| **ADMIN**   | 管理画面/ダッシュボード  | "admin", "dashboard", "管理", "settings", "users"                |
| **ERROR**   | エラーページ             | "404", "500", "not found", "error", "forbidden", "access denied" |
| **BLANK**   | 空白/ほぼ空のページ      | (エントロピー計算で判定)                                         |
| **CONTENT** | 一般的なコンテンツページ | 上記に該当しない通常のページ                                     |
| **UNKNOWN** | 分類不能                 | OCR 失敗、または判定基準未達                                     |

---

## 主要機能 (Key Features)

### 1. 画像エントロピー計算 (Entropy Calculation)

空白ページや単色背景のページを検出します。

```python
def _calculate_entropy(self, image: Image) -> float:
    """
    画像の情報エントロピーを計算します。

    - 低エントロピー (< 1.0): 空白または単色ページ
    - 中エントロピー (1.0-4.0): シンプルなページ
    - 高エントロピー (> 4.0): 複雑なコンテンツページ
    """
```

### 2. OCR テキスト抽出 (OCR Text Extraction)

Tesseract OCR エンジンを使用して、画像からテキストを抽出します。

```python
def _extract_text(self, image: Image) -> str:
    """
    画像からテキストを抽出します。

    Requirements:
    - tesseract-ocr がシステムにインストールされていること
    - 日本語を含む場合: tesseract-ocr-jpn パッケージ

    Returns:
        抽出されたテキスト文字列
    """
```

**OCR なしモード**: Tesseract が利用できない場合、エントロピーのみで分類を試みます。

### 3. キーワードマッチング (Keyword Matching)

抽出されたテキストをキーワードリストと照合し、ページタイプを決定します。

```python
KEYWORDS = {
    PageType.LOGIN: [
        "login", "sign in", "log in", "ログイン", "サインイン",
        "password", "パスワード", "username", "ユーザー名",
        "email", "メール", "forgot", "reset", "remember me"
    ],
    PageType.ADMIN: [
        "admin", "administrator", "管理", "dashboard", "ダッシュボード",
        "settings", "設定", "users", "ユーザー管理", "console"
    ],
    PageType.ERROR: [
        "404", "not found", "500", "internal server error",
        "403", "forbidden", "access denied", "error", "エラー"
    ]
}
```

---

## API リファレンス

### クラス: `VisualFilter`

#### `__init__(self, use_ocr: bool = True)`

VisualFilter を初期化します。

- `use_ocr`: Tesseract OCR を使用するかどうか

#### `analyze(self, image_path: str) -> VisualAnalysisResult`

画像ファイルを解析し、分類結果を返します。

#### `analyze_image(self, image: Image) -> VisualAnalysisResult`

PIL イメージオブジェクトを直接解析します。

#### `is_blank(self, image_path: str, threshold: float = 1.0) -> bool`

画像が空白かどうかを判定します。

### データクラス

```python
@dataclass
class VisualAnalysisResult:
    page_type: PageType      # 分類されたページタイプ
    confidence: float        # 信頼度 (0.0-1.0)
    extracted_text: str      # OCRで抽出されたテキスト
    entropy: float           # 画像エントロピー
    keywords_found: List[str]  # マッチしたキーワード
```

---

## 使用例 (Usage Examples)

### 基本的な使用法

```python
from src.core.intel import VisualFilter, PageType

filter = VisualFilter(use_ocr=True)

# スクリーンショットを解析
result = filter.analyze("screenshots/page1.png")

print(f"Page Type: {result.page_type.name}")
print(f"Confidence: {result.confidence:.0%}")
print(f"Entropy: {result.entropy:.2f}")
print(f"Keywords: {result.keywords_found}")

if result.page_type == PageType.LOGIN:
    print("🎯 Login page detected! Prioritize AuthNinja.")
```

### 一括解析

```python
from pathlib import Path

filter = VisualFilter()
screenshots_dir = Path("screenshots/")

login_pages = []
admin_pages = []

for screenshot in screenshots_dir.glob("*.png"):
    result = filter.analyze(str(screenshot))

    if result.page_type == PageType.LOGIN:
        login_pages.append(screenshot.name)
    elif result.page_type == PageType.ADMIN:
        admin_pages.append(screenshot.name)

print(f"Login Pages: {login_pages}")
print(f"Admin Pages: {admin_pages}")
```

### Cartographer との統合

```python
from src.core.intel import Cartographer, VisualFilter

# サイトマップ生成
cartographer = Cartographer(ethics_guard=guard)
sitemap = cartographer.map_site("https://target.com")

# 各ページのスクリーンショットを解析
filter = VisualFilter()
for page in sitemap.pages:
    # (注: スクリーンショット取得はヘッドレスブラウザ統合が必要)
    screenshot_path = take_screenshot(page.url)
    result = filter.analyze(screenshot_path)

    # Knowledge Graphにタグを追加
    kg.add_tag(page.url, f"page_type:{result.page_type.name}")
```

---

## 信頼度スコア (Confidence Score)

分類結果には信頼度スコアが付与されます。

| スコア  | 意味                         |
| :------ | :--------------------------- |
| 0.9-1.0 | 複数のキーワードが強くマッチ |
| 0.7-0.9 | 主要キーワードがマッチ       |
| 0.5-0.7 | 部分的なマッチ               |
| 0.3-0.5 | 弱いマッチ（要確認）         |
| < 0.3   | 分類困難                     |

---

## OCR 設定 (OCR Configuration)

### Tesseract のインストール

```bash
# Ubuntu/Debian
sudo apt install tesseract-ocr tesseract-ocr-jpn

# macOS
brew install tesseract tesseract-lang

# 確認
tesseract --version
```

### 言語設定

```python
# 日本語を優先
filter = VisualFilter()
filter.set_ocr_lang("jpn+eng")
```

---

## トラブルシューティング

### 症状: OCR が機能しない

**原因**: Tesseract がインストールされていない
**解決策**:

```bash
sudo apt install tesseract-ocr
pip install pytesseract
```

### 症状: 日本語が認識されない

**原因**: 日本語言語パックがない
**解決策**:

```bash
sudo apt install tesseract-ocr-jpn
```

### 症状: 空白ページの誤検出

**原因**: エントロピー閾値が高すぎる
**解決策**: `is_blank()` の `threshold` パラメータを調整

### 症状: ログインページが検出されない

**原因**: 画像フォーマットまたはキーワードの問題
**解決策**:

- PNG または JPG 形式を使用
- カスタムキーワードを追加

---

## 制限事項

1. **ヘッドレスブラウザ未統合**: 現在のバージョンでは、スクリーンショットの取得機能は未実装。事前に取得した画像ファイルを入力として使用。

2. **CAPTCHA ページ**: CAPTCHA 画像は OCR で読み取れるが、分類は「CONTENT」または「UNKNOWN」になることが多い。

3. **動的ページ**: SPA など、JavaScript で動的に生成されるコンテンツは、レンダリング後のスクリーンショットでないと正確に分類できない。
