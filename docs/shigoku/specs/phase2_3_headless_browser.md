---
task_id: SGK-2026-0148
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-05-19'
updated_at: '2026-05-19'
---

# Phase 2.3: Headless Browser Validator 仕様書

## 概要

**機能名**: `PlaywrightValidator`

**目的**:
Reflected XSS などのクライアントサイド脆弱性を検証するために、実際のブラウザ (Chromium) で URL にアクセスし、JavaScript (`alert()`など) の発火を確認する。

---

## 変更範囲

| ファイル                                    | 変更内容                         |
| ------------------------------------------- | -------------------------------- |
| `src/tools/browser/playwright_validator.py` | 🆕 新規作成 - Playwrightラッパー |
| `src/tools/browser/dom_analyzer.py`         | 🆕 新規作成 - DOM解析（任意）    |
| `src/core/agents/spec/xss_verifier.py`      | 🆕 新規 - XSS検証Agent           |

---

## 機能詳細

### 1. PlaywrightValidator

Playwright を用いてヘッドレスブラウザを操作する。

#### 安全な実行とスキップ

Playwright がインストールされていない、またはブラウザバイナリが見つからない場合、処理を中断せずに **Warning ログを出力してスキップ** する。

```python
class PlaywrightValidator:
    def __init__(self):
        self._is_available = self._check_availability()

    def _check_availability(self) -> bool:
        try:
            from playwright.async_api import async_playwright
            return True
        except ImportError:
            logger.warning("[Headless] Playwright module not found. XSS verification will be skipped.")
            return False

    async def validate_xss(self, url: str, expected_alert_text: str = None) -> bool:
        if not self._is_available:
            return False

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                # ... (以下同様)
        except Exception as e:
            logger.error("[Headless] Failed to launch browser: %s", e)
            return False
```

### 2. PlaywrightValidator

```python
        # ブラウザ操作ロジック
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            xss_triggered = False

            async def handle_dialog(dialog):
                nonlocal xss_triggered
                # ... (判定ロジック)
                await dialog.dismiss()

            page.on("dialog", handle_dialog)

            try:
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                await page.wait_for_timeout(2000)
            except:
                pass

            await browser.close()
            return xss_triggered
```

---

## 完了条件

- Playwright がある環境では XSS を検知できること。
- Playwright がない環境でもクラッシュせず、ログを出力して `False` を返すこと。
