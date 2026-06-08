---
task_id: SGK-2026-0071
doc_type: spec
status: active
parent_task_id: null
related_docs: []
created_at: '2026-01-26'
updated_at: '2026-05-19'
---

# 2026-01-26_OOB_Headless.md Implementation Spec

## 1. Target Phase (from Roadmap)

- **Phase 2.2**: OOB (Out-of-Band) Detection
- **Phase 2.3**: Headless Browser Verification

## 2. Phase 2.2: OOB Detection (LocalOOBListener)

### 概要

既存の `src/core/utils/oob_listener.py` と `src/core/agents/spec/oob_verifier.py` を活用し、Swarm Agent (InjectionSwarm等) から利用可能にする統合を行います。
コード自体は実装済みであるため、検証とインターフェース統合が主眼です。

### Changes

#### 1. `src/core/utils/oob_listener.py` (Verify & Integrate)

- **Status**: Implemented ✅
- **Action**:
  - 単体テスト (`tests/unit/utils/test_oob.py`) を作成し、動作を検証する。
  - 動作に問題があれば修正する（現状のコードは `aiohttp` ベースで実装済み）。

#### 2. `src/core/agents/spec/oob_verifier.py` (Verify & Integrate)

- **Status**: Implemented ✅
- **Action**:
  - 単体テストで動作確認。
  - `InjectionSwarm` から呼び出すためのDI（依存注入）またはファクトリー統合を確認。

#### 3. Integration

- `InjectionSwarm` の `Specialist` ロジック内で、`OobVerifier` を呼び出すフローを確立する。

### Verification

- `pytest tests/unit/utils/test_oob.py` がPassすること。
- ローカルOOBサーバーが正しく起動し、外部からのHTTPリクエストを検知できること。

---

## 3. Phase 2.3: Headless Browser (PlaywrightValidator)

### 概要

XSS (Reflected) 検証のため、Playwright を用いたヘッドレスブラウザ検証を新規実装します。

### Changes

#### 1. `src/tools/browser/playwright_validator.py` (New)

- **Status**: Not Implemented ❌
- **Action**:
  - `PlaywrightValidator` クラスを新規作成。
  - `async_playwright` を使用。
  - `validate_xss(url, expected_alert_text)` メソッド実装。
  - 依存ライブラリがない場合のGraceful Skip処理。

#### 2. `tests/tools/test_playwright.py` (New)

- `PlaywrightValidator` の動作検証テストを作成。

### Verification

- Playwright がインストールされている環境で XSS (alert) が検知できること。
