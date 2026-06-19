---
task_id: SGK-2026-0244-S01
doc_type: work_report
status: done
parent_task_id: SGK-2026-0244
related_docs:
  - docs/shigoku/plans/2026-05-24_xss-hunter-enhancement_plan.md
  - docs/shigoku/subtasks/2026-05-27_sgk-2026-0244-s01_xss-hunter-remaining-implementation_subtask_plan.md
  - docs/shigoku/reports/2026-05-29_sgk-2026-0244_x2-x4-status_work_report.md
  - src/core/agents/swarm/injection/stored_xss_detector.py
  - src/core/detection/xss_detector.py
  - src/core/agents/swarm/injection/smart_xss.py
  - src/core/agents/swarm/injection/smart_xss_runtime.py
  - src/core/detection/browser_pool.py
  - tests/core/agents/test_stored_xss_detector.py
  - tests/core/agents/swarm/injection/test_smart_xss_logic.py
  - tests/core/agents/swarm/test_smart_xss.py
  - tests/integration/test_smart_xss_hunter_integration.py
  - tests/integration/test_browser_pool_verification.py
  - tests/core/detection/test_xss_detector.py
created_at: '2026-06-18'
updated_at: '2026-06-18'
---

# SGK-2026-0244-S01: XSS Hunter 未実装項目 完了報告

## 1. 要約
- `src/core/detection/xss_detector.py::detect_stored_xss` の保存処理プレースホルダを除去し、基準実装 `StoredXSSDetector` へ委譲する形で実装を完了。
- `SmartXSSHunter` の DOM 実行検証主経路が `BrowserPoolXSSVerifier` 優先のまま維持されていることを確認。
- `tests/integration/test_browser_pool_verification.py::test_pool_exhaustion_handling` の失敗原因（ロック保持中のスリープによるデッドロック）を解消。
- 対象テスト 6 ファイル・計 47 件が全件成功（内 `tests/core/detection/test_xss_detector.py` は新規追加）。

## 2. 実装内容

### 2.1 Stored XSS 実装経路の整合
- 変更ファイル: `src/core/detection/xss_detector.py`
- 変更点:
  - `detect_stored_xss` からプレースホルダコメントを除去。
  - 保存処理は `StoredXSSDetector._submit_form` に委譲し、実際にペイロードを storage エンドポイントへ送信するよう実装。
  - 表示確認は `BrowserPoolXSSVerifier.verify_stored()` を新設して使用。`display_url` をそのまま開き、クエリ文字列にペイロードを注入しない形で Stored XSS 発火を確認。
  - `BrowserPoolXSSVerifier` はエンジンの `self.browser_pool`（`src.core.detection.browser_pool.BrowserPool`）を使用。
  - evidence 構造は `StoredXSSDetector._verify_execution()` と同じ `method` / `url` / `dialog_message`（Playwright 時）または `snippet`（静的フォールバック時）を返すよう揃えた。
  - 保存失敗時は警告ログを出力して `None` を返す。
  - 検出時は `browser_confirmed=True` を設定。

### 2.2 BrowserPoolXSSVerifier の Stored XSS 対応
- 変更ファイル: `src/core/detection/browser_pool.py`
- 変更点:
  - `BrowserPoolXSSVerifier.verify_stored()` を新設。
  - `display_url` をそのまま開き、保存済みペイロードの発火（JavaScript ダイアログ）を確認。
  - evidence dict は `StoredXSSDetector._verify_execution()` と同じキー構造（`method`, `url`, `dialog_message` / `snippet`）を返すよう統一。
  - Playwright 未導入時は静的反射チェックにフォールバック。
  - `_MockPage` に `add_init_script` / `evaluate` / `url` を追加し、Playwright 非導入環境でも `detect_dom_xss` が例外を起こさないよう補強。

### 2.3 BrowserPool 統合経路のクローズ
- 確認ファイル: `src/core/agents/swarm/injection/smart_xss_runtime.py`
- 確認結果:
  - `validate_dom_runtime_xss` は第 1 優先で `BrowserPoolXSSVerifier.verify()` を呼び出している。
  - フォールバックとして `PlaywrightValidator`、さらに生の Playwright 起動が後続する。
  - `smart_xss.py` の `_validate_dom_runtime_xss` は `smart_xss_runtime.validate_dom_runtime_xss` に委譲されており、主経路が BrowserPool 経由であることを維持。
- 変更はなし（既存実装が計画を満たしていた）。

### 2.4 回帰テストの失敗解消
- 変更ファイル: `tests/integration/test_browser_pool_verification.py`
- 失敗原因:
  - `VerifiedBrowserPool.acquire()` が `async with self._lock` 内で `await asyncio.sleep(0.01)` を呼び出していたため、他タスクがロックを取得できず、プール枯渇時の待ちタスクが解放を受け取れない状態（ロック保持中スリープによるデッドロック）。
- 修正内容:
  - ロック範囲を最小化し、空待ちの間はロックを解放してからスリープするよう再構成。
  - 併せて、max_requests 到達時の再起動で返却されるブラウザが新しいインスタンスとなるよう修正（旧実装は再起動後も古いインスタンスを返却していた）。

## 3. 実行した検証

### コマンド
```bash
.venv/bin/pytest -q tests/core/detection/test_xss_detector.py
.venv/bin/pytest -q tests/core/agents/test_stored_xss_detector.py
.venv/bin/pytest -q tests/core/agents/swarm/injection/test_smart_xss_logic.py
.venv/bin/pytest -q tests/core/agents/swarm/test_smart_xss.py
.venv/bin/pytest -q tests/integration/test_smart_xss_hunter_integration.py
.venv/bin/pytest -q tests/integration/test_browser_pool_verification.py
```

### 結果
- `tests/core/detection/test_xss_detector.py`: 3 passed
- `tests/core/agents/test_stored_xss_detector.py`: 24 passed
- `tests/core/agents/swarm/injection/test_smart_xss_logic.py`: 3 passed
- `tests/core/agents/swarm/test_smart_xss.py`: 5 passed
- `tests/integration/test_smart_xss_hunter_integration.py`: 5 passed
- `tests/integration/test_browser_pool_verification.py`: 7 passed
- **合計: 47 passed, 0 failed**

## 4. 判断理由
- `xss_detector.py` は既存のレガシーインターフェースを維持しつつ、保存処理を `StoredXSSDetector._submit_form` に委譲し、表示確認は `BrowserPoolXSSVerifier.verify_stored()` を使用することで、プレースホルダを解消しつつ `display_url` をそのまま開いた実ブラウザ確認を実現した。
- `BrowserPoolXSSVerifier.verify_stored()` の evidence 構造は `StoredXSSDetector._verify_execution()` と揃え、両経路の整合を確保した。
- `XSSDetectionEngine` は `src.core.detection.browser_pool.BrowserPool` を使用するよう統一し、レガシーなローカル `BrowserPool` 実装との重複を解消する方向に寄せた。
- `smart_xss_runtime.py` はすでに BrowserPool 主経路になっており、追加変更は不要と判断。
- テスト失敗はテスト用モック `VerifiedBrowserPool` の同期制御バグであり、プロダクションの `BrowserPool`（`asyncio.Semaphore` + `asyncio.Queue` 使用）には該当しない。テストを修正して動作を保証。

## 5. リスク・未対応事項
- Playwright 未導入環境では、Stored XSS / DOM XSS のブラウザ発火確認が静的反射チェックにフォールバックする（計画書リスク記載通り）。
- 今回の `detect_stored_xss` は単一パラメータ・単一ペイロードの呼び出しに対応。フォーム自動検出や複数パラメータ探索は `StoredXSSDetector.scan()` を使用する必要がある。
- `xss_detector.py` のローカル `BrowserPool` クラスは現状残存しているが、`XSSDetectionEngine` は canonical `browser_pool.BrowserPool` を使用するよう移行済み。ローカルクラスの完全削除は別タスクのクリーンアップとして扱う。
- `SGK-2026-0244` 本体はすでに `done` となっているため、本サブタスク完了後は親計画との整合が保たれる。

## 6. 次アクション
- 台帳・レジストリの `SGK-2026-0244-S01` status は `done` に更新済み。
- コミット時は本タスクと無関係な変更が混ざらないよう、registry 3 ファイルは `git add -p` などでパッチ単位で分離してステージングすること。
