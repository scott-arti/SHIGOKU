---
task_id: SGK-2026-0244-S01
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0244
related_docs:
  - docs/shigoku/plans/2026-05-24_xss-hunter-enhancement_plan.md
  - docs/shigoku/reports/2026-05-29_sgk-2026-0244_x2-x4-status_work_report.md
  - docs/shigoku/reports/2026-06-18_sgk-2026-0244-s01_xss-hunter-remaining-implementation_work_report.md
  - docs/shigoku/worklogs/2026-06-18_sgk-2026-0244-s01_xss-hunter-remaining-implementation_work_log.md
  - src/core/agents/swarm/injection/stored_xss_detector.py
  - src/core/detection/xss_detector.py
  - src/core/agents/swarm/injection/smart_xss.py
  - src/core/agents/swarm/injection/smart_xss_runtime.py
  - src/core/detection/browser_pool.py
  - src/core/detection/xss_pipeline.py
  - tests/core/agents/test_stored_xss_detector.py
  - tests/core/agents/swarm/injection/test_smart_xss_logic.py
  - tests/core/agents/swarm/test_smart_xss.py
  - tests/integration/test_smart_xss_hunter_integration.py
  - tests/integration/test_browser_pool_verification.py
  - tests/core/detection/test_xss_detector.py
created_at: '2026-05-27'
updated_at: '2026-06-18'
---

# SGK-2026-0244-S01: XSS Hunter未実装項目の完了計画

## 1. 目的
- SGK-2026-0244 の残課題を、コード・テスト・記録まで含めて完了扱いにできる状態へ揃える。
- 今回の対象は以下2点に限定する。
  - Stored XSS 系の実装を `stored_xss_detector.py` と legacy `xss_detector.py` の両経路で整合させる。
  - SmartXSSHunter の DOM 検証経路を BrowserPool 主経路のまま回帰まで含めて完了させる。

## 2. 完了状況（2026-06-18）
- `src/core/agents/swarm/injection/stored_xss_detector.py` を基準実装として Stored XSS フローを整理済み。
- `src/core/detection/xss_detector.py::detect_stored_xss` から保存処理プレースホルダを除去し、`StoredXSSDetector._submit_form` + `BrowserPoolXSSVerifier.verify_stored()` に置き換え済み。
- `src/core/agents/swarm/injection/smart_xss.py` / `smart_xss_runtime.py` の DOM 検証主経路が `BrowserPoolXSSVerifier` 優先のまま維持されていることを確認済み。
- 対象テスト 6 ファイル・計 47 件が `.venv` で成功済み。
- `SGK-2026-0244-S01` の work_report / work_log を作成済み、台帳 status は `done` に更新済み。

## 3. スコープ
- In Scope
  - `src/core/agents/swarm/injection/stored_xss_detector.py` を基準実装として Stored XSS フローを整理する
  - `src/core/detection/xss_detector.py` の `detect_stored_xss` placeholder 解消または基準実装への委譲
  - `src/core/agents/swarm/injection/smart_xss.py` / `smart_xss_runtime.py` の DOM 実行検証経路の回帰確認
  - `tests/core/agents/test_stored_xss_detector.py` ほか関連テストの再実行と必要最小限の修正
  - `SGK-2026-0244-S01` の work_report / work_log / 台帳更新
- Out of Scope
  - DalFoxエンジンの再設計
  - Browser Pool 全面再設計
  - 既存レポートフォーマットの改変
  - 新規スキーマ変更

## 4. 実装タスク（完了）
1. Stored XSS 実装経路の整合 ✅
   - [x] `stored_xss_detector.py` を基準実装として扱う
   - [x] `xss_detector.py::detect_stored_xss` の placeholder を除去し、実装または委譲へ置き換える
   - [x] 保存失敗時のエラー記録と表示確認時の `evidence` 構造を両経路で揃える

2. BrowserPool 統合経路のクローズ ✅
   - [x] SmartXSSHunter の DOM 実行確認が `BrowserPoolXSSVerifier` 主経路で維持されていることを確認する
   - [x] 直接Playwright実行はフォールバックに限定する
   - [x] `tests/integration/test_browser_pool_verification.py::test_pool_exhaustion_handling` の失敗原因を解消する

3. 回帰確認 ✅
   - [x] `.venv/bin/pytest -q tests/core/agents/test_stored_xss_detector.py` (24 passed)
   - [x] `.venv/bin/pytest -q tests/core/agents/swarm/injection/test_smart_xss_logic.py` (3 passed)
   - [x] `.venv/bin/pytest -q tests/core/agents/swarm/test_smart_xss.py` (5 passed)
   - [x] `.venv/bin/pytest -q tests/integration/test_smart_xss_hunter_integration.py` (5 passed)
   - [x] `.venv/bin/pytest -q tests/integration/test_browser_pool_verification.py` (7 passed)
   - [x] `.venv/bin/pytest -q tests/core/detection/test_xss_detector.py` (3 passed, 新規追加)

4. 完了記録 ✅
   - [x] 実装差分、テスト結果、未対応事項を `work_report` / `work_log` に記録する
   - [x] `SGK-2026-0244-S01` を `done` に更新する（検証通過後）

## 5. 受け入れ基準（すべて達成）
- [x] `src/core/detection/xss_detector.py::detect_stored_xss` に保存処理プレースホルダが残らない、または基準実装へ明示的に委譲されている。
- [x] SmartXSSHunter の DOM 検証の主経路が BrowserPool 経由のままである。
- [x] 以下の対象テストが `.venv` で成功する。
  - [x] `tests/core/agents/test_stored_xss_detector.py`
  - [x] `tests/core/agents/swarm/injection/test_smart_xss_logic.py`
  - [x] `tests/core/agents/swarm/test_smart_xss.py`
  - [x] `tests/integration/test_smart_xss_hunter_integration.py`
  - [x] `tests/integration/test_browser_pool_verification.py`
  - [x] `tests/core/detection/test_xss_detector.py`（新規追加）
- [x] `SGK-2026-0244-S01` の work_report / work_log / 台帳 status が実態と一致している。

## 6. リスク
- Playwright 非導入環境では実ブラウザ確認がフォールバック運用になる。
- Browser Pool の exhaustion 系失敗は XSS ロジックではなく pool 同期制御の問題である可能性がある。
- 既存の SmartXSSHunter 推論ループに副作用が出る可能性。

## 7. 完了条件（すべて達成）
- [x] 実装差分、テスト結果、未対応事項を work_report/work_log に記録する。
- [x] `SGK-2026-0244-S01` の台帳 status を `done` に更新する。
- [x] 親計画 `SGK-2026-0244` と矛盾しない状態で完了証跡が残っている。

---

**完了日: 2026-06-18**
