---
task_id: SGK-2026-0244-S01
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0244
related_docs:
  - docs/shigoku/plans/2026-05-24_sgk-2026-0244_xss-hunter-enhancement_plan.md
  - src/core/detection/xss_detector.py
  - src/core/agents/swarm/injection/smart_xss.py
  - src/core/detection/browser_pool.py
  - src/core/detection/xss_pipeline.py
created_at: '2026-05-27'
updated_at: '2026-06-30'
---

# SGK-2026-0244-S01: XSS Hunter未実装項目の完了計画

## 1. 目的
- SGK-2026-0244 の残課題を実装完了にする。
- 今回の対象は以下2点に限定する。
  - Stored XSS の保存フェーズをプレースホルダから実装へ置換する。
  - SmartXSSHunter の DOM 検証経路を BrowserPool 統合経路へ揃える。

## 2. スコープ
- In Scope
  - `src/core/detection/xss_detector.py` の `detect_stored_xss` 実装強化
  - `src/core/agents/swarm/injection/smart_xss.py` の DOM 実行検証経路の統一
  - 必要最小限の検証テスト追加・更新
- Out of Scope
  - DalFoxエンジンの再設計
  - 既存レポートフォーマットの改変
  - 新規スキーマ変更

## 3. 実装タスク
1. Stored XSS保存フェーズ実装
- HTTPクライアント経由で `storage_url` へ payload を送信
- 送信方式（GET/POST、json/form）をオプション化
- 送信失敗時は明示的に `error` 記録

2. Stored XSS表示フェーズ検証
- `display_url` への到達後に BrowserPool 検証を実行
- 成功/失敗を `evidence` に構造化出力

3. SmartXSSHunter統合経路の統一
- DOM実行確認を `BrowserPoolXSSVerifier` 呼び出しへ寄せる
- 直接Playwright実行はフォールバックに限定

4. 回帰防止テスト
- Stored XSSフロー（保存失敗/成功/表示確認）単体テスト
- SmartXSSHunter DOMフローの BrowserPool 経由確認テスト

## 4. 受け入れ基準
- `detect_stored_xss` に「保存処理プレースホルダ」のコメントが残らない。
- SmartXSSHunter の DOM 検証の主経路が BrowserPool 経由になっている。
- 追加/更新した対象テストがローカルで成功する。

## 5. リスク
- Playwright 非導入環境では実ブラウザ確認がフォールバック運用になる。
- 既存の SmartXSSHunter 推論ループに副作用が出る可能性。

## 6. 完了条件
- 実装差分、テスト結果、未対応事項を work_report/work_log に記録し、`SGK-2026-0244-S01` を `done` へ更新する。
