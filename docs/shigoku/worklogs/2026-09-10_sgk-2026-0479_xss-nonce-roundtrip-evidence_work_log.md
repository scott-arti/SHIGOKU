---
task_id: SGK-2026-0479
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence.md
- docs/shigoku/reports/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- xss
created_at: '2026-09-10'
updated_at: '2026-09-10'
---

# SGK-2026-0479 作業ログ（XSS 合言葉往復証拠・実対象で実 poc_judge 通過率改善）

## 1. 発端（実測・実LLM）
- 実 poc_judge×N: DOM XSS finding は「証拠が実行時生データでなくスキャナ自身の要約で自己申告に
  見える」で 3 回中 2 回非承認（実測 reason）。バー低下せず証拠の見せ方を底上げする方針。

## 2. 事実確認（実測）
- 発火後 page.content() に注入文字列は残らない → 生 DOM 案は不採用。
- `<img src=x onerror=alert('<nonce>')>` 注入で dialog message == nonce（完全一致・実 Juice Shop）。
- dialog message は両経路で既に捕捉済（browser_pool evidence.dialog_message / playwright
  _last_observation_logs）→ インフラ改変不要・smart_xss のみ。

## 3. 台帳・計画
- SGK-2026-0479 採番・登録。範囲 smart_xss.py＋テストのみ。凍結5無改変。ユーザーは実装者=DeepSeek を選択。

## 4. 実装（DeepSeek / genuine deepseek-v4-flash）
- nonce 生成 `_generate_xss_nonce`（sgk+token_hex）。param ループで `_current_xss_nonce` 再生成。
- DOM/precheck/stored の payload を alert('<nonce>') 化。4 経路の browser_execution に
  nonce/observed_dialog_message/nonce_match 記録。poc_response・evidence.response_body に往復生記録。
- opencode デタッチ＋opencode.json 一時 agent→deepseek 上書き（makora 回避）→完了後復元。

## 5. 独立検証（Claude・実出力）
- 実エンジン→nonce_match=True＋往復生記録（実 Juice Shop）。
- 実 poc_judge 通過率 1/3→5/6（judge が nonce 往復を明示評価）。
- 完全 3 ゲート（機械フロア＋実 poc_judge＋実再現）→ CONFIRMED（クリーン環境 attempt1）。
- 再現 matched 3/3（クリーン環境・nonce 非依存＝回帰なし）。not_run は資源競合の fail-closed。
- injection 771 passed・新規 21 passed。凍結4 exit 0・sealed 無干渉（0478 実 DVWA E2E 引き続き CONFIRMED）。token 0。

## 6. 完了
- 完了条件1〜5 PASS・in_scope_blocker 0 → done。能力マップの XSS 行に「実 AI 審査の通過率を
  合言葉往復で底上げ（1/3→5/6・バー非低下）」を追記。
