---
task_id: SGK-2026-0479
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence.md
- docs/shigoku/worklogs/2026-09-10_sgk-2026-0479_xss-nonce-roundtrip-evidence_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0477_xss-browser-execution-confirmation.md
tags:
- shigoku
- detection
- xss
- evidence-quality
created_at: '2026-09-10'
updated_at: '2026-09-10'
---

# SGK-2026-0479 作業完了報告 — XSS 実行証拠を「合言葉往復」で独立検証可能にする

## 何をしたか / なぜ

反射/DOM型XSS は SGK-2026-0477 で ◎（機械フロア＋実対象再現は本物）。だが**本物の AI 審査
（poc_judge・実LLM）**を通したところ、DOM XSS finding は 3 回中 2 回で非承認だった。理由は
「証拠が弱い」ではなく **「提示する response_body / poc_response が実行時の生データでなく、
スキャナ自身が書いた観測要約（`dialog=alert message=1` 等）で自己申告に見える」**（実測・
poc_judge の reason）。バーは下げず、**証拠の見せ方を本物の強さへ底上げ**した。

## 実装（`smart_xss.py` 非凍結のみ・DeepSeek 実装 / Claude 独立検証）

- **合言葉(nonce)注入**: 検証ペイロードの `alert(1)` を、実行毎のランダム nonce（`sgk`＋乱数）を
  引数に持つ `alert('<nonce>')` に置換（DOM 検証 payload・deterministic precheck payload・
  stored 再訪 payload の全経路）。param ループ開始時に `_current_xss_nonce` を再生成。
- **往復検証**: 発火後、ブラウザが返した dialog message（browser_pool 経路＝
  `evidence.dialog_message`、Playwright フォールバック 3 経路＝`_last_observation_logs`）が nonce と
  一致するかを検査し、`browser_execution` に `nonce` / `observed_dialog_message` /
  `nonce_match`(bool) を記録。一致時のみ True（捏造しない・fail-closed）。
- **提示強化**: `_build_browser_execution_poc_response` に往復記録
  `[Runtime execution proof (nonce round-trip)]` を追記。`execute()` の `evidence.response_body` を、
  要約文だけでなく `[XSS runtime execution] test_url=.. injected_nonce=.. observed_dialog_message=..
  nonce_match=..` の**生記録**にする。
- 凍結5ファイルは無改変。payout_grade の xss 発火（`dialog_observed`）・再現チェッカーの DOM 再実行は
  無変更（nonce は発火条件・再現に非依存）。

## 結果（独立検証・Claude が実測）

- **実 Juice Shop・実エンジン**: `SmartXSSHunter.execute` が search `q` の DOM XSS を自力検出し、
  `browser_execution` に **nonce_match=True**（例 nonce=observed=`sgk612277e7aa55`）と往復生記録を付与。
- **本物 poc_judge 通過率が 1/3 → 5/6 に改善**（実LLM×6）。judge は理由で明示的に
  「注入 nonce とダイアログ message の一致（nonce_match=True）」を実行証拠として評価。残り 1 回の
  非承認は「生 req/res・被害者視点の影響も欲しい」というより厳しめ判定（バー低下ではない）。
- **完全 3 ゲート（機械フロア＋実 poc_judge＋実再現）→ CONFIRMED**（クリーン環境 attempt1 で
  reproduction=matched → `hybrid_confirmed`）。
- **非回帰**: 再現はクリーン環境で matched 3/3（nonce 非依存を実証）。`tests/core/agents/swarm/injection/`
  = 771 passed。新規テスト（nonce 往復・stored 再訪）= 21 passed。
- **凍結・保全**: `payout_grade.py` / `poc_judge.md` / `task_queue.py` / `finding_validator.py` は
  `git diff --quiet HEAD` exit 0。`sealed_reproduction_checker.py`（別タスク 0478 の未コミット WIP）は
  0479 で無干渉（nonce/xss grep 0・0478 実 DVWA E2E が引き続き CONFIRMED＝機能無傷）。製品非依存 token 0。

## 注記（正直な限界）

- AI 審査は非決定的。「必ず通る」ではなく「通過率が 1/3→5/6 に上がった」を実測で示す（誇張しない）。
- 実対象での not_run（1 度観測）は、同時多重ブラウザ実行による資源競合の fail-closed であり、
  0479 の回帰ではない（単独クリーン環境で matched 3/3 を確認）。
- コマンドインジェクション側の judge 非承認理由（「教育用ターゲット」）は本タスク対象外（別問題）。

## 完了条件の充足

計画の完了条件 1〜5 すべて PASS。`in_scope_blocker=0`。

## 実装フローの注記（インフラ）

DeepSeek/opencode デタッチ起動＋repo `opencode.json` 一時 agent→deepseek 上書き
（fixer→makora 対策・[[opencode-fixer-subagent-makora-fallback]]）で genuine deepseek 完走、
完了後 `opencode.json` 復元（無改変確認）。DeepSeek の「smart_cmd_ssrf.py を並行セッションが変更」
という説明は不正確だったが、Claude 独立検証で無干渉・機能無傷を確認済み（額面を信用しない原則を適用）。
