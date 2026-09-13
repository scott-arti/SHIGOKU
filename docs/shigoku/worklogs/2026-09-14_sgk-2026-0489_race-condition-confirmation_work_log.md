---
task_id: SGK-2026-0489
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0489_race-condition-confirmation.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0489_race-condition-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- race-condition
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0489 作業ログ（Race Condition・実 SKF ラボ・◎）

## 1. 偵察（事実優先・実測）
- 既存 RaceConditionTester は並列側のみ（逐次コントロールなし・確定バー未接続）。
- 想定対象 crAPI apply_coupon を実測→**並列6/30 とも成功1＝原子ロック済みで race 非脆弱**と判明し棄却。
- SKF に本物の race ラボ（`racecondition` 他）を発見。SSTI/XXE と同 posture で 127.0.0.1:5091 に起動。
- race.py 解析: validate が hello.sh 書込直後〜sed 検証削除までの窓で run(bash hello.sh)が並列に走ると
  注入コマンド実行＝TOCTOU。実測で逐次=マーカー非反映／並列バースト=マーカー反映(round1)を確認。reset で
  戻せる=再現可能・非破壊。

## 2. 台帳・計画・承認
- SGK-2026-0489 採番（registry.yaml・DOC-0559）。Race 新設の選択＝ビルド承認（凍結2 追加）。

## 3. 実装（Claude 直接）
- smart_race_condition（新規）: task 由来 trigger/observe/reset で逐次コントロール×並列バーストの差分＋
  一意マーカーで確定。_client seam・同一オフセット窓スニペット・race_evidence(race+control)・race_replay・
  差分2ステップ poc。製品固有ハードコードなし。
- payout_grade: `_MARKER_CATEGORIES["race_condition"]="race_condition_toctou"`＋発火分岐（request_url/marker
  非空＋並列2xx＋marker が race_body 実在＋control_body 非実在・全て揃いで発火・fail-closed）。
- sealed_reproduction: `_check_race_replay`（新マーカーで並列バーストを ThreadPoolExecutor で1シーケンス
  再実行→再出現で matched・両URLスコープ再検証・上限クランプ・GET 限定）＋dispatch。

## 4. 独立検証（Claude・実出力）
- smoke: 発火 positive／control にも出現／race 非反映／非2xx／空marker の fail-closed を確認。
- 実 SKF E2E: execute→逐次非反映/並列反映→payout_grade=True/race_condition_toctou→封印再現 matched→CONFIRMED。
- 実 poc_judge: **初回 0/5**（control スニペットが head/ロゴ領域のみで差分が審査で不成立と正しく却下）→
  **control と race を同一オフセット窓で見せる底上げで 5/5**（Step1 逐次 missing／Step2 並列 system-message に
  マーカーの差分を評価）＝[[poc-judge-raw-evidence]] の拡張・バー非低下。
- 新規22テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・0488 で stash 確認済み）
  ＝0489 起因の回帰ゼロ（1201 passed）。凍結3 exit 0。製品 token0・whitespace0・秘密値非露出。

## 5. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: **Race Condition 行を新規追加し ◎**＋高度化 低(L1)。ビジネスロジック節に補記。
- 教訓: (1) 差分型の証拠は control と race を**同一領域**で見せないと審査で差分が成立しない
  （別領域の切り出しは不成立）。(2) race は単発再送で再現不可＝封印再現は**バースト再実行＋新マーカー**が
  正当。(3) 想定対象は必ず実測で検証（crAPI クーポンは原子ロックで race 非脆弱だった）。
  [[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・[[no-capability-minimization]]。
- 観測(別件): 実運用アプリ race・POST trigger・クロール自動発見・パイプライン統合は高度化フェーズで deferred。
