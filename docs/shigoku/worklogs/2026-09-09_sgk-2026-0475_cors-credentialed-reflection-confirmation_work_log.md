---
task_id: SGK-2026-0475
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation.md
- docs/shigoku/reports/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- cors
created_at: '2026-09-09'
updated_at: '2026-09-09'
---

# SGK-2026-0475 作業ログ（CORS 認証付きオリジン反映・本物確定能力）

## 1. 事実確認（実コードで確定・2026-09-09）
- 確定バー `payout_grade._MARKER_CATEGORIES` に cors 無し → unknown_category 却下（オープンリダイレクト同型）。
- smart_cors/cors_tester は test_origin/acao/acac/misconfiguration を出すが応答本文を持たない（status 200 固定）。
- 再現チェッカーは Location しか見ない → CORS はヘッダ観測型＋Origin 付き再送が要る。
- 実 Juice Shop の CORS は全 EP `ACAO:*`（反映なし・ACAC なし）＝公開データのみ。本物の高影響 CORS 非実在。

## 2. 台帳・計画・承認
- SGK-2026-0475 採番・登録。凍結2ファイル（payout_grade.py / sealed_reproduction_checker.py）改変はユーザー明示承認。
  「◎は制御対象・Juice Shop の `*` は正しく非確定」方針もユーザー承認。

## 3. 実装（opencode / genuine deepseek-v4-flash・Claude 独立検証）
- A①payout_grade: cors_credentialed_reflection マーカー（反映+acac==true+excerpt のみ発火・fail-closed）。
- A②sealed_reproduction: _check_cors_replay（Origin 付き再送・ACAO反映+ACAC true で matched）。
- B smart_cors/cors_tester: 認証付き越境本文の抜粋（最小32字）+実 status を証拠化。
- インフラ: 1回目サブエージェント Aborted で早期終了（無変更）→ repo opencode.json 一時 agent→deepseek 上書きで
  再起動し完走→復元。[[opencode-fixer-subagent-makora-fallback]]。

## 4. 独立検証（Claude）
- 制御対象 E2E: 反映+ACAC true+機微本文99字→payout_grade=True/cors_credentialed_reflection→再現matched→CONFIRMED。
- 実 Juice Shop E2E: 15件全て acao=* → payout_grade=False/no_firing_marker → 非確定（偽◎なし・fail-closed）。
- 新規48テスト緑。injection+validation 944 passed / 2 failed（phase_b 環境依存・無関係）。
- 凍結: 改変は payout_grade.py / sealed_reproduction_checker.py のみ。他3凍結 exit 0。denylist 0。

## 5. 完了
- 完了条件1〜8 PASS・in_scope_blocker 0 → done。能力マップ CORS を △ → ○（本物確定能力あり・制御対象◎・
  実Juice Shopは`*`で正しく非確定）に更新。
