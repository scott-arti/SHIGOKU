---
task_id: SGK-2026-0474
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation.md
- docs/shigoku/reports/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- lfi
- path-traversal
created_at: '2026-09-08'
updated_at: '2026-09-08'
---

# SGK-2026-0474 作業ログ（LFI パス方式・本物確定）

## 1. 事実確認（実コードで確定・2026-09-08）
- 確定バーは LFI 対応済み（payout_grade file_content_leak は excerpt でも発火）。だが (1) smart_lfi は
  パラメータ方式のみで実 Juice Shop のパス方式ヌルバイト LFI に噴かない、(2) Finding impact/repro 空で
  missing_impact 落ち、(3) 再現チェッカー（凍結）は _LFI_PATTERNS だけで照合し .bak（JSON/MD）は再現不成立。
- 実 Juice Shop 実測（GET のみ）: `/ftp/package.json.bak%2500.md`→200・`.bak` 漏洩。`/etc/passwd` 走査は 403。

## 2. 台帳・計画・承認
- SGK-2026-0474 採番・登録。凍結 `sealed_reproduction_checker.py` 1ファイル改変はユーザー明示承認。
  スコープ「パス方式対応＋差分成功判定＋impact/repro＋誤検知ガード」もユーザー承認。

## 3. 実装（opencode / genuine deepseek-v4-flash・Claude 独立検証）
- B（smart_lfi.py）: パス方式検出＋差分ガード＋impact/repro。A（sealed_reproduction_checker.py）: excerpt 再出現照合。
- インフラ事象: opencode サブエージェント fixer が未認証 makora へフォールバックし 1 回目中断（無変更）。
  repo opencode.json に一時 agent→deepseek 上書き→再実行→完了後に復元。詳細 [[opencode-fixer-subagent-makora-fallback]]。

## 4. 独立検証（Claude）
- 実 Juice Shop E2E: クリーン403→バイパス200→excerpt→payout_grade=True/file_content_leak→再現matched→CONFIRMED。
- 新規18テスト緑。injection+validation 896 passed / 2 failed（phase_b 環境依存・無関係）。
- 凍結: 改変は sealed_reproduction_checker.py のみ。他4凍結 exit 0。denylist 0。FP fail-closed 担保。

## 5. 完了
- 完了条件1〜7 PASS・in_scope_blocker 0 → done。能力マップ LFI を △〜○ → ◎ に更新。
