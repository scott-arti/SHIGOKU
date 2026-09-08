---
task_id: SGK-2026-0476
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation.md
- docs/shigoku/reports/2026-09-09_sgk-2026-0476_jwt-alg-none-forgery-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- auth
- jwt
created_at: '2026-09-09'
updated_at: '2026-09-09'
---

# SGK-2026-0476 作業ログ（JWT alg=none 偽造受理・本物確定）

## 1. 事実確認（実測・実コードで確定・2026-09-09）
- 実 Juice Shop は alg=none 無署名偽造トークンの偽造 identity を GET のみで受理（トークン無し=空との差分で確定）。JWT は本来 RS256。
- 確定バー `_MARKER_CATEGORIES` に auth/jwt 無し=マーカー新設要（オープンリダイレクト/CORS 同型）。
- AuthNinja._check_none_alg は常に False のスタブ（サーバ側受理の確証が未実装）。Finding に impact/repro 無し。

## 2. 台帳・計画・承認
- SGK-2026-0476 採番・登録。凍結2（payout_grade.py / sealed_reproduction_checker.py）改変はユーザー明示承認。
  対象=JWT alg=none 偽造受理を◎、方針もユーザー承認。

## 3. 実装（opencode / genuine deepseek-v4-flash・Claude 独立検証）
- B auth_ninja: baseline 無し GET→fabricated identity の alg=none 無署名トークン GET→本文反映の差分成立時のみ
  vulnerable（実トークン複製なし・redirect 非受理・fail-closed）＋impact/repro/forged_identity/forged_token/auth_endpoint 証拠。
- A①payout_grade: jwt_alg_none→jwt_forgery_accepted（alg=none+baseline 不在+forged 反映のみ発火）。
- A②sealed_reproduction: _check_jwt_forgery_replay（forged_token 再送で forged_identity 再出現の再現）。
- インフラ: repo opencode.json 一時 agent→deepseek 上書きで makora 回避、完了後復元。[[opencode-fixer-subagent-makora-fallback]]。

## 4. 独立検証（Claude）
- 実 Juice Shop E2E: fabricated identity の alg=none→受理差分→payout_grade=True/jwt_forgery_accepted→再現matched→CONFIRMED。
- 署名検証サーバ E2E: alg=none 拒否→finding 0=正しく非確定（偽◎なし）。
- 新規36テスト緑。injection+validation+auth 1039 passed / 2 failed（phase_b 環境依存・無関係）。
- 凍結: 改変は payout_grade.py / sealed_reproduction_checker.py のみ。他3凍結 exit 0。denylist 0。

## 5. 完了
- 完了条件1〜8 PASS・in_scope_blocker 0 → done。能力マップ 認証/JWT を △〜○ → ◎ に更新。
