---
task_id: SGK-2026-0468
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/reports/2026-09-03_sgk-2026-0468_cross-account-e2e-and-preflight_work_report.md
created_at: '2026-09-03'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- idor
- bola
---

# SGK-2026-0468 作業ログ（part-2/3）

## 1. 環境
- Caido 8081・本物 Juice Shop 3000 稼働。実2アカウントを `.env`（`docs/shigoku/.env`・JUICE_A/B_EMAIL/PASSWORD）に登録（値は非表示）。

## 2. part-1 検証（カスタムヘッダ対応・Claude 独立）
- `pytest tests/core/agents/swarm/injection/test_cross_account_bola.py -q` → 9 passed。injection 634 passed。
- 実 HTTP E2E（authA=X-Auth-Token）: 広域剥離プローブで境界確立 → cross_account finding=1・payout_grade=True。
  Authorization ケースでは広域プローブ不発（既存経路不変）を実リクエスト内訳で確認。

## 3. part-2 実 Juice Shop E2E（本物の証拠）
- ログイン helper（`.env` 読込・値非表示）で authA/authB のトークンとかご番号を自動取得（A=6, B=7）。
- 3-way 実測（B のかご=7）: unauth=401 / authA=200 / authB=200・本文一致 → cross-account 成立確認。
- 実 `_run_api_minimal_check`（実 HTTP・proxy無し直結）→ matrix signals=[authA_success, auth_boundary_observed,
  authB_success, authA_authB_both_success] / cross_account finding=1 /
  `evaluate_payout_grade`=True / payout_grade_satisfied / marker=authz_diff。
- 証拠を `workspace/projects/idor_cross_account_real_evidence_20260902.txt` に保存（合言葉マスク）。

## 4. part-3 preflight JSON API 対応（Claude 独立検証）
- `auth_probe.py` diff 精読: Rule 10b を Rule10後・Rule11前に追加・Rules1-10 無改変（削除0）。settings フラグ既定OFF。
- `pytest tests/unit/preflight -q` → 189 passed（baseline 183 + 新規 6）。
- 確定バー5: `git diff --quiet HEAD -- ...` exit 0。denylist grep 0。

## 5. 正式フル走行（方法②）の試行と中止
- run1（`/rest/basket/7` 直撃・フラグOFF）: preflight AUTH_UNKNOWN で中止 → part-3 の必要性を実証。
- run2（part-3 フラグON）: **preflight PASSED**（JSON API を AUTHENTICATED 判定）→ recon/injection 進行。
- 観測: ~54分で LLM 呼び出し 186 回・思考 42 ターン・並列度 7→3・basket 狙いのつもりがクロールで7URL検査。
  トークン失効（~1h）と競合し確定到達前に時間切れの公算 → ユーザー合意でフル走行中止。
- 露呈課題を SGK-2026-0469（認証寿命管理）/ SGK-2026-0470（AI往復削減）へ起票。

## 6. 反省（秘密の扱い）
- 検証中 `pgrep -af` で主認証 JWT が一度端末出力に露出（練習アカウント・短命）。以後 PID のみ確認へ切替。
  認証は argv でなく env/stdin 経由が望ましい（再発防止メモ）。

## 7. ドキュメント整合
- `.venv/bin/python scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py --repo-root .`（0 エラー）。

## 8. 参照ルール
`rules/task-ledger.md` / `rules/lessons.md` / `rules/shigoku-docs.md`。
