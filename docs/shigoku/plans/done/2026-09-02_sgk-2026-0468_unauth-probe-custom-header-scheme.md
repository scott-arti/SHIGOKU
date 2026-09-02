---
task_id: SGK-2026-0468
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0467_idor-bola-confirmation-fact-first.md
- docs/shigoku/reports/2026-09-02_sgk-2026-0467_idor-bola-confirmation-fact-first_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-02_sgk-2026-0468_custom-header-unauth-probe_part1_work_report.md
- docs/shigoku/worklogs/2026-09-02_sgk-2026-0468_custom-header-unauth-probe_part1_work_log.md
- docs/shigoku/reports/2026-09-03_sgk-2026-0468_cross-account-e2e-and-preflight_work_report.md
- docs/shigoku/worklogs/2026-09-03_sgk-2026-0468_cross-account-e2e-and-preflight_work_log.md
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0469_authenticated-scan-token-refresh.md
- docs/shigoku/plans/2026-09-03_sgk-2026-0470_llm-in-loop-latency-reduction.md
created_at: '2026-09-02'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- idor
- bola
---

# SGK-2026-0468 計画 — unauth probe のカスタムヘッダスキーム対応検討＋cross-account 確定の実走行 E2E 再確認

## 目的（何を・なぜ）

SGK-2026-0467 で cross-account BOLA 確定（authB マトリクス）を実装したが、2 つの追跡事項が残った（いずれも阻害ではない・fail-closed で誤検知なし）:

1. **カスタムヘッダスキーム対応**: `manager.py` の unauth probe は Authorization/Cookie のみ剥離する（manager.py:1749 相当）。X-Auth-Token 等のカスタムヘッダで認証する場合、unauth probe が token を保持してしまい `auth_boundary_observed` が立たない → cross-account ブロックは fail-closed でサイレント（誤検知なし・機会損失のみ）。既存経路の挙動変更は SGK-2026-0467 の「追加のみ・後方互換」契約で禁止のため、本タスクで設計検討する。
2. **実走行 E2E 再確認**: SGK-2026-0467 の確定経路はモックベース unit（fixture 実挙動を忠実に再現）で実証済み。`multi_session.enabled`＋authA/authB 登録＋`SHIGOKU_IDOR_CROSS_ACCOUNT_CONFIRM_ENABLED=1` の実走行での発火を E2E で再確認する。

## 対象（in scope）

1. unauth probe の auth 判定ヘッダ集合拡張の設計（既定 OFF の settings フラグ gate・後方互換維持）と、影響調査（既存 unauth 判定経路の非回帰確認）。
2. 実走行（2 ユーザー fixture をターゲットにしたフルパイプライン診断）での cross-account finding 発火と payout_grade 到達の確認。

## 完了条件

- カスタムヘッダスキーム（例: fixture の `X-Auth-Token`）でも unauth probe が真に未認証になり、cross-account 確定が発火する。または「対応しない」判断が理由付きで記録される。
- 実走行 E2E で cross-account finding の payout_grade=True を実物で確認、または達成不能な署名レベル真因を特定して追跡タスク化。
- 確定バー 5 ファイル無改変・token 0・validator 0。

## NOT in scope

- 確定バー 5 ファイルの改変。
- 破壊的（状態変更）リクエストの追加。
- 既存 finding 経路の挙動変更（additive のみ）。

## 手順

1. unauth probe の auth 判定経路の精読と拡張案設計（フラグ gate）。
2. 実装＋unit テスト（既存 683 テスト非回帰を含む）。
3. 実走行 E2E（2 ユーザー fixture）→ consistency 確認。
4. work_report / work_log 更新、validator 0。

## 完了記録（2026-09-03）

### part-1: カスタムヘッダ対応（unauth probe 広域剥離）— done
`manager.py` の cross-account ブロック内で、マトリクスに境界が無く authA が 2xx のときのみ
広域剥離した真の未認証 GET を1回送り境界を独自確立（`_UNAUTH_STRIP_HEADER_KEYS`・追加のみ・
既存共有 unauth プローブ無改変）。unit 9 緑・injection 634 緑・確定バー無改変・token 0（Claude 独立検証済）。
X-Auth-Token を主認証にした実 HTTP E2E でも payout_grade=True を確認。

### part-2: 実 Juice Shop での cross-account 確定実証（本物の証拠）— done
本物の Juice Shop・**実2アカウント**（.env の資格情報から自動ログイン・値は非表示）・**実 manager コード**・
**実 HTTP** で、`GET /rest/basket/{Bのかご}` に対し「未認証=401 / authA(別アカウント)=200 / authB(所有者)=200・
本文一致」を観測し、`_run_api_minimal_check` が cross_account_bola finding を発火・
**`evaluate_payout_grade`=True / reason=payout_grade_satisfied / marker=authz_diff** に到達。
証拠: `workspace/projects/idor_cross_account_real_evidence_20260902.txt`（合言葉マスク）。
→ 「別アカウントで実際に見えた BOLA」を本物の対象で確定まで実証（能力マップ IDOR ◎ 昇格の根拠）。

### part-3: preflight 認証ゲートの JSON API 対応 — done
`auth_probe.py` に Rule 10b（`auth_probe_json_api_enabled` 既定OFF）を追加。認証情報付き 2xx の JSON API 応答を
AUTHENTICATED と判定し、JSON エンドポイント直撃時の AUTH_UNKNOWN 走行中止を解消。Rules1-10 無改変・
preflight 189 緑・確定バー無改変・token 0（Claude 独立検証済）。フラグON でフル走行が preflight を通過することを実走行で確認。

### 方法②（正式フル走行）の中止判断と気づき
part-3 で preflight は通過したが、フル自律走行は AI 逐次判断で低速（~54分で LLM 呼び出し186回・思考42ターン）、
かつ認証トークン（~1時間）失効と競合。狙い撃ちの高速確定（part-2・数秒）の方が実戦的で本物の証拠として十分と判断し、
遅いフル走行はユーザー合意のもと中止。露呈した実戦上の課題は下記 deferred で追跡。

## deferred_tasks

```yaml
deferred_tasks:
  - summary: "認証付き自律走査でトークン失効（~1h）をまたいで認証を維持する自動再ログイン/更新能力。フル走行の認可系確定の実戦化に必須。"
    tracking_task_id: SGK-2026-0469
    blocking: false
  - summary: "フル自律走行の AI 逐次判断（LLM往復）による遅延の削減（決定論化/キャッシュ/スコープ制御）。検出網羅性は落とさない。"
    tracking_task_id: SGK-2026-0470
    blocking: false
```
