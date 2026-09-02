---
task_id: SGK-2026-0468
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
- docs/shigoku/worklogs/2026-09-03_sgk-2026-0468_cross-account-e2e-and-preflight_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0469_authenticated-scan-token-refresh.md
- docs/shigoku/plans/2026-09-03_sgk-2026-0470_llm-in-loop-latency-reduction.md
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

# SGK-2026-0468 作業完了報告（part-2/3）— 実 Juice Shop での cross-account BOLA 確定実証＋preflight JSON API 対応

## 何をしたか / なぜ

SGK-2026-0467 で cross-account BOLA 確定（authB マトリクス）を実装（モック unit で実証）。本タスクで
(1) カスタムヘッダ認証への対応（part-1）、(2) **本物の Juice Shop での確定実証**（part-2）、
(3) 実走行を阻む preflight の JSON API 非対応の解消（part-3）を行い、能力を実戦の対象で証明した。
コーディングは DeepSeek へ指示し、Claude が独立検証（DeepSeek 報告は額面通り信用しない方針）。

## 結果（確定）

- **本物の対象で cross-account BOLA を確定まで実証（part-2）**: 本物 Juice Shop・実2アカウント
  （`.env` 資格情報から自動ログイン・値は非表示）・実 manager コード・実 HTTP。
  `GET /rest/basket/{Bのかご}` で 未認証=401 / authA(別アカウント)=200 / authB(所有者)=200・本文一致 →
  `_run_api_minimal_check` が cross_account_bola finding を発火 →
  **`evaluate_payout_grade`=True / payout_grade_satisfied / marker=authz_diff**。
  証拠: `workspace/projects/idor_cross_account_real_evidence_20260902.txt`（合言葉マスク）。
- **part-1（カスタムヘッダ対応）**: `manager.py` に広域剥離の境界確立を追加（`_UNAUTH_STRIP_HEADER_KEYS`・
  cross-account ブロック内・追加のみ・共有 unauth プローブ無改変）。unit 9 緑 / injection 634 緑。
  X-Auth-Token 主認証の実 HTTP E2E で payout_grade=True 確認。
- **part-3（preflight JSON API 対応）**: `auth_probe.py` に Rule 10b（`auth_probe_json_api_enabled` 既定OFF）追加。
  認証情報付き 2xx JSON を AUTHENTICATED と判定し AUTH_UNKNOWN 走行中止を解消。Rules1-10 無改変 / preflight 189 緑。
  フラグON で実フル走行が preflight 通過を確認。
- **確定バー5ファイル無改変**（`git diff --quiet HEAD` exit 0）。token 0。

## 方法②（正式フル走行）の中止判断

part-3 で preflight は通過したが、フル自律走行は AI 逐次判断で低速（~54分で LLM 呼び出し 186 回・思考 42 ターン・
basket 狙いのつもりがクロールで7URL検査）、かつ認証トークン（~1時間）失効と競合。狙い撃ちの高速確定（part-2・数秒・
トークン失効の影響なし）が実戦的かつ本物の証拠として十分と判断し、ユーザー合意のもとフル走行を中止。露呈した
実戦課題は deferred で追跡（SGK-2026-0469 / 0470）。

## 検証（Claude 独立実行・観測）

- part-1: `pytest tests/core/agents/swarm/injection/test_cross_account_bola.py` 9 passed / injection 634 passed。
- part-3: `pytest tests/unit/preflight` 189 passed。
- 実 E2E（part-1 X-Auth-Token 主認証 / part-2 本物 Juice Shop）: cross_account finding=1・payout_grade=True。
  負のコントロール（secure / authA=403）で finding=0。
- 確定バー5: `git diff --quiet HEAD` exit 0。denylist grep 0。
- ドキュメント: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。

## リスク / 正直な限界

- **秘密露出の反省**: 検証中、プロセス確認で `pgrep -af` を用いた際に主認証 JWT が一度端末出力に露出した
  （練習アカウント・短命トークン）。以後は PID のみ確認に切替。再発防止として認証は argv でなく env/stdin 経由が望ましい。
- **フル自律走行の実戦性**: 遅延（AI往復）＋認証トークン失効という実在の弱点を確認。確定の実力とは別問題として
  SGK-2026-0469/0470 で追跡。
- 別プロセス（本作業と無関係・約1.5日ハングの src.main pid=4478）が SIGKILL に応答しない I/O 待ち状態で残存。
  今回の作業由来ではない。手動確認を推奨。

## 次の一手

- 能力マップ IDOR ○→◎ 昇格（本報告で実施）。
- SGK-2026-0469（認証付き走査の自動再ログイン/トークン更新）・SGK-2026-0470（AI往復削減の高速化）を active で追跡。

## deferred_tasks

```yaml
deferred_tasks:
  - summary: "認証付き自律走査でトークン失効（~1h）をまたいで認証を維持する自動再ログイン/更新。フル走行の認可系確定の実戦化に必須。"
    tracking_task_id: SGK-2026-0469
    blocking: false
  - summary: "フル自律走行の AI 逐次判断（LLM往復）遅延の削減（決定論化/キャッシュ/スコープ制御）。検出網羅性は落とさない。"
    tracking_task_id: SGK-2026-0470
    blocking: false
```
