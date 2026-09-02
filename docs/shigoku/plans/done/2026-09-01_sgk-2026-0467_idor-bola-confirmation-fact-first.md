---
task_id: SGK-2026-0467
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-08-10_sgk-2026-0437_authz-gap-closure-e2e-verification_plan.md
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification.md
- docs/shigoku/reports/2026-09-02_sgk-2026-0467_idor-bola-confirmation-fact-first_work_report.md
- docs/shigoku/worklogs/2026-09-02_sgk-2026-0467_idor-bola-confirmation-fact-first_work_log.md
- docs/shigoku/plans/2026-09-02_sgk-2026-0468_unauth-probe-custom-header-scheme.md
created_at: '2026-09-01'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- idor
- bola
- authz
---

# SGK-2026-0467 計画 — IDOR/BOLA を「別アカウントで実際に見えた」証拠付きで確定へ（事実優先）

## 目的（何を・なぜ）

能力マップ（SGK-2026-0465）で IDOR は △（「別アカウントで実際に見えた差分の証拠づくりが弱点」）。
SQLi（SGK-2026-0466）・保存型XSS（0459-0463）と同じ「本物の証拠で confirmed=1」路線を IDOR にも通す。
**仮説を実装より先に置かない**（SGK-2026-0466 と同じ規律）: まず実走行と製品非依存 fixture で
「現状 IDOR がどこで止まるか」を事実確定してから設計する。

## コード精読で確定済みの事実（着手前調査・挙動仮説ではなくコード上の事実）

- IDOR の確定用 authz マーカー `authz_diff` は payout_grade.py:335-343 が判定。要件は
  `additional_info.authz_differential.signals` に **`auth_success` かつ `unauth_success`**（＝認証あり成功
  かつ 認証なしでも成功＝未認証アクセス許可型）、または `status_improved_with_auth`。
- この確定用トークンを出す唯一の生成器は `build_authz_differential`（api_probe_analysis.py）で、
  injection manager の API probe `_run_api_minimal_check`（manager.py:1740-2080）が本線。
  logic/idor.py の cross-session BOLA は ResponseComparator 由来 signal（`status_match`/`id_reflection` 等）で
  この語彙を出さない（語彙不一致）。
- IDOR/BOLA object_ab ブロック（manager.py:2007-2080）はマーカーは満たし得るが `impact`/`reproduction_steps` を
  **意図的に付けない**（2075-2078: 両方認証済みリクエストゆえ「未認証で許可」主張は捏造になるため）→
  payout_grade 第2条件（impact）で missing_impact → candidate 止まりの公算。かつ object_ab は
  「未認証APIアクセス成功」判定の入れ子内でのみ発火。
- `_VDP_IMPACT_MARKERS` に `second_account_compared` / `authz_impact_proven` / `cross_account_compared`
  が存在し、SGK-2026-0437（authz gap-closure e2e）で second-account 概念が使われた形跡。→ クロスアカウント
  impact の部品が一部ある可能性。真偽は実走行/実装で確認する。

## 完了契約

### 対象（in scope）
1. 実 Juice Shop へのフルパイプライン診断走行（Caido 8081・GET-only・T3有効）で IDOR/authz が
   「未発火 / candidate / confirmed」のどこで止まるかを事実確定し、真因（署名レベル）を特定。
2. 製品非依存（product token 0）の**2ユーザー authz fixture** を `tests/fixtures/` 配下に作成し、
   (a) 未認証アクセス許可型 と (b) クロスユーザーBOLA（authAがauthBの資源を読む）の両方を再現。
   これに対する検出/確定経路を事実確認し、確定に何が足りないかを署名レベルで特定。
3. 上記事実に基づき、確定バー5ファイル無改変のまま IDOR/BOLA を本物の証拠で confirmed へ運ぶための
   最小実装（必要な場合）または「現行で到達可能」の実証。

### 完了条件
- run1（実 Juice Shop）の停止点と真因が report/session 実物で裏付けられ、consistency=consistent。
- 2ユーザー fixture が存在し product 非依存チェック（`check_vdp_product_independence.py`）PASS。
- IDOR/BOLA が本物の証拠（別アカウント差分 or 未認証許可差分）で確定に到達、または
  「確定不可の署名レベル真因」を実物で特定し追跡タスク化。
- 確定バー5ファイル（payout_grade.py / poc_judge.md / task_queue.py / finding_validator.py /
  sealed_reproduction_checker.py）は `git diff --quiet HEAD` exit 0。
- token 0（/vulnerabilities/・juice・dvwa 等の製品固有トークンを test/code/comment に入れない）。
- ドキュメント: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0エラー。

### NOT in scope
- 破壊的テスト（POST/PUT/DELETE/PATCH による状態変更）。GET-only を維持。
- Juice Shop 固有の期待検知マトリクス（対象固有の当てはめ＝カーブフィッティング禁止）。
- 確定バー5ファイルの改変。
- 併走成果物（data/vuln_roi_db.json・wordlists/custom/learned_params.txt）のコミット。

## 手順
1. 台帳/registry に SGK-2026-0467 を active 登録・本計画作成（済）。
2. 環境準備（Caido 8081・Juice Shop 3000 永続起動・転送検証）（済）。
3. run1: 実 Juice Shop 診断走行 → IDOR/authz の停止点を事実確定。
4. 製品非依存 2ユーザー authz fixture 作成 → 検出/確定経路を事実確認。
5. 事実に基づく最小実装 or 到達実証。確定バー無改変・token0 を検証。
6. work_report / work_log 作成、registry/ledger・能力マップ更新、validator 0。

## リスク
- 認証コンテキスト無し走行では authB 不在でクロスユーザーBOLA が試行不可 → fixture 側で補完。
- 確定バー無改変の制約下でクロスアカウント確定を通すには VDP impact marker 経路が鍵になり得る（要事実確認）。
