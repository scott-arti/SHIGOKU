---
task_id: SGK-2026-0471
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-03_sgk-2026-0470_llm-in-loop-latency-reduction.md
- docs/shigoku/reports/2026-09-07_sgk-2026-0471_open-redirect-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-07_sgk-2026-0471_open-redirect-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0472_open-redirect-allowlist-enum-and-chains.md
created_at: '2026-09-07'
updated_at: '2026-09-07'
tags:
- shigoku
- detection
- open-redirect
- confirmation-bar
---

# SGK-2026-0471 計画 — オープンリダイレクトを「本物確定（◎）」まで到達させる

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]]（`docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md` 43行目）で
オープンリダイレクトは「○ 対応エンジンあり（IDORの次）」。IDOR/SQLi/保存型XSS のように
**実対象で本物と確定（◎）できる状態**へ引き上げる。

## 事実（実物観測で確定・2026-09-07）

自作の最小脆弱リダイレクトサーバに **既存 `OpenRedirectSpecialist`** を当てて実測（GET-only・製品非依存の観測台）。

- 検出は機能する: 実ブラウザ（Playwright）が攻撃者ホストへ実際に遷移したのを捉え、
  `[!!!] Open Redirect CONFIRMED via Playwright` を出力。Finding を1件生成。
  - 証拠: `evidence.request_method=GET` / `request_url=<攻撃URL>` / `response_status=302` /
    `response_headers` に `location` / `additional_info.redirect_to=<攻撃者ホストURL>`。
  - 攻撃者ホストは毎回ユニーク（`shigoku-verify-<uuid>.evil.com`）＝偽装耐性のある良い発火目印。
- ◎に届かない理由は **2つ**（両方とも実測で確定）:
  - **A（確定バー・凍結）**: `evaluate_payout_grade` が `reason=unknown_category` を返す。
    `_MARKER_CATEGORIES`（`payout_grade.py`）に `open_redirect` が無く、
    未登録種別は証拠が揃っても自動却下 → `finding_validator.evaluate` は `NEEDS_MORE` 止まり（`CONFIRMED` 到達不能）。
  - **B（エンジン・非凍結）**: 生成 Finding の `impact=''` / `reproduction_steps=[]`。
    A を直しても機械フロア step3（影響＋再現手順が必須）で `missing_impact` により却下される。
- 補足事実:
  - 機械フロアの再現性ゲートは `status>0` を要求（`_response_status_ok`）＝**302 は有効**。
  - 再現チェッカー `SealedReproductionChecker` は **本文のみ**でマーカー照合（`_send_get` が
    `(body,status)` のみ返し **ヘッダを捨てる**）。オープンリダイレクトの発火は `Location` ヘッダにあるため、
    再現経路では **Location ヘッダも見る**最小追加が必要。
  - AI 審査 `poc_judge.md` は **種別非依存・証拠駆動**（改変不要）。
  - 実製品の許可リスト付き `/redirect` は素朴ペイロードを 406 で拒否した
    → エンジンのペイロードは素朴（`evil.com` 直）で、**ガチガチに守った実対象では素通りしない**。
    これは「検出の賢さ（許可リスト回避ペイロード）」という別課題であり本タスクの ◎ とは分離する（下記 deferred）。

## 完了契約の拡張（ユーザー明示承認・2026-09-07）

当初計画は「実製品が素朴攻撃を弾くため観測台E2Eで代替」としていたが、実測で
**Juice Shop の `/redirect?to=` は許可リスト部分文字列チェック付きの本物のオープンリダイレクト**であり、
現行エンジンの素朴ペイロード（`evil.com` 直）は 406 で全弾き＝未検出と判明。手動バイパス
（`?to=https://<攻撃者>/?_=<許可された値>`）で攻撃者ホストへ実際に 302 することを確認した。
ユーザー承認のもと、完了契約を拡張し **実製品（Juice Shop）で本当に ◎（CONFIRMED）を取る**ことを本タスクの完了条件に含める。

- **B'（非凍結・open_redirect.py）追加**: 許可リスト回避ペイロードを追加する。攻撃者管理ホストを基点に、
  **アプリ自身がその redirect パラメータで使う正規値（runtime に観測した元パラメータ値）を path/query/fragment に
  部分文字列として付す**形（`https://<attacker>/?_ok=<orig>` / `https://<attacker>/#<orig>` / `https://<attacker>/<orig>`）。
  製品名・特定許可URLはハードコードしない（token 0維持）。元の正規値が空のときは従来の素朴ペイロードのみ。
  発火判定は既存の Playwright/反射＋A①マーカー（Location ホスト==攻撃者ホスト）で不変。
- **実測で確定した汎用バイパス構造（curve-fit 回避のため複数形）**: 攻撃者ホストを base に許可値を
  path/query/fragment で付す形が攻撃者ホストへ確実に遷移（`.<attacker>` 連結や `@` 記法は攻撃者ホストにならず不採用）。

## 対象（このタスクで触るもの）

凍結5ファイルのうち **2つに手が入る（ユーザー明示承認済み・2026-09-07）**。残り3つ
（`poc_judge.md` / `task_queue.py` / `finding_validator.py`）は **無改変（byte-identical）を維持**。

- **B（非凍結）** `src/core/agents/swarm/injection/open_redirect.py`
  - 発火時の Finding に `impact`（セキュリティ影響を具体化: 認証済み利用者を攻撃者管理の外部URLへ誘導可能＝
    フィッシング/資格情報・OAuthトークン窃取の起点）を設定。
  - `reproduction_steps`（GET攻撃URL・観測した302の Location=攻撃者ホスト・ブラウザ遷移確認、の順）を設定。
  - 判定・再現が決定的にキーにできるよう、攻撃者ホスト/注入ペイロードホストを安定フィールドに残す
    （既存 `redirect_to`・`response_headers.location` を維持。必要なら注入ホストの明示フィールドを追加）。
- **A①（凍結）** `src/core/agents/swarm/injection/payout_grade.py`
  - `_MARKER_CATEGORIES` に `"open_redirect": "external_redirect"` を追加。
  - `_match_firing_marker` に `open_redirect` 分岐を追加。発火（`external_redirect`）は
    **「応答が 3xx で、注入した攻撃者管理ホストが実際に Location（response_headers.location または redirect_to）に出現し、
    かつそのホストが対象自身のホストと異なる（外部）」を実測で満たす場合のみ**。既存別種マーカーへの相乗り禁止。
- **A②（凍結）** `src/core/validation/sealed_reproduction_checker.py`
  - `external_redirect` を「1回のGETで観測可能・ただしヘッダ経由」のマーカーとして扱う
    （`_NON_BODY_MARKERS` には**入れない**＝ `authz_diff` のような観測不能扱いにしない）。
  - `check()` の `external_redirect` 経路で、封印GET再送（`allow_redirects=False`）の
    **Location ヘッダ**を取得し、元 Finding の攻撃者ホストが再送応答の Location に再出現かつ外部なら `matched`、
    応答ありで非再出現なら `mismatched`、応答なし/エラー/予算切れ等は `not_run`（fail-closed 不変）。
  - そのため `_send_get`（および `_sync_http_get` / `_extract_response` の整合）で Location ヘッダを取得できるよう最小拡張。
    既存の本文経路（他種別）は byte-identical を維持。

## 完了条件（このタスクの完了契約）

1. B により、発火 Finding が `impact` 非空・`reproduction_steps` 非空を持つ。
2. A①により `evaluate_payout_grade({vuln_type:'open_redirect', ...実証拠...})` が
   `payout_grade=True` / `reason=payout_grade_satisfied` / `marker=external_redirect` を返す
   （攻撃者ホストが Location に出た本物の証拠に対して）。逆に、外部ホスト非出現・同一ホスト内リダイレクト・
   3xx でない等の**偽陽性ケースでは `payout_grade=False`**（fail-closed）。
3. A②により、同じ攻撃URLの封印GET再送で攻撃者ホストが Location に再出現すれば `matched`、
   出現しなければ `mismatched`、送信不能/予算切れは `not_run`。
4. `finding_validator.validate_finding` に AI 賞金級（payout_grade=true）と再現 `matched` を与えると
   `CONFIRMED / hybrid_confirmed` に到達する（3条件AND成立）。
5. 凍結の残り3ファイル（`poc_judge.md` / `task_queue.py` / `finding_validator.py`）は
   `git diff --quiet HEAD` exit 0（無改変）。
6. 製品非依存 token 0（denylist `config/diagnostics/sealed_product_denylist.txt`。コード/コメント/テストに
   juice/dvwa/localhost:3000 等を入れない。観測用 `evil.com` は攻撃者ホストの汎用表現でありエンジン既存語彙）。
7. 実対象での ◎ 実証（拡張後の本条件）: 認可された実対象 **Juice Shop** の `/redirect?to=` に対し、
   B' の許可リスト回避ペイロードでフル判定経路が `CONFIRMED` に到達することを実証する
   （攻撃者ホストがユニークかつ外部・Location に再出現・証拠は合言葉マスク）。
   参考として観測台（自作脆弱サーバ）でのE2E ◎ も維持する。

## 必須テスト

- `payout_grade` 単体: open_redirect の (a) 本物発火→payout_grade=True/marker=external_redirect、
  (b) 外部ホスト非出現→False、(c) 同一ホスト内リダイレクト→False、(d) 3xx でない→False。
- `sealed_reproduction_checker` 単体: open_redirect の (a) 再出現→matched、(b) 非再出現→mismatched、
  (c) 送信不能/client None→not_run。既存他種別テストの非回帰。
- `open_redirect` エンジン単体: 発火時に impact/reproduction_steps が非空・攻撃者ホストが安定フィールドに残る。
- 統合: `validate_finding` が open_redirect 本物証拠＋AI賞金級＋再現matched で CONFIRMED。
- injection スイート全体（`tests/core/agents/swarm/injection/`）非回帰。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope（本タスクで扱わない）

- 確定バーの敷居を下げる変更・見かけだけ通す curve-fitting（禁止）。
- 許可リスト値そのものの能動的列挙/推測（本タスクは runtime 観測済みの正規値を再利用する範囲に留める。
  未観測時の許可リスト探索・多段リダイレクト連鎖は将来タスク）。
- `poc_judge.md` / `task_queue.py` / `finding_validator.py` の改変。
- オープンリダイレクト以外の種別追加。

## リスク

- 凍結2ファイルへの変更＝確定バーの語彙拡張。**能力追加であり敷居低下ではない**ことを、
  偽陽性ケースの fail-closed テスト（完了条件2/3の否定側）で担保する。
- `_send_get` の戻り値拡張が他種別経路に波及しないよう、本文経路の byte-identical を単体で確認。

## 実装・検証の分担

- 実装は DeepSeek/opencode（ユーザー指定の実行系）に**テキストで**指示（ドキュメント化しない）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結残り3ファイル無改変・実物E2E）。
