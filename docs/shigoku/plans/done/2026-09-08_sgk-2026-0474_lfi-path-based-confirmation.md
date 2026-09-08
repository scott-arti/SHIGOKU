---
task_id: SGK-2026-0474
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
tags:
- shigoku
- detection
- lfi
- path-traversal
- confirmation-bar
created_at: '2026-09-08'
updated_at: '2026-09-08'
---

# SGK-2026-0474 計画 — LFI/パストラバーサルを「本物確定（◎）」まで到達させる（パス方式対応）

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]] で LFI は「△〜○」。SQLi/IDOR/オープンリダイレクトと同様に、
**実対象（Juice Shop）で本物と確定（◎）** できる状態へ引き上げる。

## 事実（実コードで確定・2026-09-08）

- **確定バーは LFI 対応済み**: `payout_grade._MARKER_CATEGORIES["lfi"]="file_content_leak"`。
  `_match_firing_marker` の lfi 分岐は、本文が `_LFI_PATTERNS`（`root:x:0:0:` 等）に一致、
  **または** `additional_info.file_marker_excerpt` が非空なら `file_content_leak` を返す（payout_grade.py:380-384）。
- **エンジン smart_lfi はパラメータ方式のみ**: `_send_request` は payload をクエリパラメータにだけ注入し
  URL パスは書き換えない（smart_lfi.py:502-）。決定的プローブのペイロードは `/etc/passwd`・win.ini・
  PHP ソース狙い（smart_lfi.py:280-289）。成功判定も `_LFI_PATTERNS` 一致（同ファイル内）。
- **エンジンの Finding は impact/reproduction_steps が空**（smart_lfi.py:124-159）→ 機械フロア step3
  （impact＋reproduction_steps 必須・VDPマーカー代替のみ許容、payout_grade.py:546-553）で
  `missing_impact` により却下される（`file_marker_excerpt` は VDP インパクトマーカーではない）。
- **実 Juice Shop の LFI はパス方式**（実測・2026-09-08・GET のみ）:
  - `/ftp/package.json.bak%2500.md` → 200・約4263バイト（本来ダウンロード不可の機密 `.bak` が漏洩）。
    `coupons_2013.md.bak%2500.md` / `eastere.gg%2500.md` も同様に 200。
  - `/ftp` へのディレクトリ走査（`..%2f..%2f..%2fetc/passwd` 等）は 403 で遮断（/ftp 内サンドボックス）。
  - 漏洩内容は JSON/Markdown で `_LFI_PATTERNS` に非一致 → 定型パターン依存では検出できない。
- **再現チェッカー（凍結）は `file_content_leak` を `_LFI_PATTERNS` だけで照合**
  （sealed_reproduction_checker.py:180-184）。よって Juice Shop の `.bak`（定型非一致）は再現不成立
  → ◎ に届かない（機械フロアは抜粋で発火し得るが再現が一致しない非対称）。
- 再現チェッカーは `check(payload,...)` の payload（=finding payload・additional_info 含む）から
  `file_marker_excerpt` を読める（`_expected_marker` は payout_grade の marker を採用）。
- AI 審査 poc_judge は種別非依存・証拠駆動（改変不要）。

## 対象（このタスクで触るファイル）

- **B（非凍結）** `src/core/agents/swarm/injection/smart_lfi.py`
  - **パス方式のトラバーサル/ヌルバイト検出モードを追加**（既存パラメータ方式は非回帰で維持）:
    対象エンドポイントの **URL パス**にトラバーサル/ヌルバイト（例: `<path>/<file>%00.<ext>`、
    `%2e%2e%2f` 連結、`....//` 連結）を適用して GET する経路を追加する。製品名・特定パス・特定
    ファイル名のハードコード禁止（対象の構造＝観測したパス/拡張子から一般的に組む）。
  - **差分ベースの成功判定（誤検知ガードの核）**: 「クリーンなパスでは取得不可（403/404 等）だが、
    バイパス適用で 200 かつ実体のある本文が取得できた」差分が成立したときのみ本物の漏洩とみなす。
    その差分成立時にだけ `additional_info.file_marker_excerpt` に **取得した機密内容の安定した抜粋**
    （十分な長さ・対象固有の specific な断片）を格納する。エラーページや非差分の 200 では
    excerpt を残さない（fail-closed）。
  - **impact / reproduction_steps を設定**（取得URL・観測した 200/漏洩・クリーン時の不可、の順で再現手順）。
    パラメータ方式（`/etc/passwd` 系）の既存経路でも impact/repro が埋まること。
- **A（凍結・ユーザー明示承認済み・2026-09-08）** `src/core/validation/sealed_reproduction_checker.py`
  - `file_content_leak` の再現照合を拡張: 封印 GET 再送の本文に対し、`_LFI_PATTERNS` 一致に加えて
    **元 Finding の `file_marker_excerpt`（payload additional_info 由来・最小長ガードつき）が再出現**
    したときも `matched` とする。空/短すぎ/一般的すぎる抜粋は不採用（fail-closed）。
    本文経路のみ（`_NON_BODY_MARKERS` / `_HEADER_OBSERVABLE_MARKERS` には入れない）。既存の
    `_LFI_PATTERNS` 経路・他種別（sql_error/reflected_payload/command_execution/ssrf 等）は byte-identical。

## 確定バー（凍結・本タスクでは無改変）

- `payout_grade.py`（既に `file_content_leak` を excerpt でも発火）・`poc_judge.md`・`task_queue.py`・
  `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）

1. B: パス方式で「クリーン不可→バイパスで取得可」の差分が成立したファイルに対し、発火 Finding が
   `impact` 非空・`reproduction_steps` 非空・`file_marker_excerpt` 非空（本物の取得抜粋）を持つ。
   差分不成立（クリーンでも 200・エラーページ・非実体）では vulnerable=False（fail-closed）。
2. A①（無改変確認）: `evaluate_payout_grade({vuln_type:'lfi', ...実証拠...})` が
   `payout_grade=True / marker=file_content_leak` を返す（excerpt 経由）。
3. A②（凍結改変）: 同じ攻撃 URL の封印 GET 再送で、元 excerpt が再出現すれば `matched`、
   再出現しなければ `mismatched`、送信不能/予算切れは `not_run`。空/短すぎる excerpt は matched にしない。
4. `finding_validator.validate_finding` に AI 賞金級（payout_grade=true）と再現 `matched` を与えると
   `CONFIRMED / hybrid_confirmed` に到達する。
5. 凍結: 改変は `sealed_reproduction_checker.py` のみ。`payout_grade.py` / `poc_judge.md` /
   `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0。
6. 製品非依存 token 0（denylist）。コード/コメント/テストに juice/dvwa/localhost:3000 等を入れない。
   テスト fixture は example 系の一般パス/ファイル名のみ。
7. **実対象での ◎ 実証**: 認可対象 **Juice Shop** の `/ftp` 機密ファイル（ヌルバイトバイパス）に対し、
   パス方式エンジン→差分成立→excerpt→`payout_grade=True/file_content_leak`→封印再送で excerpt 再出現
   `matched`→`CONFIRMED`。証拠は合言葉マスク・GET-only。

## 必須テスト

- engine（パス方式）単体: (a) クリーン不可→バイパス取得可の差分で vulnerable=True＋excerpt/impact/repro、
  (b) クリーンでも 200（差分なし）→ False、(c) エラーページ 200 → False、(d) 既存パラメータ方式
  `/etc/passwd` 検出の非回帰。
- sealed_reproduction_checker 単体: (a) excerpt 再出現→matched、(b) 非再出現→mismatched、
  (c) 空/短すぎ excerpt→matched にしない、(d) 既存 `_LFI_PATTERNS` 経路・他種別の非回帰、client None→not_run。
- 統合: `validate_finding` が LFI 本物証拠＋AI賞金級＋再現matched で CONFIRMED。
- injection + validation スイート非回帰。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope

- 確定バーの敷居低下・見かけだけ通す curve-fitting。
- `payout_grade.py` / `poc_judge.md` / `task_queue.py` / `finding_validator.py` の改変。
- RFI・多段・他種別の追加。
- 書き込み系/破壊的テスト（GET-only 維持）。

## リスク

- 凍結 `sealed_reproduction_checker.py` の拡張＝再現語彙の追加。**能力追加であり敷居低下ではない**ことを、
  空/短すぎ抜粋を matched にしない fail-closed テストで担保する。
- excerpt ベースは定型パターンより弱いので、最小長・specific 性ガードと「差分成立時のみ excerpt を残す」
  エンジン側規律の両輪で誤検知を防ぐ。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結無改変・実 Juice Shop E2E）。
