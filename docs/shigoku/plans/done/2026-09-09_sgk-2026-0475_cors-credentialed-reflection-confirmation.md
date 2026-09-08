---
task_id: SGK-2026-0475
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/reports/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-09_sgk-2026-0475_cors-credentialed-reflection-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/plans/done/2026-09-07_sgk-2026-0471_open-redirect-confirmation.md
- docs/shigoku/plans/done/2026-09-08_sgk-2026-0474_lfi-path-based-confirmation.md
tags:
- shigoku
- detection
- cors
- confirmation-bar
created_at: '2026-09-09'
updated_at: '2026-09-09'
---

# SGK-2026-0475 計画 — CORS 誤設定を「本物確定（◎）」できる能力を構築（認証付きオリジン反映）

## 目的（何を・なぜ）

検出能力マップ [[sgk-2026-0465]] で CORS は「△ 検出はするが機微データ漏えいまで示さないと確定に上げない」。
**本物の高影響 CORS（攻撃者オリジン反映＋認証付き＋機微データ越境読み取り）を確定（◎）できる能力**を構築する。

**重要（ユーザー承認・2026-09-09）**: 実測で認可対象 Juice Shop の CORS は全エンドポイント
`Access-Control-Allow-Origin: *`（オリジン反映なし・`Access-Control-Allow-Credentials` なし）で、
ブラウザ仕様上**公開データしか越境で読めない低影響**＝本物の高影響 CORS バグは実在しない。
CLAUDE.md 既知セーフホールドでも「CORS は公開データのみ＝confirmed に上げない」。よって
**Juice Shop の `*` を ◎ にするのは curve-fitting で禁止**。本タスクの ◎ 実証は**認可済みの制御対象**
（オリジン反映＋ACAC:true＋認証付き機微データを返すサーバ）で行い、**Juice Shop の `*` は fail-closed で
正しく非確定（偽 ◎ を出さない）ことを実証**する。

## 事実（実コードで確定・2026-09-09）

- 確定バー: `payout_grade._MARKER_CATEGORIES` に `cors` が**無い** → unknown_category で自動却下
  （CONFIRMED 到達不能）。オープンリダイレクト（SGK-2026-0471）と同型でマーカー新設が要る。
- エンジン: `SmartCORSHunter`（`smart_cors.py`）は `CORSTester`（`cors_tester.py`）を使い、
  test_origin / acao_header / acac_header / misconfiguration を出す。`_is_vulnerable` は
  `origin_reflection_with_credentials`（acao==test_origin かつ acac==true）を最上位、`*` は "wildcard"、
  null は "null_origin_allowed" として分類。Finding には impact/reproduction_steps を既に設定。
  **ただし応答本文を証拠に持たない**（`CORSResult` に body なし・Evidence.response_status は 200 固定）。
- 再現チェッカー: `_send_get` は `(body, status, location)` のみ返し、Location ヘッダしか見ない。
  CORS はヘッダ観測型（ACAO/ACAC）かつ**再送に Origin ヘッダを付ける**必要があるため専用再現パスが要る。
- 機械フロア step3 は impact＋reproduction_steps 必須（エンジンは設定済み）・status>0（200 で有効）。
- AI 審査 poc_judge は種別非依存（改変不要）。

## 対象（このタスクで触るファイル）

- **B（非凍結）** `src/core/agents/swarm/injection/smart_cors.py` ＋ `src/core/attack/cors_tester.py`
  - `origin_reflection_with_credentials`（acao がテストオリジンにホスト一致で反映＋acac==true）のとき、
    **その認証付き応答本文の安定した抜粋**（機微データ可読の実証）を取得し、Finding の
    `additional_info.credentialed_body_excerpt`（十分な長さ・specific）と `evidence.response_body` に残す。
    認証コンテキスト（_auth の cookies/headers）付きで越境応答本文を読む。
  - `evidence.response_status` を実観測値にする（200 固定をやめ、実 status を入れる）。
  - test_origin / acao / acac / misconfiguration を安定フィールドに保持（マーカー・再現が使う）。
  - `*` / null / 反映なし / 認証なし反映では credentialed_body_excerpt を残さない（fail-closed）。
- **A①（凍結・ユーザー明示承認済み・2026-09-09）** `src/core/agents/swarm/injection/payout_grade.py`
  - `_MARKER_CATEGORIES["cors"] = "cors_credentialed_reflection"` を追加。
  - `_match_firing_marker` に cors 分岐: **acao がテストオリジンにホスト一致で反映（`*`/null/self でない）
    かつ acac==true かつ credentialed_body_excerpt が非空**のときだけ `"cors_credentialed_reflection"` を返す。
    それ以外（`*`・null・反映なし・認証なし・本文なし）は None（fail-closed）。既存マーカーへ相乗り禁止。
- **A②（凍結・承認済み）** `src/core/validation/sealed_reproduction_checker.py`
  - `"cors_credentialed_reflection"` を `_HEADER_OBSERVABLE_MARKERS` に追加。
  - 専用再現 `_check_cors_replay`（`_check_external_redirect_replay` と同じ流儀）: 元 Finding の
    test_origin を **Origin ヘッダに付けて**封印 GET 再送し（auth があれば付与）、再送応答の
    ACAO が test_origin にホスト一致で反映＋ACAC==true なら `matched`、非反映/非 true なら `mismatched`、
    送信不能/client None は `not_run`。既存 `_send_get`（他種別の本文経路）は byte-identical を維持し、
    CORS 用の Origin 付き送信＋ACAO/ACAC 抽出は専用ヘルパーで行う。

## 確定バー（凍結・本タスクでは無改変）

- `poc_judge.md` / `task_queue.py` / `finding_validator.py` は無改変（`git diff --quiet HEAD` exit 0）。

## 完了条件（完了契約）

1. B: `origin_reflection_with_credentials` を認証付き機微エンドポイントで捉えたとき、発火 Finding が
   test_origin/acao(反映)/acac(true) と `credentialed_body_excerpt` 非空、impact/reproduction_steps 非空、
   実 status を持つ。`*`/null/反映なし/認証なしでは excerpt を残さない（fail-closed）。
2. A①: `evaluate_payout_grade({vuln_type:'cors', ...反映+creds+excerpt...})` が
   `payout_grade=True / marker=cors_credentialed_reflection`。逆に `*`・null・反映なし・acac!=true・excerpt空は
   `payout_grade=False`（fail-closed）。
3. A②: 同じ攻撃（test_origin を Origin に付けた）封印 GET 再送で ACAO 反映＋ACAC true なら `matched`、
   非反映/非 true なら `mismatched`、送信不能/client None は `not_run`。
4. `finding_validator.validate_finding` に AI 賞金級＋再現 matched で `CONFIRMED / hybrid_confirmed`。
5. 凍結: 改変は `payout_grade.py` と `sealed_reproduction_checker.py` のみ。`poc_judge.md` /
   `task_queue.py` / `finding_validator.py` は `git diff --quiet HEAD` exit 0。
6. 製品非依存 token 0（denylist）。テスト fixture は example 系オリジン（attacker.example / trusted.example）と
   汎用機微データのみ。juice/dvwa/localhost:3000 等を入れない。
7. **制御対象での ◎ 実証**: オリジン反映＋ACAC:true＋認証付き機微データを返す認可済み制御サーバに対し、
   フル判定経路が `CONFIRMED` に到達する E2E を1件。
8. **実対象 Juice Shop の正しい非確定（必須の否定側）**: 実 Juice Shop の `*` ワイルドカードに対し、
   `evaluate_payout_grade` が `payout_grade=False`（発火せず）で `CONFIRMED` に到達しないことを実証
   （偽 ◎ を出さない・fail-closed）。

## 必須テスト

- `payout_grade` 単体: (a) 反映+creds+excerpt→True/marker=cors_credentialed_reflection、(b) `*`→False、
  (c) 反映だが acac!=true→False、(d) null→False、(e) excerpt 空→False。
- `sealed_reproduction_checker` 単体: (a) 反映再現→matched、(b) 非反映→mismatched、
  (c) client None→not_run、(d) 既存 external_redirect/本文マーカー・他種別の非回帰。
- engine 単体: (a) 反映+creds で credentialed_body_excerpt を残す、(b) `*`/null/反映なしでは残さない、実 status 反映。
- 統合: `validate_finding` が CORS 本物証拠＋AI賞金級＋再現matched で CONFIRMED。
- injection + validation スイート非回帰。
- 変更後 `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py` が 0 エラー。

## NOT in scope

- 確定バーの敷居低下・`*`/公開データ CORS の ◎ 昇格（禁止）。
- `poc_judge.md` / `task_queue.py` / `finding_validator.py` の改変。
- CORS 以外の種別。

## リスク

- 凍結2ファイルへの変更＝確定バーの語彙拡張。**能力追加であり敷居低下ではない**ことを、`*`/null/認証なし/
  本文なしの fail-closed テスト（完了条件2/3の否定側）と Juice Shop の正しい非確定（条件8）で担保する。
- `_send_get` の他種別本文経路は byte-identical を維持し、CORS の Origin 付き送信は専用ヘルパーで隔離する。

## 実装・検証の分担

- 実装は DeepSeek/opencode に**テキストで**指示（ドキュメント化しない）。opencode は fixer サブエージェントの
  makora フォールバック対策として repo opencode.json に一時 agent→deepseek 上書きを入れて起動し、完了後復元
  （[[opencode-fixer-subagent-makora-fallback]]）。
- 完了報告は額面通り信用せず、Claude が独立検証（テスト実出力・diff・凍結残り3無改変・制御対象E2E・
  Juice Shop の正しい非確定）。
