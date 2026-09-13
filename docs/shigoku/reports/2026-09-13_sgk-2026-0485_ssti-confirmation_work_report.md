---
task_id: SGK-2026-0485
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0485_ssti-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0485_ssti-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0484_graphql-authz-exposure-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssti
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0485 作業完了報告 — SSTI（サーバサイドテンプレートインジェクション）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の残る △「SSTI / CRLF」のうち **SSTI** を ◎ 化。GET のみの実測で
現行4ラボ（DVWA / Juice Shop / crAPI / DVGA）に SSTI/CRLF の実シンクが無いことを確認し、DVGA と
同じ posture で本物の脆弱アプリ **OWASP SKF ラボ `blabla1337/owasp-skf-lab:ssti`**（Python/Flask・
Jinja2）を制御対象として起動（`127.0.0.1:5085`）。実測で **404 ハンドラが `render_template_string`
に `request.url` を埋め込む**ため、任意クエリ param（`?q={{7*7}}`）が Jinja2 で評価され `49` になる
本物の SSTI を確認。本タスクはこの SSTI を実対象で機械フロア＋実再現＋実 poc_judge の完全3ゲートで
◎ に到達させた。非破壊（読み取りクエリのみ・テンプレート評価は状態変更なし）。秘密情報は扱わない
（算術ペイロードのみ）。

## 実装（承認済み凍結2＋非凍結1）

- **smart_ssti.py（非凍結・エンジン）**: 既存 `SmartSSTIHunter`（`SSTIScanner` の算術確認ペア方式）は
  SSTI を自走検出するが Finding の evidence が `response_status=0`・生証拠不足で payout_grade 非到達
  だった。確定済み payload を `self._client` 注入 seam で 1 回再送し、算術積 `expected`
  （例 `49<hex marker>`・一意マーカー付きで自然混入・テンプレ捏造不可）を含む生応答本文＋実 status を
  捕捉（`_capture_ssti`。**GET は `params={param: payload}` で 1 回だけエンコード**＝事前エンコード
  URL の二重エンコード回避）。`expected` を中心にしたスニペット（`_evidence_snippet`。反映が本文
  後方＝offset>2000 にあっても証拠を保持）で Evidence（method/url/status/response_body）＋構造化
  `ssti_evidence`＋`ssti_replay`（再現記述子）＋生 `poc_request`/`poc_response`＋impact/repro を付与。
  製品固有ハードコードなし（対象/パラメータは task 由来・token 0）。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["ssti"]="template_evaluated"` を追加。
  `_match_firing_marker` の `ssti` 分岐は `ssti_evidence` の①request_url 非空 ②response_status>0
  ③payload 非空 ④expected 非空、かつ⑤served_body に expected 実在が**全て揃ったときだけ**発火
  （1つでも欠ければ None＝fail-closed）。expected はマーカー付きで自然混入・捏造不可のため、
  算術積の再出現が評価の決定的証拠。既存マーカー経路は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_ssti_replay` を追加。`ssti_replay`
  記述子に従い確定済み payload を封印スコープ内へ 1 回再送（GET＝テンプレート評価は読み取り・
  POST は非破壊フォーム再送に限る）→応答本文に expected 再出現で matched。dispatch 分岐を
  GET-only ガードより前に追加。ライブ再取得本文は照合のみで非永続。client None / スコープ外 /
  fingerprint 不一致 / 記述子不正 は not_run（fail-closed）。

## 結果（独立検証・Claude が実測）

- **実 SKF SSTI ラボ**で実 `SmartSSTIHunter.execute` が自走検出（`SSTI (jinja2) in parameter 'q'`・
  payload `{{7*7}}<marker>`・engine=jinja2）→ 生証拠捕捉（status 404・応答本文に `49<marker>` 反映）
  →`payout_grade=True/template_evaluated`→**実 `SealedReproductionChecker` が payload を封印スコープ内で
  再 GET し `49<marker>` を再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・
  counter_evidence=False）。審査理由は「`{{7*7}}<marker>`→`49<marker>` はサーバ側テンプレート評価で
  あり反射では説明できない・一意マーカーで偶然/捏造を排除・SSTI＝RCE 隣接の重大な実害」。
  **完全3ゲート達成＝◎**。（注: 初回試行は DeepSeek API の DNS 一時失敗で 2/4 だったが、これは
  ネットワーク flake であり判定拒否ではない。回復後のクリーン実行で 5/5。）
- テスト: 新規21テスト緑（payout_grade 発火/404発火/fail-closed7種・engine 変換確定/スニペット
  後方反映/未評価 fail-closed/replay 記述子/capture params 送信/非脆弱 None・sealed_reproduction
  matched/mismatched/not_run×3/スコープ外）。非回帰: 失敗3件は本変更前（HEAD）でも失敗する既存
  （phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget・stash で HEAD 比較確認・1115 passed）＝
  **0485 起因の回帰ゼロ**。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済凍結2は承認範囲の追加のみ。製品非依存 token 0（追加コード・新規テストは target.example/
  evil.example のみ。SKF/5085 は scratchpad E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **SSTI（Jinja2 テンプレート評価）＝実害あり**（RCE 隣接）で、実 poc_judge も通り **◎（完全3ゲート）**。
  バーを下げて通す curve-fit はしていない（新マーカーは fail-closed の追加・証拠は算術積＋一意
  マーカーの再出現という決定的な評価証拠・エンジンは製品固有ハードコードなし）。
- **対象の正当性**: SKF ラボは DVWA/Juice Shop/crAPI/DVGA と同じく意図的脆弱アプリ（本物の脆弱シンク）。
  「対象が無い」ギャップは推測でシンクを捏造せず本物ラボを1つ立てることで解消。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15（単一正本・台帳ワークフロー）・§17（動的ルールロード）・§19（完了契約の固定・
カーブフィット禁止）、`rules/lessons.md`（封印実行は実対象到達を証明）、`rules/codingrules.md`
（bare except 禁止・境界のみ noqa 付き broad catch）、メモリ [[no-capability-minimization]]・
[[poc-judge-raw-evidence]]・[[dvga-graphql-lab]]。

## 非阻害の観測（deferred / 別件）

- CRLF は △ のまま（SKF `http-response-splitting` を次タスクで ◎ 化予定・`non_blocking_observation`）。
- 台帳 `task_registry.yaml` の構造ずれ（0465 以降が `tasks:` 外・validator 0 エラー・運用影響なし）は
  既存慣習どおり同位置に登録。構造修正は §12 に基づき別途判断（`non_blocking_observation`）。
