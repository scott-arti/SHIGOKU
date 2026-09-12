---
task_id: SGK-2026-0482
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0482_inband-ssrf-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-09_sgk-2026-0478_command-injection-inband-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- ssrf
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0482 作業完了報告 — in-band SSRF（内部到達・応答本文反映）を実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] で SSRF は △（OOB 基盤未整備・エンジン未接続・到達性未確証）。偵察で
**実 crAPI の認証付き POST が、リクエスト内の URL 値フィールドをサーバ側で取得し応答本文を in-band 反映する**
ことを実測確認（OOB 不要）。本タスクはこの in-band SSRF を実対象で機械フロア＋実再現＋実 poc_judge の
完全3ゲートで ◎ に到達させた。非破壊（サーバに読み取り GET を行わせるのみ）。

## 実装（承認済み凍結2＋非凍結1・ユーザー明示承認済み）

- **payout_grade.py（凍結・承認）**: `ssrf` 分岐の先頭に in-band 用の新マーカー `ssrf_inband` を追加。
  `additional_info.ssrf_inband_evidence` の①`fetched_url` ②`server_reflected_body` ③`client_direct_unreachable=True`
  が**全て揃ったときだけ**発火（1つでも欠ければ None＝fail-closed）。既存 `ssrf_callback`（OOB/メタデータ/
  指標エコー）経路は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `ssrf_inband` 専用再現パス `_check_inband_ssrf_replay`＋
  JSON 送信ヘルパー `_send_post_json`（+ 同期フォールバック `_sync_http_post_json`）。トリガ POST(JSON) を
  **封印スコープ内の対象エンドポイント**へ再送し、応答の `reflect_key` 値が再び非空なら matched。probe_url
  （内部/スコープ外ホスト）へはクライアントから直接送信しない（差分は元 finding の payout-grade 証拠で確定済み）。
- **smart_ssrf.py（非凍結）**: `task.params["ssrf_inband"]` opt-in 経路を追加（製品非依存: endpoint/method/
  url_field/probe_url/reflect_key/body_template/headers をパラメータで受ける。ハードコードなし）。サーバに
  probe_url を取得させ、`reflect_key` で反映本文を抽出、スキャナ自身の probe_url 直接取得が失敗なら
  `client_direct_unreachable=True` を算出。反映非空かつ直接到達不可のときだけ vuln_type=SSRF の Finding を
  発行（`ssrf_inband_evidence`＋`ssrf_inband_replay`＋生の `poc_request`/`poc_response`＋生の反映本文を
  `evidence.response_body` に併記＋impact/repro）。従来の GET クエリ走査経路は未指定時そのまま非回帰。

## 結果（独立検証・Claude が実測）

- **実 crAPI** で実 `SmartSSRFHunter.execute` が自力で in-band SSRF を検出→URL 値フィールドに内部専用サービス
  `http://mailhog:8025/` を指定→サーバが取得し MailHog の UI を in-band 反映→スキャナは内部ホスト名 `mailhog`
  を解決できず直接到達不可（差分）→`payout_grade=True/ssrf_inband`→**実 `SealedReproductionChecker` が
  トリガ POST を封印スコープ内で再送し反映を再観測→matched→CONFIRMED**。
- **本物の poc_judge（実LLM）で 4/4 承認（real=True・impact=True・errors=0）**。証拠の底上げ前（反映本文が
  内部サービスのエラー文字列／生の poc_request/poc_response が null）は 1/4 だったが、(a) 生の poc_request/
  poc_response を付与し、(b) probe 先を「200 で認識可能な内部サービス内容を返す MailHog UI」にした（脆弱性・
  確定バーは不変・証拠の実体と見せ方の強化）ことで 4/4。**完全3ゲート達成＝◎**。
- テスト: 新規12テスト緑（payout_grade 発火/fail-closed＋既存 ssrf_callback 非回帰・smart_ssrf in-band 発行/
  fail-closed・sealed_reproduction matched/mismatched/not_run）。非回帰: `injection/` `validation/` の失敗3件は
  本変更前（HEAD）でも失敗する既存（phase_b_readiness×2＝環境依存・t3_hybrid_wiring budget・stash で HEAD 比較
  確認）＝**0482 起因の回帰ゼロ**。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済み凍結2は承認範囲の追加のみ。製品非依存 token 0（コード・テストに crapi/mechanic/mailhog/dvwa 等なし。
  製品固有値は scratchpad E2E の task.params データのみ）。

## 確度の結論（正直な格付け）

- **in-band SSRF（内部到達・応答本文反映）＝実害あり**で、実ブラウザ不要・OOB 不要で実 poc_judge も通り
  **◎（完全3ゲート）**。OOB/DNS blind SSRF の外部受信基盤は未整備（別問題・in-band で ◎ 到達済み）。
  バーを下げて通す curve-fit はしていない（生証拠の付与＋意味ある内部 probe 先の選択）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の「実 poc_judge も通す」を 4/4 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §15（台帳ワークフロー）・§17（動的ルールロード）・§19（完了契約の固定・カーブフィット禁止）、
`rules/lessons.md`（再発防止）、メモリ [[no-capability-minimization]]。

## 非阻害の観測（deferred / 別件）

- 台帳 `task_registry.yaml` の構造ずれ: SGK-2026-0465 以降のエントリが `tasks:` リストではなく
  `status_allowed_values:` 以降に連なる位置にある（validator は配置に関わらず全ブロックを読むため 0 エラー・
  運用影響なし）。本タスクは既存慣習どおり同位置に登録。構造修正は §12（スキーマ変更は全読者確認）に基づき
  別途ユーザー判断で実施する `non_blocking_observation`。
