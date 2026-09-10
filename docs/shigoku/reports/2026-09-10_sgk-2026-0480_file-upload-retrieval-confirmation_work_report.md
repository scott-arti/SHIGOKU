---
task_id: SGK-2026-0480
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-10_sgk-2026-0480_file-upload-retrieval-confirmation.md
- docs/shigoku/worklogs/2026-09-10_sgk-2026-0480_file-upload-retrieval-confirmation_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- file-upload
- confirmation-bar
created_at: '2026-09-10'
updated_at: '2026-09-10'
---

# SGK-2026-0480 作業完了報告 — ファイルアップロード（設置＋Web取得）を実DVWAで確定経路化（○）

## 何をしたか / なぜ

検出能力マップ [[sgk-2026-0465]] でファイルアップロードは「△」。実 DVWA で
**任意の良性・非実行ファイルをアップロードし Web から取得できる（unrestricted file upload with
retrieval）**ことを、機械フロア＋実対象再現で確定できる状態へ引き上げた。非破壊
（PHP/webshell/.htaccess/RCE は扱わない）。

## 実装（凍結2＋非凍結3・凍結はユーザー明示承認済み）

- **payout_grade.py（凍結・承認）**: `file_upload` → 新マーカー `uploaded_file_retrieved`。
  file_upload_evidence が完備（upload_allowed 真＋retrieved 真＋retrieval_marker 非空＋
  retrieval_url 非空）のときのみ発火。1 つ欠落で None（fail-closed）。追加のみ・他マーカー非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `uploaded_file_retrieved` 専用
  `_check_file_upload_retrieval`。アップロード POST の再送ではなく、記録済み retrieval_url へ
  **純 GET 再読**し retrieval_marker 再出現で matched。GET-only ガードの緩和は不要。他マーカー byte-identical。
- **file_upload.py / file_upload_tester.py / payload_manager.py（非凍結）**: probe payload に
  実行毎の一意マーカー（良性・非実行）。`_verify_retrieval` が一致マーカーを `retrieval_marker` に記録。
  retrieved＋marker 一致時に impact/reproduction_steps＋retrieval_marker＋取得本文抜粋を設定。

## 結果（独立検証・Claude が実測）

- **実 DVWA `/vulnerabilities/upload/`** に実 `FileUploadSpecialist.execute` が良性マーカーファイルを
  アップロード→保存先を応答 echo＋一意マーカーの往復 GET で確定→`payout_grade=True/
  uploaded_file_retrieved`→**実 `SealedReproductionChecker` が retrieval_url を GET 再読し
  マーカー再観測→matched→CONFIRMED**（AI 審査はスタブ）。取得なし/マーカー無しは
  `payout_grade=False/no_firing_marker`（fail-closed）。
- **本物の poc_judge（実LLM）は非承認（有効3回とも payout_grade=False・1回 LLMエラー）**。
  理由は証拠の質ではなく **「良性・非実行ファイルの設置＋取得だけでは実害（コード実行・保存型XSS・
  他人ファイル上書き等）が未証明＝賞金級でない」**という正当な判断。よって**完全3ゲート
  （実 poc_judge 込み）は未達**。
- テスト: 新規 35 テスト緑。`tests/core/validation/ injection/ attack/ logic/` の失敗 6 件は本変更前
  （HEAD）でも失敗する既存/環境依存（phase_b readiness・graphql・idor_mass_assignment・
  attack/test_file_upload の既存アサーション）で、**0480 起因の回帰はゼロ**（stash で HEAD 比較・確認）。
- 凍結: `poc_judge.md`/`task_queue.py`/`finding_validator.py` は exit 0。製品非依存 token 0
  （既存コードにあった "DVWA" コメント1件も本改変ファイル内で汎用表現へ除去）。

## 確度の結論（正直な格付け）

- コマンドインジェクション(0478)・XSS(0479)は脆弱性自体が本質的に実害ありのため実 poc_judge も通り
  **◎（完全3ゲート）**。
- **ファイルアップロードは本タスクスコープ（設置＋取得のみ・実行/RCE は NOT in scope）だと実害が無く、
  実 poc_judge を通らない → 能力マップでは ◎ ではなく ○（機械＋再現は本物で確定・実害未証明で完全3
  ゲート未達）と記録**。バーを下げて通す curve-fit はしない。

## 完了条件の充足

計画の完了条件 1〜6 は充足（条件5 の「実対象で機械＋再現 CONFIRMED」は達成、「可能なら実 poc_judge」は
実害未証明のため不成立＝bonus 未達）。`in_scope_blocker=0`。

## 後続（deferred → SGK-2026-0481）

- **実害の実証**: 良性 HTML/SVG に合言葉(nonce)入り alert を仕込んでアップロード→取得 URL を実ブラウザで
  開き dialog 発火＝**アップロード経由の保存型XSS**（非破壊・実害あり）。実測で feasibility 確認済み
  （DVWA は .html を text/html 配信・取得 URL で nonce alert 発火）。凍結変更不要（0477/0479 の XSS
  ブラウザ発火バー＋再現を再利用・finding を xss 型で発行）。→ SGK-2026-0481 で ◎ を狙う。
