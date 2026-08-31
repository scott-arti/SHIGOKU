---
task_id: SGK-2026-0464
doc_type: work_report
status: done
created_at: '2026-09-01'
updated_at: '2026-09-01'
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0464_candidate-xss-dedup-url-normalization.md
---

# SGK-2026-0464 作業完了報告 — 候補ノイズ是正（XSS等 injection 候補の脆弱性署名単位 重複排除）

## What changed
- `src/reporting/haddix_formatter.py` `_candidate_dedup_key`（+52行）: 末尾 `return None` 前に injection/reflected 系（xss/sqli/command_injection/rce/lfi/path_traversal/rfi/ssti/open_redirect/crlf(_injection)/xxe/ssrf）へ root-cause 署名 `("injection", vuln_class, endpoint(scheme://netloc/path・クエリ/fragment除去・127.0.0.1↔localhost正規化), method, parameter)` を返す分岐を追加。authz/cors/csrf は上位分岐で return 済みのため非対象。
- `tests/unit/reporting/test_candidate_injection_dedup.py`（新規・3件）: 同param×汚染URL違い→1件収束 / 別param→分離 / merged_duplicate_count 記録。
- `tests/unit/reporting/test_finding_funnel_reporting.py`: `_finding_dict` に `endpoint` 引数を追加し、同一署名 F1/F2 を用いていた2テスト（`test_only_difference_is_appended_block` / `test_funnel_absent_adds_no_additional_info_keys`）で F2 を別エンドポイントへ。意図（複数の**別** finding での funnel 動作）を保持。

## Why
保存型XSS confirmed=1 走行（session_20260901_005406）で Candidate 189 に膨張。真の脆弱性は `(host,path,param,vuln_type)` 署名で2種（comment/name）のみ。真因は候補側 `_candidate_dedup_key` が XSS 等に `None` を返し重複排除されず、かつ候補URLが内部メタキー（method/url_evidence/detection_mode）＋注入payloadで汚染され payload ごとに別URL化していたこと。confirmed 側 `_confirmed_dedup_key` は同型署名でまとめており（確定は1に収束済み）、候補側に同型を欠いていたのが差分。

## Validation run（実出力）
- 実データ再生成（main.py:180 経路の忠実再現・session_20260901_005406）: 修正なし `Confirmed:1/Candidate:189`（実 frozen report と一致）→ 修正あり `Confirmed:1/Candidate:1`（variant=stored 確定保持）。**189→1 は本修正の因果**。
- DVWA 中立: DVWA session 再生成が 修正なし `Confirmed:9/Candidate:6` = 修正あり `9/6`（完全一致・DVWA 影響ゼロ）。5候補は authz/cors/csrf/api で injection 分岐に非該当。（frozen 正本18/5 の gate 判定は不変。）
- 確定バー5ファイル `git diff --quiet HEAD` = BAR_UNCHANGED。製品非依存 verdict=pass/token0。
- `tests/unit/reporting/` 1093 passed / 1 skipped。新規 dedup 3 passed。docs validate 0 issues。

## Risks
- 本変更は injection/reflected 系候補の重複排除を新設するグローバル挙動変更。同一 `(class,endpoint,method,param)` の候補はマージされる（意図通り）。confirmed 分類・件数・降格には非関与（confirmed 側ロジック無改変）。
- URL汚染そのもの（内部メタキーが URL クエリに載る）は smart_xss/manager 側の発生源に残る。表示・件数・重複排除は本修正で解決済みのため、発生源是正は追跡任意（deferred）。

## Next step
- deferred（非阻害）: 練習台 per-id 化（テスト環境副因）、URL汚染発生源の是正。必要になれば別タスク起票。

## deferred_tasks
（本タスクの完了を阻害しない追跡候補）
- [ ] URL汚染発生源（内部メタキーが finding URL クエリに載る smart_xss/manager 経路）の正規化。dedup で解決済みのため優先度低。
