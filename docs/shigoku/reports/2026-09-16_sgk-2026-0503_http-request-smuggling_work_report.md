---
task_id: SGK-2026-0503
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0503_http-request-smuggling.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0503_http-request-smuggling_work_log.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- request-smuggling
- desync
- confirmation-bar
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0503 作業完了報告 — HTTP リクエストスマグリング（CL.TE desync）を実対象で本物確定（◎）

## 何をしたか / なぜ

賞金最高額帯のスマグリングはコードベースに実装皆無だった。最大の関門「ローカルで本物の脆弱構成」を
依存ゼロの制御対象で組み、CL.TE desync を**トークン相関のクロスリクエスト汚染**で ◎ 化。

## 実装（新設1＋承認済み凍結2）

- **smart_request_smuggling.py（非凍結・新規）**: `SmartRequestSmugglingHunter`。CL.TE/TE.CL の
  desync ビルダ（`build_clte_smuggle`/`build_tecl_smuggle`）で、隠しプレフィックスに**一意トークン**を
  仕込んだ desync 要求を送る。clean baseline victim → smuggle → 別接続 victim の3手で、victim 応答に
  トークン出現＋clean 非出現なら確定。生バイト制御のため raw socket（`_raw_send` seam・既定は
  Content-Length を見て応答1つを読み切る `_default_raw_send`＝keep-alive でのタイムアウト待ちを回避）。
- **payout_grade.py（凍結・承認）**: 新 vuln_type `http_request_smuggling`→新マーカー
  `http_request_smuggling_confirmed`＋発火分岐（request_url 非空＋variant が clte/tecl＋token 非空＋
  token が poisoned_victim_body に実在＋clean_victim_body に非実在）。fail-closed。`finding.py` に
  `VulnType.HTTP_REQUEST_SMUGGLING`。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_smuggling_replay`（fresh トークンで desync
  要求を封印スコープ内で再送し、別 victim 応答に混入＋clean 非出現を再観測。raw socket・非破壊）。

## 実対象（制御対象・正直なスコープ）

スマグリングは topology 依存で SKF 等の既製ラボが無い。**自前の制御対象**（`smuggle_lab.py`＝
back-end が Transfer-Encoding: chunked を尊重、front-end が Content-Length だけで本体長を決め単一上流
接続を共有する、現実的に脆弱な front/back ペア）を用いた。これは curve-fit ではなく CL.TE 不一致という
教科書的な本物の脆弱挙動であり、エンジンはラボ内部を知らず**汎用の CL.TE/TE.CL 探索**で検出する。

## 結果（独立検証・Claude が実測）

- socket レベルで古典 CL.TE スマグルが決定論的に成立（victim REQLINE にスマグル残余が混入）を確認。
- 実 `SmartRequestSmugglingHunter.execute` が CL.TE を検出（token をスマグル側プレフィックスにのみ配置
  → 別 victim 応答 `REQLINE=GET /<token> HTTP/1.1` に出現・clean baseline は `REQLINE=GET /`）→
  **GATE1 payout_grade=True/http_request_smuggling_confirmed**。
- **GATE2**: 実 `SealedReproductionChecker._check_smuggling_replay` が fresh トークンで再送し汚染を
  再観測→**matched**（`reproduction_marker_matched:http_request_smuggling_confirmed`）。
- **GATE3**: 本物の poc_judge（実 LLM）で **is_real=True・has_actual_impact=True・counter_evidence=False・
  needs_human=False を3回連続**（審査理由「一意トークンをスマグル側プレフィックスにのみ埋め、victim 要求
  には含めていない。clean 応答に非出現・別接続 victim 応答に同一トークンがリクエスト行として出現＝
  front/back の境界判断不一致で攻撃者制御バイトが別要求の処理・応答に混入＝応答キュー汚染・キャッシュ
  汚染・資格情報奪取に発展し得る実害」）。**完全3ゲート達成＝◎（初回一発）**。
- テスト: 新規10テスト（engine CL.TE 汚染確定・非脆弱で非検出・PoC にトークン/相関・payout fail-closed×3／
  sealed matched・mismatched・not_run×2）緑。凍結3（poc_judge.md/task_queue.py/finding_validator.py）
  exit 0（無改変）。製品トークン0・秘密値非露出。

## 確度の結論（正直な格付け）

- **HTTP リクエストスマグリング（CL.TE desync・クロスリクエスト汚染）＝ ◎（完全3ゲート）**。curve-fit
  なし（トークン相関は捏造不可・発火は fail-closed・エンジンはラボ内部非依存の汎用探索）。**高度化 低(L1)**
  （CL.TE 1形態・制御対象・http のみ。TE.CL/タイミングベース/TLS/実インターネット標的・パイプライン統合は
  別途）。非破壊（良性トークンの観測のみ）。

## 完了条件の充足

計画の完了条件 1〜4 をすべて充足（条件2 の実 poc_judge を3回安定で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・feasibility を先に socket で実証）、
`rules/codingrules.md`（bare except 禁止・OSError 境界・明示タイムアウト・keep-alive の読み切り・秘密非露出）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]。

## 非阻害の観測（deferred / 別件）

- TE.CL topology・タイミングベース一次検出・TLS(https) raw socket・実インターネット標的での運用・
  パイプライン/スコープガード統合は `deferred_followup`。
