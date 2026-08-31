---
task_id: SGK-2026-0464
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0463_stored-stage2-redirect-marker-fix.md
- docs/shigoku/plans/done/2026-08-30_sgk-2026-0462_canonical-save-endpoints-wiring.md
created_at: '2026-09-01'
updated_at: '2026-09-01'
tags:
- shigoku
- vdp
- reporting
- dedup
- xss
- noise
---

# SGK-2026-0464 計画書 — 候補ノイズの是正（XSS等 injection候補の URL単位重複排除→脆弱性署名単位へ・汚染URL正規化）

## 目的（Objective）

保存型XSS confirmed=1 到達走行（SGK-2026-0463・session_20260901_005406）で **Candidate: 189** と多数の重複候補が出た。真の脆弱性は **2種類のみ**（`/comment` の `comment` 欄XSS＝確定済み・`name` 欄XSS）だが、レポートの候補重複排除が効かず189件に膨張している。これを脆弱性署名単位の重複排除に是正し、確定（confirmed=1）を一切変えずに候補ノイズを収束させる。

## 背景・真因（2026-09-01・実データで確定）

session_20260901_005406 の候補を分解:
- 生 finding 768件は全て `127.0.0.1:5008` / path `/comment` / `xss`（**他ターゲット混入なし**＝SGK-2026-0460 隔離健全）。
- `(host, path, parameter, vuln_type)` の distinct 署名は **わずか2**（`comment`・`name`）。しかし distinct 生URLは94、確定レポート候補は189。

真因（引用）:
1. `haddix_formatter._candidate_dedup_key`（:2144-2184）は **authz/cors/csrf のみ**署名を返し、**XSS等は `None` を返す** → `_deduplicate_candidate_findings`（:2277-2294）で `key is None` はマージされず**そのまま全件保持**。→ XSS候補が重複排除されない。
2. 候補URLが汚染: 内部メタキー（`method=GET`, `url_evidence=...`, `detection_mode=phase1`）＋注入payload（`&name=<script>...>`）がクエリに紛れ、payloadごとにURLが変わる（94種）。仮にキーがあっても `_canonical_candidate_target`（:2186-2199）はクエリ保持のため別物化する。
3. 副因（テスト環境）: `name` は smart_xss の既定シード候補（smart_xss.py:87-96 等）。retain-all 練習台が GET / で過去の全payloadを描画するため、`name` 注入が stale payload を拾い偽反射。確定済みの本物（comment・stored・dialog）には無影響。

対比: confirmed 側 `_confirmed_dedup_key`（:2296-2320）は `(vuln_class, endpoint(クエリ除去), method, parameter)` でまとめており、これが効いて確定は1に収束していた。候補側に同型署名が無いのが差分。

## 完了契約（Fixed completion criteria）

- CB-1: `_candidate_dedup_key` を injection/reflected 系（xss 等）にも拡張し、`(vuln_class, endpoint(クエリ除去), method, parameter)` 署名でまとめる。session_20260901_005406 からのレポート再生成で **Candidate が 189 → 2〜数件**に収束し、**Confirmed は 1 のまま不変**（variant=stored・dialog_observed）。consistency=consistent。
- CB-2: 確定バー5ファイル無改変。confirmed 側の分類・件数・確定判定を一切変えない。降格しない。
- CB-3: DVWA 既知安全保留の baseline を壊さない（authz/cors/csrf は既存キーで処理され本変更の対象外＝5候補不変）。製品非依存 token0。新規/変更ユニット緑。

## 実装方針（最小・reporting層のみ）

- `_candidate_dedup_key`（haddix_formatter.py）の末尾 `return None` の前に、injection/reflected 系 vuln_class に対し `_confirmed_dedup_key` と同型の root-cause 署名 `(("injection"), vuln_class, endpoint(scheme://netloc/path・クエリ除去), method, parameter)` を返す分岐を追加。
- parameter は `additional_info.parameter` → タイトル正規表現の順。method は poc_request 先頭行 → payload_delivery。endpoint はクエリ・fragment 除去（メタキー＋payload汚染を自動排除）。
- authz/cors/csrf の既存分岐は不変（先に return するため DVWA 5候補は非対象）。

## NOT in scope

- 確定バー5ファイル・confirmed 分類・検出の発火判定・smart_xss のシード候補（`name` 等）の変更。
- 練習台の per-id 化（副因3・テスト環境側）。SGK-2026-0459〜0463 の確定能力（不変）。

## ガードレール

- カーブフィッティング禁止・確定を減らさない/増やさない・降格しない・製品非依存 token0。
- DVWA 既知安全保留と既存ゲート/フォーマッタ テストでの回帰確認必須。
- commit は検証後・push はユーザー。実装/検証は Claude（ユーザー指示）。実出力（ユニット＋実セッション再生成の候補件数＋バー無改変＋token0）を報告する。

## 実装・検証結果（2026-09-01・Claude 実施）— 完了

**実装（reporting層のみ・最小）**: `haddix_formatter._candidate_dedup_key` の末尾 `return None` 前に injection/reflected 系（xss/sqli/command_injection/lfi/... 14クラス）へ root-cause 署名 `("injection", vuln_class, endpoint(scheme://netloc/path・クエリ/fragment除去), method, parameter)` を返す分岐を追加（+52行）。authz/cors/csrf は上位で return 済みのため非対象。

**CB-1 達成（実データ・忠実性証明）**: session_20260901_005406 をレポート再生成（main.py:180 経路を忠実再現）:
- 修正**なし**（stash）: `Confirmed: 1 / Candidate: 189`（実パイプライン frozen report と一致＝再生成が忠実）。
- 修正**あり**: `Confirmed: 1 / Candidate: 1`（variant=stored 確定は保持）。
- → 189→1 は本修正の因果。真の脆弱性 2種（comment=確定・name=候補）に収束。

**CB-2 達成**: 確定バー5ファイル `git diff --quiet HEAD` = BAR_UNCHANGED。confirmed 側 `_confirmed_dedup_key`/`_deduplicate_confirmed_findings` 無改変・確定件数不変（1）。降格なし。

**CB-3 達成**:
- DVWA 既知安全保留 **中立**を再生成で裏取り: DVWA session を修正**なし**再生成=`Confirmed:9/Candidate:6`、修正**あり**=`Confirmed:9/Candidate:6`（**完全一致**＝本修正は DVWA に影響ゼロ）。DVWA の5候補は authz/cors/csrf/api クラスで injection 分岐に非該当。（注: 再生成9/6 は frozen 正本18/5 を完全再現しないが、これは再生成経路が当時の生成環境を再現しない既知事象で本修正と無関係。正本は frozen report で gate 判定も不変。）
- 製品非依存 verdict=pass / token0。reporting 全テスト 1093 passed（funnel テスト2件は同一署名 F1/F2 を別エンドポイントへ修正＝意図保持）。新規 `test_candidate_injection_dedup.py` 3 passed（同param汚染URL収束/別param分離/merged_count）。

### 完了契約の判定: CB-1/CB-2/CB-3 すべて達成 → done
deferred（非阻害・別事象）: 練習台の per-id 化（副因3・テスト環境側）。候補URL汚染そのものの発生源（内部メタキーが URL クエリに載る smart_xss/manager 側）の是正は、dedup で表示・件数は解決済みのため追跡任意。
