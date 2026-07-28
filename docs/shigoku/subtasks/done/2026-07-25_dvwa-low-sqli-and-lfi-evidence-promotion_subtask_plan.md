---
task_id: SGK-2026-0388
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
title: DVWA low SQLi and LFI evidence promotion
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / SQLi LFI evidence quality / Haddix confirmed promotion
---

# 実装計画書：DVWA low SQLi and LFI evidence promotion

## 1. 目的

DVWA low の SQLi / LFI findings を、候補止まりから confirmed に近づける。最優先は実 request / response と差分 evidence を保存し、Haddix の candidate reason を減らすこと。

この task は DVWA の特定ページに合わせるのではなく、実アプリの SQLi / LFI でも使える証拠化の型を整える。

## 2. 対象

- SQLi normal: `/vulnerabilities/sqli/`
- SQLi blind: `/vulnerabilities/sqli_blind/`
- LFI: `/vulnerabilities/fi/`

## 3. 現状の主な不足

- `payload_request_mismatch`
- `synthetic_response_evidence`
- `insufficient_timing_validation`
- `insufficient_response_difference`
- OOB チャネルや timing 統計が confirmed 判定の前提として明文化されていない。
- LFI がファイル読み取り証拠で止まり、非破壊 wrapper や chain candidate への接続条件が弱い。
- control canary と impact evidence が分かれておらず、response diff だけで判断しやすい。

## 4. 作業内容

- [x] SQLi normal で、通常値 / true 条件 / false 条件 / SQL error / data diff のいずれかを実 HTTP evidence として残す。
- [x] SQLi normal で、MariaDB/MySQL の構文エラーが response diff 側に出た場合も SQL error evidence として拾い、candidate 止まりを避ける。
- [ ] SQLi normal の evidence を `proof_of_control` と `proof_of_impact` に分ける。control-only は candidate に留める。
- [x] SQLi blind で、baseline N サンプル、true / false 非対称、sleep payload の統計的差分を保存する。
- [ ] timing 判定は baseline mean / stddev / margin / 再現回数を保存し、単発 sleep だけで confirmed にしない。
- [ ] OOB callback が使える環境では blind SQLi の第一級 evidence として保存する。OOB 未稼働時は `oob_channel_unavailable` として非脆弱と分離する。
- [x] SQL error、stack trace、DB名、内部パス、バージョン露出を error/disclosure evidence として保存する。
- [x] LFI で、payload 入り URL と、読み込まれたファイル内容または通常応答との差分を保存する。
- [ ] LFI で `php://filter` など非破壊 wrapper を評価する。`data://`, `expect://`, `php://input`, log poisoning など RCE に寄る probe は lab / 明示許可時だけ chain candidate として扱う。
- [ ] LFI→source disclosure / wrapper impact / RCE candidate を chain_builder に渡せる metadata として残す。
- [x] finding の `evidence` と `additional_info` が Haddix formatter まで欠落せず届くことを確認する。
- [ ] synthetic evidence だけで confirmed に上げない。
- [ ] DVWA の URL 名だけを根拠に confirmed 化しない。

## 5. 完了条件

- `/vulnerabilities/sqli/`, `/vulnerabilities/sqli_blind/`, `/vulnerabilities/fi/` の raw finding が出る。
- SQLi / LFI の candidate reason が減る。
- 少なくとも SQLi または LFI の confirmed 昇格が確認できる、または昇格できない理由が reason code で明確になる。
- confirmed 昇格時に、control-only ではなく impact evidence が保存されている。
- blind/time-based の confirmed は、統計・OOB・再現性のいずれかで説明できる。
- OOB や wrapper が未評価の場合は、非脆弱ではなく `oob_channel_unavailable` / `wrapper_probe_not_allowed` などで説明されている。
- report/session consistency が PASS する。

## 6. リスク

- [重要度:高] 単発 sleep だけで SQLi を confirmed にすると提出品質が落ちる。必ず比較証拠を残す。
- [重要度:中] LFI は payload が実 URL に残っていないと evidence と finding がずれる。request URL と response 差分を両方保存する。
- [重要度:中] DVWA 特有のレスポンス文字列だけを検知条件にすると実アプリで役に立たない。一般化できる差分証拠を優先する。
- [重要度:中] LFI→RCE 系 wrapper は危険になりえる。bug bounty mode では自動拡張せず、lab / 明示許可時だけ扱う。

## 7. 2026-07-26 実装メモ

第一スライスとして、SQLi / LFI の evidence を Haddix evidence quality gate が読める形に寄せた。

- SQLi normal は、SQL error の分類、DB 推定、実 PoC request / response、response differential を `additional_info` に保存する。
- SQLi blind は、単発 sleep ではなく baseline 3 回、positive 3 回、inverse condition 1 回の timing samples を保存する。
- LFI は、実際に送った payload 入り URL、PoC request / response、`file_marker_excerpt`、`target_file`、payload delivery telemetry を保存する。
- 過去レポートは再生成していないため、既存の `haddix_report_20260725_153346.md` の candidate 数はこの時点では変わらない。

未対応:

- SQLi の boolean true / false 差分の専用 evidence 化。
- OOB callback の preflight と `oob_channel_unavailable` reason code。
- LFI wrapper / chain_builder 連携。

## 8. 2026-07-26 追補メモ

通常 SQLi で、実レスポンスには `mysqli_sql_exception` / SQL syntax error が出ているのに `error_classification=none` のまま candidate に落ちる経路を修正した。

- response diff が `error` / `syntax` / `schema` / `data` / `auth` で、HTTP response が実在する場合は SQL error evidence として補完する。
- MariaDB/MySQL 系の `"You have an error in your SQL syntax"` と `mysqli_sql_exception` を SQL error signature に追加する。
- PoC request / response と response differential を finding の `additional_info` に保持する。
