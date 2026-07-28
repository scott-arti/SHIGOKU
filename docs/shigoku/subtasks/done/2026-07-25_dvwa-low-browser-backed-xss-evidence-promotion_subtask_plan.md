---
task_id: SGK-2026-0390
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
title: DVWA low browser backed XSS evidence promotion
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / reflected stored DOM XSS browser evidence
---

# 実装計画書：DVWA low browser backed XSS evidence promotion

## 1. 目的

DVWA low の Reflected / Stored / DOM XSS findings を、反射検知だけでなくブラウザ実行証拠つきの confirmed finding に近づける。

この task は、DVWA の教材 payload に合わせるのではなく、実アプリでも使える「ブラウザで実際に JavaScript が実行された証拠」を残すための改善に限定する。

## 2. 対象

- Reflected XSS: `/vulnerabilities/xss_r/`
- Stored XSS: `/vulnerabilities/xss_s/`
- DOM XSS: `/vulnerabilities/xss_d/`

## 3. 現状の主な不足

- `browser_execution_missing`
- `payload_request_mismatch`
- `synthetic_response_evidence`
- 注入点の文脈分類が計画上の必須条件になっておらず、HTML body / 属性 / JS 文字列 / URL / CSS / JSON / XML で異なる payload が必要なケースを取りこぼしやすい。
- Stored XSS 以外の second-order sink が follow-up candidate として整理されていない。

## 4. 作業内容

- [ ] 注入点を HTML body / 属性 / JS 文字列 / URL / CSS / JSON / XML / DOM source などに分類する。
- [ ] 文脈別 payload 行列を使う。1つの汎用 payload 集合だけで全コンテキストを否定しない。
- [ ] payload が sink に届かなかった場合は、status、redirect chain、content-type、body length、login redirect を `payload_not_delivered_*` として保存する。
- [x] Reflected XSS で payload 反射だけでなく JavaScript 実行を確認する。
- [x] Stored XSS で投稿後の再訪問と実行を確認する。
- [x] Stored XSS では保存面と読出し面を canary / execution token で紐づける。
- [x] DOM XSS で URL fragment / query / DOM sink の実行を確認する。
- [ ] second-order は XSS に限定せず、保存した canary が別画面/API/ログビュー等に出る場合は follow-up candidate として残す。
- [x] browser evidence と PoC request / response を finding に紐づける。
- [ ] スクリーンショットやブラウザ trace を finding に紐づける。
- [ ] XSS の evidence が Haddix report に候補理由なしで届くか確認する。
- [ ] DVWA の既知 payload やページ名だけを根拠に confirmed 化しない。

## 5. 完了条件

- XSS 3種の raw finding が安定して出る。
- `browser_execution_missing` が解消または減少する。
- 少なくとも 1 種以上の XSS が confirmed へ昇格、または未昇格理由が reason code で明確になる。
- コンテキスト別に tested / failed / not_applicable / not_delivered が分かる。
- Stored / second-order は保存面と読出し面の対応が evidence で追跡できる。
- report/session consistency が PASS する。

## 6. リスク

- [重要度:中] ブラウザ実行は重くなりやすい。並列化は今は行わず、対象URLとpayloadを絞る。
- [重要度:中] Stored XSS は状態を汚しやすい。投稿内容と再訪問手順を evidence に残し、再実行可能にする。
- [重要度:中] DVWA 固有の alert 文字列だけに依存すると実アプリで弱い。実行イベント、DOM 変化、スクリーンショットなど一般化できる証拠を優先する。
- [重要度:中] 文脈別 payload を広げすぎると実行時間が増える。まず sink 文脈を分類し、必要な payload だけを送る。

## 7. 2026-07-26 実装メモ

第一スライスとして、XSS finding にブラウザ実行証拠を持たせる経路を追加した。

- Reflected XSS は反射検知後に `BrowserPoolXSSVerifier` で実行確認し、static reflection は browser execution evidence として扱わない。
- Stored XSS は保存後に再訪問し、Playwright で実行を確認した場合に `stored_xss_revisit` を保存する。
- DOM XSS は query / fragment のブラウザ検証結果を `browser_execution` に保存する。
- finding の `additional_info` に `browser_execution`, `stored_xss_revisit`, `poc_request`, `poc_response` を渡す。

未対応:

- 注入点の文脈分類と、文脈別 payload 行列。
- ブラウザ trace / screenshot の保存。
- XSS 以外の second-order sink sweep。
