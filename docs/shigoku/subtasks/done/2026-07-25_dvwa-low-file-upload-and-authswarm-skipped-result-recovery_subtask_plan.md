---
task_id: SGK-2026-0391
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
title: DVWA low File Upload and AuthSwarm skipped result recovery
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / File Upload LogicSwarm / AuthSwarm skipped results
---

# 実装計画書：DVWA low File Upload and AuthSwarm skipped result recovery

## 1. 目的

File Upload と AuthSwarm が、タスクは生成されているのに `result=None` / skipped で成果物化されない問題を直す。

ただし、DVWA の教材的な特殊仕様だけを finding 化するための修正はしない。一般的な upload flow、認証差分、権限差分として実アプリでも成立する場合だけ成果物化する。

## 2. 対象

- File Upload: `/vulnerabilities/upload/`
- AuthBypass:
  - `/vulnerabilities/authbypass/`
  - `/vulnerabilities/authbypass/get_user_data.php`
  - `/login.php`

## 3. 現状

直近 107 tasks run では、File Upload の LogicSwarm と AuthSwarm タスクが result None / skipped になり、authbypass finding の復旧に繋がっていない。

根本的には、`result=None` / skipped だけを見ると「脆弱でない」のか「ペイロードが届いていない」のかが分からない。File Upload / AuthSwarm の修正では、配送失敗と非脆弱性を分離することを完了条件に含める。

## 4. 作業内容

- [x] File Upload の LogicSwarm が `result=None` になる原因を確認する。
- [ ] AuthSwarm の skipped reason が手動方針由来か実行漏れかを切り分ける。
- [ ] 各 probe で status、redirect chain、content-type、body length、login redirect、transport error、guard/WAF/block を delivery telemetry として保存する。
- [ ] ペイロード未配送は `payload_not_delivered_redirect_login`, `payload_not_delivered_transport_error`, `payload_not_delivered_blocked`, `payload_not_delivered_content_type_mismatch` などの reason code に分離する。
- [x] File Upload は upload request、保存先、取得可否、実行可否、content-type を分けて記録する。
- [x] AuthBypass / IDOR / API BFLA は、2つの独立した認証アイデンティティが必要な場合に `untested_no_second_account` として扱う。
- [x] `scn_08`, `scn_10`, `scn_12` の手動方針と Auth/FileUpload 実行を混同しない。
- [ ] 実行しない場合も reason code 付き skipped として残す。
- [ ] 実行すべき場合は raw finding または reason-coded non-finding まで成果物化する。
- [ ] File Upload / AuthBypass が実アプリでも成立する問題か、DVWA 教材仕様だけかを分類する。

## 5. 完了条件

- File Upload が finding になる、または明確な reason code 付きで非対象化される。
- AuthSwarm skipped が実行漏れなら修正される。
- `/vulnerabilities/authbypass/get_user_data.php?id=2` の authbypass finding が復旧する、または未復旧理由が明確になる。
- `result=None` が残る場合でも、配送失敗・前提不足・手動方針・非対象のどれかが reason code で分かる。
- 2アカウント未設定による IDOR/AuthBypass 未検証が、candidate / non-finding に混ざらない。
- 復旧または非対象化の理由が、実アプリ妥当性の観点で説明できる。
- report/session consistency が PASS する。

## 6. リスク

- [重要度:高] 手動 scenario の deferred と、実行漏れ skipped を混同するとデグレを隠す。skip reason を必ず見る。
- [重要度:高] ペイロード未配送を非脆弱として扱うと見逃しになる。delivery telemetry を必ず残す。
- [重要度:中] File Upload は状態を汚しやすい。DVWA lab の範囲で安全な payload と後片付け方針を決める。
- [重要度:中] DVWA の upload 成功画面や固定パスだけに合わせると実アプリで役に立たない。アップロード可否、到達可否、実行可否、認可差分を分けて扱う。

## 7. 2026-07-26 実装メモ

第一スライスとして、File Upload を「安全canaryのみ」の自動検証に切り替え、AuthBypass/weak_id は2アカウント証明不足を別理由に分けた。

- `safe_only=True` の File Upload タスクだけ、SCN09 の manual defer から除外する。
- File Upload は PHP / `.htaccess` ではなく、無害な canary ファイルをアップロードし、推測保存先への GET で canary が取得できた場合だけ impact evidence とする。
- アップロード応答本文にファイル名入りの保存先パスが含まれる場合は、そのパスを最優先の取得候補にする。
- upload status、body length、content-type、retrieval attempts を delivery telemetry として保存する。
- File Upload の evidence quality gate は、アップロード成功だけでは confirmed にせず、取得または実行 impact が必要になる。
- AuthBypass / weak_id などで2アカウント証明が必要なのに用意できない場合は、`authz_impact_not_proven` ではなく `untested_no_second_account` に分離する。

## 8. 2026-07-27 追補メモ

2026-07-26 17:00 実行の raw session では、File Upload task が `signal_bundle.upload` から生成され、`safe_only=None` のまま SCN09 manual defer に巻き込まれていた。

このため、legacy tagged recon 経路だけでなく signal-first upload 経路にも `safe_only=True` と SCN09 メタ情報を付ける。これにより、安全な canary upload/retrieval 検証だけを自動実行し、危険な web shell / RCE 検証とは分離する。

2026-07-26 22:29 実行では File Upload task が `safe_only=True` で実行され、canary upload と retrieval は成功した。しかし Finding の `Evidence` が `request_body=""` / `response_status=0` のままだったため、Haddix evidence quality gate が `payload_request_mismatch` / `synthetic_response_evidence` と判定し candidate に落としていた。

このため、FileUploadSpecialist が Finding を作る際に、multipart upload の安全な要約、ファイル名、HTTP status、retrieval evidence、confidence を明示して保存する。

2026-07-26 23:31 実行では File Upload task は `safe_only=True` のまま実行されたが、`run_file_upload_check` に渡った `extra_params` が dict ではなく JSON 文字列だった。下流の FileUploadTester は dict 前提だったため、フォーム追加パラメータ処理で失敗し、tool result が `findings_count=0` になっていた。

このため、LogicManager と FileUploadSpecialist の境界で upload `extra_params` を正規化し、JSON 文字列でも dict と同じように扱えるようにする。

再点検で、正規化を LogicManager / FileUploadSpecialist だけに置くと FileUploadTester 直接呼び出し経路に同じ型ズレが残ることが分かった。また、旧式の `params={...}` 呼び出しではフォーム追加パラメータ全体が落ちる可能性があった。

このため、upload `extra_params` の正規化を FileUploadTester 境界へ移し、dict / JSON文字列 / Python dict 文字列 / query-string 形式を同じ mapping として扱う。さらに `params={...}` にフォーム項目だけが入っている場合も `extra_params` として扱う。

2026-07-27 07:33 実行では File Upload task 自体は `findings_count=1` となり、safe canary upload と retrieval は成功した。しかし Haddix Report 上では `file_upload` が `candidate=1` のまま残り、reason code は `payload_request_mismatch` / `synthetic_response_evidence` だった。

raw session の Finding には `evidence.request_body`、`evidence.response_status=200`、`file_upload_evidence.retrieved=true` が入っていたため、残原因は検知側ではなく、HaddixFormatter が structured `Finding.evidence` から `poc_request` / `poc_response` を補完していないことだった。このため、Haddix 変換境界で structured evidence から最小PoCを生成する。

未対応:

- AuthSwarm 全体の `payload_not_delivered_*` reason taxonomy。
- redirect chain / login redirect / content-type mismatch の全 probe 共通 telemetry。
- 2アカウント設定がある場合の AuthBypass confirmed 証明。
