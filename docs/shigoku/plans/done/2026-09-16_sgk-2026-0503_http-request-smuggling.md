---
task_id: SGK-2026-0503
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0503_http-request-smuggling_work_report.md
- docs/shigoku/worklogs/2026-09-16_sgk-2026-0503_http-request-smuggling_work_log.md
tags:
- shigoku
- detection
- request-smuggling
- desync
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0503 計画 — HTTP リクエストスマグリング（CL/TE desync）

## 背景・事実（偵察で実測）

コードベースにスマグリング実装は**皆無**（`high_risk_tester` にも無し）＝新規構築。front-end
（プロキシ/LB/CDN）と back-end が本体長を Content-Length と Transfer-Encoding のどちらで判断するかで
食い違うと、片方が本体の一部を「次のリクエストの先頭」として解釈する＝desync（クロスリクエスト汚染）。
最高額帯の脆弱性クラスだが、**ローカルで本物の脆弱構成を組むのが最大の関門**。

実測（feasibility gate）: 依存ゼロの制御対象（`smuggle_lab.py`＝**現実的な脆弱挙動**を実装した
front-end/back-end ペア。back-end は Transfer-Encoding: chunked を尊重、front-end は Content-Length
だけで本体長を決め単一上流接続を共有）で、古典的 CL.TE スマグルが**決定論的に成立**することを socket
レベルで確認（victim 応答の REQLINE にスマグル残余が混入）。さらに**一意トークンをスマグル側の隠し
プレフィックスにのみ置くと、別 victim 応答にそのトークンが出現**（clean には非出現）＝捏造不可の相関で
汚染を証明できることを確認。curve-fit ではなく CL.TE 不一致という教科書的な本物の脆弱挙動。

## 対象（完了契約）

1. 新エンジン `smart_request_smuggling`（`SmartRequestSmugglingHunter`）: CL.TE / TE.CL の desync を
   **トークン相関のクロスリクエスト汚染**で確定（clean baseline → smuggle（隠しプレフィックスに一意
   トークン）→ victim（別接続）で、victim 応答にトークン出現＋clean に非出現）。生バイト制御のため
   raw socket（`_raw_send` seam・既定は実 socket）。
2. 確定バー（凍結・承認）: 新 vuln_type `http_request_smuggling`→新マーカー
   `http_request_smuggling_confirmed`（fail-closed）。
3. 封印再現（凍結・承認）: `_check_smuggling_replay`（fresh トークンで再送し汚染再観測）。
4. 実対象（制御対象の CL.TE desync）で完全3ゲート＋実 poc_judge。

## poc_judge 対策（[[poc-judge-raw-evidence]]）

生の smuggle リクエストバイト＋clean/poisoned の両 victim 応答＋トークン相関（スマグル側にしか無い
トークンが別 victim 応答に出現）を raw で提示。OOB と同型の「一意トークンが別経路で漏れ得ない」論法。

## 完了条件

1. エンジンが制御対象で CL.TE desync を検出しトークン汚染を捕捉。
2. GATE1 payout_grade=True/http_request_smuggling_confirmed → GATE2 封印再現 matched → GATE3 実
   poc_judge is_real=True/impact=True（3回安定）。
3. payout_grade fail-closed（トークンが clean にも出る／poisoned に無い／variant 不正）。
4. 他エンジン非回帰。凍結3 exit 0。製品トークン0・秘密値非露出。

## NOT in scope（正直なスコープ）

- 実インターネット標的の運用: TLS(https) の raw socket 対応・タイミングベース一次検出・パイプライン
  統合・スコープガード連携は別途。TE.CL は本制御対象（CL.TE）では fail-closed で正しく非発火
  （TE.CL topology は別途）。実対象は**自前の制御対象**（CL.TE を実装した front/back ペア）で、
  SKF 等の既製ラボは無い（スマグリングは topology 依存のため）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明）、`rules/codingrules.md`
（bare except 禁止・明示タイムアウト・OSError 境界・秘密非露出）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]。
