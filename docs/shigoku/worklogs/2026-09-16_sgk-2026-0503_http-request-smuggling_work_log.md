---
task_id: SGK-2026-0503
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-16_sgk-2026-0503_http-request-smuggling.md
- docs/shigoku/reports/2026-09-16_sgk-2026-0503_http-request-smuggling_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- request-smuggling
- desync
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0503 作業ログ（HTTP リクエストスマグリング・CL.TE desync・◎）

## 1. 偵察(事実優先・実測)
- コードベースにスマグリング実装皆無(high_risk_tester にも無し)＝新規構築。
- スマグリングは topology 依存で SKF 等の既製ラボ無し。最大の関門=ローカルで本物の脆弱構成。

## 2. feasibility gate(先に socket で実証)
- 依存ゼロの制御対象 smuggle_lab.py(back=TE:chunked 尊重・front=CL のみで本体長判断・単一上流共有)で
  古典 CL.TE スマグルが決定論的成立を確認(victim REQLINE にスマグル残余 'G' 混入)。
- 一意トークンをスマグル側プレフィックスにのみ置くと別 victim 応答にトークン出現・clean 非出現を確認
  (捏造不可の相関)。curve-fit でなく CL.TE 不一致という本物の脆弱挙動。

## 3. 台帳・計画・承認
- SGK-2026-0503 採番(registry.yaml・DOC-0573)。スマグリングの選択=ビルド承認(凍結2 追加)。

## 4. 実装(Claude 直接)
- smart_request_smuggling(新規): CL.TE/TE.CL ビルダ+トークン相関のクロスリクエスト汚染確定。
  raw socket(_raw_send seam・_default_raw_send は Content-Length を見て応答1つを読み切る=keep-alive の
  タイムアウト待ち回避)。
- payout_grade: VulnType.HTTP_REQUEST_SMUGGLING + _MARKER_CATEGORIES + fail-closed 発火分岐
  (token が poisoned に実在・clean に非実在・variant clte/tecl)。
- sealed_reproduction: _check_smuggling_replay(fresh トークンで再送し汚染再観測・raw socket)。

## 5. 独立検証(Claude・実出力)
- E2E(制御対象 CL.TE): 検出(token をスマグル側にのみ→victim 応答に出現/clean 非出現)→GATE1
  payout_grade=True/http_request_smuggling_confirmed→GATE2 sealed matched→GATE3 poc_judge
  3回連続 is_real=True/impact=True/counter=False/needs_human=False(初回一発)。
- 落とし穴: _default_raw_send が keep-alive で「切断まで」読み各リクエストで timeout 待ち→ハング。
  Content-Length を見て応答1つを読み切る実装に修正。
- 新規10テスト緑(engine 汚染確定/非脆弱で非検出/PoC トークン相関/payout fail-closed×3、sealed
  matched/mismatched/not_run×2)。凍結3 exit0。製品token0・秘密値非露出。

## 6. 完了
- 完了条件1〜4充足(条件2 実 poc_judge 3回安定)。in_scope_blocker 0 → done。
- 能力マップ: リクエストスマグリング行を新設(CL.TE desync・◎・高度化 低 L1)。
- 教訓: (1) スマグリングは topology 依存で既製ラボが無い→**現実的な脆弱挙動を実装した自前制御対象**で
  ◎ 可能(curve-fit でなく CL.TE 不一致という本物)。feasibility は先に socket で実証してからエンジン化。
  (2) 確定は**一意トークンのクロスリクエスト汚染**(スマグル側にしか無いトークンが別 victim 応答に出現)＝
  OOB と同型の捏造不可の相関で poc_judge 初回一発。(3) raw socket は keep-alive で Content-Length を見て
  読み切る(切断待ちでハングしない)。[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]。
- 観測(別件): TE.CL topology・タイミングベース・TLS・実インターネット標的・パイプライン統合は deferred。
