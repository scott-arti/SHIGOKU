---
task_id: SGK-2026-0488
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0488_mass-assignment-confirmation.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0488_mass-assignment-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- mass-assignment
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0488 作業ログ（Mass Assignment・実 Juice Shop・◎）

## 1. 事前整理（誤認防止・削除）
- スタブ追加調査: 「エンジン無し」は誤りと判明。`attack/` に deserial/host_header/mass_assignment/
  prototype_pollution/race_condition/jwt/session/ldap/time_based tester、`high_risk_tester` に
  Smuggling/CachePoisoner、`tools/oob/interactsh_client`（実動・cmd_ssrf 専用）、subzy/subjack/nuclei が実在。
- 全候補は専用テストを持つ「テスト付き未配線 groundwork」＝削除不可（capability minimization 回避）。
  純粋なゴミは `.bak` のみ→`smart_cmd_ssrf.py.bak`/`smart_xss.py.bak` を削除。
- 誤認防止のためメモリ [[detection-capability-wiring-map]] に正確な配線マップを記録。

## 2. 偵察（事実優先・実測）
- Mass Assignment は「tester・swarm 配線・authz_diff 経路あり」最短候補だが、既存経路は◎不可:
  MassAssignmentTester は2xxで success の status ヒューリスティック（受理未検証）、authz_diff は
  IDOR/BAC 意味論で不整合（依存テスト皆無）。
- 実対象探し: Juice Shop `POST /api/Users`（登録・認証不要）で control（role無し）→customer、
  injection（role:admin）→admin を実測（決定論的差分・非破壊）。`PUT /api/Users/{id}` は JWT DECODER
  エラーで昇格不成立＝不適。登録の冪等性の壁（メール一意→再送409）は「封印再現は単発送信」を利用し
  fresh email を1つ予約する設計で解決。

## 3. 台帳・計画・承認
- SGK-2026-0488 採番（registry.yaml・DOC-0558）。Mass Assignment 新設の選択＝ビルド承認（凍結2 変更）。

## 4. 実装（Claude 直接）
- smart_mass_assignment（新規）: 特権フィールド候補に control/injection を送り応答同名フィールドの
  再帰読取で差分確定（echo は control 非present で排除）。`_client` seam・一意フィールド uuid 更新・
  fresh replay body 予約・2ステップ差分 poc・auth は poc マスク/evidence 保持。製品固有ハードコードなし。
- payout_grade: `_MARKER_CATEGORIES["mass_assignment"]` を authz_diff→専用 `privileged_field_assigned`
  に分離（authz_diff 集合からも除去）＋発火分岐（request_url/field/injected_value 非空＋2xx＋反映==攻撃者値
  ＋control 反映非空かつ≠攻撃者値・全て揃いで発火・fail-closed）。
- sealed_reproduction: `_check_mass_assignment_replay`（予約 injection body を封印内1回再送→同名フィールド
  攻撃者値再観測→matched・`_read_field`/`_norm` 再利用）＋dispatch 分岐。

## 5. 独立検証（Claude・実出力）
- smoke: 発火 positive／echo(control空)／control==injection／非2xx の fail-closed を確認。
- 実 Juice Shop E2E: execute→field role・control customer/injection admin・201→payout_grade=True/
  privileged_field_assigned→封印再現 matched→CONFIRMED。poc マスク・judge 可視に生トークンなし。
- 実 poc_judge: **初回から 5/5**（差分の両ステップ＋profileImage 差分まで裏付けと評価）＝差分2ステップ
  poc（0487 の教訓 [[poc-judge-raw-evidence]]）を先取り適用。バー非低下。
- 新規27テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・stash 比較で
  再確認）＝0488 起因の回帰ゼロ（1179 passed）。凍結3 exit 0。製品 token0・whitespace0・秘密値非露出。

## 6. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: **Mass Assignment 行を新規追加し ◎**＋高度化 低(L1)。
- 教訓: (1) 差分型（mass assignment）は control でサーバが既定値を入れる＝server-controlled の確認が
  echo 排除の要（control 非present は不発火）。(2) 冪等でない create の封印再現は「単発送信」を活かし
  fresh 値を予約する。(3) 意味論の異なるマーカー相乗りは避け専用マーカーに分離する
  （[[detection-capability-wiring-map]]・[[no-capability-minimization]]）。
- 観測(別件): 更新系/2段階 mass assignment・第2対象・パイプライン統合は高度化フェーズで deferred。
