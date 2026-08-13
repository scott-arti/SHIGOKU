---
task_id: SGK-2026-0448
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live.md
created_at: '2026-08-13'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
target: src/core/agents/swarm/injection/manager_internal/execution_policy.py,src/core/agents/swarm/injection/manager.py,src/core/agents/swarm/logic/idor.py
---

# 実装計画: SGK-2026-0448 — 本物の対象で「確定1件」を実際に出すための3レバー

（親ロードマップ: SGK-2026-0442。前提 0447=done で「攻撃が本物の的に届く」土台は固まった。本タスクは「届いた上で、なぜ確定が0のままか」を潰す。）

## 背景（なぜこのタスクが必要か）

- 0447 で偽プロキシ問題を解消し、**本物 Caido（`127.0.0.1:8081`）経由で本物 Juice Shop（`localhost:3000`）に攻撃が届くこと**を実測で確認した（finding 本文がパス依存の本物 JSON/HTML、funnel F0–F6 記録、GET-only を live で強制）。
- それでも `confirmed = 0` のまま。これは偽の的が原因ではなく、**パイプライン内の3つのゲート（レバー）が、証明可能な脆弱性を確定前に落としている**ためと考えられる。0447 の funnel も再び `phase2_skipped_early_return` を示した。
- Juice Shop には「本来 payout-grade で確定できるはずの易しいバグ」（例: ログインの SQLi 認可回避、反射 XSS 等）が存在する。したがって「確定=0」は現状では**検出能力ではなくパイプラインの取りこぼし**の疑いが濃い。これを証拠で切り分けて潰すのが本タスク。

### 用語（平易な言い換え）

- **レバー1「早期終了」**: Phase-1 で候補が出た瞬間に Phase-2（追加検証・裏取り）を打ち切る仕組み。打ち切ると再現裏取りに進めず確定できない。
- **レバー2「impact ゲート」**: 「賞金級」判定は `impact`（実害の説明）と `reproduction_steps`（再現手順）が空だと `missing_impact` で不合格になる。認可系の検出器が impact を空で出すと、ここで確定に届かない。
- **レバー3「再現裏取り」**: `SealedReproductionChecker`（0447/T3 で配線済み）で「もう一度やって本当に再現するか」を確認する工程。ここに到達しないと 3条件 AND の3つ目が埋まらない。

## 目的

本物 Juice Shop に対する封印 run（GET-only・本物 Caido 経由）で、**3条件 AND の確定バーを一切下げず・カーブフィッティングせず**に、少なくとも1件の「本物の確定 finding」を出せるようにする。もし正当な理由で0件のままなら、**各候補がどの実ゲートで・なぜ正しく（fail-closed で）止まったかを候補単位のトレースで示す**（＝バーを下げずに、取りこぼしと正当な保留を区別できる状態にする）。

## スコープを固定するための「現状の切り分け（confirmed vs hypothesis）」

lessons.md `[2026-08] ERROR`（1ファイルの挙動を仕様と断定しない）に従い、着手時点の理解を明示分類する。実装前に **各レバーの実データ根拠を1回の封印 run のトレースで確定**させてから修正する（下記フェーズ0）。

- **[confirmed]** 攻撃は本物の的に届いている（0447 で実測）。
- **[confirmed]** early-return には既に `payout_grade_hold` ゲートがある（`execution_policy.py:96 should_auto_early_return`、SGK-2026-0441 Lane A）。「候補が payout-grade PoC を持たない場合は Phase-2 を走らせる（fail-closed）」設計。`fast_types = {"lfi","redirect","csrf","api"}` は候補が出た時点で早期終了しうる。
- **[hypothesis — フェーズ0で要確定]** 0447 run で `phase2_skipped_early_return` が出たのは、`payout_grade_hold` が False と判定された（＝候補が payout-grade 扱いされた、あるいは hold 条件に該当しなかった）ため。真因は run のトレースで確定する。
- **[hypothesis — フェーズ0で要確定]** 認可系（`idor.py` / access-control）の finding が `impact=''` / `reproduction_steps=[]` で出て `missing_impact` に落ちる（0441 D02）。`idor.py:309/396/549` は `authz_differential` を組むが、impact/repro を埋めているかは要確認。
- **[hypothesis — フェーズ0で要確定]** `SealedReproductionChecker`（`manager.py:1256–1277` で配線）が候補に対して起動していない／起動しても signal 不足で確定に至らない。

## フェーズ0（実装前・必須）: 1回の封印 run で真因を候補単位に確定する

コードを変える前に、本物 Caido 経由・GET-only・`diagnostics.enabled=true` で1回封印 run を実行し、**候補ごとに「どのレバーで止まったか」を1件ずつ**表にする。

- 各 finding について記録: vuln_type / funnel 到達段（F0–F6）/ early-return したか（`phase2_skipped_early_return` の有無）/ payout_grade 判定と reason（`missing_impact` / `no_firing_marker` / `unknown_category` 等）/ reproduction checker が起動したか / 起動した場合の verdict。
- この表で 3レバーの各 hypothesis を confirmed / 否定に更新する。**否定されたレバーは本タスクのスコープから外す**（スコープを推測で広げない）。
- 出力: この計画書の「フェーズ0結果」節に追記し、確定した真因だけを以降の修正対象にする。

## 修正方針（フェーズ0で confirmed になったレバーのみ実施）

> どのレバーも「取りこぼしを止める」方向にのみ変更する。**確定バー（`payout_grade.py` の 3条件 AND）と firing marker 語彙・impact 定義は変更しない**。AI の断定だけで確定に至る経路を作らない。

### レバー1: early-return が Phase-2 を潰す場合
- `should_auto_early_return` の `fast_types`／`payout_grade_hold` 判定を精査し、「payout-grade PoC が未成立の候補があるのに Phase-2 を打ち切る」経路を fail-closed 側へ寄せる。
- 変更は「保留を増やす（Phase-2 を走らせる）」方向のみ。既定 run のバイト等価性が崩れる変更は task_params 越しのオプトインにする。

### レバー2: impact ゲートで認可系が落ちる場合
- 認可系検出器（`idor.py` 等）が `authz_differential` を確立できたケースで、**その差分そのものから** `impact` と `reproduction_steps` を機械的に（LLM なしで）埋める。
- ここでの impact は「認可差分が実在する」という**検出済みの事実**の言語化に限る。新しい確証を捏造しない。`authz_differential` が signals 要件（`auth_success` かつ `unauth_success` 等）を満たさない候補は従来どおり落とす（バーは下げない）。

### レバー3: 再現裏取りに到達しない場合
- Phase-2 に到達した候補で `SealedReproductionChecker` が起動するよう配線の欠落を埋める。
- reproduction が本物の的で成立するために必要な入力（request 再送の GET-only 範囲、scope）を確認する。**GET-only 境界（0447 B4）は維持**。状態変更を伴う再現は行わない。

## 完了条件（完了契約 — 固定）

1. **フェーズ0のトレース表が存在**し、3レバーの各 hypothesis が run 実データで confirmed / 否定に更新されている。
2. confirmed になったレバーの修正が入り、対象ファイルの**確定バー（`payout_grade.py` 3条件 AND）・firing marker 語彙・impact の定義は無改変**（diff で証明）。
3. 本物 Juice Shop への封印 run（本物 Caido・GET-only）で **次のいずれか**を満たす:
   - (a) 3条件 AND を独立に満たす**確定 finding が 1件以上**出る（証拠本文がパス依存の本物・再現 verdict あり）。**または**
   - (b) 依然 0件だが、**候補単位トレースで「各候補がどの実ゲートで・なぜ正しく止まったか」**が示され、いずれもバーを下げれば確定する類ではない（正当な fail-closed）ことが説明できる。
4. 必須テストが全 pass。
5. `check_vdp_product_independence.py` が exit 0（製品トークン 0）。PCR-P1 assertion の diff 0。secret の生値がアーティファクトに残らない。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` が 0 エラー。

## 必須テスト

- `should_auto_early_return` の payout_grade_hold 分岐（レバー1を触る場合）: hold=True で早期終了しない／全候補 payout-grade で従来挙動、の単体テスト。
- 認可系 impact 埋め（レバー2を触る場合）: `authz_differential` が signals を満たす→impact/repro が埋まる、満たさない→従来どおり落ちる、の単体テスト。
- reproduction 到達（レバー3を触る場合）: Phase-2 到達候補で checker が起動する配線テスト。
- 回帰: 既定 run（オプトイン無効時）のバイト等価性を壊さない。

## NOT in scope（明示）

- 確定バー（3条件 AND）を下げること／firing marker 語彙を増やすこと／impact 定義を緩めること。
- CORS を payout-grade にすること（`cors_misconfiguration` は marker 語彙外＝設計どおり）。
- 状態変更（非 GET）を伴う再現・攻撃（0447 B4 境界を維持）。
- 特定製品（Juice Shop）向けの分岐・スタブ・焼き込み答え（カーブフィッティング禁止）。
- T4=0446（Haddix レポートへの確定/棚上げ/人間送り明記）— 本タスクの後段の別タスク。
- 6件の既存 `test_network_client.py` 失敗（テストスイート健全性、別追跡）。

## リスクと対処

- **カーブフィッティング圧**: 「確定1件」を完了条件(a)に置くと、答えを焼き込む誘惑が生じる。→ 完了条件を (a) **または** (b)（正当な fail-closed の説明）にし、バー無改変を diff で必須化することで、「確定を出す」より「取りこぼしを正す」を優先させる。
- **既定 run への回帰**: レバー1/2 の変更が既存挙動を変える。→ オプトイン化＋バイト等価性テストで隔離。
- **impact 捏造リスク**: レバー2で impact を機械生成する際、実在しない確証を書く危険。→ `authz_differential` の検出済み事実の言語化に限定し、signals 未達は落とす。
