---
task_id: SGK-2026-0447
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0445_wire-hybrid-judge-into-swarm-live.md
- docs/shigoku/reports/2026-08-13_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard_work_report.md
- docs/shigoku/worklogs/2026-08-13_sgk-2026-0447_real-caido-rerun-and-fake-proxy-guard_work_log.md
created_at: '2026-08-12'
updated_at: '2026-08-13'
tags:
- shigoku
- vdp
- security-sensitive
- preflight
target: src/core/preflight/caido_check.py,src/core/preflight/entry_gate.py
---

# 実装計画: SGK-2026-0447 — 本物 Caido 経由の正しい再実行 ＋ 偽プロキシ検知ガード

（親ロードマップ: SGK-2026-0442。T3=0445 の検証中に判明した「評価が偽の的で行われていた」問題への対処。T4=0446 の前提。）

## 背景（なぜこのタスクが必要か）

- T3（0445）の封印 run（session_20260812_175220）を精査した結果、**エンジンの攻撃通信が全て偽プロキシ（`127.0.0.1:18080` の caido スタブ）に吸い込まれ、本物の Juice Shop に1発も届いていなかった**ことが判明した。
  - 証拠: 20件の finding のレスポンス本文が全て `{"service":"caido-probe-stub"}`（30バイト固定）。この文字列は `tests/fixtures/vdp_juiceshop_sealed/caido_stub.py` からのみ出る。
  - run ログ: `ProxyChainManager ... settings proxy: http://127.0.0.1:18080` / `Injecting proxy into httpx probe: http://127.0.0.1:18080`。
  - スタブは `do_GET` で canned body を返すだけで**転送機能（do_CONNECT）が無い**＝本物のプロキシではない。
- **ソースコードの改変は無い**（f76c999 は preflight/caido/entry_gate/main.py/proxy を触っていない。`SHIGOKU_SKIP_ENTRY_GATE` は既存フラグ）。SHIGOKU は「Caido identity プローブに Caido っぽく応答する偽スタブ」に騙されて起動し、その偽物に攻撃していた。
- したがって T3 の「confirmed=0」も「機構は健全」も、**偽の的に対する数字なので検出能力の証明にならない**。
- 現状（実測）: 本物 Caido が `127.0.0.1:8081` で稼働（`/graphql` が `{"data":{"__typename":"QueryRoot"}}` を返す本物）・`8081` 経由でプロキシすると本物 Juice Shop の商品JSONが返る（＝本物の転送プロキシ）。本物 Juice Shop は `localhost:3000`。偽スタブ（18080）は本タスク着手時に停止済み。

## 目的

1. **正しい再実行**: 本物 Caido（`127.0.0.1:8081`）経由で本物 Juice Shop（`localhost:3000`）を1回攻撃し、**応答が本物であること**を確認したうえで、finding pipeline（0440 funnel）と確定/棚上げ/人間送りの件数を実測する。これで初めて「SHIGOKU が易しい脆弱性を見つけ確定できるか」が測れる。
2. **偽プロキシ検知ガード**: 「identity プローブには Caido っぽく応答するが、実際には対象へ転送しない（全リクエストに同一 canned 応答を返す）ダミープロキシ」を preflight で **fail-closed に弾く**。二度と偽の的で走らないようにする。

## 1. ⚠️ 実装前に設計承認を得る（必須）

まず提示 → 承認 → 実装:
(a) **ガードの検証ロジック**（何通のどんな GET を、どの順序で、どう判定して転送/非転送を分けるか。カーブフィッティングを避ける一般原理）、
(b) **ガードの配置**（`caido_check.py` へ additive か新規 preflight check か・既存 identity チェックは無改変か）、
(c) **fail 時の挙動**（reason code・run 中止・kill switch/無効化フラグの既定は有効）、
(d) **正しい再実行の設定手順**（proxy=8081・入口ゲート ON・偽スタブ不在の確認・snapshot 復元）。

## 2. スコープ

### Part A: 偽プロキシ検知ガード（コード）
- 実装場所: `src/core/preflight/caido_check.py` に**転送検証ステップを追加**（既存 TCP/identity チェックは無改変・additive）。preflight の一部として entry_gate から呼ばれる。
- 検証ロジック（**製品非依存・カーブフィッティング禁止**）:
  1. プロキシ経由で run の in-scope target へ **異なる 2 つ以上の benign GET** を送る。うち少なくとも 1 つは**実在しにくいユニークな nonce パス**（例 `/__shigoku_fwd_probe_<random>`）。
  2. **本物の転送プロキシ**ならパスごとに対象由来の応答が返る（root と nonce で status/body が異なるのが自然）。**全リクエストに同一 canned 応答を返すダミー**なら全応答が byte-identical になる。
  3. 判定（2026-08-12 レビュー修正・ユーザー承認済み）: 送った複数応答の **status が全て 200** かつ **body が全て byte-identical** かつ **body ≤ 512B**（canned とみなせる極端に短い応答） → `proxy_not_forwarding` で **FAIL closed**（run 中止）。
     - status==200 限定の理由: 本物ターゲットでも全パス 302（http→https リダイレクト）やルート無し API 404（同一短 body）が起こり得るため、非 200 の同一応答は「origin が応答した証拠」として **PASS** とする（誤検知防止・レビュー B2）。
     - status==200 かつ byte-identical かつ **>512B** は PASS としつつ **WARNING ログ**で「大きな canned ダミーの可能性」を可視化（false-negative の人間検知用）。
     - パス依存に異なる（status または body）→ PASS。
  - 補助として既知スタブ署名（例 `caido-probe-stub`）検知も可能だが、**主判定は「転送しているか（応答がパス依存か）」の一般原理**とし、特定製品・特定スタブへの決め打ちにしない。
  - **GET-only**・対象は run の in-scope target のみ・タイムアウト付き・応答/ログは秘密マスク。
  - 無効化フラグを設けてよいが**既定は有効（fail-closed）**。
   - **guard 相互作用**（2026-08-12 レビュー B1 修正・ユーザー承認済み）: `AsyncNetworkClient.request()` は bugbounty モードで compiled guard（`evaluate_at_layer`）を評価し policy 未設定なら fail-closed block するため、転送プローブは `network_client.request(skip_guard=True)` を**唯一の呼び出し箇所**として使用する。`skip_guard` は **preflight 内部プローブ専用**（docstring に明記・攻撃コードからの利用禁止）。検証時に `grep` で呼び出し箇所が転送プローブ 1 か所のみであることを確認する（ユーザーも独立検証）。
- **GET-only ネットワーク境界ガード**（2026-08-13 封印 run 実測 B4 対応・ユーザー承認 §19 スコープ追加）:
  - 背景: 本物ターゲットでの封印 run 実測で、InjectionManager の mass_assignment recheck が **PATCH を実送信**していた（run6 は偽の的の canned 応答のため発動せず「GET-only 20/20」に見えていた — これも偽の的の数字）。認可エンベロープ「read-only GET のみ」をネットワーク境界で強制する。
  - settings に `sealed_run_get_only: bool = False` を additive 追加（既定 off → 既存 run は byte-identical）。
  - `AsyncNetworkClient.request()` で `sealed_run_get_only=True` のとき GET 以外のメソッドを**送信前にブロック**し、専用 reason code（例 `READONLY_GET_ONLY_ENFORCED`）付きの `NetworkClientError` を raise（fail-closed・ログに method のみ）。
  - InjectionManager の mass_assignment 経路は当該例外を捕捉し、finding を **needs_human**（`LifecycleState.NEEDS_HUMAN` / `hybrid_needs_human`）に写像（状態変更検証は人間待ち）。confirmed には絶対しない。
  - テスト: (a) フラグ ON で PATCH/POST/PUT がブロックされ GET は通る (b) フラグ OFF で byte-identical (c) ブロック時に finding が needs_human に写像される。
  - **deferred（2026-08-13 レビュー D-B4-1・追跡タスク化）**: mass_assignment の discovery ループ（manager.py L2017-2028・L2043-2050）の `except Exception: continue` が `ReadonlyEnforcedError` をサイレントに飲むため、write method が Allow に出ないターゲットでは「状態変更が必要」の検知・needs_human 写像が欠落する（送信はゼロで安全・検知のみ欠落）。親ロードマップ SGK-2026-0442 の追跡タスクで対応を設計判断する。

### Part B: 正しい再実行（1回・封印）
- 前提確認: 本物 Caido が 8081 で稼働・本物 Juice Shop が 3000・**偽スタブが 8080/18080 に不在**であることを起動前に確認。
- 設定: `config/shigoku.yaml` の `proxy: "http://127.0.0.1:8081"` に一時設定 → run 後 **byte-exact 復元**（sha256 snapshot）。`caido.url` は env `SHIGOKU_CAIDO__URL=http://127.0.0.1:8081` で上書き（env が YAML より優先・永続変更なし）。
- **funnel 記録のため `diagnostics.enabled=true` を一時有効化**（2026-08-13 B3 対応・ユーザー承認）: `finding_funnel_v1` は diagnostics 有効時のみ記録される（`finding_funnel_trace.get_finding_funnel`）。env `SHIGOKU_DIAGNOSTICS__ENABLED=true` で一時有効化（config 無変更）。
- **GET-only 境界ガード ON**: env `SHIGOKU_SEALED_RUN_GET_ONLY=1`（B4 対応・ユーザー承認）。状態変更が必要な finding は needs_human へ。
- **入口ゲート ON**（`SHIGOKU_SKIP_ENTRY_GATE` を使わない）。caido_check が 8081 の本物 Caido identity を正規確認して通過し、**Part A の転送検証も PASS する**ことをログで示す。
- `--target http://localhost:3000` を **1回**実行。
- 計測・証拠:
  - **応答が本物であること**（finding/scan のレスポンス本文が 30バイト canned でない・実 Juice Shop 由来）。
  - 0440 funnel の before/after（F0〜F6 到達）・confirmed/parked/needs_human の件数・candidate_ledger の状態。
  - confirmed が出れば**賞金級 PoC artifact（opaque）**。**誤確定 0**（3条件AND 未達は confirmed にしない）。

## 3. 認可エンベロープ（従来同一・逸脱は fail-closed）
封印使い捨てローカル Juice Shop のみ・実VDP外部は対象外。攻撃・検証・ガードのプローブは **read-only GET のみ**。実行1回・snapshot 復元・kill switch・時間予算・成果物 bbb 読取可・安全0。今回は通信が**本物 Caido に記録される**。

## 4. 不変条件（絶対）
- **確定＝3条件AND（機械フロア＋AI賞金級＋再現一致）を変えない・敷居を下げない。** VDP 署名確定は無変更で共存。
- **カーブフィッティング禁止**（ガードの主判定を特定製品/特定スタブに決め打ちしない・製品 token を code/session/report/ledger/docs に入れない・`check_vdp_product_independence.py` exit 0）。
- 秘密はマスク。**PCR-P1 assert 無改変**・schema additive。既存 identity/TCP チェックは無改変（ガードは additive）。

## 5. 完了条件（設計承認後）
1. **ガード self-checking**: (a) ダミー（全同一 canned 応答・status 200）→ FAIL closed、(b) 本物転送（パス依存応答）→ PASS、(c) 到達不可/タイムアウト → fail-closed、**(d) 全 302 同一 / 全 404 同一 → PASS（誤検知なし・レビュー B2）**。製品非依存 fixture で実証。**skip_guard=True の呼び出し箇所が転送プローブ 1 か所のみ**であること（grep・ユーザー独立検証）。
2. **GET-only 境界ガード self-checking**（2026-08-13 追加）: (a) フラグ ON で PATCH/POST/PUT が送信前にブロック（`READONLY_GET_ONLY_ENFORCED`・GET は通る）、(b) フラグ OFF で byte-identical、(c) ブロック時に該当 finding が needs_human に写像される。実測（封印 run 再実行）で session の evidence に PATCH 等の状態変更メソッドが**0 件**であることを確認。
3. **正しい再実行**: 本物 Caido(8081) 経由で本物 Juice Shop に当たり、**レスポンスが本物**（canned でない）であることを証拠提示。**funnel before/after（F0〜F6・diagnostics 有効で記録）**・confirmed/parked/needs_human 件数。confirmed が出れば賞金級 PoC artifact（opaque）・誤確定0。
4. preflight exit 0・PCR-P1 diff 0・consistent・GET-only・実行1回・docs opaque・validator 0・秘密漏洩0。

## 6. 完了報告に必須（独立検証できる形で）
- ガードの検証ロジック・配置・fail 挙動と self-checking 結果（上記1）。
- 再実行の設定手順（proxy=8081・ゲート ON・偽スタブ不在確認）と、**応答が本物である証拠**・funnel before/after・確定/棚上げ/人間送り件数。
- 変更ファイル・既存 identity/TCP チェック無改変（diff 0）・PCR-P1 diff 0・preflight exit 0・`check_vdp_product_independence.py` exit 0・docs opaque・validator 0。
- in_scope_blocker / deferred_followup / non_blocking_observation の分類（§19）。

## 7. NOT in scope
Haddix レポートへの明記（T4=0446）・確定閾値/判定ロジックの変更・状態変更攻撃・m3b 以上・実VDP外部・Caido 以外のプロキシ製品対応。

## 8. 通信規律
**まず §1 の設計（ガード検証ロジック・配置・fail 挙動・再実行手順）を提示して承認を得る。** 承認後に実装＋封印 run（従来エンベロープ同一）。
