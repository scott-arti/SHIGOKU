---
task_id: SGK-2026-0504
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
tags:
- shigoku
- detection
- autonomous-integration
- swarm-wiring
- phase-b
created_at: '2026-09-16'
updated_at: '2026-09-16'
---

# SGK-2026-0504 計画 — 自律走行への検出エンジン統合（フェーズB）: 棚卸し確定＋配線土台の一般化

## 背景・事実（コードで実測・読み取り専用調査）

能力マップ [[sgk-2026-0465]] の「高度化」列が示すとおり、直近セッションで◎化した新設
ハンター群は**単体E2Eでは動くが、フル自律走行（task 生成→ハンター起動→scope guard→
payout_grade→sealed→poc_judge）の入口に載っていない**。「単発◎でも自走で出せなければ
賞金にならない」ため、フェーズBの最優先は「配線ギャップの解消」である。

### 自律走行の入口と3点の継ぎ目（canonical owner を確認）

自律走行のハンター起動は `InjectionManagerAgent`（`src/core/agents/swarm/injection/manager.py`、
`src/core/engine/master_conductor.py` から起動）が担う。ハンターを実際に呼ぶ仕組みは3段構え：

1. **登録** — `manager.py:569-637` の `self.specialists[...]`。旧9種のみ import・instantiate。
2. **選択（signal→hypothesis→specialist）** —
   `manager_internal/unknown_hypotheses.py`（応答 signal から hypothesis を生成）＋
   `manager_internal/specialist_router.py`（hypothesis→specialist の routing 表）。旧9種のみ。
3. **起動（dispatch）** — `manager.py:718-754` の `for specialist in selected:` if/elif 分岐＋
   各 `run_*_hunter`。旧9種のみ。

### 事実（証拠：全クラス名の instantiate 箇所を grep）

- 自走に載っているのは9種のみ：`smart_sqli` / `smart_xss` / `smart_lfi` / `smart_cmd_ssrf` /
  `smart_ssrf` / `smart_ssti` / `smart_cors` / `smart_crlf` / `smart_graphql`
  （IDOR は `swarm/logic`、認証は `swarm/auth` の別 manager 系統）。
- 未配線（単体E2Eのみ）の新設15ハンターは、**自分のモジュール以外どこからも instantiate
  されていない**ことを確認：
  `smart_blind_sqli`(0502) / `smart_request_smuggling`(0503) / `smart_prototype_pollution`(0497) /
  `smart_blind_ssrf`(0495) / `smart_blind_deser`(0496,0501) / `smart_blind_xxe`(0494) /
  `smart_nosql`(0487) / `smart_ldap_injection`(0499) / `smart_xxe`(0486) /
  `smart_mass_assignment`(0488) / `smart_race_condition`(0489) / `smart_host_header`(0491) /
  `smart_cache_poisoning`(0492) / `smart_subdomain_takeover`(0493) / `smart_jwt_forgery`(0490)。
- これらは `src/core/validation/sealed_reproduction_checker.py`（発見後の再現ゲート）や
  `payout_grade.py` の `_MARKER_CATEGORIES`（確定バー）からは既に参照されている＝
  **下流ゲートは配線済み。欠けているのは入口（ハンター起動）だけ**。
- `finding.py` の `SmartXXEHunter`/`SmartRequestSmugglingHunter` 参照はコメント（型ドキュメント）
  で、dispatch ではない。

### サブギャップ（OOB 系）

blind/OOB 系（`smart_blind_ssrf` / `smart_blind_deser` / `smart_blind_xxe`・HTTP＋DNS）は受信器が
自走で起動していないと確定できない。`master_conductor.py` には HTTP OOB listener の
ライフサイクル（`get_oob_listener`・停止処理・`_ensure_global_oob_guard_task`）が既にあるが、
これは SCN08（パスワードリセット等の OOB 面マッピング）用。新 blind ハンターが使う
`LocalOOBProvider` / DNS 受信器（`utils/dns_oob_listener`）と同一系統かは未確認。本タスクでは
**OOB 系は対象外**（後続タスクでこの確認込みで統合）。

## 対象（完了契約）

この 0504 は**入口の配線機構そのものを一般化する土台タスク**であり、
全15ハンターの個別配線や自走E2E◎認証は含まない（後続で1本ずつ）。

1. 棚卸し結果を本計画書に確定記録する（上記「事実」）。
2. `manager.py` の3点継ぎ目（登録・routing・dispatch）を、**新しい脆弱性クラスのハンターを
   データ駆動で追加できる一般化された仕組み**にリファクタする。既存9ハンターは新機構へ
   移行しても外部挙動が不変（回帰ゼロ）。
3. パイロットとして in-band・受信器不要・既に◎の `smart_nosql` を**新機構で1本登録**し、
   「登録→routing 選択→dispatch 起動→finding 生成の呼び出し」が通ることをテストで実証する
   （新機構が実ハンターを通せる証明）。

## 実装方針（最小差分・追加優先）

- ハンター定義を**レジストリ（データ）化**する: 各ハンターが `(specialist_key, ハンタークラス,
  起動トリガとなる hypothesis/signal)` を宣言し、
  - `self.specialists` の instantiate はレジストリから生成、
  - `specialist_router` の hypothesis→specialist 表はレジストリから拡張、
  - dispatch は `for specialist in selected:` の if/elif を**キー→ハンター呼び出しの汎用
    ディスパッチ**に置換（旧9種は互換 shim または同一メソッド経由で挙動不変）。
- 既存9種は「レジストリ経由でも従来と同じ順序・引数・結果」を保つ回帰テストで固定する。
- パイロット `smart_nosql` は既存 signal `api_json_surface`（`unknown_hypotheses.py` に実在）を
  トリガに割り当て、新機構経由で選択・起動されることをテスト（fixture ハンター＋実 nosql 登録）。
- 凍結5ファイル（`payout_grade.py` / `sealed_reproduction_checker.py` / `poc_judge.md` /
  `task_queue.py` / `finding_validator.py`）は**改変しない**（本タスクは入口配線のみ）。
- 秘密規律: 環境変数/.env の値は読まない。テスト対象は制御対象/fixture のみ。

## 完了条件

- CB-1: 一般化した登録・routing・dispatch 機構のユニット/統合テストが green
  （fixture ハンターがレジストリ登録→routing で選択→dispatch で起動されることを検証）。
- CB-2: パイロット `smart_nosql` が新機構で登録され、`api_json_surface` 系 signal で選択・
  起動されることを示すテストが green。
- CB-3: 既存9ハンターの回帰なし（injection manager の既存テストスイートが green・挙動不変）。
- CB-4: 能力マップ [[sgk-2026-0465]] の該当行（高度化/統合の記述）を、配線土台＋pilot の
  事実に更新する。
- CB-5: `python3 scripts/sync_shigoku_updated_at.py` → `python3 scripts/validate_shigoku_docs.py`
  が 0 エラー。
- 検証は `.venv/bin/pytest` の**実コマンドと観測結果**を報告する（テストのみ/実成果物/両方の別を明記）。

## NOT in scope

- 残り14ハンターの個別配線（`smart_xxe` / `smart_ldap_injection` / `smart_mass_assignment` /
  `smart_host_header` / `smart_prototype_pollution` / `smart_cache_poisoning` /
  `smart_race_condition` / `smart_blind_sqli` / `smart_request_smuggling` /
  `smart_blind_ssrf` / `smart_blind_deser` / `smart_blind_xxe` / `smart_jwt_forgery` /
  `smart_subdomain_takeover`）— 後続タスクで1本ずつ採番・配線・自走E2E◎認証。
- OOB 受信器（HTTP/DNS）の自走統合・SCN08 系との統一 — 別タスク。
- パイロット `smart_nosql` の実 crAPI フル自走E2E◎認証（target 依存の強い確認）— 後続タスク。
- 走査速度・トークン失効（[[sgk-2026-0469]] / [[sgk-2026-0470]] で追跡済み）。
- 凍結5ファイルの改変。

## 後続タスクの想定順（採番は着手時・本タスクでは未採番）

1. in-band 受信器不要群を1本ずつ配線＋自走E2E認証（推奨順: nosql 認証→xxe→ldap→
   mass_assignment→host_header→prototype_pollution→cache_poisoning→race_condition→
   blind_sqli→request_smuggling）。
2. OOB 受信器の自走統合を確認・統一（HTTP＋DNS）→ blind_ssrf / blind_deser / blind_xxe。
3. jwt_forgery（auth 系経路）／subdomain_takeover（discovery 系経路）は経路が別のため個別判断。

## 参考にしたルール

- `CLAUDE.md` §14〜§19（ドキュメント単一正本・台帳ワークフロー・CLI-first・LLM設定・完了スコープ固定）
- `rules/lessons.md`（特に `[2026-08] ERROR: 一ファイルの局所挙動を仕様と断じない` →
  3点継ぎ目の canonical owner を manager.py / unknown_hypotheses.py / specialist_router.py で確認）
- `rules/task-ledger.md`・`rules/shigoku-docs.md`（採番・front matter・related_docs）
- メモリ [[detection-capability-wiring-map]]（浅い grep で「無い」と断じない）
