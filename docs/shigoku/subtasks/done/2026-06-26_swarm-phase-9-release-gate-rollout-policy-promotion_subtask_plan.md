---
task_id: SGK-2026-0318
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/done/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
- docs/shigoku/manuals/2026-06-30_phase9_operator_runbook.md
- docs/shigoku/reports/2026-06-30_sgk-2026-0318_work_report.md
- docs/shigoku/worklogs/2026-06-30_sgk-2026-0318_work_log.md
title: 'Swarm並列化 Phase 9: release gate rollout policy promotion'
created_at: '2026-06-26'
updated_at: '2026-07-02'
tags:
- shigoku
target: release gate, rollout flags, operator control, compatibility checks
---

# 実装計画書：Swarm並列化 Phase 9: release gate rollout policy promotion

## 1. 達成したいゴール（ユーザー視点）
- [x] 並列runtimeを shadow -> canary -> limited default -> broader default の順に安全に昇格できること。
- [x] lane policy、compatibility profile、specialist maturity を実測に基づいて昇格/降格できること。
- [x] operatorが kill switch を使って即時制御できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - release gate script / check: serial baseline、Finding parity、scope violation、request budget、reader compatibility。
  - `config/shigoku.yaml`: rollout flag、risk tier、specialist maturity。
  - operator control plane: lane pause、queue drain、aggressive suppress、parallelism kill switch。
  - docs/runbook: rollout、rollback、canary運用、audit確認。
- **データの流れ / 依存関係:**
  - shadow/canary results -> release gate -> policy promotion/demotion -> config defaults -> operator runbook / audit。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** serial/parallel compare、target risk tier、specialist maturity、request metrics、event/pruning audit、reader compatibility result。
- **出力/結果 (Output):** Go/No-Go verdict、promotion/demotion decision、rollback trigger、operator summary。
- **制約・ルール:**
  - High/Critical finding parity 100%を満たさない場合は昇格しない。
  - scope violation、origin budget violation、critical event drop、reader互換性破壊が1件でもあればNo-Go。
  - `public / authenticated / admin / mutating-heavy` target risk tier と `ga / beta / experimental` specialist maturity を組み合わせてdefault flagを決める。
  - rollback手順は実行コマンド/設定/確認方法までrunbook化する。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: release gateの入力指標と合格/失格条件を固定する。
- [x] ステップ2: shadow compare reportとoperator summaryの出力形式を定義する。
- [x] ステップ3: risk tier / specialist maturity / lane policy のpromotion/demotion matrixを作る。
- [x] ステップ4: kill switchの操作要件と監査ログを定義する。
- [x] ステップ5: rollout / rollback runbookを作成する。
- [x] ステップ6: release gate script、rollback drill、downstream reader compatibility checkを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] 速度改善だけで昇格すると検出品質が落ちる - Finding parityとscope/budget violationを必須gateにする。
- [x] [重要度:高] rollback手順が曖昧だと事故復旧が遅れる - kill switchとserial互換確認をrunbook化する。
- [x] [重要度:中] maturity昇格が属人的になる - promotion/demotion matrixとaudit evidenceを必須にする。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0318-D01
    title: "継続監視: parallel runtime release gate の継続運用"
    reason: "targetやspecialistの追加で昇格条件が変わるため継続監視が必要"
    impact: medium
    tracking_task_id: SGK-2026-0318
    recommended_next_action: "canary結果とrollback drill結果を定期レビューし、default flagを調整する"
```

---

## 6. Phase 5 レビュー由来の横断制約（2026-06-28・実装前必須・Blocker級）
Phase 5（SGK-2026-0314）完了レビューで判明した制約。Phase 9 は成功指標と rollout gate の正本化。指標を誤ると「速度だけ向上して品質低下」を見逃す。

### 6.1 必須設計制約（MUST・違反は実装停止）
- [x] **C1【指標の正しい解釈】: 成功指標は「serial 強制 vs gated」で測る（PCR-1）。** 並列実行は Phase 5 以前から無門番で存在した（`mc:5855`→`po:283`）。Phase 5 は「gate を被せて非 read_only を serial 降格」したのであり「並列を新規有効化」したではない。速度改善の測定基準を「無門番時代 vs gated」にすると misleading（無門番時代の方が速いが危険）。正しくは「serial 強制(kill_switch) vs gated」で。
- [x] **C2【parity 比較器は再利用】: Phase 5 LB-6 の比較器を使う。** `src/reporting/finding_extractor.extract_all_findings()` で serial 強制経路と gated 経路の (severity+id) 集合の集合相等を判定（`rules/lessons.md` の真正性ルール・canonical extractor 使用）。canary 昇格判定にこれを使う。新規比較器は作らない。
- [x] **C3【kill_switch で serial 復帰】: rollback は Phase 5 既存 field（PCR-2）。** `settings.parallelism.kill_switch` で即時 serial 強制。rollback drill はこの field を flip して serial 互換性を確認する手順を含む。
- [ ] **C4【rich telemetry は Phase 9 で実装】: Phase 5 D-1 の引継ぎ。** `serial_gap_summary`/`rollback_signal`/`queue_wait_ms` の恒久 runtime metrics は Phase 5 では最小 parity のみで deferred。Phase 9 で shadow compare report へ実装。
- [ ] **C5【main-thread assert を gate へ】: task_queue main-thread 制約を release gate 回帰テストへ（PCR-4）。** GA 昇格前に `task_queue` mutation が main thread 制約を破っていないかを release gate script でチェック。

### 6.2 Phase 9 Go/No-Go Gate（追加）
- [x] **Go:** serial 強制 vs gated の finding parity 100% が canary 全対象で成立（C2）。
- [x] **Go:** kill_switch flip で即時 serial 復帰が rollback drill で実証済み（C3）。
- [x] **No-Go:** 速度改善だけで parity gate を通さず昇格する（C1/C2 違反）。
- [ ] **No-Go:** task_queue main-thread 制約違反が release gate で検出される（C5）。

### 6.3 参照
Phase 5 計画書 6.13・LB-6・PCR-1/PCR-2/D-1。参照ルール: `rules/lessons.md`・`rules/report-session-consistency.md`（parity 真正性）。

---

## 7. 実装前レビュー更新（2026-06-30）

### 7.1 Ready / Not Ready 判定
- **判定: Ready（条件付き実装可）。**
- **理由:** Phase 9 は新しい探索ロジックではなく、既存の gated parallel runtime を release gate / rollout / rollback / policy promotion で包む最終安全Phaseである。既存コードには `settings.parallelism.enabled` / `kill_switch` / `shadow_mode` / lane flags の安全default（`src/core/config/settings.py:247-260`）、runtime control gate helper（`src/reporting/runtime_control_release_gate.py:7-78`）、`shigoku-ops runtime-control gate` entrypoint（`scripts/shigoku_ops_cli.py:1115-1143`）、Phase 8 の limited parallel / replay artifact（`src/core/engine/swarm_dispatcher.py:348-428`, `src/core/models/swarm.py:40-75`）があるため、既存部品を拡張する最小実装で足りる。
- **条件:** 7.4 の Local Blocker を Step 0 / Step 1 の TDDで先に解消し、7.9 の Go/No-Go Gate を通すこと。Phase 9 実装は、この計画書に明記した release gate evidence bundle と operator runbook を揃えるまで default flag 昇格を行わない。

### 7.2 対象Phaseの要約
- **目的:** 並列runtimeを一括GA化せず、`shadow -> canary -> limited default -> broader default` の順で、実測 evidence に基づき昇格/降格できるようにする。成功指標は Phase 5 PCR-1 どおり「無門番時代 vs gated」ではなく **forced serial (`kill_switch=true` or `parallelism.enabled=false`) vs gated** で測る。
- **Non-Goals:** 新規脆弱性検出ロジック、SwarmManager specialist 全面並列化、mutating/aggressive lane の無条件default有効化、外部依存追加、親計画・他Phase計画書の直接編集、operator dashboard UI の本格実装、Phase 9 gateを通らない速度優先昇格。
- **前提条件:** Phase 5 の gated outer parallelism / canonical parity comparator、Phase 6 の EventBus reliability / pruning decision trace、Phase 7 の kill switch / suppress / mutex manager / protective degrade、Phase 8 の SwarmDispatcher limited parallel / `PerUrlSubResult` schema / shadow decisions が利用可能であること。
- **完了条件:** release gate script、shadow compare report、rollback drill、downstream reader compatibility check、promotion/demotion matrix、operator runbook、default flag変更手順、No-Go時の復旧手順が揃う。High/Critical finding parity 100%、scope violation 0、origin/request budget violation 0、critical event drop 0、reader compatibility break 0、secret leak 0 を満たすまで昇格しない。

### 7.3 根拠コード / 既存テスト
- `runtime_control_release_gate.py` は gate record の必須項目（`gate_name`, `status`, `date`, `evidence_source`, `evidence_summary`, `risk_if_failed`, `decision`, `approver`）と `fail -> hold` / critical waiver禁止を検証する（`src/reporting/runtime_control_release_gate.py:25-60`）。ただし既存 gate 名は generic なので、Phase 9 の evidence schema では subcheck と metrics を追加する必要がある。
- `shigoku-ops runtime-control gate` は evidence JSON と critical gate 指定を受ける入口がある（`scripts/shigoku_ops_cli.py:1115-1143`）。Phase 9 ではこの入口を release gate script の正本に寄せ、CLI-first ops routing に従う。
- `ParallelismSettings` は `enabled=false`, `kill_switch=false`, `shadow_mode=true`, `mutating.enabled=false`, `aggressive_exclusive.enabled=false` を持つ（`src/core/config/settings.py:247-260`）。default昇格は `config/shigoku.yaml` への変更前に gate evidence を要求する。
- `SwarmDispatcher` は `parallelism.enabled` かつ `kill_switch=false` のときだけ limited parallel に入り、merge は `swarm_names` 順に安定化する（`src/core/engine/swarm_dispatcher.py:300-305`, `348-428`）。Phase 9 の differential gate はこの serial path と gated path を比較対象にする。
- `SwarmManager.dispatch()` は High/Critical finding 後に後続 specialist を skip する意味論を持つ（`src/core/agents/swarm/base.py:377-385`）。Phase 9 はこの意味論を壊す promotion を No-Go とする。
- `PerUrlSubResult` は Phase 8 で schema ready だが、実URL並列の budget decision / post-join merge は Phase 9 scope と明記されている（`src/core/models/swarm.py:87-131`, `tests/unit/engine/test_phase8_gate.py:377-410`）。Phase 9 はこの未配線を gate対象として扱う。
- `ExecutionBudgetPolicy.consume()` は per-origin burst を thread-safe に消費/拒否できる（`src/core/engine/budget_policy.py:70-101`）。Injection URL actual parallel では skipped/rejected `PerUrlSubResult` へ budget decision を残す。
- `TargetSessionMutexManager` は acquire/release/timeout/orphan recovery と audit を持つ（`src/core/engine/mutex_policy.py:67-162`）。mutating/aggressive default昇格は mutex contention / rollback drill / audit確認なしに行わない。
- Phase 7 control-plane tests は aggressive suppress と kill switch serial revert を固定している（`tests/core/engine/test_master_conductor_phase7_control_plane.py:198-214`, `349-363`）。

### 7.4 Local Blocker（実装前にこのPhase内で解消）
- [x] **LB-1: Phase 9 専用 evidence schema を固定する。** 既存 `runtime_control_release_gate` は generic gate record だけを検証するため、Phase 9 実装前に `finding_parity`, `scope_violation_count`, `origin_budget_violation_count`, `request_budget_violation_count`, `critical_event_drop_count`, `reader_compatibility_status`, `rollback_drill_status`, `secret_leak_count`, `promotion_stage`, `candidate_default_flags` を含む schema を定義する。解消方法: `tests/unit/reporting/test_runtime_control_release_gate.py` に RED test を追加し、schema validation を先に固める。
- [x] **LB-2: 前提Phase evidence の整合を Step 0 pre-flight にする。** Phase 9 は前提Phaseの成果に依存するため、SGK-2026-0314/0315/0316/0317 の status、work_report、validation結果、Deferred 引継ぎが揃わない場合は No-Go。現状、`task_registry.yaml` と `task_ledger.md` の Phase status 表示に差分があり得るため、実装開始時に `python3 scripts/validate_shigoku_docs.py` と registry/ledger照合を必須にする。
- [x] **LB-3: Injection URL actual parallel を release gate 対象に昇格する。** Phase 8 は `PerUrlSubResult` schema のみ完了し、実URL並列 + budget enforcement + post-join deterministic merge は Phase 9 に送った。これを Deferred のまま default昇格すると request budget gate が空になるため、Phase 9 の Local Scope として扱う。
- [x] **LB-4: rollback drill は config flip だけでなく reader/audit確認まで含める。** `kill_switch=true` / `parallelism.enabled=false` で serial pathへ戻る単体テストはあるが、Phase 9 は rollback後の report/session reader compatibility、operator summary、reason code を evidence bundle に残す。
- [x] **LB-5: promotion/demotion matrix は default flag変更と分離する。** matrix作成、shadow/canary判定、limited default変更、broader default変更を同一patchに混ぜない。特に mutating/aggressive default有効化は matrix上も `manual_approval_required` かつ gate全通過まで disabled。

### 7.5 Local Deferred
| # | 項目 | Deferred先Phase | Deferredしても安全な理由 | 将来の検出方法 |
|---|---|---|---|---|
| D-1 | operator dashboard UI / 長期トレンド表示の本格実装 | SGK-2026-0320（Recon途中再開・可視化・対話型オペレーション） | Phase 9 の Go 条件は CLI evidence bundle、Markdown runbook、operator summary JSON で満たせる。UIがなくても release gate / rollback / default flag 判定は実行可能 | SGK-2026-0320 の可視化タスクで Phase 9 `operator_summary.json` / gate evidence JSON を ingest するテスト |
| D-2 | EventBus runtime の根本的な main-loop 統合 | SGK-2026-0322（並行タスク途中保存＋判断ツリー可視化） | Phase 6 で handler marshaling と delay queue により直接 mutation は回避済み。Phase 9 は queue full / critical event drop / dead-letter audit を gate対象にすればGo条件を壊さない | Phase 9 fault injection で `critical_event_drop_count=0`、SGK-2026-0322 で resume/checkpoint replay 時の event trace 差分検出 |
| D-3 | long-term maturity score の自動学習・自動昇格 | SGK-2026-0320 | Phase 9 は初回 rollout の promotion/demotion matrix と手動承認つき evidence で十分。自動学習を混ぜると release gate の説明可能性が落ちる | canary履歴が一定件数を超えた時点で maturity score 欠落を dashboard / report lint で検出 |

### 7.6 Parent Change Request
- [x] **PCR-1: release gate evidence schema を親計画の共通契約へ昇格。** Phase 5-9 の比較軸を揃えるため、`finding_parity`, `scope/budget`, `event_drop`, `reader_compatibility`, `rollback_drill`, `operator_approval` を親計画 4.3/4.4 の共通 gate vocabulary に追加候補とする。
- [x] **PCR-2: registry / ledger / work_report の pre-flight consistency を全Phase完了条件へ追加。** Phase 9 で初めて default昇格すると、過去Phaseの status不整合が rollout 判断へ混入する。親計画へ「Phase N+1 着手前に Phase N の registry/ledger/work_report validationを通す」横断ルールを提案する。
- [x] **PCR-3: default flag変更は code patch と運用承認 patch を分離する。** `config/shigoku.yaml` の default昇格は、release gate script / evidence / runbook / rollback drill が通った後の別patchにする運用ルールを親計画へ反映候補とする。
- [x] **PCR-4: Phase 9 後の継続監視は SGK-2026-0320 系へ接続。** 初回 release gate は本Phaseで扱い、長期可視化・対話型運用・履歴dashboardは SGK-2026-0320 配下へ送る境界を親計画で固定する。

### 7.7 Out of Scope
- [x] 新しい vulnerability detector / specialist / payload generator の追加。
- [x] High/Critical adaptive skip 意味論の変更。
- [x] `mutating` / `aggressive_exclusive` の無条件 default 有効化。
- [x] scope unknown / allowlist なし target への active/mutating/aggressive 実行。
- [x] operator dashboard UI の本格実装、長期時系列分析、自動学習による maturity 自動昇格。
- [x] 親計画・前提Phase・後続Phase計画書の直接編集。
- [x] gateを通さない `config/shigoku.yaml` default flag変更。

### 7.8 TDDチェックリスト
- [x] **T-0.1 pre-flight docs/ledger consistency:** SGK-2026-0314/0315/0316/0317 の status、primary_doc、work_report、work_log、Deferred 引継ぎが矛盾しない。矛盾があれば Phase 9 implementation は blocked として operator summary に reason を出す。
- [x] **T-1.1 evidence schema validation:** Phase 9 evidence record に `finding_parity`, `scope_violation_count`, `origin_budget_violation_count`, `request_budget_violation_count`, `critical_event_drop_count`, `reader_compatibility_status`, `rollback_drill_status`, `secret_leak_count` が欠けると fail。
- [x] **T-1.2 critical gate cannot be waived:** finding parity / scope budget / critical event drop / reader compatibility / rollback drill は waived 不可。既存 `critical_cannot_be_waived` を Phase 9 critical gate に適用する。
- [x] **T-2.1 forced serial vs gated parity:** 同一 task queue snapshot を `parallelism.enabled=false` または `kill_switch=true` と gated path で実行し、`extract_all_findings()` 由来の High/Critical finding set が100%一致する。
- [x] **T-2.2 response differential axes:** finding parity が一致しても `status`, `body length`, `JSON shape`, `DOM marker`, `redirect chain`, `cache header`, `timing delta` の許容差分を shadow compare report に出す。
- [x] **T-3.1 Injection URL budget enforcement:** 実URL並列で `ExecutionBudgetPolicy` burst超過分が skipped/rejected `PerUrlSubResult` として残り、共有 `current_context` を worker が直接 mutate しない。
- [x] **T-3.2 deterministic post-join merge:** Injection URL結果は URL priority order / request_fingerprint / payload_fingerprint に基づき deterministic merge され、finding欠落ではなく sub-result failure として残る。
- [x] **T-4.1 rollback drill:** `kill_switch=true` flip後、次batchが serial path へ戻り、rollback evidence に config diff、operator command、verification result、reader compatibility result が残る。
- [x] **T-5.1 reader compatibility:** 旧session/report、新metadata欠落artifact、Phase 8 `shadow_decisions`、Phase 6 `decision_traces`、Phase 9 evidence bundle を downstream reader が読める。
- [x] **T-6.1 promotion/demotion matrix:** `public/authenticated/admin/mutating-heavy` x `ga/beta/experimental` x lane policy の matrix が default flag候補を返し、No-Go reason がある場合は demote/hold へ倒す。
- [x] **T-7.1 operator runbook lint:** rollout / canary / rollback / audit確認のコマンド、期待出力、失敗時分岐、承認者、証跡保存先が runbook に揃う。
- [x] **T-8.1 shigoku-ops route:** gate評価は `.venv/bin/shigoku-ops runtime-control gate ...` または `python3 scripts/shigoku_ops_cli.py runtime-control gate ...` を通る。

### 7.9 Go/No-Go Gate
- [x] **Go:** pre-flight docs/ledger consistency が passし、前提Phaseの work_report と validation結果を参照できる。
- [x] **Go:** forced serial vs gated の High/Critical finding parity 100%。
- [x] **Go:** scope violation 0、origin budget violation 0、request budget violation 0、critical event drop 0、reader compatibility break 0、secret leak 0。
- [x] **Go:** Injection URL actual parallel は budget decision と skipped/rejected `PerUrlSubResult` を残し、post-join deterministic merge が確認済み。
- [x] **Go:** rollback drill が `kill_switch=true` / `parallelism.enabled=false` の両方または明示選択した正本経路で実証済み。
- [x] **Go:** promotion/demotion matrix が target risk tier / specialist maturity / lane policy から default flag候補と hold理由を説明できる。
- [x] **Go:** default flag変更は release gate pass 後の別patchとして扱われ、operator approval evidence が残る。
- [x] **No-Go:** 速度改善だけを根拠に昇格する。
- [x] **No-Go:** High/Critical finding 欠落、adaptive skip破壊、scope/budget違反、critical event drop、reader互換性破壊、secret leak が1件でもある。
- [x] **No-Go:** gate evidence が古い report/session と混ざる、または consistency verdict が `consistent` 以外。
- [x] **No-Go:** mutating/aggressive defaultを approval / allowlist / mutex audit / rollback drill なしで有効化する。

### 7.10 Shadow / Differential Testing
- [x] **Shadow-1: `shadow_mode=true` で gate evidence bundle を生成し、実 default flag は変えない。
- [x] **Shadow-2: canary targetごとに forced serial と gated path の task queue snapshot / event trace / mutex state / request fingerprint / payload fingerprint を保存する。
- [x] **Shadow-3: Phase 8 `shadow_decisions` と limited parallel結果を release gate report に取り込み、candidate / reject reason / state isolation を operator summary に出す。
- [x] **Shadow-4: Injection URL actual parallel はまず dry-run budget decision を出し、skipped/rejected count が期待どおりになるまで request送信を増やさない。
- [x] **Differential-1: `extract_all_findings()` で High/Critical finding set（severity + id または canonical target + evidence key）を比較する。
- [x] **Differential-2: response differential は finding parity の補助指標として保存し、許容外差分は `hold` に倒す。
- [x] **Differential-3: rollback drill 前後で session/report reader、run narrative、target profile、debug bundle reader が同じ artifact を読めることを確認する。
- [x] **Differential-4: 429/403/406/timeout/queue full/handler error を注入し、protective degrade、budget reject、dead-letter、partial failure が finding欠落ではなく reason code として残ることを確認する。

### 7.11 対象Phase計画書への具体的な修正案
- [x] Phase 9 の目的、Non-Goals、前提条件、完了条件を 7.2 に明文化する。
- [x] 既存 `runtime_control_release_gate` / `shigoku-ops` を再利用する方針を 7.3 と 7.8 に固定する。
- [x] Phase 8 Deferred のうち、Injection URL actual parallel / budget enforcement を Phase 9 Local Scope として 7.4 / 7.8 / 7.9 に戻す。
- [x] Deferred は SGK-2026-0320/0322 へ送るものだけに限定し、安全理由と将来検出方法を 7.5 に記録する。
- [x] 親計画へ直接反映すべき横断ルールは 7.6 Parent Change Request に留める。
- [x] Phase 9 の Go/No-Go と Shadow/Differential Testing を 7.9 / 7.10 に追加する。

### 7.12 Phase順序再レビュー
- [x] **Phase 5 -> Phase 9:** 妥当。ただし Phase 5 は「並列新規有効化」ではなく「既存無門番並列への gate 付与」なので、Phase 9 の性能比較は forced serial vs gated に固定する。Phase 5 の status / work_report / validation evidence が不整合なら Phase 9 Step 0 で blocked。
- [x] **Phase 6 -> Phase 9:** 妥当。Phase 6 の EventBus reliability / decision_traces / debug bundle Deferred は Phase 9 の reader compatibility と fault injection に接続する。critical event drop が残る場合は No-Go。
- [x] **Phase 7 -> Phase 9:** 妥当。Phase 7 は kill switch / suppress / mutex manager / protective degrade の runtime機構を用意し、Phase 9 はそれらの rollout / rollback / promotion evidence を揃える。
- [x] **Phase 8 -> Phase 9:** 妥当。Phase 8 は limited parallel と schema ready まで。Phase 9 は default昇格、Injection URL actual parallel budget enforcement、operator runbook、恒久 gate evidence を扱う。
- [x] **結論:** Phase順序の概念は壊れていない。ただし Phase 9 実装開始時に前提Phaseの ledger/work_report/validation evidence が揃わない場合は順序実行の証跡が壊れるため、T-0.1 pre-flight を最初に実行して No-Go 判定できるようにする。
