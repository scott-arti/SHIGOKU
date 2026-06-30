---
task_id: SGK-2026-0318
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0291
related_docs:
- docs/shigoku/subtasks/2026-06-23_sgk-2026-0291_swarm-parallelism-review_subtask_plan.md
title: 'Swarm並列化 Phase 9: release gate rollout policy promotion'
created_at: '2026-06-26'
updated_at: '2026-06-30'
tags:
- shigoku
target: release gate, rollout flags, operator control, compatibility checks
---

# 実装計画書：Swarm並列化 Phase 9: release gate rollout policy promotion

## 1. 達成したいゴール（ユーザー視点）
- [ ] 並列runtimeを shadow -> canary -> limited default -> broader default の順に安全に昇格できること。
- [ ] lane policy、compatibility profile、specialist maturity を実測に基づいて昇格/降格できること。
- [ ] operatorが lane pause、queue drain、aggressive suppress、kill switch を使って即時制御できること。

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
- [ ] ステップ1: release gateの入力指標と合格/失格条件を固定する。
- [ ] ステップ2: shadow compare reportとoperator summaryの出力形式を定義する。
- [ ] ステップ3: risk tier / specialist maturity / lane policy のpromotion/demotion matrixを作る。
- [ ] ステップ4: lane pause、queue drain、aggressive suppress、kill switchの操作要件と監査ログを定義する。
- [ ] ステップ5: rollout / rollback runbookを作成する。
- [ ] ステップ6: release gate script、rollback drill、downstream reader compatibility checkを実行する。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] 速度改善だけで昇格すると検出品質が落ちる - Finding parityとscope/budget violationを必須gateにする。
- [ ] [重要度:高] rollback手順が曖昧だと事故復旧が遅れる - kill switchとserial互換確認をrunbook化する。
- [ ] [重要度:中] maturity昇格が属人的になる - promotion/demotion matrixとaudit evidenceを必須にする。

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
- [ ] **C1【指標の正しい解釈】: 成功指標は「serial 強制 vs gated」で測る（PCR-1）。** 並列実行は Phase 5 以前から無門番で存在した（`mc:5855`→`po:283`）。Phase 5 は「gate を被せて非 read_only を serial 降格」したのであり「並列を新規有効化」したではない。速度改善の測定基準を「無門番時代 vs gated」にすると misleading（無門番時代の方が速いが危険）。正しくは「serial 強制(kill_switch) vs gated」で。
- [ ] **C2【parity 比較器は再利用】: Phase 5 LB-6 の比較器を使う。** `src/reporting/finding_extractor.extract_all_findings()` で serial 強制経路と gated 経路の (severity+id) 集合の集合相等を判定（`rules/lessons.md` の真正性ルール・canonical extractor 使用）。canary 昇格判定にこれを使う。新規比較器は作らない。
- [ ] **C3【kill_switch で serial 復帰】: rollback は Phase 5 既存 field（PCR-2）。** `settings.parallelism.kill_switch` で即時 serial 強制。rollback drill はこの field を flip して serial 互換性を確認する手順を含む。
- [ ] **C4【rich telemetry は Phase 9 で実装】: Phase 5 D-1 の引継ぎ。** `serial_gap_summary`/`rollback_signal`/`queue_wait_ms` の恒久 runtime metrics は Phase 5 では最小 parity のみで deferred。Phase 9 で shadow compare report へ実装。
- [ ] **C5【main-thread assert を gate へ】: task_queue main-thread 制約を release gate 回帰テストへ（PCR-4）。** GA 昇格前に `task_queue` mutation が main thread 制約を破っていないかを release gate script でチェック。

### 6.2 Phase 9 Go/No-Go Gate（追加）
- [ ] **Go:** serial 強制 vs gated の finding parity 100% が canary 全対象で成立（C2）。
- [ ] **Go:** kill_switch flip で即時 serial 復帰が rollback drill で実証済み（C3）。
- [ ] **No-Go:** 速度改善だけで parity gate を通さず昇格する（C1/C2 違反）。
- [ ] **No-Go:** task_queue main-thread 制約違反が release gate で検出される（C5）。

### 6.3 参照
Phase 5 計画書 6.13・LB-6・PCR-1/PCR-2/D-1。参照ルール: `rules/lessons.md`・`rules/report-session-consistency.md`（parity 真正性）。
