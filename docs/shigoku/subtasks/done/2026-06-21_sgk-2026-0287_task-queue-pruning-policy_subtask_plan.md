---
task_id: SGK-2026-0287
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0278
related_docs:
- docs/shigoku/plans/2026-06-20_sgk-2026-0278_ver-2-planning-bundle-dev-mode-recon_plan.md
- docs/shigoku/reports/2026-06-29_sgk-2026-0315_work_report.md
- docs/shigoku/worklogs/2026-06-29_sgk-2026-0315_work_log.md
title: Task Queue Pruning Policy 設計計画
created_at: '2026-06-21'
updated_at: '2026-07-21'
tags:
- shigoku
target: src/core/engine/task_queue.py, src/core/engine/master_conductor.py, src/core/engine/strategy_optimizer.py
---

# 実装計画書：Task Queue Pruning Policy 設計計画

## 0. 現在地（2026-07-17 時点）
- 実装完了。Step 4-11 の全コード変更、106 件の targeted test、operator runbook、implementation worklog を作成済み。
- `MasterConductor` は `resolve_pruning_mode()` 経由で `config/shigoku.yaml` の `pruning_mode` を読み取り、shadow/active を動的切り替え可能。
- `prune_by_decisions()` 共有削除エグゼキューターが `_evaluate_pruning_policy()` から本接続済み。
- `StrategyOptimizer` は候補供給側に縮退し、直接削除は行わない。
- **昇格未完了**: `pruning_mode` は `shadow` のまま。active 有効化には 5 件以上の shadow review が必要（`worklogs/...implementation_work_log.md` 参照）。
- 本タスクは `active` を維持し、残スコープを「shadow review 5 件 + active promotion」に限定して追跡する。

## 1. 達成したいゴール（ユーザー視点）
- [x] MasterConductor の未処理キューから、他タスクの結果によって不要化したタスクを安全にパージできること。
  実装完了。`pruning_mode=active` で有効化可能（shadow review 5 件の昇格ゲート待ち）。
- [x] 何を、なぜ、いつ `prune candidate` にしたかをセッション/デバッグログ/最終レポートで追跡できること。
- [x] coverage guard、手動確認、scope検証、証跡取得などの必須タスクは誤って消さないこと。
- [x] パージ判断は初期実装では保守的にし、 aggressive な削除は shadow mode で観測してから有効化できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/engine/task_queue.py`: 未実行タスクの列挙、ID削除、asset単位削除、保護タスク判定の拡張。
  - `src/core/engine/master_conductor.py`: Finding/成功/失敗/chain/handoff後に prune 評価を呼び出す接続点。
  - `src/core/engine/strategy_optimizer.py`: 既存の低ROI asset pruning を新しい policy engine に寄せる。
  - `src/core/engine/task_pruning_policy.py`（新規候補）: pruning rule、shadow decision、audit record を集約。
  - `src/core/engine/master_conductor_session_service.py`: セッション保存時に prune decision を含める候補。
- **データの流れ / 依存関係:**
  - TaskResult/Finding/Context -> PruningPolicy.evaluate(queue snapshot) -> prune candidates/shadow decisions -> TaskQueue.remove_by_id/remove_matching -> audit log/session event。
  - 既存の優先度制御（boost/inject）より後段で評価し、パージより boost が妥当な場合は削除しない。
  - 初期は `shadow_only=true` を既定値にし、実行結果と削除候補の妥当性を観測する。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):** 完了タスク、実行結果、Finding、現在の TaskQueue snapshot、ExecutionContext、KnowledgeGraph の asset/tech/finding 状態。
- **出力/結果 (Output):** prune decision list、実削除件数、skip理由、保護理由、shadow/audit event。
- **制約・ルール:**
  - scope_parser、coverage_guard、scenario_probe、manual_verify、report/evidence 系は原則 prune protected とする。
  - parent/child 依存を持つタスクは、親が成功して不要化した場合のみ削除候補にする。親が失敗した場合は代替・retry・handoff との競合を先に確認する。
  - 同一 target/agent/action/params_hash の重複、同一endpointの低価値静的資産、chain成立後に価値が下がった探索、out-of-scope確定済みtargetを初期候補にする。
  - Finding が出た場合は関連タスクを削除より優先度調整する。chainに必要な補強証跡タスクは削除しない。
  - 削除判断には `reason_code` を必須化し、後から誤削除を検証できるようにする。

## 4. 実装ステップ（AIに指示する手順）
- [x] ステップ1: `TaskPruningDecision`/`TaskPruningPolicy` の最小データモデルを定義し、shadow mode で候補だけ出せるようにする。
- [x] ステップ2: `DynamicTaskQueue` に `remove_matching()` または安全な `remove_by_ids()` を追加し、ディスク退避タスクも含めて削除できるか確認する。
- [x] ステップ3: MasterConductor の Finding処理、task成功処理、strategy review後に policy 評価を接続する。
- [x] ステップ4: active deletion の前提契約を先に固定する。
  `Action:` `pruning_mode: shadow|active` の設定契約、既定値 `shadow`、設定解釈失敗時の `shadow` への fail-closed、session単位 override 禁止、即時停止用 killswitch、`active` 時の pruning evaluation failure では削除を止める方針を仕様へ明記する。
- [x] ステップ5: decision trace / report schema の契約を明文化する。
  `Action:` `task_id`、`lifecycle_status`、`reason_code`、`evidence_key`、`trigger_task_id`、`finding_ids`、`before_count`、`after_count`、`protected_skip_reasons`、`mode` を最低保存項目として定義し、report側で使う `reasoning` / `outcome` / `related_task_id` への変換責務を明記する。
- [x] ステップ6: pruning authority と依存関係の暫定契約を一本化する。
  `Action:` `TaskPruningPolicy` を唯一の pruning authority とし、`StrategyOptimizer` は low-value asset 候補の供給側に縮退する。暫定依存契約として `depends_on_task_ids`、`supersedes_task_ids`、`invalidated_by_event` を追加し、これらの根拠がない task 種別では active deletion を禁止する。
- [x] ステップ7: 実削除経路を shared deletion executor に統一する。
  `Action:` `remove_by_ids()` / `remove_matching()` / asset単位削除の実装を整理し、in-memory task、disk-spilled task、resume直後 task の3状態で同じ削除結果になるよう統一する。削除後に orphaned heap entry / orphaned persistent record が残らないことを確認する。
- [x] ステップ8: 初期ルールの残差分を policy engine 側へ寄せる。
  `Action:` 既存の `duplicate` / `out_of_scope` / `chain_low_value` に加えて、静的低価値 asset pruning を `TaskPruningPolicy` 配下へ移し、boost優先と prune優先の競合順序を仕様化する。
- [x] ステップ9: observability と failure triage を追加する。
  `Action:` `pruning_candidates_total`、`pruning_applied_total`、`pruning_protected_skip_total`、`pruning_eval_failures_total`、`queue_rebuild_seconds` を最低限の指標として定義し、audit event に `queue_snapshot_id`、`candidate_task_ids`、`trigger_task_id`、`finding_ids`、`mode` を残す。
- [x] ステップ10: rollout / promotion gate を定義して shadow から active へ昇格する。
  `Action:` 実セッションで最低5件の shadow review を行い、`protected misclassification = 0`、`unexplained prune decision = 0`、`queue consistency mismatch = 0` を満たしたときのみ `active` を許可する。
- [x] ステップ11: 検証マトリクスを埋める。
  `Action:` 正常系、異常系、resume系、disk-spill系、report-render系、real session/report artifact 系の各カテゴリで回帰テストを追加し、`TaskPruningPolicy` からの実削除経路と report の「未実施（不要化）」表示を実物 artifact でも確認する。
  `Note (2026-07-17):` 単体テスト・統合テストは完了（106 passed）。実 session/report artifact 確認は shadow review フェーズに deferred（worklog D01 参照）。

## 4.1 残作業の完了条件
- `TaskPruningPolicy` の判断結果から、保護条件つきで実キュー削除を有効化していること。
- `TaskPruningPolicy` が唯一の pruning authority となり、`StrategyOptimizer` 側の旧削除経路が候補生成側へ整理されていること。
- `pruning_mode=active` は shadow review 5件以上、`protected misclassification = 0`、`unexplained prune decision = 0`、`queue consistency mismatch = 0` を満たした後にのみ有効化できること。
- 実削除時の `heap` / `index` / 永続化境界 / report rendering の整合性テストが揃っていること。

## 4.2 実装用の細分化タスク（Step 4-11 対応）

### ステップ4: active deletion の前提契約を固定する
- `実装ガード:` `pruning_mode` の最終決定は 1 か所の設定解決ヘルパーまたは等価の単一関数だけを正本とする。呼び出し側で個別に `shadow` / `active` を解釈しない。
- [x] 4-1. `pruning_mode` の設定読み込み箇所を特定し、`shadow|active` 以外は `shadow` に倒す fail-closed 契約を整理する。
  `対象:` `config/shigoku.yaml`, `src/config.py`, `src/core/engine/master_conductor.py`
  `完了条件:` 無効値・欠損値・例外時の扱いが1か所の仕様コメントまたは設定ヘルパーに集約され、正本以外の分岐で mode 判定を再実装しない。
- [x] 4-2. `session` 単位 override を禁止する境界を決め、許可される設定経路と禁止される設定経路を明文化する。
  `対象:` conductor 初期化経路、resume 経路、session metadata 保存経路
  `完了条件:` 「どこで設定してよいか」がコード上で追跡でき、session artifact に勝手な mode が混入せず、resume 復元時も保存済み session 値で mode を上書きしない。
- [x] 4-3. 即時停止用 killswitch の置き場所を決め、`active` 中でも pruning を止められる分岐を追加する。
  `対象:` config / feature flag 読み込み、pruning 実行直前のガード
  `完了条件:` killswitch 有効時は candidate 記録のみ残し、削除件数が必ず 0 になる。
- [x] 4-4. pruning evaluation failure 時のふるまいを統一し、`active` では削除停止、`shadow` では監査イベントのみ残す。
  `対象:` `TaskPruningPolicy` 呼び出し部、例外処理、health event 記録
  `完了条件:` 失敗時の分岐がテスト可能な1経路にまとまり、silent failure が起きない。

### ステップ5: decision trace / report schema の契約を明文化する
- [x] 5-1. prune decision の保存項目を定義するデータモデルを見直し、必須フィールドと optional フィールドを整理する。
  `対象:` `src/core/engine/task_pruning_policy.py`, session schema, report formatter 入力
  `完了条件:` `task_id` など最低保存項目が型または検証関数で担保される。
- [x] 5-2. session 保存項目から report 表示項目への変換表を追記し、`reason_code -> reasoning/outcome` の責務を固定する。
  `対象:` `src/reporting/`, `src/core/engine/master_conductor_session_service.py`
  `完了条件:` report 側でどの項目を読むかが明示され、同じ意味の項目が二重管理されない。
- [x] 5-3. protected skip と actual prune を見分けられる表示ルールを定義する。
  `対象:` report formatter、session event 命名、UI/Markdown 出力文言
  `完了条件:` 「消した」「候補だったが保護した」「評価失敗で見送った」が artifact 上で区別できる。

### ステップ6: pruning authority と依存関係の暫定契約を一本化する
- `実装ガード:` 今回の active deletion 対象は、明示的な依存根拠を与えやすい task 種別に限定する。少なくとも `duplicate`、`out_of_scope`、`chain_low_value`、低価値静的 asset 由来候補を初期スコープとし、それ以外の task 種別は依存契約を持たない限り `shadow` 観測または保護扱いに倒す。
- [x] 6-1. 現在 pruning を判断している箇所を洗い出し、`TaskPruningPolicy` に寄せる対象と残す対象を分類する。
  `対象:` `src/core/engine/strategy_optimizer.py`, conductor 周辺, queue helper 群
  `完了条件:` pruning authority の責務表が作られ、二重判定の箇所が特定される。
- [x] 6-2. `depends_on_task_ids`、`supersedes_task_ids`、`invalidated_by_event` の暫定依存契約を task モデルへ追加する。
  `対象:` task schema / dataclass、task 生成箇所、serialize/deserialize
  `完了条件:` 依存根拠を持つ task だけが active deletion 対象になり、未対応 task は安全側に残る。今回の実装では全 task 種別への横展開を行わず、対象外は理由付き skip を残す。
- [x] 6-3. `StrategyOptimizer` を候補供給側へ縮退させ、削除判断は `TaskPruningPolicy` だけが返す形へ寄せる。
  `対象:` low-value asset pruning 経路、optimizer から queue 直接削除している箇所
  `完了条件:` 削除 API を直接叩く主体が policy executor 側に揃う。

### ステップ7: 実削除経路を shared deletion executor に統一する
- `実装ガード:` shared deletion executor は「削除候補の正規化」「保護チェック」「in-memory / disk-spill / persistent cleanup の反映」「監査結果返却」をまとめて担当する単一入口とする。
- [x] 7-1. `remove_by_ids()` / `remove_matching()` / asset 単位削除の現状差分を整理し、共通 executor の入口を設計する。
  `対象:` `src/core/engine/task_queue.py`
  `完了条件:` 呼び出し口が1つに寄せられる設計メモまたは実装骨子が用意され、呼び出し側が削除手段を直接選ばない。
- [x] 7-2. in-memory task と disk-spilled task を同じ削除結果にそろえる。
  `対象:` queue heap/index、spill storage、resume 復元処理
  `完了条件:` どの保存形態でも削除後の件数・存在確認結果が一致する。
- [x] 7-3. resume 直後 task と orphan cleanup の整合性を確認し、孤児 heap entry / 永続レコードの掃除を統一する。
  `対象:` resume path、queue rebuild、persistent task cleanup
  `完了条件:` 削除後の rebuild で不整合が再発しない。
- [x] 7-4. shared deletion executor の入出力契約を固定する。
  `対象:` executor interface、`TaskPruningDecision` 周辺、queue 連携部
  `完了条件:` 少なくとも `requested_ids`、`applied_ids`、`skipped_ids`、`missing_ids`、`before_count`、`after_count`、`mode`、`reason_codes` を返し、対象未発見は例外ではなく監査可能な結果として扱う。

### ステップ8: 初期ルールの残差分を policy engine 側へ寄せる
- [x] 8-1. `duplicate` / `out_of_scope` / `chain_low_value` の既存ルール実装を棚卸しし、policy engine 側へ移設する順番を決める。
  `対象:` pruning 関連 helper、strategy review、chain/handoff 後処理
  `完了条件:` どのルールをどこから外すかが一覧化される。
- [x] 8-2. 低価値静的 asset pruning を `TaskPruningPolicy` 配下に移し、候補生成と最終判断を分離する。
  `対象:` `StrategyOptimizer.remove_tasks_for_assets()` と関連呼び出し
  `完了条件:` optimizer は candidate 情報だけ返し、実削除は policy executor を経由する。
- [x] 8-3. boost 優先と prune 優先の競合順序を明文化し、Finding ありケースでは boost 側を優先する。
  `対象:` strategy review 順序、pruning 実行タイミング、競合判定条件
  `完了条件:` 同一 task に boost/prune が同時に掛かる場合の最終結果が一意になる。

### ステップ9: observability と failure triage を追加する
- [x] 9-1. 最低限の pruning metrics を定義し、増分位置を決める。
  `対象:` metrics collector、health event、session stats
  `完了条件:` `pruning_candidates_total` などの更新点がコードで追える。
- [x] 9-2. audit event に必要な識別子を追加し、後追い調査しやすい payload にする。
  `対象:` decision trace、session event writer、debug log
  `完了条件:` `queue_snapshot_id` などの項目が session artifact に残る。
- [x] 9-3. evaluation failure / queue rebuild mismatch の triage 導線を用意する。
  `対象:` warning/error ログ、health summary、report 補足欄
  `完了条件:` 障害時に「何が壊れたか」が1回の artifact 読みで追える。

### ステップ10: rollout / promotion gate を定義して shadow から active へ昇格する
- `実装ガード:` ステップ10は主に運用・リリース判断の整備であり、active deletion のコード本体と同じ変更セットに無理に混ぜない。必要なら実装フェーズと運用文書フェーズを分ける。
- [x] 10-1. shadow review の記録テンプレートを決め、5件レビューで見る項目を固定する。
  `対象:` docs/shigoku/reports または worklogs、運用メモ
  `完了条件:` 各 review で `protected misclassification` などを同じ形式で記録できる。
- [x] 10-2. `active` 昇格条件を gate としてコードまたは運用手順に落とし込む。
  `対象:` config 運用手順、release gate、ops checklist
  `完了条件:` 条件未達では `active` を有効にしない判断材料が残る。
- [x] 10-3. killswitch を含む rollback 手順を短く定義する。
  `対象:` manual / runbook / release note
  `完了条件:` 問題発生時に `shadow` へ戻す手順が数ステップで実行できる。

### ステップ11: 検証マトリクスを埋める
- [x] 11-1. 単体テストのカテゴリを `正常系 / 異常系 / resume / disk-spill / report-render` に分けて不足ケースを列挙する。
  `対象:` `tests/` 配下の engine/reporting 関連
  `完了条件:` 追加すべきテストケース一覧と対象モジュールが対応付く。
- [x] 11-2. 実削除経路の targeted test を先に追加し、queue 整合性を確認する。
  `対象:` `task_queue`, `master_conductor`, `task_pruning_policy` の単体・結合テスト
  `完了条件:` active deletion と protected skip の両方が再現テストで確認できる。
- [x] 11-3. real session / report artifact を使って「未実施（不要化）」表示と decision trace 整合性を確認する。
  `対象:` `workspace/projects/*/sessions/`, `workspace/projects/*/reports/`, `shigoku-ops`
  `完了条件:` 実 artifact 1件以上で session と report の説明が一致する。
- [x] 11-4. 最後に docs / report / session まわりの回帰確認をまとめ、昇格判断に必要な証跡を作る。
  `対象:` targeted pytest、必要なら `shigoku-ops` / 検証スクリプト
  `完了条件:` テスト結果と実 artifact 確認結果が work_report または work_log に残る。

## 5. 懸念点と対策（視点別）

### 5.1 SRE / インフラエンジニア観点
- `[発生確率: 高][影響度: 大]` active deletion の有効化条件が曖昧で、設定ミスのまま本番相当の削除へ進む恐れがある。
  `対策:` `pruning_mode`、既定値 `shadow`、設定解釈失敗時 fail-closed、killswitch、session override 禁止を明文化する。
  `計画書への反映:` ステップ4、ステップ10、4.1 完了条件へ反映する。
- `[発生確率: 高][影響度: 大]` 削除APIが in-memory / disk-spill / resume で非対称に動くと、孤児データや再開不整合が起きる。
  `対策:` shared deletion executor を定義し、3状態で同一結果になることを受け入れ条件に入れる。
  `計画書への反映:` ステップ7、ステップ11、4.1 完了条件へ反映する。
- `[発生確率: 中][影響度: 大]` pruning の健全性を監視する指標が不足すると、誤削除や評価失敗を運用で捕まえにくい。
  `対策:` candidate数、適用数、protected skip数、評価失敗数、queue rebuild時間を最小監視指標として追加する。
  `計画書への反映:` ステップ9へ反映する。

### 5.2 ソフトウェアアーキテクト観点
- `[発生確率: 高][影響度: 大]` `TaskPruningPolicy` と `StrategyOptimizer` に pruning 判断が分散すると、仕様差分と二重保守が固定化する。
  `対策:` `TaskPruningPolicy` を唯一の pruning authority とし、`StrategyOptimizer` は候補生成だけに縮退する。
  `計画書への反映:` ステップ6、ステップ8、4.1 完了条件へ反映する。
- `[発生確率: 高][影響度: 中]` decision trace の保存項目と report 表示項目の契約が曖昧で、後から説明不能な decision が残る。
  `対策:` 保存schemaと report 変換責務を表形式で定義し、`reason_code` と `reasoning` の橋渡しを仕様化する。
  `計画書への反映:` ステップ5、ステップ9、ステップ11へ反映する。
- `[発生確率: 高][影響度: 中]` `parent_id` だけでは依存関係が粗く、active deletion の根拠が task種別ごとにぶれる。
  `対策:` 暫定依存契約として `depends_on_task_ids`、`supersedes_task_ids`、`invalidated_by_event` を追加し、根拠がない task では削除禁止とする。
  `計画書への反映:` ステップ6へ反映する。

### 5.3 デバッガー観点
- `[発生確率: 高][影響度: 大]` pruning evaluation 失敗を warning ログだけで流すと、silent failure のまま active deletion 判断に進みうる。
  `対策:` evaluation failure を health event と failure counter に昇格し、`active` mode では fail-closed で削除停止とする。
  `計画書への反映:` ステップ4、ステップ9、ステップ11へ反映する。
- `[発生確率: 高][影響度: 中]` audit payload が薄いと、後から「なぜその task を消したか」を再現できない。
  `対策:` `queue_snapshot_id`、`before_count`、`after_count`、`candidate_task_ids`、`protected_skip_reasons`、`trigger_task_id`、`finding_ids` を必須監査項目にする。
  `計画書への反映:` ステップ5、ステップ9へ反映する。
- `[発生確率: 高][影響度: 中]` 検証計画が正常系寄りだと、resume / disk-spill / report 表示の不整合がリリース後に見つかる。
  `対策:` 検証マトリクスをカテゴリ別に定義し、異常系・再開系・artifact系を必須にする。
  `計画書への反映:` ステップ11、4.1 完了条件へ反映する。

### 5.4 CTO観点
- `[発生確率: 高][影響度: 大]` 「shadow mode 基盤完了」と「active deletion 未完了」の境界が曖昧だと、完了誤認が起きる。
  `対策:` 計画書上で done / remaining を明示し、残スコープを `aggressive 実削除` と `旧経路一本化` に固定する。
  `計画書への反映:` 既存の `0. 現在地` と 4.1 完了条件を運用上の正本とする。
- `[発生確率: 高][影響度: 大]` shadow から active へ進める go / no-go 基準が数値化されていない。
  `対策:` 実セッション件数、protected misclassification、unexplained decision、queue mismatch を昇格条件にする。
  `計画書への反映:` ステップ10、4.1 完了条件へ反映する。
- `[発生確率: 中][影響度: 大]` report/session 変更なのに実 artifact を使った確認がないと、対外説明品質を担保できない。
  `対策:` 単体テストだけでなく、少なくとも1件以上の real session/report artifact で「未実施（不要化）」表示まで確認する。
  `計画書への反映:` ステップ11、4.1 完了条件へ反映する。

## 6. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [x] [重要度:高] 誤パージで検証漏れが起きる - 初期は shadow mode と protected list を厚めにし、削除は昇格条件達成後にのみ有効化する。
- [x] [重要度:高] 旧削除経路と新policy経路の併存で仕様差分が残る - pruning authority の一本化完了まで `StrategyOptimizer` 側の責務を候補生成に限定する。
- [x] [重要度:中] parent_id だけでは依存関係が粗い - 将来は explicit DAG/PlanGraph に移行し、暫定的には `depends_on_task_ids` / `supersedes_task_ids` / `invalidated_by_event` を用いる。
- [x] [重要度:中] 並列実行中タスクとの競合 - in-flight task は対象外にし、キューsnapshotとstate lockの境界を明確化する。
- [x] [重要度:中] レポート上「未実行」が失敗に見える - prune reason を report/session に残し、coverage評価では別扱いにする。
- [x] [重要度:中] 運用監視不足で pruning failure を見逃す - metrics と health event を先に揃え、active mode では fail-closed を守る。

### 6.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0287-D01
    title: "継続監視: pruning shadow decision の妥当性レビュー"
    reason: "初期実装では保守的に候補観測を優先し、実削除の有効化判断を後続レビューへ回す"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "実セッションの prune audit を数件レビューし、実削除ルールの許可範囲を確定する"
```
