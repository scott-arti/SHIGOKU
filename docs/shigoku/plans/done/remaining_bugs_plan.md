---
task_id: SGK-2026-0215
doc_type: plan
status: done
parent_task_id: null
related_docs:
  - docs/shigoku/specs/2026-05-22_should_observe_observation_policy_spec.md
created_at: '2026-05-19'
updated_at: '2026-07-02'
---

# 残存バグ修正タスク (Remaining Bug Fixes)

このドキュメントは、2026-01-05 のバグ修正スプリントで修正対象外（スコープ外）となった重要バグ `#1` および `#6` に関する詳細タスク定義です。

## 🔴 Bug #1: ReAct 観察機能のコスト最適化 (High Priority)

### 現状の問題点

`MasterConductor._observe_and_rethink` メソッドは、タスクが成功(`success: True`)するたびに無条件で呼び出されます。
`enable_react_observation` が有効（True）の場合、たとえ単純なファイル読み込みや明白な成功結果であっても LLM API を呼び出します。これにより、タスク数に比例して API コストが直線的に増加する「コスト爆発」のリスクがあります。

※現状の暫定対応として、デフォルト設定は `False` に変更されていますが、機能を有効にした瞬間にこのリスクが顕在化します。

### PM主導の解決方針（計画強化版）

全件実行ではなく、LLM の洞察が真に価値を持つ場面へ限定する。加えて、運用上の予算統制と段階導入を組み合わせ、コスト削減と検知品質を同時に管理する。

### 統合実装方針（SRE/Architect指摘の解消を反映）

以下は、致命リスク指摘を「必要性」「重要性」「解消策」に分解し、実装方針へ統合した必須要件である。

1. `MasterConductor` 過密結合の解消
   - 必要性: 観察判定・予算制御・通知制御が単一クラスに集中すると変更衝突が常態化する。
   - 重要性: クリティカル。局所変更で全体回帰が起こる構造は継続運用不能。
   - 解消策: `ObservationPolicy` / `ObservationExecutor` / `ObservationTelemetry` / `ObservationCircuitBreaker` を分離し、`MasterConductor` はオーケストレーションのみ担当。

2. 判定ロジックと実行ロジックの密結合解消
   - 必要性: A/B policy や target別policyの追加時に分岐増殖を防ぐ。
   - 重要性: クリティカル。拡張不能化を防ぐ中核要件。
   - 解消策: `_should_observe` は pure decision API とし、副作用（LLM call/通知）は executor層へ完全分離。

3. 語彙ドリフト（reason code / metric / alert）防止
   - 必要性: 監視とコードの意味不一致を防ぐ。
   - 重要性: クリティカル。障害時の誤判定は復旧不能化につながる。
   - 解消策: `src/core/engine/observation_reason.py` を単一正本とし、ログ・メトリクス・アラートは enum 参照を強制。

4. ツールチェーン統合契約の固定
   - 必要性: 設定欠損や型不一致による起動失敗を防ぐ。
   - 重要性: クリティカル。全環境同時停止を回避する要件。
   - 解消策: 設定スキーマ（必須/任意/デフォルト）と telemetry スキーマを文書化し、起動時バリデーションを必須化。

5. ネットワーク/再試行暴走の封じ込め
   - 必要性: 劣化時の自己増幅（retry storm）を止める。
   - 重要性: クリティカル。負荷連鎖による全体停止を防ぐ。
   - 解消策: global/target inflight上限、queue上限、retry budget、circuit breaker、bulkhead を実装し、ハード停止条件を適用。

6. デバッグ観点の高リスク分岐不整合の解消
   - 必要性: 判定順序・理由コード・メトリクス更新のズレは、障害を「見えない状態」で増幅させる。
   - 重要性: クリティカル。誤判定のまま運用継続すると、検知品質とコスト制御の双方が崩壊する。
   - 解消策: 判定順序を仕様固定し、分岐網羅テスト・境界テスト・状態遷移テストを必須化する。

### 目的・KPI・完了条件

- 目的: ReAct 観察の価値を維持しつつ、実行コストの爆発を防止する。
- KPI-1（コスト）: `react_executed / successful_tasks` を現行比で 70% 以上削減。
- KPI-2（品質）: 重要 finding の取りこぼし率を 5% 未満に維持。
- KPI-3（運用安定）: ReAct 由来の token 使用量を run 単位の上限内に収める（上限値は設定値で管理）。
- KPI-4（予算統制）: 日次の ReAct 予算超過回数を 0 回に維持する。
- KPI-5（意思決定速度）: Gate 判定遅延（予定日時からの遅延）を 1 営業日以内に維持する。
- KPI-6（判定安定性）: KPI 判定は 7日移動平均でも閾値を満たすこと。
- 完了条件: KPI-1〜3 を 3 回連続の評価 run で満たすこと。

### スコープ（Bug #1）

- 対象:
  - `src/core/engine/master_conductor.py` の ReAct 観察呼び出し導線。
  - `_observe_and_rethink` 実行可否の判定追加。
  - ReAct 実行・スキップ理由のメトリクス/ログ追加。
- 非対象:
  - ReAct プロンプト自体の内容最適化。
  - Swarm 専用 Specialist のアルゴリズム変更。

### 実装方針（アーキテクチャ指針を含む）

1.  判定関数導入
    - `MasterConductor` に `_should_observe(task, result) -> tuple[bool, ObservationReason]` を追加する。
    - `bool` は実行可否、`ObservationReason` は skip/execute reason code（例: `ALLOW_HIGH_VALUE_SIGNAL`, `SKIP_LOW_VALUE_TASK`, `SKIP_BUDGET_EXCEEDED`）。

2.  判定ルール
    - タスクタイプ除外: 単純 I/O、定型ツール実行、重複高頻度タスクを既定で除外。
    - 重要度判定: finding 有無、結果中キーワード、コンテキスト重要タグで昇格。
    - サンプリング: 同種タスク連続時は先頭・末尾・確率抽出のみ許可。
    - 予算判定: run/target ごとの ReAct 呼び出し上限・token 予算上限を超える場合は停止。

3.  呼び出し導線の統一
    - `_observe_and_rethink` を呼ぶ全経路で、同一の `_should_observe` を必ず通す。
    - 実行モード差分（通常実行 vs 対話実行）で判定仕様が乖離しないように統一する。

4.  可観測性
    - 追加メトリクス: `react_attempted`, `react_executed`, `react_skipped`, `react_skip_reason`, `react_token_spend`。
    - 構造化ログ: task id, agent type, reason code, budget snapshot を記録。
    - 予算防衛: `SKIP_BUDGET_EXCEEDED` の急増を監視し、自動でサンプリング率を低下させる制御を備える。
    - 自動抑制ルール: `SKIP_BUDGET_EXCEEDED` が直近 15 分で閾値超過時、`react_observation_sampling_rate` を段階的に低下（例: 1.0 → 0.5 → 0.2）し、SRE 通知を発報する。
    - 下限制御: サンプリング率は `react_observation_sampling_rate_min` を下回らない。
    - 復帰ルール: 30 分連続で閾値未満なら 1 段階ずつ復帰する。
    - 通知運用: 通知チャネルは `react_observation_alert_channel`（例: Slack/Pager）で指定し、初期閾値は `react_observation_budget_exceeded_threshold_15m` で設定する。

5.  ネットワーク保護制御（致命障害回避）
    - グローバル同時実行上限: ReAct由来の外部呼び出しに `max_inflight_react_requests_global` を設定する。
    - ターゲット別上限: 単一ターゲット集中を避けるため `max_inflight_react_requests_per_target` を設定する。
    - キュー長上限: `react_observation_queue_maxsize` を超えた場合は新規観察要求を破棄し `SKIP_QUEUE_OVERFLOW` として記録する。
    - Retry Budget: `react_observation_retry_budget_per_run` を導入し、予算枯渇時はリトライ禁止に切り替える。
    - Circuit Breaker: LLM/RAG/通知の失敗率・遅延超過時に観察経路を自動遮断し、一定時間後に half-open で復帰判定する。

### フェーズ計画（段階導入）

1.  Phase A: 計測のみ（1日）
    - `_should_observe` を導入するが実行判定は常時許可。
    - reason code とメトリクスのみ収集して現行ベースラインを取得。

2.  Phase B: Dry-run（1-2日）
    - `_should_observe` 判定結果を記録するが、実行は従来どおり。
    - 「実際に止めた場合」の削減率と見逃しリスクを推定。

3.  Phase C: 段階有効化（2-3日）
    - 環境フラグで有効化（canary → 50% → 100%）。
    - KPI を日次で確認し、閾値逸脱時は即時ロールバック。

### フェーズゲート（Go/No-Go）

1.  Gate A（Phase A終了）
    - 入力: 現行ベースライン、reason code 分布、token 消費分布。
    - 判定: PM/SRE/Architect で Dry-run 進行可否を決定。
2.  Gate B（Phase B終了）
    - 入力: 推定削減率、推定取りこぼし率、予算超過見込み。
    - 判定: PM が canary 投入可否を決定。
3.  Gate C（Phase C 50%終了）
    - 入力: 実測 KPI、アラート履歴、障害有無。
    - 判定: PM/SRE が 100% 展開可否を決定。
    - 初版計画時に `scheduled_at` と `decision_due_at` を先行入力し、遅延KPIを即時計測開始する。

### Gate運用テンプレート（必須）

- 各 Gate で以下を事前に記入すること:
  - `owner_pm`
  - `owner_sre`
  - `owner_architect`
  - `scheduled_at`
  - `decision_due_at`
  - `required_metrics`
  - `go_no_go_decision`
  - `decision_reason`

### タスク分解（実行順）

1.  `ObservationPolicy`（判定）と `ObservationExecutor`（実行）を新設し、責務分離を先行完了する。
2.  `ObservationReason` enum と telemetry schema を単一正本として導入し、既存ログ/メトリクスを移行する。
3.  `_observe_and_rethink` の全導線を共通ゲートへ統一し、`MasterConductor` の直接分岐を削減する。
4.  circuit breaker / retry budget / inflight cap / queue cap / bulkhead を実装し、ハード停止条件を有効化する。
5.  設定スキーマの起動時バリデーションと後方互換（旧キー読み替え）を実装する。
6.  Phase A/B/C の順で rollout し、KPI/Gate 条件で Go/No-Go 判定を行う。

### 検証計画

- 単体テスト:
  - `_should_observe` 判定（重要度、除外、サンプリング、予算超過）を網羅。
  - reason code の期待値を固定化。
  - 境界ケース: budget 閾値ちょうど、signal 競合、sampling 境界値（0/最小値/1.0）を検証。
  - 最小再現入力例をケースごとに固定（task/result fixture）し、再現手順を1コマンドで実行可能にする。
  - 判定優先順テスト: `budget skip` と `high-value allow` の優先関係を固定し、逆転を禁止する。
  - reason code 網羅テスト: enum 全値をログ・メトリクス・アラート変換で検証する。
  - メトリクス整合テスト: `attempted/executed/skipped` の原子的一貫性を検証する。
- 統合テスト:
  - 偵察タスクフローで `react_executed / successful_tasks` の削減を確認。
  - 重要 finding を含むケースで ReAct 実行が維持されることを確認。
  - breaker 往復テスト: open/half-open/close のフラップが発生しないことを確認する。
  - queue overflow テスト: 破棄ポリシーが重要タスクを優先保持することを確認する。
- 実運用検証:
  - canary 実行で token 使用量と finding 取りこぼし率を計測。

### リスク・ロールバック

- 主リスク:
  - フィルタが強すぎて重要洞察を失う。
  - メトリクス不足により逸脱検知が遅れる。
- ロールバック条件:
  - 取りこぼし率 > 5% が連続 2 run。
  - token 使用量が上限を超過。
  - 重大不具合（観察ロジックで例外連鎖）が発生。
- ロールバック手段:
  - `enable_react_observation` または新設ゲート設定で即時停止。
  - 直前安定設定へ戻し、Phase B に戻って再評価。

### 障害封じ込め条件（ネットワーク）

- ハード停止条件:
  - `react_inflight` が上限を連続超過（例: 5分）した場合、ReAct観察を強制停止する。
  - `react_dependency_error_rate`（LLM/RAG/通知）が閾値超過時、Circuit Breaker を open にする。
  - `react_queue_depth` が上限超過時、投入停止と古いリクエスト破棄を実施する。
- 復帰条件:
  - 連続観測ウィンドウで失敗率/遅延が閾値内へ戻った場合のみ段階復帰する。
- 封じ込め方針:
  - ReAct経路障害が本体スキャン処理へ波及しないよう、ワーカー・キュー・レートを分離（bulkhead）する。

### 役割分担（RACI簡易）

- PM: KPI/完了条件承認、フェーズゲート判断、リスク承認。
- SRE/Infra: 予算上限・監視・アラート設計、canary 運用。
- Architect: 判定責務分離・呼び出し導線統一設計レビュー。
- Developer/Debugger: 実装、テスト、再現シナリオ整備。

### 実装規約（reason code / enum）

- `_should_observe` の reason code は文字列直書き禁止とし、共通 enum 定義を参照する。
- ログ、メトリクス、テスト期待値は同じ enum 定数を利用して語彙不一致を防ぐ。
- enum 定義は `src/core/engine/observation_reason.py` に集約し、他モジュールは同定義のみ参照する。
- 互換規約: 旧 reason code を受け取る既存ダッシュボード/アラート向けに移行期間中は alias map を提供し、監視断絶を防止する。
- 原子更新規約: KPI算出に使うカウンタ更新は単一トランザクション単位で実施し、分母分子不整合を禁止する。

---

## 🟡 Bug #6: 非同期実行の安全性向上 (Global Async Safety)

### 現状の問題点

`master_conductor.py` の `#2` で修正された `asyncio.run()` の問題（既存ループがあるスレッドで呼ぶと `RuntimeError` になる）と同様のコードパターンが、他のモジュールにも残存しています。
これらは現在顕在化していない可能性がありますが、将来的に並列実行や別スレッドからの呼び出しが行われた際にクラッシュする潜在的な「爆弾」です。

### 対象ファイル（要監査）

`src/core` 監査時点で、`asyncio.run()` 実呼び出しは以下でした（2026-05-22 時点）：

1.  `src/core/engine/runner.py`: `run_sync()`
2.  `src/core/engine/master_conductor.py`: `initialize_workspace()`

### PM主導の解決方針（Bug #1と同粒度）

`asyncio.run()` の散在利用を廃止し、共通安全実行ヘルパーへ集約する。加えて段階導入と障害時ロールバックを定義し、並列実行時のクラッシュリスクを運用可能なレベルまで下げる。

### 統合実装方針（SRE/Architect指摘の解消を反映）

1. 非同期実行規約の単一化
   - 必要性: モジュール毎の独自ラップ乱立を防ぐ。
   - 重要性: クリティカル。将来アップデート時の部分破綻を防ぐ。
   - 解消策: `safe_run_async`（`src/core/utils/async_utils.py`）を唯一の同期→非同期ブリッジに固定し、独自ラップ実装を禁止する。

2. 実体Bulkheadの強制
   - 必要性: 論理分離だけでは障害波及を止められない。
   - 重要性: クリティカル。単一モジュール暴走で全体停止を防ぐ。
   - 解消策: crawler / race_condition / runner で executor と queue を物理分離する。

3. Executor容量管理と fail-fast
   - 必要性: queue膨張とスレッド枯渇を防ぐ。
   - 重要性: クリティカル。待ち行列肥大で復旧不能化する。
   - 解消策: max_workers / queue_maxsize / timeout / retry budget を必須設定化し、上限超過時は即失敗。

4. ツールチェーン互換維持
   - 必要性: 既存CI・監視・運用手順との断絶を防ぐ。
   - 重要性: クリティカル。観測不能化は実質運用停止。
   - 解消策: 旧メトリクス名・旧ログイベント向け互換出力を移行期間で維持し、段階削除する。

5. デバッグ観点の実行時ハング/枯渇バグの解消
   - 必要性: fail-fast 失敗時の解放漏れや単位不一致は長時間運用で致命化する。
   - 重要性: クリティカル。復旧不能な待ち行列肥大・疑似デッドロックを招く。
   - 解消策: リソース解放保証、timeout単位統一、retry二重計上防止、モード差分排除を実装規約に固定する。

### 目的・KPI・完了条件

- 目的: 既存イベントループ環境での `RuntimeError` を恒久的に防止する。
- KPI-1（安定性）: `Event loop is running` / `Event loop is closed` 系エラー発生件数を 0 にする。
- KPI-2（回帰抑制）: 置換対象モジュールの関連テスト成功率 100% を維持。
- KPI-3（運用影響）: 実行時間劣化をベースライン比 5% 以内に抑える。
- KPI-4（意思決定速度）: Gate 判定遅延（予定日時からの遅延）を 1 営業日以内に維持する。
- KPI-5（判定安定性）: KPI 判定は 7日移動平均でも閾値を満たすこと。
- 完了条件: 3回連続 run と関連 CI で KPI-1〜3 を満たすこと。

### スコープ（Bug #6）

- 対象:
  - `src/core/engine/runner.py`
  - `src/core/engine/master_conductor.py`
  - その他 `asyncio.run(` の grep ヒット箇所
- 非対象:
  - 完全な async 化リファクタ（呼び出し規約の大規模変更）
  - ツール固有の業務ロジック変更

### 実装方針

1.  共通ヘルパー化
    - `src/core/utils/async_utils.py` の `safe_run_async(coro, timeout=...)` を共通利用する。
    - 方針: `get_running_loop` チェック + 必要時の ThreadPoolExecutor フォールバック。

2.  呼び出し置換
    - 置換対象の `asyncio.run(...)` を `safe_run_async(...)` へ置換。
    - 置換時に timeout の既定値を明示し、挙動差分を最小化する。

3.  可観測性
    - メトリクス: `async_safe_run_total`, `async_safe_run_fallback_total`, `async_safe_run_error_total`。
    - ログ: フォールバック発生時の呼び出し元モジュール、実行時間、例外種別を記録。

4.  スケーラビリティ保護（致命障害回避）
    - Executor上限: `async_safe_executor_max_workers` を固定し、無制限拡張を禁止する。
    - Executorキュー上限: `async_safe_executor_queue_maxsize` を超えたら即失敗（fail-fast）し再試行へ流さない。
    - Bulkhead分離: crawler / race_condition / runner で executor プールを分離し、相互巻き込みを防ぐ。
    - Retry Budget: `async_safe_retry_budget_per_run` を導入し、劣化時の再試行嵐を抑止する。
    - 宛先別レート制御: target/endpoint 単位で同時接続上限を設け、ホットターゲットによる飢餓を防ぐ。

### フェーズ計画（段階導入）

1.  Phase A: 監査とベースライン取得（1日）
    - `asyncio.run(` 使用箇所を棚卸しし、影響面を確定する。
2.  Phase B: 低リスク箇所から置換（1-2日）
    - 単体実行パス中心に置換し、回帰有無を確認する。
3.  Phase C: 並列/統合パスへ展開（2日）
    - 並列モードでの安定性確認後、全対象へ適用する。

### フェーズゲート（Go/No-Go）

1.  Gate A（監査完了）
    - 入力: 置換対象一覧、影響度、テスト計画。
    - 判定: PM/Architect が置換範囲を確定。
2.  Gate B（低リスク置換完了）
    - 入力: 単体テスト結果、性能差分、エラー有無。
    - 判定: SRE/Debugger が統合展開可否を判断。
3.  Gate C（統合展開完了）
    - 入力: 並列実行結果、監視メトリクス、障害有無。
    - 判定: PM が完了判定を実施。
    - 初版計画時に `scheduled_at` と `decision_due_at` を先行入力し、遅延KPIを即時計測開始する。

### Gate運用テンプレート（必須）

- 各 Gate で以下を事前に記入すること:
  - `owner_pm`
  - `owner_sre`
  - `owner_architect`
  - `scheduled_at`
  - `decision_due_at`
  - `required_metrics`
  - `go_no_go_decision`
  - `decision_reason`

### タスク分解（実行順）

1.  `asyncio.run(` の全ヒットを棚卸しし、置換対象と依存関係を確定する。
2.  `safe_run_async` を唯一APIとして実装し、独自ラップ禁止ルールを静的チェックへ追加する。
3.  executor/queue の実体bulkheadをモジュール単位で構築する。
4.  max_workers / queue上限 / retry budget / timeout を設定スキーマへ組み込み、起動時検証する。
5.  対象コードを段階置換し、互換メトリクス/ログを同時出力する。
6.  並列/統合試験で封じ込め挙動（fail-fast/復帰）を確認し、Gate 判定を実施する。

### 検証計画

- 単体テスト:
  - ループ非存在/存在時の両経路を検証。
  - timeout と例外伝播の一貫性を検証。
  - 境界ケース: timeout 閾値ちょうど、フォールバック発火境界、例外種別境界を検証。
  - 最小再現入力例をケースごとに固定（loop state/timeout/exception fixture）し、再現手順を1コマンドで実行可能にする。
  - リソース解放テスト: 例外経路で semaphore/slot/token が必ず解放されることを検証する。
  - 単位整合テスト: timeout の sec/ms 変換を静的・動的に検証する。
  - retry会計テスト: retry budget の二重計上/未計上がないことを検証する。
- 統合テスト:
  - 対象3モジュールを含むフローで `RuntimeError` 非発生を確認。
  - 並列モードでの再現試験を実施。
  - 長時間ヒステリシステスト: 閾値近傍の振動で制御フラップが発生しないことを確認する。
  - 実行モード同値テスト: 通常実行/対話実行で同一ゲート結果になることを確認する。
- 実運用検証:
  - 展開後の `async_safe_run_error_total` を監視し、増加がないことを確認。

### リスク・ロールバック

- 主リスク:
  - フォールバック経路で性能劣化が顕在化する。
  - 置換漏れにより一部経路で旧挙動が残る。
- ロールバック条件:
  - loop関連 `RuntimeError` が再発。
  - 実行時間劣化が 5% を超過。
  - 重要機能で回帰が確認される。
- ロールバック手段:
  - 置換箇所をモジュール単位で切り戻し。
  - 監査一覧を基準に再置換計画へ戻す。

### 障害封じ込め条件（ネットワーク/並列実行）

- ハード停止条件:
  - `async_safe_run_error_total` が閾値超過時、対象モジュールの新規投入を停止する。
  - executor 待機キューが上限超過時、追加投入を停止し fail-fast へ切替える。
  - run 全体の retry budget 枯渇時、再試行を全面停止する。
- 復帰条件:
  - キュー深度と失敗率が連続ウィンドウで閾値内へ戻った場合のみ段階復帰する。
- 封じ込め方針:
  - 単一モジュール障害を全体停止へ波及させないため、投入制御とexecutorをモジュール単位で分離する。

### 役割分担（RACI簡易）

- PM: 範囲確定、ゲート判定、完了判断。
- SRE/Infra: 監視設計、性能評価、展開監視。
- Architect: 共通ヘルパー設計、呼び出し規約整合。
- Developer/Debugger: 置換実装、再現テスト、回帰分析。
