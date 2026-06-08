---
task_id: SGK-2026-0222
doc_type: work_log
status: done
parent_task_id: null
related_docs:
  - docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md
  - src/core/agents/swarm/runtime_control_backend.py
  - src/core/agents/swarm/discovery/graphql.py
  - tests/core/agents/swarm/test_discovery_graphql_contract.py
created_at: '2026-05-26'
updated_at: '2026-05-26'
---

# SGK-2026-0222 作業ログ（Runtime Control Backend 実装）

## 実施日
- 2026-05-26 (JST)

## 実施内容
1. 共通ランタイム制御バックエンドの追加
- `RuntimeControlBackend` プロトコルを追加。
- `InMemoryRuntimeControlBackend` を実装。
- `RedisRuntimeControlBackend` を実装（inflight/QPS/host quarantine/half-open 制御）。

2. Discovery GraphQL への段階導入
- `GraphQLNavigator` で runtime control を backend 経由に切替。
- `graphql_probe_runtime_control_backend` / `graphql_probe_runtime_control_redis_url` を追加。
- backend障害時ポリシー `graphql_probe_backend_unavailable_policy`（fail_open/fail_safe）を追加。

3. 回帰テスト強化
- fail-safe で拒否、fail-open で継続するケースをテスト追加。

4. ナレッジグラフ更新
- `graphify update .` を実行し、コードグラフを更新。

## 検証結果
- `.venv/bin/pytest tests/core/agents/swarm/test_discovery_graphql_contract.py tests/core/agents/swarm/test_discovery_graphql_alerting.py tests/core/agents/swarm/test_discovery_graphql_longrun.py -q`
  - 26 passed

## メモ
- 既存契約（`backpressure_rejected` / `host_quarantined` / `half_open_trial`）は維持。

## 追加計画書改訂
- `docs/shigoku/plans/2026-05-21_sgk-2026-0222_distributed-runtime-control_plan.md` に以下を統合。
  - backend劣化モード表（接続不可、timeout、failover、atomic operation失敗、TTL/clock skew、stale key）
  - shadow mode差分分類（`same` / `new_reject` / `missed_reject` / `reason_mismatch` / `latency_regression`）
  - fail-safe時の未検査扱い（`not_tested_runtime_control_fail_safe`）
  - Release Gate（互換、分散制御、障害注入、shadow mode、KPI、rollback drill）

## 次アクション
- 改訂したRelease Gateを実装・検証タスクへ展開する際は、各ゲートの結果を個別に記録し、未達ゲートがある場合は全swarm有効化を止める。

## 追加改訂（懸念解消の実装方針化）
- 計画書へ `Concern Resolution Matrix` を追加し、懸念ごとに「改善提案 / 解消方法 / 必要性 / 重要性」を統合した。
- `Integration Implementation Policy` を追加し、backend層・caller層・observability層・release判定層での必須実装方針を固定した。
- 受け入れ条件に `Critical` 全完了、`High` はリスク受容理由なしでは有効化不可を追加した。

## 追加改訂（運用固定化）
- `SLO Threshold Baseline (Initial)` を追加し、閾値未設定での本番有効化禁止と14日再評価方針を明記した。
- `Event Schema Contract Policy` を追加し、`v1` 互換ルール（必須キー削除/型変更禁止、破壊変更は `v2`）を固定した。
- `Release Gate Evidence Template` を追加し、6ゲートの証跡形式と `fail -> hold` 強制ルールを固定した。

## 実装反映（コード）
1. GraphQL runtime control 実装強化
- `src/core/agents/swarm/discovery/graphql.py`
  - fail-safe時の返却を `not_tested_runtime_control_fail_safe` に統一。
  - `graphql_runtime_control_policy.v1` / `graphql_runtime_control_shadow_diff.v1` のイベントスキーマ必須キー検証を追加。
  - shadow mode有効時に差分分類イベントを出力。
  - SLO閾値の初期値を runtime config に追加し、明示 `None`/空値設定時は起動時エラーで拒否。

2. Release Gate証跡テンプレートのバリデータ追加
- `src/reporting/runtime_control_release_gate.py`
  - `fail -> hold` 強制
  - `waived` 時の理由必須
  - Criticalゲートの waived 禁止
  - 6ゲートレコードの存在検証

3. テスト追加/更新
- `tests/core/agents/swarm/test_discovery_graphql_contract.py`
  - fail-safe未検査扱いへの更新
  - runtime control policyイベント必須キー検証
  - shadow diffイベント必須キー検証
  - 閾値未設定拒否の検証
- `tests/unit/reporting/test_runtime_control_release_gate.py`
  - テンプレート検証ルールの単体テスト追加

## 追加検証結果
- `.venv/bin/pytest tests/core/agents/swarm/test_discovery_graphql_contract.py tests/core/agents/swarm/test_discovery_graphql_alerting.py tests/unit/reporting/test_runtime_control_release_gate.py -q`
  - 33 passed

## 追加改訂（CTO懸念クローズ方針）
- 計画書へ `CTO Concern Closure Addendum` を追記し、以下を「改善提案 / 解消方法 / 必要性 / 重要性」で固定した。
  - shadow実差分化（legacy decision provider 接続）
  - shigoku-ops への gate evidence validation 統合
  - 14日再評価の必須ゲート化（未提出時 hold）
  - fail-safe未検査のE2E整合検証
  - Critical項目の waiver 技術的封止
- `CTO Concern Implementation Policy` を追記し、実装優先順を明文化した。

## 追加改訂（4観点詳細化）
- 計画書へ `Four-Perspective Detail Pack` を追記。
  - SRE: 14日再評価のデータ品質基準（サンプル数/日次下限/欠損率）を数値で固定。
  - Architect: `legacy_decision_provider` の入出力契約、失敗モード、version不一致時のfail条件を固定。
  - Debugger: shadow比較ログの最小必須キーと調査優先順位を固定。
  - CTO: 14日期限、承認者、hold解除条件、判定会議の必須議題を固定。

## 追加改訂（CTO運用停滞/可用性/因果分離 対応）
- `High` の期限付き暫定許可ルールを追加（最大7日・1回、期限超過で自動 hold）。
- `legacy_decision_provider` の可用性要件を追加（availability/p95/timeout率、timeout budget、cache fallback）。
- KPI因果分離の自動添付ルールを追加（変更一覧メタデータ必須、欠落時 `causality_evidence_missing` で gate fail）。

## 追加改訂（CTO最終確定事項）
- High waived 回数制限の正本ストアを `docs/shigoku/registry/runtime_control_waiver_registry.yaml` に固定。
- 因果分離メタデータの責務を「CIが生成、shigoku-ops が検証」に分離。
- fallback cache の鮮度許容を `<=300秒`、利用率閾値を `5% warning / 10% hold候補` に固定。

## 追加改訂（CTO運用境界の最終詰め）
- waiver registry 更新競合の排他ルール（`registry_version` 楽観ロック、conflict時非0終了）を追加。
- causality manifest の品質基準（時刻整合、生成鮮度、カテゴリ有効性、時系列単調）を追加。
- cache比率の hold/解除にヒステリシス（2窓連続）を追加し、単発スパイクでの過剰 hold を防止。

## 追加改訂（CTO残懸念の詳細化）
- waiver競合時のCI再試行戦略を固定（2秒→4秒の指数backoff、再試行枯渇で hold）。
- `infra_changes.yaml` の品質保証責務を固定（SRE入力 + Reviewer承認 + CI lint必須）。
- cacheヒステリシスの窓長を15分固定とし、昇格/解除を各30分連続条件に明記。

## 追加改訂（CTO実装順序/承認統合/30日再評価）
- `shigoku-ops runtime-control` を最優先の Critical Path とし、未実装時は hard hold を明記。
- 承認フローを PR/CODEOWNERS 正本へ統一し、`infra_changes.yaml` は `review_id` 参照のみ保持する方式へ固定。
- 30日再評価トリガー（30日経過または月3回以上 hold）と、未提出時 `recalibration_missing` fail を追加。

## 追加改訂（ユーザー指定の最終固定）
- 承認照合ソースを GitHub PR Review API（+ branch protection）に固定。
- `review_id` 形式を `owner/repo#pull_number:review_id` に固定し、照合不能時は `approval_source_unavailable` fail。
- 改訂適用SLAを日数基準から廃止し、連続3検証サイクル達成基準へ置換（未達時 hold 維持）。

## 追加改訂（計画書フォーマット再構成）
- 追記累積状態を解消するため、計画書本文を「ソフトウェア開発計画書」形式へ全面再編。
- 章構成を整理（背景/スコープ/成果物/アーキテクチャ/統治/承認/再評価/実装順序/受入条件/検証計画/リスク/完了条件）。
- 既存で確定済みの統治ルール（waiver, approval, manifest, cache hysteresis, non-day rollout criteria）は保持したまま統合。

## 追加実装（runtime-control CLI Critical Path）
- `scripts/shigoku_ops_cli.py`
  - 新ドメイン `runtime-control gate` を追加。
  - `--evidence-file` で gate証跡JSONを読み込み、`src/reporting/runtime_control_release_gate.py` の検証ロジックを実行。
  - `status=pass/fail/blocked` と `decision=proceed/hold` を返す統一出力を実装。
  - 証跡欠落/JSON不正/スキーマ不正時の reason code（`runtime_control_evidence_*`）を追加。
- `tests/unit/scripts/test_shigoku_ops_cli.py`
  - `runtime-control gate` の pass ケース（6ゲート証跡）を追加。
  - 証跡ファイル欠落時の blocked/hold ケースを追加。

## 追加検証結果（runtime-control CLI）
- `.venv/bin/pytest tests/unit/reporting/test_runtime_control_release_gate.py tests/unit/scripts/test_shigoku_ops_cli.py -q`
  - 22 passed

## CTOコメント解消 実装（CI強制/真正性/承認正本）
- `scripts/shigoku_ops_cli.py`
  - `runtime-control gate` に真正性チェックを追加:
    - `--integrity-manifest`（`gate_evidence_sha256`）を照合し、改ざん検知時は `runtime_control_evidence_hash_mismatch` で fail。
  - 承認正本照合を追加:
    - `--approval-evidence-file`（`approved_review_ids`）と critical gate の `review_id` を照合。
    - `review_id` 形式 `owner/repo#pull_number:review_id` を強制。
    - 不一致/形式不正/ソース欠落は `approval_source_*` で fail。
- `docs/shigoku/registry/`
  - `runtime_control_gate_evidence.json`（6ゲート正本証跡）を追加。
  - `runtime_control_integrity_manifest.json`（sha256正本）を追加。
  - `runtime_control_approval_evidence.json`（承認正本証跡）を追加。
- `.github/workflows/test.yml`
  - `runtime-control-governance` ジョブを追加し、上記3正本ファイルを使った `runtime-control gate` をCI必須実行。
  - 同ジョブで runtime-control 関連の単体テストを実行。

## CTOコメント解消 追加検証結果
- `python3 scripts/shigoku_ops_cli.py --json runtime-control gate --evidence-file docs/shigoku/registry/runtime_control_gate_evidence.json --integrity-manifest docs/shigoku/registry/runtime_control_integrity_manifest.json --approval-evidence-file docs/shigoku/registry/runtime_control_approval_evidence.json`
  - `status=pass`, `decision=proceed`
- `.venv/bin/pytest tests/unit/reporting/test_runtime_control_release_gate.py tests/unit/scripts/test_shigoku_ops_cli.py -q`
  - 24 passed

## CTO残懸念（承認正本ライブ照合）解消実装
- `scripts/generate_runtime_control_approval_evidence.py` を追加。
  - GitHub PR Review API から `approved_review_ids` を動的生成。
  - branch protection から `required_approving_review_count` を取得し、承認必要数を証跡化。
- `.github/workflows/test.yml` の `runtime-control-governance` を pull_request 限定に変更し、
  CI実行時に live API 由来の approval evidence を生成して `runtime-control gate` に投入する構成へ変更。
- `scripts/shigoku_ops_cli.py` を拡張し、
  `required_approving_review_count` と `approved_unique_count` を評価して
  `approval_source_insufficient_approvals` を fail判定に追加。
- `tests/unit/scripts/test_shigoku_ops_cli.py`
  - 承認数不足時 fail（`approval_source_insufficient_approvals`）の単体テストを追加。

## CTO残懸念 解消後の追加検証結果
- `.venv/bin/pytest tests/unit/reporting/test_runtime_control_release_gate.py tests/unit/scripts/test_shigoku_ops_cli.py -q`
  - 25 passed

## CTO追加懸念（証跡自動化/再試行/branch protection範囲）解消
- 証跡自動化:
  - `scripts/generate_runtime_control_gate_evidence.py` を追加し、approval evidence を入力に gate evidence + integrity manifest をCIで自動生成。
  - 静的正本ファイル更新への依存を外し、PR実行時の生成物を正本として評価するフローへ変更。
- API障害時再試行:
  - `scripts/generate_runtime_control_approval_evidence.py` に retry/backoff を追加（既定: 2回, 2s指数）。
  - 一時的なGitHub APIノイズを吸収しつつ、最終失敗時は fail-closed を維持。
- branch protection範囲:
  - approval evidence に `require_code_owner_reviews` を取り込み。
  - `runtime-control gate` に `--require-code-owner-reviews` を追加し、不一致時 `approval_source_branch_protection_mismatch` で fail。
  - 既存の `required_approving_review_count` / `approved_unique_count` 判定と合わせて統治要件を明示評価。

## CTO追加懸念 解消後の追加検証結果
- `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/reporting/test_runtime_control_release_gate.py -q`
  - 26 passed

## Next Step対応（required check 強制）
- `scripts/check_runtime_control_required_check.py` を追加。
  - GitHub branch protection の `required_status_checks.contexts` を参照し、
    `runtime-control-governance` が required check に含まれることを検証。
  - 未設定時は fail で終了し、CI側でマージ不可にする。
- `.github/workflows/test.yml`
  - `runtime-control-governance` ジョブ内に required check 検証ステップを追加。
  - これにより「設定が外れてもCIが即failする」自己防衛を実装。

## Next Step対応 追加検証結果
- `python3 scripts/check_runtime_control_required_check.py --help`
  - 実行可能で引数定義を確認。
- `.venv/bin/pytest tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/reporting/test_runtime_control_release_gate.py -q`
  - 26 passed

## CTO追加要求対応（3項目）
- `check_runtime_control_required_check.py` の単体テストを追加。
  - `tests/unit/scripts/test_check_runtime_control_required_check.py`
  - カバー: required context の CLI優先/ENV読込/default、missing時fail + runbook URL出力、present時pass
- required check 名の設定外出しを実装。
  - `scripts/check_runtime_control_required_check.py`
    - `SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS`（CSV）を追加し、CLI未指定時はENVからrequired check名を解決。
    - ENV未設定時のみ `runtime-control-governance` を既定値に使用。
  - `.github/workflows/test.yml`
    - `SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS` を env で注入。
- 失敗時のRunbookリンク出力を実装。
  - `scripts/check_runtime_control_required_check.py`
    - `--runbook-url` を追加し、fail JSON に `runbook_url` とメッセージを出力。
  - `.github/workflows/test.yml`
    - 実行時にRunbook URLを明示渡し。

## CTO追加要求対応 追加検証結果
- `.venv/bin/pytest tests/unit/scripts/test_check_runtime_control_required_check.py tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/reporting/test_runtime_control_release_gate.py -q`
  - 31 passed

## CTO気になる点の最終潰し込み
- required check名変更追従:
  - `.github/workflows/test.yml` の `SHIGOKU_RUNTIME_CONTROL_REQUIRED_CHECKS` を固定文字列から `${{ github.job }}` 参照へ変更。
  - ジョブ名変更時も required check 検証対象が自動追従するようにした。
- API一時障害時の運用基準:
  - `docs/shigoku/manuals/2026-05-26_runtime-control-fail-open-guard_runbook.md` に
    `runtime-control-governance` 失敗時の再実行基準（最大2回、待機、エスカレーション条件）を明記。
  - 3回目以降の連続再実行禁止と、監査チケット記録義務を固定化。

## 最終潰し込み 追加検証結果
- `.venv/bin/pytest tests/unit/scripts/test_check_runtime_control_required_check.py tests/unit/scripts/test_shigoku_ops_cli.py tests/unit/reporting/test_runtime_control_release_gate.py -q`
  - 31 passed

## クローズ処理（2026-05-27）
- `docs/shigoku/reports/2026-05-27_sgk-2026-0222_distributed-runtime-control_work_report.md` を作成。
- `docs/shigoku/registry/task_registry.yaml` の SGK-2026-0222（plan）を `done` に更新し、work_report エントリ（DOC-0253）を追加。
- `docs/shigoku/registry/task_ledger.md` / `task_ledger.csv` に work_report 行を追加し、plan行を `done` に更新。
