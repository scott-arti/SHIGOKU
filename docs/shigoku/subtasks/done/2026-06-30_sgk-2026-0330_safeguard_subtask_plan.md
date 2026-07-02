---
task_id: SGK-2026-0330
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0329
related_docs:
- docs/shigoku/plans/done/2026-06-30_sgk-2026-0329_bugbounty-sqli-hitl_plan.md
- docs/shigoku/specs/adr/2026-02-27_RequestGuard_Implementation.md
- docs/shigoku/reports/2026-06-30_SGK-2026-0330_work_report.md
- docs/shigoku/worklogs/2026-06-30_SGK-2026-0330_work_log.md
title: 共有SafeGuardの残適用箇所横展開
created_at: '2026-06-30'
updated_at: '2026-07-02'
tags:
- shigoku
target: src/core/security,src/core/agents/swarm/injection,src/core/conductor
---

# 実装計画書：共有SafeGuardの残適用箇所横展開

## 1. 達成したいゴール（ユーザー視点）
- [ ] `SmartLFIHunter` を含む残存 specialist 経路でも、共有 `ExecutionSafeguardService` を経由して `bugbounty` 既定の fail-closed 判定が効くこと。
- [ ] `interactive_bridge.py` の HITL 初期化経路が、共有 SafeGuard と矛盾しない形で整理されること。
- [ ] 共有 SafeGuard の導入済み specialist 群 (`smart_sqli.py`, `smart_xss.py`, `smart_cmd_ssrf.py`) と同じ呼び出し契約を、残適用箇所にも横展開できること。
- [ ] 実装後に、どの経路が共有 SafeGuard 配下に入り、どの経路が未対象かをテストと文書で追跡できること。

## 2. 全体像とアーキテクチャ
- **対象コンポーネント/ファイル一覧:**
  - `src/core/agents/swarm/injection/smart_lfi.py`: （修正）`SmartRequest` 生成時に共有 `ExecutionSafeguardService` を注入し、default mode を `bugbounty` 基準へ寄せる第一候補。
  - `src/core/conductor/interactive_bridge.py`: （修正または整理）既存 `get_request_guard()` 初期化経路が共有 SafeGuard の singleton / HITL callback と整合しているか確認し、必要なら `get_execution_safeguard()` 経由へ統一する。
  - `src/core/security/execution_safeguard.py`: （確認/必要なら修正）shared facade の初期化 API と callback 引き回し契約を、CLI 起動経路から見て一貫化する。
  - `src/core/security/request_guard.py`: （確認）HTTP/HITL adapter としての責務に留まっているか、`interactive_bridge.py` からの利用形が facade 経由へ寄せられるかを確認する。
  - `src/core/infra/smart_request.py`: （確認）`execution_safeguard` 優先、`request_guard` fallback の実装が LFI 系でも利用されることを回帰確認する。
  - `tests/core/agents/swarm/injection/test_smart_lfi.py`: （追加/修正）LFI specialist が shared safeguard を使うこと、`bugbounty`/`ctf` の mode 差分を確認する。
  - `tests/core/security/test_execution_safeguard.py`: （必要なら追加）LFI 相当 payload / aggressive method / callback wiring の横展開回帰を補強する。
  - `tests/core/infra/test_smart_request.py`: （必要なら追加）shared safeguard 優先経路と legacy fallback の両立を維持する。
- **データの流れ / 依存関係:**
  - CLI / conductor mode 解決 -> `interactive_bridge.py` の HITL callback 初期化 -> `get_execution_safeguard()` -> `RequestGuard` adapter / policy群 -> `SmartRequest` -> 実 HTTP リクエスト。
  - specialist config -> `mode` 解決 -> `SmartLFIHunter` -> `SmartRequest(execution_safeguard=...)` -> method / payload 判定 -> allow または fail-closed block。
  - deny / require_hitl / allow -> `SafeguardDecision(reason_code, matched_rules)` -> ログ / テスト / 実行結果へ反映。

## 3. 具体的な仕様と制約条件
- **入力情報 (Input):**
  - specialist config の `mode` (`bugbounty|ctf|...`)
  - `SmartLFIHunter` が送る HTTP method / payload / target URL
  - conductor 起動時に設定される HITL callback
- **出力/結果 (Output):**
  - 成功時: `smart_lfi.py` でも shared safeguard 経由で送信判定され、`bugbounty` では危険 request が fail-closed で止まる。
  - 失敗時: callback 不在、aggressive method、将来の payload risk rule に該当する場合でも bypass せず、理由付きで block される。
  - 非対象時: `interactive_bridge.py` の整理後も legacy adapter 契約は保持し、既存 specialist の挙動を壊さない。
- **制約・ルール:**
  - 既存の shared safeguard 実装 (`src/core/security/execution_safeguard.py`) を正本とし、個別 specialist 側に別ガードロジックを増やさない。
  - HTTP method 判定は `MethodRiskPolicy`、HITL/endpoint 承認は `RequestGuard` adapter、payload 判定は `PayloadRiskPolicy` の責務分離を崩さない。
  - `smart_lfi.py` の変更は最小差分に留め、LFI ロジック本体や ThoughtLoop の振る舞いは巻き込まない。
  - `interactive_bridge.py` の変更では、shared safeguard と同じ singleton に callback が入ることを保証し、二重初期化や divergent cache を作らない。
  - テストは `.venv/bin/pytest` で targeted first とし、shared safeguard 既存回帰を壊さないことを確認する。
  - 本サブタスクは「SafeGuard を残適用箇所へ横展開すること」が目的であり、親計画のクローズや `done` 化は DeepSeek V4 Pro 側の担当とする。

## 4. 実装ステップ（AIに指示する手順）
- [ ] ステップ1: 残適用箇所を確定する。少なくとも `src/core/agents/swarm/injection/smart_lfi.py` の `SmartRequest(network_client=...)` 直生成と、`src/core/conductor/interactive_bridge.py` の `get_request_guard()` 直初期化を確認し、shared safeguard 配下へ入れる変更点を固定する。
- [ ] ステップ2: `smart_lfi.py` に shared safeguard を導入する。`smart_sqli.py` / `smart_xss.py` / `smart_cmd_ssrf.py` と同様に `get_execution_safeguard(mode=mode)` を取得し、`SmartRequest(..., execution_safeguard=safeguard)` へ統一する。必要なら default mode も `bugbounty` に寄せる。
- [ ] ステップ3: `interactive_bridge.py` の HITL 初期化経路を整理する。共有 singleton に callback が入ることを前提に、`get_request_guard()` 直呼びを残すか `get_execution_safeguard()` 経由へ寄せるかをコード上で決定し、二重管理にならない形へ統一する。
- [ ] ステップ4: shared safeguard の契約を維持する追加テストを作る。`tests/core/agents/swarm/injection/test_smart_lfi.py` で safeguard 注入と mode 差分を確認し、必要に応じて `tests/core/infra/test_smart_request.py` / `tests/core/security/test_execution_safeguard.py` に callback wiring と fallback 回帰を足す。
- [ ] ステップ5: targeted validation を実行する。少なくとも `tests/core/agents/swarm/injection/test_smart_lfi.py`, `tests/core/security/test_execution_safeguard.py`, `tests/core/infra/test_smart_request.py` を通し、shared safeguard 既存回帰が壊れていないことを確認する。
- [ ] ステップ6: 非対象スコープと次段候補を明記する。たとえば manual-assist 系 SQLi モジュールや placeholder 系ツールが shared safeguard 直配下にない場合、その理由と次回横展開候補を work report / deferred task に残す。

## 5. 既知のリスクと次回の申し送り（Backlog / 技術的負債）
- ※CTO/SREレビューで「後回し可」となった懸念事項は、ここに必ず記録する。
- [ ] [重要度:高] `smart_lfi.py` だけを直しても、将来的に `SmartRequest` を独自生成する別 specialist が増えると再発する。- 次回は `SmartRequest(` と `get_request_guard(` の定期 grep / lint 的チェック導入を検討する。
- [ ] [重要度:中] `interactive_bridge.py` が facade ではなく adapter に直接依存したままだと、初期化経路の設計意図が読み取りづらい。- 今回は整合性を優先し、必要なら別タスクで bootstrap API の単純化を切り出す。
- [ ] [重要度:中] time-based SQLi policy は shared safeguard に hook があるが、現時点ではデフォルト有効ではない。- 本サブタスクではスコープ外とし、別 task/subtask で policy matrix を詰める。
- [ ] [重要度:中] `distributed_sqli.py` や `second_order_assistant.py` のような補助系モジュールは、直接 HTTP 送信主体でない経路が混在している。- 実送信 path が確認できたものから段階的に shared safeguard 配下へ寄せる。

### 5.1 work_report の deferred_tasks 記載例（推奨）
```yaml
deferred_tasks:
  - deferred_id: SGK-2026-0330-D01
    title: "継続監視: [監視対象]"
    reason: "実装スコープは完了したが、継続監視が必要"
    impact: medium
    tracking_task_id: SGK-YYYY-NNNN
    recommended_next_action: "監視用 task/subtask を active で起票し、次回レビュー日を設定する"
```
