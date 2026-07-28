---
task_id: SGK-2026-0389
doc_type: subtask_plan
status: done
parent_task_id: SGK-2026-0385
related_docs:
- docs/shigoku/plans/2026-07-25_dvwa-low-detection-sufficiency-and-evidence-quality-recovery_plan.md
title: DVWA low command injection evidence promotion
created_at: '2026-07-25'
updated_at: '2026-07-28'
tags:
- shigoku
target: DVWA Security=low / command injection evidence quality / safe verification
---

# 実装計画書：DVWA low command injection evidence promotion

## 1. 目的

`/vulnerabilities/exec/` の Command Injection finding を、候補止まりから confirmed に近づける。DVWA lab では安全な payload を使い、bug bounty mode では危険な自動拡張をしない。

この task は、DVWA 固有のコマンド実行ページにだけ効く調整ではなく、実アプリでも使える安全な検証・証拠化の型を整える。

## 2. 対象

- Target: `/vulnerabilities/exec/`
- 主な実装候補:
  - `src/core/agents/swarm/injection/smart_cmd_ssrf.py`
  - `src/core/agents/swarm/injection/manager.py`
  - `src/core/security/guard_enforcement.py`
  - `src/reporting/haddix_formatter.py`

## 3. 現状の主な不足

- `command_execution_not_verified`
- `payload_request_mismatch`
- `synthetic_response_evidence`
- deterministic precheck は `;`, `&&`, `|` など一部の安全 payload に寄っており、メタ文字ごとの未評価/不発が reason code 化されていない。
- time-based は baseline と比較しているが、統計・再現回数・OOB 裏付けが confirmed 条件として明文化されていない。

## 4. 作業内容

- [ ] DVWA lab で安全に使える command injection payload を整理する。
- [ ] `;`, `&&`, `|`, `||`, newline, encoded newline, safe subshell などのメタ文字行列を guard 内で整理する。
- [ ] 各メタ文字について、tested / failed / blocked / not_allowed / untested を reason code として残す。安全 payload 不発だけで包括的な非脆弱扱いにしない。
- [x] 可能なら command output を実 response evidence として保存する。
- [x] time-based 判定の場合は baseline / positive / negative の比較と再現サンプルを保存する。
- [ ] baseline mean / stddev / margin を明示フィールドとして保存する。
- [ ] blind command injection では、OOB callback を強い evidence として使う。OOB 未稼働時は `oob_channel_unavailable` として分離する。
- [x] `proof_of_control` と `proof_of_impact` を分け、control-only は candidate に留める。
- [ ] SSRF と Command Injection の evidence を混同しない。
- [ ] bug bounty mode では危険 payload を自動で増やさない guard を維持する。
- [ ] DVWA のページ名や既知出力だけを根拠に confirmed 化しない。

## 5. 完了条件

- `/vulnerabilities/exec/` の raw finding が安定して出る。
- `command_execution_not_verified` が解消または減少する。
- finding の request / response / payload が Haddix report で追跡できる。
- メタ文字ごとの評価結果が残り、未評価の文字が非脆弱扱いに混ざらない。
- time-based / blind の confirmed は、統計・OOB・再現性のいずれかで説明できる。
- report/session consistency が PASS する。

## 6. リスク

- [重要度:高] command injection は危険度が高い。lab mode と bug bounty mode の制御を混同しない。
- [重要度:中] time-based だけで confirmed 化すると弱い。可能な限り出力証拠または比較証拠を残す。
- [重要度:中] DVWA lab で安全に見える payload でも、実アプリでは危険になりえる。lab mode と bug bounty mode の制御を必ず分ける。
- [重要度:中] メタ文字行列を広げると安全境界を越えやすい。危険 payload は not_allowed として記録し、bug bounty mode で自動実行しない。

## 7. 2026-07-26 実装メモ

第一スライスとして、Command Injection の evidence を Haddix evidence quality gate が読める形に寄せた。

- 出力型の command injection は `command_execution_evidence.output_observed` と PoC request / response を保存する。
- time-based 型は、通常 3 回、攻撃 3 回、逆条件 1 回の timing samples を `blind_correlation` と `command_execution_evidence` に保存する。
- payload delivery telemetry を保存し、配送できたかどうかを `payload_delivery` に残す。
- SSRF と command execution の evidence は `command_execution_evidence` 側へ分けて保存する。

未対応:

- メタ文字行列全体の tested / failed / blocked / not_allowed reason code 化。
- OOB callback preflight と `oob_channel_unavailable` reason code。
