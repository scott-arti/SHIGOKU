---
task_id: SGK-2026-0441
doc_type: plan
status: active
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/reports/2026-08-11_sgk-2026-0440_finding-pipeline-instrumentation_work_report.md
created_at: '2026-08-11'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/agents/swarm/thought_loop.py,src/core/agents/swarm/injection/manager.py,config/shigoku.yaml
---

# 実装計画: 検証ループの近代化 — 見つけた候補を「賞金級 PoC」で確定させる

## 背景 / 0440 が示した事実（計測駆動）

- 0440 の計測で、封印 run の候補が **F3 phase2_skipped_early_return（5件）/ F0 task_suppressed_ownership（3件）** で全滅、確定0が確定した。
- **F3 の機構（確認済み）**: Phase 2＝**LLM が深く検証して PoC 付きで確定を作る段**（`manager.py:3439/3495/3842` の "…confirmed"＋`poc_request/response`）。
  しかし `should_auto_early_return`（`manager_internal/execution_policy.py`）が「deterministic 精度が高いカテゴリは見つけた時点で Phase2 を打ち切る（速度）」→ **確定を生む検証を飛ばし、候補のまま放置**。
- **検証ループの実体**: `thought_loop.py`（ReAct 型：考える→撃つ→観る→止めるか判断・`max_turns` 既定10・早期 finish 可）。専門家（smart_sqli/xss/lfi/cmd_ssrf/open_redirect/actor_critic）は `LLMClient(role="…_specialist")` を使用（＝モデル/熟考は `config/shigoku.yaml` の role で切替可）。当時「推論が浅いので回数で補う」設計（smart_xss に "3→8 ターン" のコメント）。
- **F0 の機構**: `_check_and_claim_ownership`（`injection_ownership_dedup_enabled`）が (URL・カテゴリ・経路) で重複排除し2件目を攻撃前に抑制。**本物の別ベクトルを落としているかは未確認。**

## 目的

**見つけた容疑を、AI 検証ループ（Phase 2）で「バグバウンティで賞金が出る粒度・根拠の PoC」まで詰めて確定させる。**
そのためにループを近代化する（回数固定→目的駆動・熟考）。**確定の敷居は下げない。カーブフィッティングしない。**

## 証拠バー（本タスクの中核・絶対基準）

- confirmed は **「賞金級 PoC」= 再現可能な request/response（実際に脆弱性が発火した生の証拠：SQLエラー顕在化・payload の反射実行・境界越えの実データ 等）＋ 実害（impact）の証明** が揃った場合のみ。
- **LLM が「confirmed」と言うだけでは確定しない。** 実 req/res 証拠を既存 Evidence Validator/検証器に通す（敷居は下げず、むしろ賞金級へ引き上げる）。
- PoC が揃わなければ **候補/refuted のまま**（無理に確定しない）。

## スコープ（① 〜 ⑤。⑥ は後段へ deferred）

- **① 熟考・強モデル化**: `config/shigoku.yaml` の `*_specialist` role の profile を格上げ＋（対応時）extended thinking を有効化。コード改修は最小。実行コスト上昇はタスク内で上限管理。
- **② 止め方の近代化**: `thought_loop.py` に **時間予算での終了** と **"賞金級 PoC が取れたら即終了/脈なしで即打切り"** フックを追加（回数固定に依存しない）。`max_turns` は安全上限として残す。
- **③ 賞金級 PoC 判定器（新規・小）**: 再現 req/res＋impact が賞金級かを判定する共有モジュール。各専門家の `should_stop` から共通利用。**判定は敷居を上げる方向のみ**。
- **④ 門番（early-return）修正**: 有望な未確定候補には Phase 2（検証ループ）を回す。速度最適化の early-return を、確定余地のある候補では検証へ回すよう `manager.py` の gating を調整（全面 OFF にしない）。
- **⑤ 専門家の停止判定を③へ接続**: 6専門家の `should_stop` を賞金級判定器に繋ぐ（各1箇所の浅い接続。攻撃本体は温存）。

## 認可エンベロープ（0433/0437/0439 と同一・逸脱は fail-closed）

- 封印使い捨てローカル Juice Shop のみ・実VDP外部は対象外。
- 攻撃は **read-only GET で確定できる部分集合のみ**（反射型XSS・エラーベースSQLi 等）。状態変更/blind/stored 依存は候補のまま保留（無理に確定しない）。auth-setup は A/B register/login のみ。
- 実行1回・snapshot 復元・kill switch・安全0・成果物 bbb 読取可・検証ループに時間予算（暴走防止）。

## 診断先行 ＋ 設計承認関門（確定パスに触るため必須）

**実装前に**: (a) Phase 2 を回す候補の選定基準、(b) 賞金級 PoC 判定器の証拠条件、(c) 止め方（時間予算・停止基準）、
(d) F0 抑制の診断結果（3件が真の重複か別ベクトルか）、(e) read-only 制約と予算 — を提示して承認を得てから実装。

## 完了条件（設計承認後）

1. 封印 run で、0440 funnel の before/after: **F3 で全滅していた候補が検証段（F4/F5）へ進む**ことを実測。
2. confirmed になるものは **賞金級 PoC（再現 req/res＋impact）を伴う**（証拠 artifact 提示）。PoC 無しは確定しない（敷居据え置きの実証）。
3. **カーブフィッティング無し**（製品固有の答えを実装分岐/正解に使わない・製品 token 遮断・preflight exit 0・docs opaque）。
4. F0 は診断結果に基づき、本物を落としている場合のみ最小限緩める（重複攻撃を乱発しない）。
5. 秘密取り扱いは 0439 のマスク＆復元を維持・PCR-P1 無改変・安全0・consistent・validator 0。

## NOT in scope

- ⑥ 多段の攻撃計画（chain planning）→ ①〜⑤ の効果を 0440 で測った上で後段タスク。
- 証拠条件/閾値の緩和・LLM 主張のみでの確定・confirmed 件数の指標化。
- 状態変更を伴う攻撃・m3b 以上・実VDP外部。

## 参照

- `src/core/agents/swarm/thought_loop.py`（ReAct ループ・max_turns・decide/act/should_stop）。
- `src/core/agents/swarm/injection/manager.py`・`manager_internal/execution_policy.py`（`should_auto_early_return`・phase2 gating）。
- `_check_and_claim_ownership`（F0 抑制）。`config/shigoku.yaml` `llm.roles.*_specialist`（①）。
- SGK-2026-0440（finding funnel＝before/after 計測）・0439（マスク＆復元）・0422（Evidence Validator）。
