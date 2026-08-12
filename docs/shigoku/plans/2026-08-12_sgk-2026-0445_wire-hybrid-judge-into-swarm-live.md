---
task_id: SGK-2026-0445
doc_type: plan
status: active
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0443_shared-hybrid-confirmation-judge.md
- docs/shigoku/plans/done/2026-08-12_sgk-2026-0444_candidate-lifecycle-and-parked-store.md
created_at: '2026-08-12'
updated_at: '2026-08-12'
tags:
- shigoku
- vdp
- security-sensitive
target: src/core/agents/swarm/injection/manager.py,src/core/engine/swarm_dispatcher.py,src/core/validation,src/core/engine/finding_funnel_trace.py
---

# 実装計画: T3 — 共有判定＋ライフサイクルを swarm 経路に配線（実戦投入）

（親ロードマップ: SGK-2026-0442。設計方針・不変条件はそちら。T1=0443 判定モジュール／T2=0444 ライフサイクル＋ledger は done。）

## 背景

- T1（0443）: `validate_finding(finding, sender=...)` が rich verdict を返す（機械フロア＋AI＋再現の 3条件AND・T1 単体では sender 無しで confirmed 到達不能）。
- T2（0444）: ライフサイクル（予算→棚上げ/人間送り）＋ candidate_ledger（run 跨ぎ・マスク保存）＋復活。
- しかし **swarm 経路にはまだ配線されていない**（`manager.py:294` で `FindingValidator()` は生成されるが、hybrid 判定/ライフサイクルは駆動していない）。0441 で見つけた「候補は F2/F3 まで来て確定に上がらない」も未解消。
- **本タスクで初めて、実際に確定/棚上げ/人間送りが起きる。** 確定に直接触れる最重要段。

## 目的

**T1 判定 ＋ T2 ライフサイクルを swarm の finding 経路に配線し、封印環境で実際に候補を「確定/棚上げ/人間送り」まで通す。** 効果は 0440 funnel で before/after 実測。**敷居は下げない・カーブフィッティングしない・秘密はマスク。**

## スコープ（T3 のみ）

1. **配線**: swarm（`InjectionManager` / `swarm_dispatcher`）が生成した finding を T1 `validate_finding()` に通し、verdict を T2 ライフサイクルへ渡す（confirmed / refuted / needs_more / inconclusive_parked / needs_human）。inconclusive_parked / needs_human は candidate_ledger へ保存。
2. **再現裏取り sender の接続（confirmed を到達可能にする核）**: T1 の injectable reproduction checker を、**封印環境で PoC を GET で再送**し同一発火印を確認する実装に接続。**GET のみ・封印ローカルのみ・時間予算**。状態変更を伴う再現は行わない（その場合は confirmed にせず候補/人間送り）。
3. **AI(poc_judge) の実起動**: reasoning/thinking role を実際に呼ぶ。**予算（時間/コスト）上限**をタスク内で管理。
4. **0440 funnel への反映**: 各候補の到達段（F4 evidence → **F5 confirmed_or_refuted** → F6 reported）と最終状態（confirmed/parked/needs_human）を診断イベントとして emit。before(F3/F4 止まり)/after を計測。
5. 0441 の early-return と整合（有望な未確定候補は Phase2/検証へ回る・payout-grade 済みは速度優先のまま）。

## 診断先行 ＋ 設計承認関門（確定に触るため必須）
実装前に: (a) 配線点（どの finding をいつ判定に通すか・重複/予算）、(b) 再現 sender の封印接続（GET-only・状態変更除外・予算・kill switch）、
(c) poc_judge 実起動の予算、(d) funnel への emit 設計、(e) confirmed になったものの成果物（賞金級 PoC artifact）— を提示し承認を得てから実装。

## 認可エンベロープ（0433/0437/0439 と同一・逸脱は fail-closed）
- 封印使い捨てローカル Juice Shop のみ・実VDP外部は対象外。
- 攻撃・再現は **read-only GET のみ**（auth-setup は A/B register/login のみ）。状態変更/blind/stored 依存は confirmed にせず候補/人間送り。
- 実行1回・snapshot 復元・kill switch・検証ループに時間予算・成果物 bbb 読取可・安全0。

## 不変条件（ロードマップ §不変条件に従う・絶対）
- **確定＝3条件AND（機械フロア＋AI賞金級＋再現一致）を変えない・敷居を下げない。** AI 主張のみで確定しない。VDP 署名確定は無変更で共存。
- confirmed になるものは **賞金級 PoC（再現 req/res＋impact＋再現一致）**を伴う。証明不足は棚上げ/人間送り（消さない）。
- カーブフィッティング禁止（製品固有の答えを使わない・preflight exit 0・docs opaque）。秘密はマスク（0439＋T2 ledger）。PCR-P1 無改変・schema additive。

## 完了条件（設計承認後）
1. 封印 run の **0440 funnel before/after**: 候補が **F5（confirmed_or_refuted）へ到達**し得ること・最終状態（confirmed/parked/needs_human）が集計できる。
2. confirmed が出た場合、**賞金級 PoC artifact（再現 req/res＋impact＋再現一致）**を提示。**誤確定ゼロ**（3条件を満たさないものは confirmed にしない）。
3. parked/needs_human が candidate_ledger に**マスク保存**され、run 終了後に取り出せる。
4. カーブフィッティング無し（preflight exit 0）・秘密漏洩0（secret-scan）・PCR-P1 diff 0・consistent・GET-only・実行1回・validator 0。

## NOT in scope（T3）
- Haddix レポートへの 確定/保留/人間送り 明記（T4=0446）。多段攻撃計画（⑥）。T1 判定ロジック/閾値の変更。状態変更を伴う攻撃・m3b 以上・実VDP外部。

## 参照
- `manager.py:294`（FindingValidator 生成点）・`manager.py:3970`（validate_findings）・`swarm_dispatcher`（findings 集約）・`finding_funnel_trace.py`（0440 F-stage）・T1 `validate_finding` / T2 lifecycle・ledger・0441 early-return。
