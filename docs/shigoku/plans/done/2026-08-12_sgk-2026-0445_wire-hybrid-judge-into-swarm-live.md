---
task_id: SGK-2026-0445
doc_type: plan
status: done
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

---

# 設計付録（2026-08-12 ユーザー承認済み・実装契約として固定）

設計承認関門（①配線点 ②再現sender 封印接続 ③poc_judge 予算 ④funnel emit ⑤confirmed 成果物）を
コード実態調査（manager.py Phase-2 merge ゲート・T1 `validate_finding` 契約・T2 lifecycle/ledger・
funnel REASON_CODES・封印送信ガード列）に基づき提示し、ユーザー承認を得た。以下を実装契約とする。

## A. 配線点（主配線 = Phase-1 finding 確定直後・早期 return 経路もカバー）

- 2026-08-12 修正（ユーザー承認・実 run 診断に基づく）: 当初の配線点（Phase-2 merge ゲートのみ）は、
  封印 run 2 回の実測で **early-return 経路が merge ゲートをバイパス**する構造問題が確定
  （`manager.py:2981-3010` で fast-types の finding は Phase 2 前に `return SwarmResult(findings=phase1_findings)`
  し、T3 ブロックに到達しない。Phase 2 実行タスクは Phase 1 0 finding スタートで新規 finding を生まない）。
  → **配線点を Phase-1 finding 確定直後（early-return 分岐の直前）へ移動**し、全 finding
  （fast-types 含む）を T1 判定→T2 ライフサイクルに通す。Phase-2 merge ゲートの既存 T3 ブロックは維持
  （merge 後は ledger 状態で再判定をスキップ・Phase-2 新規 finding のみ追加判定）。
- フロー:
  1. `evaluate_payout_grade`（既存・無変更・決定的）
  2. **phase1_findings 確定直後**: `validate_finding(f, ai_judge=BudgetedPoCJudge(...), reproduction_checker=SealedReproductionChecker(...))` → `HybridVerdict`（3条件AND・合成規則は T1 実装を無変更で使用）→ `lifecycle.apply_verdict` → `ledger.put` → save
  3. Phase-2 merge 後: 新規 finding のみ同様に判定（既存 T3 ブロック・ledger 状態チェックで重複 judge なし）
  4. F4/F5 emit を verdict ベースに拡張（§D）
- 機械フロア fail の finding は合成規則3により AI を呼ばず needs_more（初期判定の AI コストほぼゼロ・
  Phase-2 後の再判定で confirmed へ到達可能）。T2 遷移表 T2/T5 により needs_more→再判定→confirmed が自然に成立。
- 重複/予算: ledger は finding_id で upsert。`apply_verdict` は needs_more 以外 no-op → 再判定時は
  終端/parked をスキップ。run 内調査キャップは T2 `allocate_investigation_budget`（run_budget=10）を配線。

## B. 再現 sender 封印接続（新規 `SealedReproductionChecker`）

`ReproductionChecker` Protocol（T1）実装。封印ガード列（全て既存資産を再利用）:

| 段階 | 実装 | 根拠 |
|---|---|---|
| 送信可否 | `assert_read_only_probe("GET", url)` + `evaluate_readonly_request`（state-changing semantics / GraphQL mutation 拒否） | payout_grade.py:495-511 / vdp_readonly_guard.py:111-204 |
| スコープ | `revalidate_scope_for_request`（scope 未定義 fail-closed） | vdp_scope_validator.py:52-110 |
| リクエスト同一性 | `build_request_fingerprint` 一致チェック（不一致は送信しない） | vdp_follow_up_executor.py:201-224 |
| 送信 | `network_client=None` なら not_run。`use_cache=False, retries=0, allow_redirects=False, timeout=15` の GET 1 発 | executor `_send_read_request` 契約 :1090-1155 |
| 発火印比較 | 再送応答に既存マーカー語彙（`_MARKER_CATEGORIES`）を評価し**元 finding と同一カテゴリ発火 → matched**。応答なし/タイムアウト/エラー → **not_run**（mismatch にしない） | payout_grade.py:186-198 |
| 予算 | 1 finding あたり再送1回・run 全体で再送回数キャップ（既定5回）・時間予算内 | コンストラクタ既定値 |

- **mismatched は「応答あり・同一マーカー非発火」のみ**（→ refuted / reproduction_mismatch）。
  タイムアウト・状態変更依存・復元不能は not_run（→ needs_more、confirmed にしない）。
- マスク: 送信は 0439 token_map 復元（利用可能な場合）。復元不能なら送信しない（fail-closed → not_run）。
- YAML 配線なし（0444-D01 の deferred_followup 継続・コンストラクタ既定値）。

## C. poc_judge 実起動の予算（fail-closed）

| 予算 | 既定値 | 超過時 |
|---|---|---|
| run あたり judge 呼び出し回数 | 10 回 | ai_judge=None 扱い → needs_more（ai_judgement_pending）・confirmed 不可 |
| run あたり judge 時間 | 600 s | 同上 |
| 1 呼び出し | LLMClient 既存（timeout 300・retry 既存・fallback_profile 既存） | 既存のまま |

- 例外写像: `PoCJudge` の ValueError（JSON parse 失敗等）は配線側で catch → needs_more。
  LLMClient の retry/fallback は既存機構のまま。
- 計測: `run_ledger_llm_usage.extract_llm_usage` で token 数記録（コストは記録のみ）。

## D. 0440 funnel emit 設計（schema additive・off で byte-identical）

- `finding_funnel_trace.py:55-69` REASON_CODES に **additive 追加**:
  `hybrid_confirmed` / `hybrid_refuted` / `hybrid_parked` / `hybrid_needs_human` / `reproduction_transport_error`
- F5 emit: verdict 確定後 `_funnel_finding_event(f, "F5", "reached", reason_code=<verdict系>)` +
  `additional_info["hybrid_final_state"]`。
- **OUTCOMES（reached/skipped/blocked/failed）は不変**。最終状態は reason_code で表現
  （Lane B 読者 vdp_report_projection / haddix_formatter 互換維持）。
- F6 は現状 emit なしのまま（T4 の Haddix 明記に含める）。既存 emit（F0-F5・first-failure 規約・
  guarded swallow）は無変更。
- before/after: before = 0441 run（F4 by_stage 8・confirmed 0）。after は本 run の
  `summary.by_stage`/`max_stage_reached`/reason 分布で比較（learnings に従い first_failure 分布は使わない）。

## E. confirmed 成果物（賞金級 PoC artifact）

confirmed 到達時、タスク成果物として提示（Haddix レポート明記は T4 NOT in scope）:

1. **ledger レコード（マスク済）**: `workspace/projects/<target>/candidate_ledger.json` に
   `state=confirmed`・reason=`hybrid_confirmed`・evidence_summary は D5 サマリ投影
   （refs + マスク済 URL + ステータス数値のみ・生値ゼロ）。
2. **再現裏取り記録**: `ReproductionOutcome(status="matched", reason=<発火マーカー>)`。
3. **PoC 断片**: session 内 finding の `poc_request` / `poc_response` / `impact` /
   `reproduction_steps`（既存マスク済経路）を根拠として引用。
4. **誤確定ゼロの実証**: 3条件未達で confirmed にならないテスト＋封印 run の verdict 内訳。

## F. 検証手順（完了条件対応）

1. 単体: SealedReproductionChecker（GET-only・state-change 除外・タイムアウト→not_run・マーカー一致→
   matched・不一致のみ mismatch・network_client=None→not_run）+ 配線（mock で verdict→lifecycle→
   funnel emit→ledger 保存の連鎖）+ 予算超過→needs_more。
2. 回帰: 既存 funnel/validator/lifecycle/ledger テスト。
3. 封印 run 1回: funnel before/after・確定/棚上げ/人間送り件数・誤確定ゼロ・ledger secret-scan・
   preflight exit 0・PCR-P1 diff 0・GET-only・consistency consistent・validator 0。
