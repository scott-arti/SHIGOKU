---
task_id: SGK-2026-0424
doc_type: subtask_plan
status: active
parent_task_id: SGK-2026-0418
related_docs:
- docs/shigoku/plans/done/2026-07-31_vdp-capability-benchmark-and-evidence-contract_plan.md
- docs/shigoku/subtasks/done/2026-07-31_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_subtask_plan.md
- docs/shigoku/reports/2026-08-04_sgk-2026-0423_vdp-hidden-holdout-evaluation-shadow-rollout-and-recovery_work_report.md
- docs/shigoku/subtasks/done/2026-08-05_sgk-2026-0425_vdp-causal-attack-funnel-diagnosis_subtask_plan.md
- docs/shigoku/subtasks/2026-08-05_sgk-2026-0426_vdp-product-independent-improvement-and-hidden-reevaluation_subtask_plan.md
title: Approved VDP M3a read-only pilot and capability/evidence measurement
created_at: '2026-08-05'
updated_at: '2026-08-07'
tags:
- shigoku
target: (計画段階のみ。実装・通信・攻撃は本タスクの後続ターンで実施)
---

# 実装計画書：承認済みVDPでの M3a 読み取り専用パイロットと、探索の広さ・検証の深さ・証拠品質の実測

## 1. 達成したいゴール

- [ ] ユーザーの明示許可・書面 scope・ProgramCapabilityMatrix・予算・停止条件が実行前に固定され、許可がない限りネットワーク通信を一切行わないことを実行可能な契約として維持する。
- [ ] M3a（GET / 読み取り専用）のみを実行し、POST・PUT・PATCH・DELETE・状態変更・M3b・M3c・M4 を一切実施しない。
- [ ] 実VDP対象で、実際に観測できた capability / actor / trust boundary と、未到達のものとその理由を記録する（探索の広さ）。
- [ ] candidate ごとに evidence gap と NextAction を追跡し、独立したクラス固有証拠がない candidate を confirmed にしない（検証の深さと証拠品質）。
- [ ] scope逸脱、secret漏洩、状態変更、予算超過、二重送信を 0 件にし、report/session consistency と Go/Hold/No-Go を実artifactで保存する。
- [ ] パイロットの終点を「M3a 継続」または「Hold」とし、M4 への進級判断をこのタスクの判定対象にしない。

## 2. 前提とゲート（実行前固定契約）

**実行順序の前提:** SGK-2026-0425（診断基盤・診断産出）とSGK-2026-0426（一般改善・hidden再評価・readiness発行）がともにdoneとなり、hash付き `diagnostic_readiness=go` artifact（0426が発行）が生成されるまで、本タスクは計画状態のままとし、実VDPへの通信を開始しない。readinessがHoldの場合は、本タスクも通信せずHold理由を受領する。この前提は、以下の許可・scope・予算gateを置き換えるものではない。

**SGK-2026-0426注記（future-stage）:** 0426の完了契約はW1〜W4＋FO（S05 thread-confinement proven化と修正・fail-open fail-closed化・analyzer reach整合）までを固定し、**本タスク（0424）のreadiness依存充足は0426の完了条件に含めない**。0426は `config/diagnostics/readiness_sgk2026_0426.json`（hash付き根拠、`status: evidence_ready`）を産出済みであり、0424のreadiness判定（go/hold）は本タスク着手時に、このevidenceと当時の実VDP許可・scope・予算・kill switch固定と合わせてユーザーが判断する（future-stage。0424側で判定）。

本パイロットを実行するには、次のすべてが**実行ターンの開始前にユーザーによって明示され、本文書または承認記録に固定済み**であることが必須である。1つでも欠ける場合は fail-closed とし、通信を一切開始しない。

1. 書面上の許可: 対象プログラムの VDP/バグ報奨プログラム参加資格と、本パイロット実行の明示許可（ユーザーの明示指示）。
2. scope: 許可された asset の一覧と、許可されない asset（third party、OOB宛先、派生URL、リダイレクト先含む）。
3. ProgramCapabilityMatrix: capability / action ごとの allowed / confirmation_required / prohibited / unavailable の判定（SGK-2026-0419 の契約を使用）。
4. 予算: asset / actor / hypothesis 単位の最大 request 数、follow-up 数、retry 数、並列数、総実行時間（SGK-2026-0419 の ExecutionBudget を使用）。
5. 停止条件 (kill switch): 429/5xx 急増、scope不明、依存停止、予算枯渇、redaction 失敗などの即時停止条件と、停止後の再開条件。

- 許可・scope・capability・予算・kill switch の**変更は実行中の自動判断で行わない**。変更は実行ターンの開始前に固定する。
- リダイレクト先、派生URL、DNS解決結果、OOB宛先は、**各通信直前に scope を再検証**する（SGK-2026-0421 の仕組みを利用）。

## 3. 実行範囲（M3a 読み取り専用のみ）

- 実行できるのは **GET のみ**（読み取り専用）。method は ProgramCapabilityMatrix と read-only guard（SGK-2026-0421）で通信直前に再検証する。
- **POST、PUT、PATCH、DELETE、状態変更、M3b（HITL状態変更）、M3c（Chain）、M4（Enforce）は本タスクの対象外**。M3b/M3c/M4 の feature flag は有効化せず、有効化しようとする設定・コードは fail-closed で拒否する。
- confirmed は「独立したクラス固有証拠（SGK-2026-0422 の Evidence Validator による署名済み verdict）」がある場合のみ生成できる。**confirmed 件数は成功条件にしない**。
- hidden retry、WAF mutation、cache 追従、自動リダイレクト追従は無効化し、注入された network client だけを利用する（SGK-2026-0421 の制約を踏襲）。

## 4. 評価正解・実装分岐の禁止

- Juice Shop の既知脆弱性、固有URL、固有payload、challenge を**評価の正解、判定基準、実装分岐に使わない**。
- 特定製品の製品名、既知URL、既知パス、フラグ、期待payload を runtime config・prompt・recipe・コード・session・report に組み込まない（SGK-2026-0420 / 0423 の漏洩防止規約を踏襲）。
- 仮説生成は capability / actor / trust boundary ベースの一般則（SGK-2026-0420）のみを使用する。

## 5. 広さ・深さ・確度・安全の記録契約

### 5.1 広さ（探索の広さの実測）

- capability（object r/w/d、auth/session/token、role/permission/ownership、state transition、file upload、external URL、render/store/template、async job/webhook、time/order 等）ごとに、**実際に観測できたもの**と**未到達のもの**を分けて記録する。
- actor、trust boundary ごとに観測到達率（到達 / 対象 / 未到達）を保存し、**未到達には理由コード**（予算枯渇、scope外、認証前提不足、観測源未接続、依存停止など）を付ける。
- 観測0件と未到達は区別し、未到達理由が残らない「観測なし」を認めない（SGK-2026-0420 の unavailable 記録に倣う）。

### 5.2 深さ（検証の深さの実測）

- candidate ごとに EvidenceVerdict（candidate / confirmed / refuted / untested）と NextAction（evidence gap、必要前提、action class、risk class、expected information gain、stop condition）を**同一ID系列で追跡**する（observation → hypothesis → attempt → evidence → verdict → next_action）。
- 証拠不足の candidate は evidence gap と NextAction を保存し、次の実行ターンで追跡可能にする。

### 5.3 確度（証拠品質）

- **独立したクラス固有証拠**（例: 認可境界をまたぐ応答差分 + 実レスポンス一致 + 反証条件の否定 など）がない candidate を confirmed に昇格しない。
- インフラ障害・タイムアウト・依存停止は refuted にしない（pending evidence gap として保持、SGK-2026-0421 踏襲）。
- 判定は正本 Evidence Validator（SGK-2026-0422）のみが行い、detector の confidence や status=completed では confirmed にしない。

### 5.4 安全（0件目標）

次の各項目を 0 件とすることを実行時の必須条件とし、違反検出時は即時停止（kill switch）する。

- scope逸脱（scope外 asset・method・OOB宛先・リダイレクト先）
- secret漏洩（Cookie、token、credential、認証値の session・report・log・checkpoint・例外への出力）
- 状態変更（GET 以外の method による副作用）
- 予算超過（request / follow-up / retry / 並列数 / 実行時間）
- 二重送信（idempotency 違反、同一 request の重複 dispatch）

## 6. 成果物と判定（実artifactで保存）

- 実行後の session、report（haddix separated 3ファイル+manifest）、holdout/実VDP評価結果、decision records、gate 結果を実artifactとして保存する。
- report/session consistency を公式 checker で検証し、**consistent** であることを保存する（鍵 registry 指定を含む本番相当の検証コマンド）。
- Go / Hold / No-Go を理由コード付きで decision record に保存する。実VDPの真の recall は測れないため、**確定件数や推測 recall を品質指標にしない**。

## 7. パイロットの終点

- 本パイロットの終点は **「M3a 継続」または「Hold」** のいずれかであり、**M4 への進級判断はしない**。
- M3b/M3c への進級や M4 判定は、本タスクの後続タスク（別起票）で、progression records と承認を得た上で実施する。
- 終点判定の根拠（実測の到達率、未到達理由、evidence gap、安全0件の確認、consistency 結果）を work report に保存する。

## 8. 実装ステップ（本ターンは計画作成のみ）

本ターンでは計画書の作成・採番・台帳更新のみを行い、**実装・外部サイトへの通信・Juice Shop・実VDP への通信・攻撃は一切行わない**。実行ターンで実施する手順は次のとおり。

1. SGK-2026-0425とSGK-2026-0426のstatus、0426が発行した `diagnostic_readiness`、artifact hashを検証し、Go以外なら通信せずHoldにする。
2. ユーザーに §2 の許可・scope・ProgramCapabilityMatrix・予算・kill switch を提示し、明示承認と固定を得る。
3. 実行前に設定・feature flag・read-only guard・budget・key registry の状態を検査し、M3a 以外が有効化されていないことを確認する。
4. 承認された scope 内で M3a 読み取り専用実行を行い、§5 の記録契約どおりに観測・検証・判定・安全記録を保存する。
5. report/session consistency と Go/Hold/No-Go を実artifactで検証・保存する。
6. work report / work log を作成し、判定（M3a 継続 or Hold）と根拠、未到達理由、evidence gap を記録する。

## 9. 完了条件

1. SGK-2026-0425とSGK-2026-0426がdoneで、0426が発行した `diagnostic_readiness=go` とartifact hashの整合が検証済みである。
2. 許可・scope・capability・予算・kill switch が実行前に固定済みである（本文書 §2 の全項目が承認記録と一致）。
3. M3a 読み取り専用（GET）以外の通信が 0 件である（fixture/対象アクセスログで確認）。
4. capability / actor / trust boundary ごとの観測到達率と未到達理由が保存済みである。
5. candidate ごとに EvidenceVerdict と NextAction が追跡可能である（同一ID系列で保存済み）。
6. 理由不明の confirmed、scope逸脱、secret漏洩、二重送信が 0 件である。
7. report/session consistency が consistent である（公式 checker の実artifact結果）。
8. 実行後の判定が「M3a 継続」または「Hold」として根拠付きで保存済みである。
9. M3b / M3c / M4 は未実施である（feature flag 未有効化・実行記録なし）。

## 10. NOT in scope

- POST / PUT / PATCH / DELETE、状態変更、HITL状態変更（M3b）、Chain検証（M3c）、全面enforce（M4）。
- Juice Shop その他の特定製品の既知脆弱性・固有URL・固有payload・challenge の利用。
- confirmed 件数を成功指標にする運用、閾値・証拠条件の緩和。
- 許可のない破壊的操作、第三者データ取得、永続的状態変更、scope外 OOB。
- 新しい外部スキャナや依存ライブラリの追加。
- 実装責任者、要員配置、工数見積り。

## 11. 引き継ぎ事項（SGK-2026-0423 deferred の受領）

SGK-2026-0423 の work report deferred_tasks（D01: 実VDPまたは承認済み評価データセットでのM4全面運用検証、D02: WALとcheckpointの多重喪失時のwrite-ahead保証強化）は、本タスクの tracking 対象として引き継ぐ。

- D01 は本タスクの M3a パイロット結果を踏まえた後続判断（M3b/M3c/M4 進級は別起票）の材料とする。
- D02 は本パイロットの安全境界（二重送信防止）の運用確認に利用し、journal 化は本タスクの後続タスクの対象とする。
