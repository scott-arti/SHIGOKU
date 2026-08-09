---
task_id: SGK-2026-0437
doc_type: plan
status: done
parent_task_id: SGK-2026-0433
related_docs:
- docs/shigoku/plans/done/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_plan.md
- docs/shigoku/reports/2026-08-08_sgk-2026-0433_m3a-gap-closure-capability_work_report.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0436_timing-live-acquisition-and-harness-ownership_plan.md
- docs/shigoku/plans/2026-08-08_sgk-2026-0435_preflight-docs-artifact-token-scan.md
created_at: '2026-08-10'
updated_at: '2026-08-10'
tags:
- shigoku
- anti-curve-fitting
target: tests/fixtures/vdp_juiceshop_sealed + workspace/projects/localhost:3000
---

# 実装計画: 封印ローカルターゲットでの authz gap-closure エンドツーエンド実証（SGK-2026-0437）

SGK-2026-0433 で実装した第2アカウント authz 比較能力を、封印 m3a run で
**end-to-end に実証**する。狙いは「簡単な権限系脆弱性を SHIGOKU が実際に
confirmed にできるか」を honest に確かめることであり、**confirmed を無理に作らない**。

## 1. 3つの正直な帰結（判定契約）

- **(I) E2E 成立**: B が A の private resource にアクセス → Evidence Validator が
  confirmed（越境の実証）。`authz_impact_proven` / `semantic_diff_observed` が
  truthy で confirmed verdict が生成される。
- **(II) 能力は動いたが越境なし**: 比較は実行（attempts>0）だが到達 endpoint に
  破れなし → 広さ不足を診断（`second_account_compared=true` だが
  `owner_record_accessible_to_non_owner=false`）。
- **(III) 能力が動かない**: auth-setup 失敗 / 比較未実行 → 回帰・欠陥として特定
  （attempts=0、`follow_up_enqueue_failed` 等）。

**confirmed 件数は成功指標にしない**。比較が実行され独立証拠が記録されたことが
成功の基準（0433 計画 §完了条件3 と同一）。

## 2. 死守する枠（エンベロープ・0433 と同一）

- **封印ローカルのみ**: 使い捨てローカルコンテナ（loopback / sealed net /
  既存 run_m5_audit.sh harness）。実VDP（外部）は対象外。
- **auth-setup POST は A/B register/login だけ**: AuthSetupGuard の allowlist
  （config 由来）のみ。それ以外の POST/PUT/PATCH/DELETE・状態変更は fail-closed。
- **攻撃は GET のみ**: m3a read-only。注入・状態変更なし。
- **実行1回**: single-run guard（marker）で1 eval version = 1 run。
- **snapshot 復元**: config/shigoku.yaml と runtime surface を byte-exact 復元。
- **安全0**: 許可外状態変更・secret漏洩・scope逸脱・予算超過・二重送信 0 件。
- **PCR-P1 無改変**: task_queue.py の diff 0 行。
- **docs opaque**: endpoint/product 名を report/worklog に書かない
  （0435 が deferred のため手動 redaction で守る）。
- **harness 所有権**: main runner に `--user "$(id -u):$(id -g)"` を付与し、
  成果物を bbb 読取可にする（0436 の恒久対策を本 run で適用）。

## 3. 反 curve-fitting 規約

- 特定既知脆弱性・固有URL・固有payload・challenge を評価正解・実装分岐に使わない。
- 仮説生成は capability / actor / trust boundary ベースの一般則のみ
  （object-ownership / authz 推論）。
- 閾値・Evidence Validator・marker 語彙は一切変更しない。
- confirmed 件数を指標にしない。

## 4. 実行手順

1. preflight: env file（0600）・target 稼働・marker 不在・PCR-P1 clean を確認。
2. harness 所有権 fix（main runner に --user）を適用・bash -n 検証。
3. 封印 m3a run を1回実行（M5_TIMEOUT 内）。
4. 新 session を特定し、authz 比較 evidence を抽出 → (I)/(II)/(III) 判定。
5. 検証: secret redaction / PCR-P1 diff / preflight exit 0 / validator 0 /
   §8 consistency gate。
6. work report / work log 作成、registry 更新、docs validator 0。

## 5. 完了条件

1. 封印 run が1回実行され、新 session が生成される。
2. authz 比較 evidence（`second_account_compared` / `cross_account_compared` /
   `account_a_status` / `account_b_status` / `owner_record_accessible_to_non_owner` /
   `sensitive_fields_shared_with_non_owner`）が session から抽出できる。
3. (I)/(II)/(III) のいずれかに honest に判定され、根拠が記録される。
4. 安全0件 / PCR-P1 無改変 / preflight exit 0 / validator 0 / consistency consistent。
5. 成果物が bbb 読取可（--user 適用）。
6. docs opaque（endpoint/product 名を report/worklog に書かない）。

## 6. NOT in scope

- 実VDP（外部）への通信・auth-setup 以外の POST・m3b/m3c/m4・全面 enforce。
- Evidence Validator / 証拠条件 / 閾値の緩和。confirmed 件数の指標化。
- 製品固有の既知脆弱性・固有URL・固有アカウント・payload・challenge の利用。
- 新規外部スキャナ/依存の追加。
- 0435（docs token-scan 恒久対策）・0436（timing ライブ取得）の本実装
  （本タスクは所有権 fix の適用と run 実証のみ。timing は対象外）。

## 参照

- SGK-2026-0433（第2アカウント authz 比較・タイミング基盤の実装）。
- SGK-2026-0432（(H) authz / (C) timing の gap 診断）。
- SGK-2026-0422（Evidence Validator）、0421（read-only guard）、0419（capability matrix）。