---
task_id: SGK-2026-0456
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-20_sgk-2026-0455_dom-xss-confirmation-routing.md
- docs/shigoku/plans/done/2026-08-18_sgk-2026-0454_xss-dom-runtime-firing-path.md
- docs/shigoku/reports/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path_work_report.md
- docs/shigoku/worklogs/2026-08-21_sgk-2026-0456_xss-dom-fragment-firing-path_work_log.md
created_at: '2026-08-21'
updated_at: '2026-08-22'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- xss
- dom
- browser
- firing-path
---

# SGK-2026-0456 計画書 — DOM XSS の発火経路をフラグメント(hash)クライアント側ソースへ拡張

## 目的（Objective）

SmartXSSHunter の DOM 検証が **サーバ側クエリ URL**（例 `/search?q=...&name=<payload>`）に payload を置くため、SPA（クライアント側ルーティング）で実際に発火する **URL フラグメント（`#/...`）経由の DOM sink** に payload が届かず、`dialog_observed=true`（実 alert 発火）の finding を生成できない。結果、確定経路（SGK-2026-0455 で完成済み）に「本物の発火証拠」を持つ finding が流れず C1（confirmed>=1）に到達しない。本タスクは、DOM 検証の候補 URL 構築を **フラグメント(hash)をクライアント側 DOM ソースとして扱う形へ製品非依存に拡張**し、実発火 finding を生成して 0455 の確定経路で confirmed に到達させる。

## 背景・根拠（SGK-2026-0455 実走行で判明・2026-08-21）

0455 の確定経路（reproduction DOM 経路＋resurrection＋poc_judge への実発火証拠可視化）は実装・独立検証済みで、resurrection は実走行で実動作（旧 parked XSS が `resurrection_count=1` で復活）を確認した。しかし2回の実走行（`session_20260821_012307` / `_073040` ほか）の**全 XSS finding が `dialog_observed=None`・`dom_mutation_observed=true`・`event=dom_sink_reflection`** で、実 alert 発火の finding はゼロだった。poc_judge が `ai_no_prize_grade` で却下し reproduction 未到達。これは**正しい保守判定**（DOM 書換のみ＝コード実行の証明ではない）。

Claude の直接ブラウザ検証（`PlaywrightValidator.validate_xss_sync`）で発火点を切り分け:

| テスト URL | dialog 発火 |
|---|---|
| `http://localhost:3000/#/search?q=<iframe src="javascript:alert(\`xss\`)">` | True |
| `http://localhost:3000/#/search?q=<img src=x onerror=alert(1)>` | True |
| `http://localhost:3000/search?q=test&name=<img src=x onerror=alert(1)>`（ハンターが実際に叩いた形） | False |

→ **アプリは本物の発火 DOM XSS を持つ（フラグメントルート）が、ハンターがサーバ側クエリを叩いていて発火点に届いていない**。C1 未達の真因はこの上流の発火経路であり、0455 の確定経路の欠陥ではない。

## フェーズ0（診断・実装前の必須ゲート）

1. `smart_xss.py`（および 0454 で是正した DOM 検証呼び出し）で、DOM 検証に渡す候補 URL がどこで構築されるか（所有コード・呼び出し元）を引用特定する。lessons: 一ファイルの挙動を仕様と断定しない。
2. フラグメント(hash)を DOM ソースとして扱う候補生成が **製品非依存**（`#/search` 等のルートを焼き込まない・recon で得たルート／一般的な hash 注入から導出）であることを設計で担保。カーブフィッティング禁止。
3. 反射型・サーバ側 XSS の既存経路を退行させないこと（フラグメント候補は**追加**であって置換ではない）。
→ フェーズ0を提出しレビュー承認後に実装へ。

## 完了契約（Fixed completion criteria）

- C1: Juice Shop の DOM XSS が、Caido(8081) 経由の実走行で **`dialog_observed=true` の finding として生成**され、SGK-2026-0455 の確定経路を通って **confirmed=1件以上** になる。正本 session/report を残し、`verify_report_session_consistency`（または shigoku-ops）が `consistent`/`rerun_required=false`。
- C2: フラグメント候補生成は **製品非依存**（`check_vdp_product_independence.py` verdict=pass・token0、特定ルートの焼き込み禁止）。偽陽性を作らない（発火しない候補は `dialog_observed` を付けない＝従来どおり）。
- C3: 反射型・サーバ側 XSS の既存検出経路は退行なし（既存テスト緑・byte-identical でなくとも結果不変）。
- C4: SGK-2026-0455 の確定バーは**無改変**（`payout_grade.py`/`poc_judge.md`/`task_queue.py`/`finding_validator.py` の判定ルール本体、および `sealed_reproduction_checker.py` の判定基準を変えない）。本タスクは検出（発火経路）側のみ。
- C5: 新規/変更ユニットテスト全 pass。HEAD 既知失敗（`test_validate_xss_success`・`test_pool_exhaustion_handling`）以外に本変更由来の新規失敗なし。

## 必須テスト（Required tests）

- T1: フラグメント(hash)候補生成が、payload を `#/...` フラグメントに配置した URL を生成すること（ユニット・製品非依存: 任意のルートで動く）。
- T2: フラグメント URL で `PlaywrightValidator` が実 dialog を観測した場合に `dialog_observed=true` を持つ browser_execution を finding に付与すること（ユニット、playwright stub 注入）。発火しない場合は `dialog_observed` を付けない（偽陽性回帰）。
- T3: e2e で Juice Shop の DOM XSS が `dialog_observed=true` finding として生成され、0455 経路で confirmed=1・整合 consistent（Caido 8081・実走行）。

## NOT in scope

- SGK-2026-0455 の確定経路の再設計（完成済み）。確定バーの変更。
- Stored/POST XSS の網羅、他種検出の追加。
- 特定製品ルート（`#/search` 等）のハードコード（製品非依存を維持）。

## 実装計画（承認後・実装は DeepSeek / 独立検証は Claude）

- 実装: DOM 検証の候補 URL 構築に「フラグメント(hash)へ payload を配置する形」を追加（製品非依存）。実 dialog 観測時のみ `dialog_observed=true` を browser_execution に記録。
- 独立検証（Claude）: フェーズ0引用確認 → T1/T2/T3 ユニット → 実走行（Caido 8081・`SHIGOKU_T3_HYBRID_ENABLED=1`）で `dialog_observed=true` finding 生成 → 0455 経路で confirmed=1 → 整合 consistent → 製品非依存 pass/token0 → ledger 遷移確認。DeepSeek 報告は額面で信用せず実 session/report と ledger を Claude が直接確認。

## ガードレール

- カーブフィッティング禁止・確定基準を下げない・製品非依存維持。GET 中心の境界・機微データ抽出禁止・秘密の生値を成果物に残さない。
- Caido = 127.0.0.1:8081（8080 は SearXNG）。Juice Shop = http://localhost:3000。
- commit は検証後、push はユーザー。
