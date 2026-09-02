---
task_id: SGK-2026-0466
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/roadmaps/2026-08-12_sgk-2026-0442_confirmation-and-candidate-lifecycle-program.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0452_safe-sqli-impact-demonstration.md
- docs/shigoku/plans/done/2026-08-16_sgk-2026-0453_sqli-impact-demonstration-defense-evasion.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification_work_report.md
- docs/shigoku/worklogs/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification_work_log.md
created_at: '2026-09-01'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- sqli
- sealed-run
target: (検証のみ・コード変更なし)
---

# 実装計画: SGK-2026-0466 — SQLi の live confirmed=1 を現行コードベースで再実証（検証タスク・コード変更なし）

（親ロードマップ: SGK-2026-0442。SGK-2026-0452 で SQLi は本物 Juice Shop で live confirmed=1 を達成済み（2026-08-16）。その後 SGK-2026-0460 の横断状態隔離、SGK-2026-0464 の候補重複排除、および保存型XSS一連（0454〜0463）の変更が入った。本タスクは「これらの変更後の現行コードベースでも SQLi が `hybrid_final_state=confirmed` に到達するか」を、フルパイプライン実走行で事実確認する。到達すれば能力マップ SGK-2026-0465 の SQLi を ○→◎ に昇格する。）

## 目的

- 現行コードベースで SQLi が **live confirmed=1** に到達することを、本物 Caido(8081) 経由・本物 Juice Shop(3000)・GET-only の封印 run で再実証する。
- 到達する場合: 能力マップ SGK-2026-0465 の SQLi を ○（配線済み）→ ◎（本物の証拠付きで確定まで実証済み）へ昇格。
- 到達しない場合: 最初の停止点（候補止まり／検出前／judge）を事実で切り分け、追跡タスクへ deferred（本計画では NOT in scope）。

## NOT in scope（明示）

- 確定バーの変更（`payout_grade.py` / `sealed_reproduction_checker.py` / poc_judge プロンプト / `finding_validator.py` / `task_queue.py` PCR-P1）。
- 検出・確定ロジックのコード変更（本タスクは検証のみ。変更が必要と判明したら別タスク起票）。
- `t3_hybrid_enabled` の既定値変更（SQLi 確定が実行時フラグ `SHIGOKU_T3_HYBRID_ENABLED=1` を要する点は、全確定 run 共通の運用モードであり本タスクの阻害事項にしない。ポリシー変更を望む場合は別タスク）。
- 候補ノイズ（CORS 76 件等）の是正。SQLi と無関係の既知 safe-hold。
- 次ターゲット（IDOR・オープンリダイレクト）。

## 完了条件（完了契約 — 固定）

1. 本物 Caido(8081) 経由・本物 Juice Shop(3000)・GET-only の封印 run を実行し、preflight（Caido identity + 転送検証）が PASS すること（偽プロキシに当たっていないこと= SGK-2026-0447 の false-negative 罠回避）。
2. SQLi finding が現行の確定パイプラインで **Current=confirmed**（`hybrid_final_state=confirmed`）に到達し、report Confirmed に計上されること。
3. 確定 SQLi finding の証拠が本物かつ安全: error(500 SQLITE_ERROR) ＋ boolean 差分オラクル ＋ 非機微 `sqlite_version()` 抽出のみ。**機微データ（資格情報・メール・PII）抽出 0**。GET-only。
4. `verify_report_session_consistency.py` が status=consistent / rerun_required=false。
5. 確定バー無改変（本タスクはコード変更なしのため git diff で自明に担保）。
6. ドキュメント整合: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー。

## 実施結果（2026-09-01・Claude 実走行・独立検証）

### 実走行レシピ（本物 Caido・本物 Juice Shop・GET-only）

```
SHIGOKU_SCAN__PROXY=http://127.0.0.1:8081 \
SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 \
SHIGOKU_DIAGNOSTICS__ENABLED=true \
SHIGOKU_SEALED_RUN_GET_ONLY=1 \
SHIGOKU_T3_HYBRID_ENABLED=1 \
SHIGOKU_SQLI_FIRING_PATH_ENABLED=1 \
SHIGOKU_SQLI_IMPACT_PROBE_ENABLED=1 \
.venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest
```

各 run 前に candidate_ledger を退避（T3 ライフサイクルの新規判定を保証）。preflight PASS（Caido identity + 転送検証。転送検証は Juice Shop SPA の index.html 由来で「9393B 同一 200」を warning 表示するが、手動プローブで `/rest/products/search?q=` がパス依存の本物商品 JSON を返すことを事前確認済＝本物の転送プロキシ）。

### run 1（`T3_HYBRID_ENABLED` 未設定 = 誤設定）: SQLi は candidate 止まり

- report `haddix_report_20260901_024452.md` / session `session_20260901_024451.json`。consistency=consistent。
- SQLi は発火（`q=apple'`→500 SQLITE_ERROR）し impact probe も実行（session に ORDER BY 210 / sqlite_version 111 / UNION SELECT 66 / boolean AND 1=1・1=2 各 42）。だが finding は **candidate**（reason `insufficient_validation`）。ledger は XSS のみ、`hybrid_final_state=confirmed` は 4 件すべて XSS、poc_judge 起動は 1 回のみ。
- **真因（コード回帰ではなく運用設定の欠落）**: SQLi の確定は T3 hybrid pass を要し、これは `settings.t3_hybrid_enabled`（既定 False・`manager.py:1107-1115`）でゲートされる。run 1 では `SHIGOKU_T3_HYBRID_ENABLED=1` を付け忘れた。XSS は `t3_hybrid_browser_evidence_auto=True`（`settings.py:664`）により browser_evidence finding のみ T3 が自動起動するため確定したが、SQLi(real_http) は明示フラグが必要。この取り違えは `docs/shigoku/learnings.md:690` の既存 lesson が想定する事象そのもの（「配線再実装の前に `t3_hybrid_enabled` ゲートだけ確認せよ」）。

### run 2（`T3_HYBRID_ENABLED=1` 設定・レシピ以外同一）: SQLi confirmed ✅

- report `haddix_report_20260901_061505.md` / session `session_20260901_061502.json`。
- **consistency=consistent / rerun_required=false**（`verify_report_session_consistency.py`）。
- Findings by Vulnerability Class: **sqli = 2 confirmed / 2 candidate**（xss = 1 confirmed）。
- ライフサイクル表: 「SQL Injection in parameter 'q'」= **Current=confirmed / Shadow=confirmed**（real_http）、「... 'data'」= **Current=confirmed**。＝確定パイプライン（T3 hybrid pass: poc_judge + payout_grade + sealed_reproduction）が real_http 証拠で正当に confirmed（browser_evidence enforce スコープとは独立）。
- 確定 SQLi(param 'q') の証拠（本物・安全）: error-based（`q=1'`→500 SQL エラー）＋ boolean 差分（`q=1')) OR 1=1 --`→200/body_len=200 vs `OR 1=2 --`→200/rows=0/body_len=30 の決定的差分）＋ 非機微抽出（`sqlite_version()`→`3.44.2` が応答本文に出現＝サーバメタ情報の情報漏えい実証）。すべて GET。
- **安全境界 PASS**: session 内 SQLi finding オブジェクト全数で機微パターン（password/email/hash/PII）ヒット 0（172 個中 0・うち 100 個が sqlite_version 抽出を保持）。抽出は非機微 `sqlite_version()` のみ。機微データは一切抽出していない。
- GET-only: session の request_method は GET 2041 / POST 10（POST は Caido /graphql identity プローブ等の非攻撃インフラ通信。SQLi finding の payload はすべて GET）。

### 完了判定（§19）

- 完了条件 1〜6 すべて PASS。`in_scope_blocker` 0 件。→ **SGK-2026-0466 done**。
- コード変更 0（確定バー無改変は自明）。カーブフィッティング/能力矮小化なし（0452 の汎用実証機構をそのまま現行コードで再実証）。
- 能力マップ SGK-2026-0465: SQLi ○ → **◎**（本物の証拠付きで確定まで実証済み・確定2件・variant=error/boolean/version）へ昇格。
- `deferred_followup`（非阻害・追跡任意）:
  - SGK-2026-0442 配下: SQLi 確定が実行時 `SHIGOKU_T3_HYBRID_ENABLED=1` を要する運用モード（全確定 run 共通）。XSS の browser_evidence 自動確定と揃えて「SQLi も既定で確定させる」ポリシーにするかは別途検討（`t3_hybrid_enabled` 既定・shadow-hold ポリシーに関わる設計判断）。
  - 候補 CORS 76 件の safe-hold ノイズは SQLi と無関係の既知事象。

## 参照ルール

`rules/task-ledger.md` / `rules/lessons.md`（特に 2026-08 の SGK-0447 real-target/forwarding lesson と「一ファイルを spec 扱いしない」lesson）/ `rules/shigoku-docs.md`。実走行レシピの正本は SGK-2026-0447 / 0452 / 0453 / 0457 各計画書。
