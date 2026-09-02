---
task_id: SGK-2026-0466
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification.md
- docs/shigoku/reports/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
created_at: '2026-09-01'
updated_at: '2026-09-03'
tags:
- shigoku
- vdp
- detection
- confirmation
- sqli
---

# SGK-2026-0466 作業ログ — SQLi live confirmed=1 再実証

## 1. 事実調査（コード変更前）

- 台帳/レジストリ確認 → 次 ID = SGK-2026-0466（親 SGK-2026-0442）。
- 過去到達点: SGK-2026-0452 で SQLi は Juice Shop に対し live confirmed=1 達成（session_20260816_223550）。SGK-2026-0453 で防御あり fixture(18080) でも confirmed。確定パス（error marker → boolean → 非機微 version 抽出 → poc_judge → 3条件AND → hybrid_final_state=confirmed）は実装済。
- 環境確認: Caido 8081 UP（本物・転送プロキシ確認: `/rest/products/search?q=` がパス依存の本物商品 JSON を返す）/ Juice Shop 3000 UP。
- 実走行レシピ正本: SGK-2026-0447（本物 Caido 転送検証）・0452（SQLi impact probe フラグ）・0457（T3 フラグ）。

## 2. 実走行（run 1・T3 フラグ未設定）

```
$ env -C <repo> SHIGOKU_SCAN__PROXY=http://127.0.0.1:8081 SHIGOKU_CAIDO__URL=http://127.0.0.1:8081 \
  SHIGOKU_DIAGNOSTICS__ENABLED=true SHIGOKU_SEALED_RUN_GET_ONLY=1 \
  SHIGOKU_SQLI_FIRING_PATH_ENABLED=1 SHIGOKU_SQLI_IMPACT_PROBE_ENABLED=1 \
  .venv/bin/python -m src.main --target http://localhost:3000 --mode vulntest
EXIT=0（約1524s）
```

- report `haddix_report_20260901_024452.md` / session `session_20260901_024451.json`。consistency=consistent。
- 観測: SQLi 発火（`q=apple'`→500 SQLITE_ERROR）・impact probe 実行（session: ORDER BY 210 / sqlite_version 111 / UNION SELECT 66 / AND 1=1・1=2 各 42）。だが finding=candidate（`insufficient_validation`）。ledger は XSS のみ・poc_judge 1回のみ・hybrid_final_state=confirmed は全て XSS。
- 切り分け: `rg t3_hybrid_enabled|_t3_hybrid_active src/core/agents/swarm/injection/manager.py src/core/config/settings.py` →
  `settings.t3_hybrid_enabled=False`（settings.py:659・既定OFF）/ `_t3_hybrid_active`（manager.py:1107-1115）/ `t3_hybrid_browser_evidence_auto=True`（settings.py:664）。
  → run 1 は `SHIGOKU_T3_HYBRID_ENABLED=1` の付け忘れ。learnings.md:690 の lesson に合致。

## 3. 実走行（run 2・T3 フラグ設定・他同一）

```
$ env -C <repo> ...（上記に加え） SHIGOKU_T3_HYBRID_ENABLED=1 ... --target http://localhost:3000 --mode vulntest
EXIT=0
```

- report `haddix_report_20260901_061505.md` / session `session_20260901_061502.json`。
- `python3 scripts/verify_report_session_consistency.py --report <run2>` → **consistent / rerun_required=false**。
- Findings by Vulnerability Class: sqli = **2 confirmed** / 2 candidate。
- ライフサイクル表: SQL Injection 'q' = Current=confirmed/Shadow=confirmed（real_http）、'data' = Current=confirmed。
- 確定 'q' 証拠: error(500) ＋ boolean（OR 1=1→body_len=200 / OR 1=2→rows=0,len=30）＋ `sqlite_version()`=3.44.2 出現。全 GET。
- 安全境界: session 全 SQLi finding で機微パターンヒット 0（172/0・うち 100 が sqlite_version 保持）。

## 4. ドキュメント整合

```
$ .venv/bin/python scripts/sync_shigoku_updated_at.py
$ python3 scripts/validate_shigoku_docs.py --repo-root .
（0 エラーを確認）
```

## 5. 参照ルール

`rules/task-ledger.md` / `rules/lessons.md` / `rules/shigoku-docs.md`。
