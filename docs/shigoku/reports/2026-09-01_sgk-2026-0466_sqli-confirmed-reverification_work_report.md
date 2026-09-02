---
task_id: SGK-2026-0466
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification.md
- docs/shigoku/worklogs/2026-09-01_sgk-2026-0466_sqli-confirmed-reverification_work_log.md
- docs/shigoku/plans/done/2026-08-15_sgk-2026-0452_safe-sqli-impact-demonstration.md
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

# SGK-2026-0466 作業完了報告 — SQLi live confirmed=1 の現行コードベース再実証

## 何をしたか / なぜ

SGK-2026-0452 で SQLi は本物 Juice Shop に対し live confirmed=1 を達成済み（2026-08-16）。その後に横断状態隔離（SGK-2026-0460）・候補重複排除（SGK-2026-0464）・保存型XSS一連（0454〜0463）の変更が入ったため、「現行コードベースでも SQLi が確定に到達するか」を事実確認する必要があった。コード変更は行わず、フルパイプライン実走行での再実証のみを実施した。

## 結果（確定）

- **現行コードベースで SQLi は genuine confirmed に到達**（確定 2 件: param `q` と `data`）。report `haddix_report_20260901_061505.md` / session `session_20260901_061502.json`。
- `verify_report_session_consistency.py`: **status=consistent / rerun_required=false**。
- 証拠は本物かつ安全: error(500 SQLITE_ERROR) ＋ boolean 差分オラクル ＋ 非機微 `sqlite_version()`=`3.44.2` 抽出。**機微データ抽出 0**（session の SQLi finding 全数で password/email/hash/PII ヒット 0）。GET-only。
- **コード変更 0** → 確定バー 5 ファイル無改変は自明。

## 経緯（run 1 → run 2）

- run 1（`SHIGOKU_T3_HYBRID_ENABLED=1` 未設定）: SQLi は発火＋impact probe 実行まで到達したが **candidate 止まり**（`insufficient_validation`）。ledger は XSS のみ、poc_judge 1 回のみ。
- 真因: SQLi 確定は T3 hybrid pass を要し `settings.t3_hybrid_enabled`（既定 False）でゲートされる。run 1 は当該フラグを付け忘れた運用ミス（コード回帰ではない）。`learnings.md:690` の既存 lesson が想定するケースそのもの。XSS は `t3_hybrid_browser_evidence_auto=True` で自動確定するため影響を受けなかった。
- run 2（フラグ設定・他同一）: SQLi confirmed に到達。

## 検証（実行したコマンドと観測結果）

- 実走行: 上記レシピで `--target http://localhost:3000 --mode vulntest`（本物 Caido 8081 経由・GET-only）。preflight PASSED。
- 整合ゲート: `python3 scripts/verify_report_session_consistency.py --report <run2 report>` → consistent / rerun_required=false。
- 安全境界: session の全 SQLi finding オブジェクトを走査し機微パターンヒット 0 を確認。
- ドキュメント: `sync_shigoku_updated_at.py` → `validate_shigoku_docs.py` 0 エラー（本報告時点で実施）。

## リスク

- なし（コード変更なし）。実走行は workspace の実行成果物（session/report/candidate_ledger/ROI db/learned_params）を更新するが、これは正常な run の副作用でありコミット対象にしない。

## 次の一手

- 能力マップ SGK-2026-0465 の SQLi を ○→◎ に昇格（本タスクで実施）。
- 次ターゲットは IDOR（別アカウント差分の証拠づくり）。

## deferred_tasks

```yaml
deferred_tasks:
  - summary: "SQLi 確定が実行時 SHIGOKU_T3_HYBRID_ENABLED=1 を要する運用モード。XSS の browser_evidence 自動確定と揃え『SQLi も既定で確定』とするかは t3_hybrid_enabled 既定・shadow-hold ポリシーに関わる設計判断。"
    tracking_task_id: SGK-2026-0442
    blocking: false
  - summary: "候補 CORS 76 件の safe-hold ノイズ（SQLi と無関係の既知事象）。"
    tracking_task_id: SGK-2026-0442
    blocking: false
```
