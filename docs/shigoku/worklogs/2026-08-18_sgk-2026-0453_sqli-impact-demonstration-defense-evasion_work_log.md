---
task_id: SGK-2026-0453
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-08-16_sgk-2026-0453_sqli-impact-demonstration-defense-evasion.md
- docs/shigoku/reports/2026-08-18_sgk-2026-0453_sqli-impact-demonstration-defense-evasion_work_report.md
created_at: '2026-08-18'
updated_at: '2026-08-18'
tags:
- shigoku
- vdp
- security-sensitive
- detection
- confirmation
- sealed-run
---

# SGK-2026-0453 作業ログ — SQLi実害実証・防御ありの相手への対応（D02・Ver.1）

## 進行順
1. 設計討議: 自律型ハンターの理想像を確認。案A（決定的すり抜け道具箱）=Ver.1、案B（自律再優先付け）=Ver.2 と合意。Ver.2 を見据えた拡張性のある Ver.1 実装を条件化。
2. 採番・計画: SGK-2026-0453 / DOC-0508 登記、計画書作成、`validate_shigoku_docs.py` 0エラー。
3. フェーズ0（設計）: DeepSeek 提出を独立検証。初回は計画書未反映＋行番号ずれで差し戻し。再提出で実コード一致を確認し承認。
4. STEP 2（機構＋単体）: 決定的モジュール実装。バー diff0・製品非依存 token0・27件 pass・既定OFFバイト等価・拡張点あり・回帰なしを検証。既存失敗の開示漏れ（4件中3件未開示）は git stash で全件 HEAD 由来と確認。
5. STEP 3（実地e2e）: 本物の確定1件を独立検証。2つの綻び（確定成果物に最終段階記録なし・計器オン run が未確定）を honest に開示。
6. STEP 4（診断）: 「計器オンが攻撃経路を変える」主仮説をコード＋実データで否定。confirmed=0 は既確定 finding の再判定スキップ（正常）と判明。ただし DeepSeek の10回比較は既確定台帳上のため安定度を測れていない穴を指摘。
7. STEP 5（正直な実測）: まっさら台帳＋計器オン×5回。確定 4/5・回避起動 5/5・未確定1回は正当却下のみ。正本 `session_20260818_001905` に確定＋最終段階記録の同居を独立確認。consistency=consistent。
8. 完了処理: 計画書 done 化・done/ 移動、記録簿/一覧更新、作業報告・ログ作成。

## 重要な判断
- 再実行で当たりを引く/当たりだけ拾う行為は proxy gaming として一貫して不採用。安定度は全数正直報告で測定。
- バーは終始無改変（個別 diff0）。追加機能は既定OFF・バイト等価。
- 判定は狩り側でなく独立3条件の門。AI は将来も有限の汎用語彙内での並べ替えのみ（製品非依存を保つ設計）。

## 検証コマンド（実行済み）
- `verify_report_session_consistency.py --report <正本abs>` → consistent / rerun_required=false
- `check_vdp_product_independence.py ...` → pass / token 0
- バー5点 個別 `git diff --quiet HEAD -- <file>` → exit0
- `.venv/bin/pytest tests/unit/test_sqli_evasion.py tests/unit/test_vdp_filtered_search_app.py` → 27 passed
- `validate_shigoku_docs.py` → 0エラー
