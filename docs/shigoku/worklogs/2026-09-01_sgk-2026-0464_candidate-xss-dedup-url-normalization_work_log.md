---
task_id: SGK-2026-0464
doc_type: work_log
status: done
created_at: '2026-09-01'
updated_at: '2026-09-01'
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-01_sgk-2026-0464_candidate-xss-dedup-url-normalization.md
- docs/shigoku/reports/2026-09-01_sgk-2026-0464_candidate-xss-dedup-url-normalization_work_report.md
---

# SGK-2026-0464 作業ログ

- session_20260901_005406 の候補189件を分解 → 生finding768件・distinct署名 `(host,path,param,vuln)` は2のみ（comment/name）・distinct生URL94。他ターゲット混入なし（0460隔離健全）。
- 真因特定: `haddix_formatter._candidate_dedup_key` は authz/cors/csrf のみ署名を返し XSS 等は `None` → 未重複排除。候補URLは内部メタキー＋注入payloadで汚染。confirmed 側 `_confirmed_dedup_key` は同型署名で確定を1に収束していた。
- 実装: `_candidate_dedup_key` に injection/reflected 系の root-cause 署名分岐を追加（reporting層のみ・最小）。
- 検証: 実セッション再生成で修正なし189/修正あり1（Confirmed1不変）を忠実性込みで確認。DVWA session 再生成は with/without が 9/6 で完全一致（中立）。
- funnel テスト2件が同一署名 F1/F2 のマージで失敗 → フィクスチャを別エンドポイントへ（意図保持・盲目的パスにあらず）。新規 dedup テスト3件追加。
- reporting 1093 passed・新規3 passed・バー無改変・token0・docs 0エラー。
- ユーザー指示によりコミット（ブランチ feat/stored-xss-confirm-sgk-0459-0463）。push はユーザー。
