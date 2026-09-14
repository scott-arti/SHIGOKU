---
task_id: SGK-2026-0493
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0493_subdomain-takeover-detection.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0493_subdomain-takeover-detection_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- subdomain-takeover
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0493 作業ログ（Subdomain Takeover・◯・非破壊フィンガープリント）

## 1. 方針確認（ユーザー質問→指示）
- ユーザー質問「takeover はどう証明？取れるか判断つかなくない？」に対し、証明は2段階（①非破壊
  フィンガープリント検出＝◯／②実際に claim して奪取＝◎だが破壊的・スコープ外）と回答。
- ユーザー指示「まず機能として◯・チェックは当面手動でよい」→ ◯（非破壊検出）で整備。

## 2. 偵察（事実優先・実測）
- 既存資産: takeover_provider_matrix.yaml(S3/GitHub Pages/Heroku/Azure・実fingerprint+error_tokens)、
  takeover_provider_matrix_adapter(Loader/find_by_fingerprint_domain/find_by_error_token)、subzy/subjack。
  swarm未配線・Finding化なし。
- 実測: 実GitHub Pages未登録<rand>.github.io→"There isn't a GitHub Pages site here"(実error_token)確認。
  dnspython未導入→CNAMEはbest-effort(host/recon cname代用)。

## 3. 台帳・計画・承認
- SGK-2026-0493採番(registry.yaml・DOC-0563)。◯(非破壊)で確定バー未改変の方針。

## 4. 実装(Claude直接)
- finding.py: VulnType.SUBDOMAIN_TAKEOVER追加。
- smart_subdomain_takeover(新規): matrixロード→host/cnameをfingerprint_domain照合+取得本文をerror_token
  照合→error_token一致で候補Finding(0.9=CNAME委譲一致/0.6=サインのみ・fp_twin注意)。_client seam・
  error_token中心スニペット・subdomain_takeover_evidence(grade=candidate・claim_prerequisites/
  verification_urls=手動claim経路)。非破壊GETのみ。製品固有ハードコードなし。
- 確定バー/再現チェッカー: 改変なし(◯候補はpayout_grade非発火)。

## 5. 独立検証(Claude・実出力)
- 実GitHub Pages未登録サブドメインでexecute→provider=github_pages・error_token一致・cname_match=True・
  confidence0.9・grade=candidate・verification_urls付き(非破壊)。◯実証(人手claimで◎化=当面手動)。
- 新規6テスト緑(高確度/中確度/recon cname/非検出/候補はpayout非発火/複数サブドメイン)。非回帰:
  injection 842 passed・失敗1はHEADでも失敗の既存(t3_hybrid budget)=0493起因の回帰ゼロ。
- 凍結5すべてexit0(確定バー未改変)。製品token0・whitespace0・秘密値非露出。

## 6. 完了
- 完了条件1〜4充足。in_scope_blocker 0 → done。
- 能力マップ: Subdomain Takeover ○ 追加(◎は破壊的claim=人手・別途)+高度化 低(L1)。
- 教訓: (1) takeover の◎は破壊的奪取が必須でスコープ外→◯(非破壊フィンガープリント)が正直な到達点
  (CORS同型)。候補はpayout_grade非発火で偽◎回避。(2) 既存の provider matrix/adapter を新エンジンで
  配線するだけで◯に到達(groundwork活用)。[[detection-capability-wiring-map]]・[[no-capability-minimization]]。
- 観測(別件): ◎化(実claim)・CNAME自動解決(dnspython)・dependency confusion・統合は deferred。
