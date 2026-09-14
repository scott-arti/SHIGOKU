---
task_id: SGK-2026-0493
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0493_subdomain-takeover-detection_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0493_subdomain-takeover-detection_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation.md
tags:
- shigoku
- detection
- subdomain-takeover
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0493 計画 — Subdomain Takeover を機能として ◯（非破壊フィンガープリント検出）

## 背景・方針（ユーザー指示）

Subdomain Takeover は「実際にリソースを登録して奪取」しないと ◎（完全証明）にならず、それは
破壊的・スコープ外。ユーザー指示は**「まず機能として ◯ が取れるか」「チェックは当面手動でよい」**。
よって CORS と同じ立て付けで、**非破壊のフィンガープリント検出エンジン＋候補 Finding** を整備し
◯（本物確定能力あり・確定は人手 claim に委ねる）に到達させる。破壊的奪取は行わない。

## 事実（偵察で実測）

- 既存資産：`config/providers/takeover_provider_matrix.yaml`（AWS S3 / GitHub Pages / Heroku / Azure・
  `can-i-take-over-xyz` 由来の実 fingerprint_domains＋error_tokens）、`takeover_provider_matrix_adapter`
  （`ProviderMatrixLoader`・`TakeoverProviderMatrix.find_by_fingerprint_domain`/`find_by_error_token`）、
  subzy/subjack ラッパー。だが swarm specialist に未配線・Finding 化されていなかった。
- 実測：実 GitHub Pages の未登録サブドメイン `<rand>.github.io` が本文に
  `There isn't a GitHub Pages site here`（実 error_token）を返すことを確認＝実データでフィンガープリント
  検出が成立。dnspython は未インストール（CNAME 解決は best-effort・host 名/recon 由来 cname で代用）。

## 対象（完了契約）

Subdomain Takeover の**非破壊フィンガープリント検出**を機能として整備し ◯ に到達：
- CNAME（または host 名／recon 由来）が既知プロバイダの fingerprint_domain に一致、かつ取得本文に
  そのプロバイダの未登録サイン error_token が出現 → **takeover 候補**（同一プロバイダ一致＝高確度、
  error_token のみ＝中確度）。false_positive_twin は注意フラグ。
- 候補 Finding に claim_prerequisites / verification_urls を載せ、**人手での claim 確認**（◎ 化）に委ねる。
- 破壊的奪取は行わない（GET のみ）。確定バー（凍結）は**触らない**（候補＝payout 未確定が takeover の
  正直な意味・◯ の立て付け）。

## 実装方針（新設・凍結非改変）

1. **finding.py（非凍結）**: `VulnType.SUBDOMAIN_TAKEOVER` 追加。
2. **新エンジン `smart_subdomain_takeover.py`（非凍結・新規）**: `SmartSubdomainTakeoverHunter`。matrix を
   ロードし、対象（task.target＋`takeover_subdomains`）ごとに host/cname を fingerprint_domain 照合＋取得
   本文を error_token 照合。error_token 一致で候補 Finding（confidence 0.9=CNAME 委譲一致／0.6=サインのみ）。
   `self._client` 注入 seam。marker（error_token）中心スニペット。`subdomain_takeover_evidence`
   （host/cname/provider/matched_token/cname_match/verification_urls/claim_prerequisites/grade=candidate）。
   製品固有ハードコードなし（プロバイダ表は config・provider サインは実世界フィンガープリント）。
3. **確定バー・再現チェッカー：改変なし**（◯ 候補は payout_grade を発火させない＝人手 claim で ◎ 化）。

## 完了条件

1. 実 GitHub Pages 未登録サブドメインで実エンジンが候補検出（provider=github_pages・error_token 一致・
   cname_match・grade=candidate・verification_urls 付き）を自走で実証（手動確認可）。
2. 製品非依存 fixture の新規テスト緑（github_pages 高確度／error_token のみ中確度／recon cname で高確度／
   未登録サイン無しで非検出／候補は payout_grade 非発火／複数サブドメイン）。
3. 凍結5 exit 0（本タスクは確定バー未改変）。回帰ゼロ。
4. 能力マップに Subdomain Takeover ◯ を追加（◎ は破壊的 claim が要るため人手・別途と明記）。

## NOT in scope

- 破壊的なリソース奪取（実 claim）＝◎ 化は人手・要承認（本エンジンは非破壊検出まで）。
- CNAME 自動解決（dnspython 未導入・recon 由来 cname/host で代用）・多段委譲・dependency confusion。
- パイプライン自動走行への統合（当面チェックは手動でよい＝ユーザー指示）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（一ファイルの挙動を仕様としない・実対象到達の証明）、
`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、メモリ
[[no-capability-minimization]]・[[detection-capability-wiring-map]]。
