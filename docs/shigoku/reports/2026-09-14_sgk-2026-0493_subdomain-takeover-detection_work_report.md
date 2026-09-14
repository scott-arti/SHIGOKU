---
task_id: SGK-2026-0493
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0493_subdomain-takeover-detection.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0493_subdomain-takeover-detection_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- subdomain-takeover
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0493 作業完了報告 — Subdomain Takeover を機能として ◯（非破壊フィンガープリント検出）

## 何をしたか / なぜ

ユーザー指示「まず機能として ◯ が取れるか・チェックは当面手動でよい」に沿って、Subdomain Takeover の
**非破壊フィンガープリント検出**を機能として整備し ◯（本物確定能力あり・確定は人手 claim に委ねる）に
到達させた。◎（完全証明）は実際に第三者サービスでリソースを登録して奪取する必要があり破壊的・スコープ外
のため行わない（CORS と同じ立て付け＝偽◎を作らない）。

## 事実（偵察で実測）

- 既存資産：`config/providers/takeover_provider_matrix.yaml`（AWS S3/GitHub Pages/Heroku/Azure・
  `can-i-take-over-xyz` 由来の実 fingerprint_domains＋error_tokens）、`takeover_provider_matrix_adapter`
  （`ProviderMatrixLoader`・`TakeoverProviderMatrix.find_by_fingerprint_domain`/`find_by_error_token`）、
  subzy/subjack ラッパー。だが swarm specialist 未配線・Finding 化されていなかった。
- 実測：実 GitHub Pages の未登録サブドメイン `<rand>.github.io` が本文に
  `There isn't a GitHub Pages site here`（実 error_token）を返すことを確認＝実データで検出成立。
  dnspython 未導入（CNAME 自動解決は best-effort・host 名/recon 由来 cname で代用）。

## 実装（新設・凍結非改変）

- **finding.py（非凍結）**: `VulnType.SUBDOMAIN_TAKEOVER = "subdomain_takeover"` を追加。
- **smart_subdomain_takeover.py（非凍結・新規エンジン）**: `SmartSubdomainTakeoverHunter`。matrix を
  ロードし、対象（task.target＋`takeover_subdomains`）ごとに host/cname を fingerprint_domain 照合＋取得
  本文を error_token 照合。error_token 一致で **takeover 候補 Finding**（confidence 0.9=CNAME 委譲一致／
  0.6=サインのみ・false_positive_twin 注意フラグ）。`self._client` 注入 seam。error_token 中心スニペット。
  `subdomain_takeover_evidence`（host/cname/provider_id/matched_error_token/cname_provider_match/
  served_body/false_positive_twin/confidence/grade=candidate/claim_prerequisites/verification_urls）。
  **非破壊（GET のみ・実 claim は行わない）**。製品固有ハードコードなし（プロバイダ表は config・
  provider サインは実世界フィンガープリント）。
- **確定バー（payout_grade.py）・再現チェッカー（sealed_reproduction_checker.py）：改変なし**
  （◯ 候補は payout_grade を発火させない＝人手 claim で ◎ 化する立て付け）。凍結5 すべて不変。

## 結果（独立検証・Claude が実測）

- **実 GitHub Pages 未登録サブドメイン**に対し実 `SmartSubdomainTakeoverHunter.execute` が候補検出
  （provider=github_pages・error_token `There isn't a GitHub Pages site here` 一致・cname_provider_match=
  True・confidence=0.9・grade=candidate・verification_urls=`https://github.com/settings/pages`・非破壊 GET）。
  ＝◯ の検出能力を実データで実証（人手で verification_urls から claim すれば ◎ 化＝当面手動）。
- テスト: 新規6テスト緑（github_pages 高確度／error_token のみ中確度／recon cname で高確度化／未登録
  サイン無しで非検出／**候補は payout_grade 非発火**（◯ の fail-closed 意味論）／複数サブドメイン）。
  非回帰: injection スイート 842 passed・失敗1は本変更前でも失敗する既存（t3_hybrid budget）＝**0493
  起因の回帰ゼロ**。
- **凍結5（payout_grade / sealed_reproduction / poc_judge.md / task_queue.py / finding_validator.py）は
  すべて `git diff --quiet HEAD` exit 0（本タスクは確定バー未改変）**。製品非依存 token 0（追加コード・
  テストは example.com／provider サインのみ。github.io 実測は scratchpad デモのみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **Subdomain Takeover ＝ ◯（非破壊フィンガープリント検出・本物確定能力あり）**。◎ は実際にリソースを
  登録して奪取する破壊的操作が必要でスコープ外のため人手・別途（CORS と同じ honesty）。候補 Finding は
  payout_grade を発火させない（＝候補が takeover の正直な意味・偽◎回避）。**高度化 低(L1)**（provider matrix
  検出・CNAME 自動解決/dependency confusion/パイプライン統合は未）。

## 完了条件の充足

計画の完了条件 1〜4 をすべて充足（実 GitHub Pages で候補検出を実証・テスト緑・凍結5 不変・能力マップ ◯ 追加）。
`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（一ファイルの挙動を仕様としない・実対象到達の証明）、
`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、メモリ
[[no-capability-minimization]]・[[detection-capability-wiring-map]]。

## 非阻害の観測（deferred / 別件）

- ◎ 化（実 claim による奪取証明）は破壊的・要承認で人手・別途。CNAME 自動解決（dnspython 導入）・
  dependency confusion・多段委譲・パイプライン統合は本タスク対象外（`deferred_followup`）。
