---
task_id: SGK-2026-0492
doc_type: work_log
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation_work_report.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- web-cache-poisoning
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0492 作業ログ（Web キャッシュポイズニング・実 SKF ラボ・◎）

## 1. 偵察（事実優先・実測）
- 既存 CachePoisoner(high_risk_tester)は unkeyed 反映検出のみ・確定バー未接続。
- SKF に web-cache-poisoning ラボを発見。SSTI/XXE/race/HHI と同 posture で 127.0.0.1:5093 に起動。
- app 解析: X-Forwarded-Host で request.host を上書き→tracker_site に反映、キャッシュ鍵=full_path
  (X-Forwarded-Host は unkeyed)。redis 必須でコンテナ内 redis 無し→500。**サイドカー redis
  (--network container:skf-cache) で復旧**。実測で 毒入り→反映+キャッシュ、victim(クリーン)→marker 配信、
  control(別鍵)→非出現 を確認。非破壊(一意 cache-buster で隔離)。

## 2. 台帳・計画・承認
- SGK-2026-0492 採番（registry.yaml・DOC-0562）。キャッシュポイズニング新設の選択＝ビルド承認（凍結2 追加）。

## 3. 実装（Claude 直接）
- finding.py: VulnType.CACHE_POISONING 追加（MISCONFIGURATION 流用回避）。
- smart_cache_poisoning（新規）: 候補 unkeyed ヘッダを一意 cache-buster URL へ 毒入り→victim→control で送り
  marker が poison 反映かつ victim に出て control に出ない差分で確定。_client seam・marker 中心スニペット・
  cache_poisoning_evidence(poison/victim/control)・cache_poisoning_replay・3ステップ poc。製品固有ハードコードなし。
- payout_grade: `_MARKER_CATEGORIES["cache_poisoning"]="cache_poisoning_confirmed"`+発火分岐
  (request_url/header/marker 非空+victim 2xx+marker が victim に実在+control に非実在・fail-closed)。
- sealed_reproduction: `_check_cache_poisoning_replay`(新marker+新cache-buster で 毒入りGET→victimGET の2手・
  victim に再出現で matched・_send_get_jwt/_send_get 流用)+dispatch。

## 4. 独立検証（Claude・実出力）
- smoke: 発火 positive／marker control 出現・victim 非反映・非2xx・header/marker 欠落 の fail-closed 確認。
- 実 SKF E2E: 初回は redis 未起動で 500→サイドカー redis で復旧→execute→poison/victim 反映・control 非反映→
  payout_grade=True/cache_poisoning_confirmed→封印再現 matched→CONFIRMED。
- 実 poc_judge: **初回から 5/5**（marker が外部スクリプト src として反映＝キャッシュ経由 XSS ベクターと評価）。
- 新規20テスト緑。非回帰: 失敗3件は HEAD でも失敗する既存（phase_b×2・t3_hybrid budget・0488/0489 で stash
  確認済み）＝0492 起因の回帰ゼロ（1261 passed）。凍結3 exit 0。製品 token0・whitespace0・秘密値非露出。

## 5. 完了
- 完了条件1〜5 充足（条件3 実 poc_judge 5/5）。in_scope_blocker 0 → done。
- 能力マップ: **Web キャッシュポイズニング行を新規追加し ◎**＋高度化 低(L1)。
- 教訓: (1) キャッシュ系ラボは redis 等のバックエンドが要る→**サイドカーコンテナを同一 netns で起動**
  (--network container:<name>)。(2) キャッシュポイズニングの確定は「クリーンな victim に marker が配信される」
  差分＋別鍵 control で偶然を排除。(3) キャッシュは単発再送で再現不可＝封印再現は poison→victim の2手＋
  fresh 鍵。[[poc-judge-raw-evidence]]・[[skf-labs-ssti-crlf]]・[[no-capability-minimization]]。
- 観測(別件): cache deception・多段CDN/ESI・実運用対象・統合は高度化フェーズで deferred。
