---
task_id: SGK-2026-0492
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0491_host-header-injection-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- web-cache-poisoning
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0492 作業完了報告 — Web キャッシュポイズニングを実対象で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] のキャッシュポイズニング（ユーザー当初案）を ◎ 化。既存 `CachePoisoner`
（`attack/high_risk_tester.py`）は unkeyed 反映のヒューリスティック検出のみで swarm specialist・確定バーに
未接続だった。差分確認の新エンジンを新設し、実対象で機械フロア＋実再現＋実 poc_judge の完全3ゲートで
◎ に到達させた。

実対象（実測・非破壊）：DVGA/SKF と同じ posture で **OWASP SKF ラボ `web-cache-poisoning`**（Flask＋
flask_caching）を 127.0.0.1:5093 に起動。ラボは redis 必須（コンテナ内に redis 無しで 500）だったため、
**同一ネットワーク名前空間にサイドカー redis（`--network container:skf-cache`）を起動**して復旧。`/<path>` は
`X-Forwarded-Host` で `request.host` を上書きし `tracker_site` に反映、キャッシュキーは `full_path`
（**X-Forwarded-Host は unkeyed**）。実測で **毒入り（`X-Forwarded-Host: <一意marker>`＋一意 cache-buster）
→ marker 反映＋キャッシュ格納**、**victim（同URL・クリーン＝ヘッダ無し）→ marker 配信（キャッシュ HIT で
毒が victim に届く）**、**control（別 cache-buster・クリーン）→ marker 非出現**。非破壊（一意 cache-buster で
隔離した鍵に良性 marker のみ・実ユーザー経路は汚さない）。

## 実装（新設・非凍結2＋承認済み凍結2）

- **finding.py（非凍結・モデル）**: `VulnType.CACHE_POISONING = "cache_poisoning"` を追加（MISCONFIGURATION
  流用はマーカーが広すぎるため専用 vuln_type）。
- **smart_cache_poisoning.py（非凍結・新規エンジン）**: `SmartCachePoisoningHunter`。候補 unkeyed ヘッダ
  （X-Forwarded-Host/X-Forwarded-Scheme/X-Host/X-Forwarded-Server/X-Forwarded-Proto）を一意 cache-buster
  付き URL へ ①毒入り（header=一意 marker）②victim（同URL・クリーン）③control（別 cache-buster・クリーン）
  の順で送り、**marker が poison 反映 かつ victim に出て control に出ない**差分で確定。`self._client` 注入
  seam。marker 中心スニペット。構造化 `cache_poisoning_evidence`（poison/victim/control）＋
  `cache_poisoning_replay`＋差分3ステップ poc を付与。製品固有ハードコードなし。
- **payout_grade.py（凍結・承認）**: `_MARKER_CATEGORIES["cache_poisoning"]="cache_poisoning_confirmed"`。
  `_match_firing_marker` の分岐は request_url／injected_header／marker 非空＋victim 2xx＋marker が
  victim_served_body（クリーン応答）に実在＋control_served_body に非実在が**全て揃ったときだけ**発火
  （fail-closed）。クリーン victim に攻撃者 marker が出ることがキャッシュ配信の決定的証拠。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_cache_poisoning_replay` を追加。新 marker＋新
  cache-buster で 毒入り GET（unkeyed ヘッダ付き・`_send_get_jwt` の汎用ヘッダ GET）→ victim GET
  （クリーン・`_send_get`）の2手を封印スコープ内で送り、victim に新 marker 再出現→matched。キャッシュは
  単発再送では再現不可のため 2手再現が正当（GET のみ・fresh 鍵で隔離）。記述子不正/marker 非再出現は
  not_run/mismatched（fail-closed）。

## 結果（独立検証・Claude が実測）

- **実 SKF ラボ**で実 `SmartCachePoisoningHunter.execute` が差分確認で自走検出（X-Forwarded-Host・poison
  反映／victim(クリーン)反映／control 非反映）→`payout_grade=True/cache_poisoning_confirmed`→**実
  `SealedReproductionChecker` が 毒入り→victim を新 marker で再実行しクリーン victim に再出現→matched→
  CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・counter=False・初回から）。
  審査理由は「X-Forwarded-Host の一意攻撃者ホストが `<script src="//<attacker>/js/tracking.js">` として
  反映（実行可能な外部スクリプト＝XSS ベクター）し、クリーンな victim にキャッシュ経由で配信される」。
  **完全3ゲート達成＝◎**。
- テスト: 新規20テスト緑（payout_grade 発火/fail-closed 各否定側＝欠落・空URL/header/marker・victim 非反映・
  control にも marker・非2xx・impact 欠落／engine 差分確定・3ステップ poc・replay 記述子・非キャッシュで
  不確定・非反映で不確定／sealed matched・mismatched(非キャッシュ)・not_run(client なし/スコープ外/記述子
  不備)）。非回帰: 失敗3件は本変更前でも失敗する既存（phase_b×2・t3_hybrid budget・SGK-2026-0488/0489 で
  stash 確認済み）＝**0492 起因の回帰ゼロ**（1261 passed）。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。承認済凍結2は承認範囲の追加のみ。
  製品非依存 token 0（追加コード・新規テストは target.example のみ。SKF/5093/web-cache は scratchpad E2E
  のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **Web キャッシュポイズニング（unkeyed 入力の他ユーザー配信・XSS/改ざんベクター）＝実害あり**で、実
  poc_judge も通り **◎（完全3ゲート）**。curve-fit なし（新マーカーは fail-closed・victim/control 差分・
  エンジンは製品固有ハードコードなし）。**高度化は 低(L1)**（SKF ラボ単一・X-Forwarded-Host 反映1形態・
  cache deception/多段CDN は別途・未統合）＝幅優先方針どおり。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・一ファイルの挙動を
仕様としない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- SKF web-cache ラボは redis 必須（サイドカー redis で運用）。cache deception・多段 CDN/ESI・キャッシュ鍵
  探索最適化・実運用アプリ対象・パイプライン統合は本タスク対象外（`deferred_followup`）。
