---
task_id: SGK-2026-0492
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0492_web-cache-poisoning-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0491_host-header-injection-confirmation.md
tags:
- shigoku
- detection
- web-cache-poisoning
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0492 計画 — Web キャッシュポイズニングを実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] のキャッシュポイズニング。既存 `attack/high_risk_tester.py` の
`CachePoisoner`（X-Forwarded-Host 等の unkeyed 候補・unkeyed 検出・cache buster 生成）は在るが、
swarm specialist にも確定バーにも未接続。`_MARKER_CATEGORIES` に cache マーカー無し。

実対象（実測・非破壊）：DVGA/SKF と同じ posture で **OWASP SKF ラボ
`blabla1337/owasp-skf-lab:web-cache-poisoning`**（Flask＋flask_caching）を 127.0.0.1:5093 に起動。
`/<path>` は `X-Forwarded-Host` で `request.host` を上書きし `tracker_site=request.host` をページに反映、
キャッシュキーは `request.full_path`（**X-Forwarded-Host は unkeyed**）。実測で：
- **毒入り**（`X-Forwarded-Host: <一意marker>` ＋ 一意 cache-buster）→ marker 反映＋キャッシュ格納。
- **victim**（同 URL・クリーン＝ヘッダ無し）→ **marker が配信された**（キャッシュ HIT で毒が victim に届く）。
- **control**（別 cache-buster・クリーン）→ marker 非出現。
＝unkeyed 入力がキャッシュされ victim に配信される教科書的 Web キャッシュポイズニング。非破壊
（一意 cache-buster で隔離したキーに良性 marker のみ・実ユーザー経路は汚さない）。

## 確定バーの欠落点（事実）

- specialist 未接続・確定バーに cache マーカー無し。
- 既存 CachePoisoner は unkeyed 反映検出のみで「キャッシュされ victim に配信された」差分証拠を作れない。

## 対象（完了契約）

SKF キャッシュラボの Web キャッシュポイズニングを実対象で **機械フロア＋実再現＋実 poc_judge の
完全3ゲート**で ◎ に到達。確定は**決定論的差分**（一意 marker が **クリーンな victim 応答**に出て、
別キーの control には出ない）で行う。marker はエンジンが選ぶ一意攻撃者ホストで偶然混入・捏造不可。

## 実装方針（新設・最小差分）

1. **新エンジン `smart_cache_poisoning.py`（非凍結・新規）**: `SmartCachePoisoningHunter`。候補 unkeyed
   ヘッダ（X-Forwarded-Host/X-Forwarded-Scheme/X-Host/X-Forwarded-Server/X-Forwarded-Proto）を1つずつ、
   一意 cache-buster 付き URL へ ①毒入り（header=一意marker）②victim（同 URL・クリーン）③control
   （別 cache-buster・クリーン）の順で送り、**marker が poison に反映 かつ victim に出て control に出ない**
   差分で確定。`self._client` 注入 seam。marker 中心スニペット。構造化 `cache_poisoning_evidence`
   （victim/control/poison）＋`cache_poisoning_replay`＋差分poc（毒→victim→control）を付与。製品固有
   ハードコードなし。非破壊（一意キーに良性 marker のみ）。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["cache_poisoning"]=
   "cache_poisoning_confirmed"`。`_match_firing_marker` の分岐は request_url 非空＋injected_header 非空＋
   marker 非空＋victim 2xx＋marker が victim_served_body（クリーン応答）に実在＋marker が
   control_served_body に非実在が**全て揃ったときだけ**発火（fail-closed）。クリーン victim に攻撃者
   marker が出ることがキャッシュ配信の決定的証拠。
3. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `_check_cache_poisoning_replay`。
   **新しい marker と新しい cache-buster**で、封印スコープ内へ 毒入り GET（header 付き）→ victim GET
   （クリーン）の2手を送り、victim 応答に新 marker が再出現→matched（キャッシュが単発再送で再現不可の
   ため poison→victim の2手再現が正当・GET のみ・fresh キーで隔離）。記述子不正/marker 非再出現は
   not_run/mismatched（fail-closed）。

## 完了条件

1. 実 SKF ラボで実 `SmartCachePoisoningHunter.execute` が差分確認で自走検出→
   payout_grade=True/cache_poisoning_confirmed。
2. 実 `SealedReproductionChecker` が poison→victim を再実行し新 marker を victim に再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（毒→victim(クリーン)反映→control 非反映の差分を提示）。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側＝marker 欠落・control にも marker・
   非2xx・victim 非反映／engine 差分確定・victim に出なければ不確定・poison 非反映で不確定／
   sealed matched・mismatched・not_run・スコープ外）。
5. 凍結3 exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- キャッシュ鍵に含まれる入力の探索最適化・多段キャッシュ（CDN/ESI）・キャッシュ欺瞞（cache deception）。
- 実ユーザー経路（cache-buster なし）へのポイズニング（破壊的・対象外）。SKF 以外への一般化。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・一ファイルの挙動を
仕様としない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
