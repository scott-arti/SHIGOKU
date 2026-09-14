---
task_id: SGK-2026-0491
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0491_host-header-injection-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0491_host-header-injection-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0490_jwt-key-confusion-confirmation.md
tags:
- shigoku
- detection
- host-header-injection
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0491 計画 — Host Header Injection（認証バイパス）を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] の Host Header Injection。既存 `attack/host_header_injection.py`
（`HostHeaderInjectionTester`・X-Forwarded-Host 等の書き換えペイロード）は在るが、swarm specialist にも
確定バーにも未接続（reflection ヒューリスティックのみ）。`_MARKER_CATEGORIES` に host マーカー無し。

実対象（実測・非破壊）：DVGA/SKF と同じ posture で **OWASP SKF ラボ
`blabla1337/owasp-skf-lab:host-header-authentication-bypass`**（Flask）を 127.0.0.1:5092 に起動。
`/dashboard` は未ログイン時、リクエストの Host が `localhost`/`127.0.0.1`（is_local_request）だと
admin panel（製品・給与データ）を返すが、非該当ホストだと redirect('/') で拒否する実装欠陥
（Host ヘッダを認可判定に使用）。実測で **Host: localhost → 200＋給与データ（"Mr Mark Oney"/
"50000000" 等）を未ログインで取得**、**Host: attacker.example → 302 リダイレクト（データ無し）** を確認。
＝Host ヘッダ注入による認証バイパス（制限データ漏洩）。非破壊（読み取り GET のみ・破壊系エンドポイント
は使わない）。

## 確定バーの欠落点（事実）

- specialist 未接続・確定バーに `host_header_injection` マーカー無し。
- 既存テスターは reflection パターン一致のみで、認可バイパスの差分証拠を作れない。

## 対象（完了契約）

SKF ラボの Host ヘッダ認証バイパスを実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で
◎ に到達。確定は**決定論的差分**（注入ホスト＝制限コンテンツ反映／control ホスト＝非反映）で行う。
制限コンテンツの署名（restricted_signature）は task 由来（製品固有値はエンジンにハードコードしない）。

## 実装方針（新設・最小差分）

1. **新エンジン `smart_host_header.py`（非凍結・新規）**: `SmartHostHeaderHunter`。task 由来の observe
   エンドポイント＋制限コンテンツ署名で駆動。候補ホストヘッダ（Host/X-Forwarded-Host/X-Host/
   X-Forwarded-Server）× 候補バイパス値（localhost/127.0.0.1＋task 由来）を注入し、①control（非バイパス
   ホスト）②injection の応答を比較、**署名が injection に出て control に出ない**差分で確定（allow_redirects=
   False で即時応答を評価）。`self._client` 注入 seam。構造化 `host_header_evidence`（injection/control
   両方）＋`host_header_replay`＋差分2ステップ poc を付与。製品固有ハードコードなし。
2. **確定バー `payout_grade.py`（凍結・承認）**: `_MARKER_CATEGORIES["host_header_injection"]=
   "host_header_auth_bypass"`。`_match_firing_marker` の分岐は request_url 非空＋injected_header 非空＋
   injected_host_value 非空＋restricted_signature 非空＋injection 2xx＋署名が injected_body に実在＋
   control_body に非実在が**全て揃ったときだけ**発火（fail-closed）。
3. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `_check_host_header_replay`。
   host_header_replay 記述子（url/header/value/signature）に従い、注入ヘッダ付き GET を封印スコープ内へ
   1 回再送し、署名が 2xx 応答に再出現→matched（GET＋ヘッダ送信は既存 `_send_get_jwt` の汎用ヘッダ GET
   経路を流用）。記述子不正/署名非再出現は not_run/mismatched（fail-closed）。

## 完了条件

1. 実 SKF ラボで実 `SmartHostHeaderHunter.execute` が差分確認で自走検出→
   payout_grade=True/host_header_auth_bypass。
2. 実 `SealedReproductionChecker` が注入ヘッダで署名を再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認（注入ホスト＝制限データ／control ホスト＝拒否の差分を提示）。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側＝署名欠落・control にも署名・非2xx・
   ヘッダ欠落／engine 差分確定・control にも出れば不確定／replay 記述子／sealed matched・mismatched・
   not_run・スコープ外）。
5. 凍結3 exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- パスワードリセットポイズニング（メールリンク観測が必要・別経路）・Host reflection 型（別サブクラス）。
- 破壊的エンドポイント（/admin/delete）は使わない。SKF 以外への一般化（実対象1件で ◎ 到達）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明・一ファイルの挙動を
仕様としない）、`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、
メモリ [[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
