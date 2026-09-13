---
task_id: SGK-2026-0486
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-13_sgk-2026-0486_xxe-confirmation_work_report.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0486_xxe-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0485_ssti-confirmation.md
tags:
- shigoku
- detection
- xxe
- new-engine
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0486 計画 — XXE（XML External Entity）を新エンジン新設で本物確定（◎）

## 背景・事実（偵察で実測）

能力マップ [[sgk-2026-0465]] の「エンジンが無いギャップ領域」のうち XXE を新設。
コードベースに XXE のテスター・VulnType・specialist は一切存在しなかった（真の greenfield）。
DVGA/SKF と同じ posture で OWASP SKF ラボ `blabla1337/owasp-skf-lab:xxe`（Python/Flask）を
制御対象として起動（`127.0.0.1:5089`）。実測で `/home` が `request.form['xxe']` を
`xml.dom.pulldom.parseString` で XML パースし、`<items>` 要素を expandNode→toxml() で本文反映
することを確認。外部実体 `<!ENTITY x SYSTEM "file:///etc/passwd">` を含む XML を送ると
`/etc/passwd` の内容（`root:x:0:0:root:/root:/bin/ash`）が応答に反映＝本物の in-band XXE を確認。

## 対象（完了契約）

SKF XXE ラボの in-band XXE（外部実体によるローカルファイル読み取り）を実対象で
**機械フロア＋実再現＋実 poc_judge の完全3ゲート**で ◎ に到達。非破壊（ファイル読み取りのみ）。
`/etc/passwd` はユーザーの秘密ではなく標準的な XXE 実証用システムファイル（機微値なし・
本文は署名中心スニペットで有界化）。

## 実装方針（新設・最小差分）

1. **VulnType（finding.py・非凍結）**: `XXE = "xxe"` を追加。
2. **新エンジン `smart_xxe.py`（非凍結・新規）**: `SmartXXEHunter`。汎用の外部実体ペイロード
   （`<!ENTITY <uniq> SYSTEM "file:///etc/passwd">`）を、一般的な XML ラッパ要素名
   （items/data/root/xml/foo）× 汎用パラメータ名（task 由来＋xml/xxe/data/body/content）×
   モード（生 XML ボディ / form パラメータ）で試行し、応答に `/etc/passwd` 署名
   （`root:.*:0:0:`）が反映されたら確定（製品固有ハードコードなし）。`self._client` 注入 seam。
   署名中心スニペット＋構造化 `xxe_evidence`＋`xxe_replay`＋生 poc 対＋impact/repro を付与。
3. **確定バー `payout_grade.py`（凍結・承認）**: `_XXE_FILE_PATTERNS`（passwd/PEM 署名）＋
   `_XXE_ENTITY_PATTERN`（`<!ENTITY ... SYSTEM`）を追加。`_MARKER_CATEGORIES["xxe"]="xxe_file_read"`。
   `_match_firing_marker` の `xxe` 分岐は request_url 非空＋status>0＋payload に外部実体宣言＋
   served_body にファイル署名一致が全て揃ったときだけ発火（fail-closed）。
4. **再現チェッカー `sealed_reproduction_checker.py`（凍結・承認）**: `_check_xxe_replay`。
   `xxe_replay` に従い外部実体ペイロードを封印スコープ内へ 1 回再送（form/raw）→応答に
   ファイル署名再出現で matched。外部実体を含まない payload は not_run（fail-closed）。

## 完了条件

1. 実 SKF ラボで実 `SmartXXEHunter.execute` が XXE を自走検出→payout_grade=True/xxe_file_read。
2. 実 `SealedReproductionChecker` が payload を再送しファイル署名を再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で承認。
4. 製品非依存 fixture の新規テスト緑（発火／fail-closed 各否定側／PEM署名／engine 変換／
   スニペット有界／再現 matched・mismatched・not_run・スコープ外・外部実体なし）。
5. 凍結3（poc_judge.md / task_queue.py / finding_validator.py）exit 0。製品トークン 0・回帰ゼロ。

## NOT in scope

- OOB/blind XXE（外部受信基盤が必要・別タスク）。
- XXE 経由の SSRF/内部到達の実証（in-band ファイル読み取りで ◎ 到達）。
- 実バグバウンティ対象への適用。

## 参考にしたルール

CLAUDE.md §14/§15/§16（外部ツール/エンジン配置）/§17/§19、`rules/lessons.md`（封印実行は実対象
到達を証明）、`rules/codingrules.md`（bare except 禁止・境界のみ noqa）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[skf-labs-ssti-crlf]]。
