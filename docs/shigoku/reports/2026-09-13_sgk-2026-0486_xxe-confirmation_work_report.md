---
task_id: SGK-2026-0486
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0486_xxe-confirmation.md
- docs/shigoku/worklogs/2026-09-13_sgk-2026-0486_xxe-confirmation_work_log.md
- docs/shigoku/plans/done/2026-09-13_sgk-2026-0485_ssti-confirmation.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- xxe
- new-engine
- confirmation-bar
created_at: '2026-09-13'
updated_at: '2026-09-13'
---

# SGK-2026-0486 作業完了報告 — XXE（XML External Entity）を新エンジン新設で本物確定（◎）

## 何をしたか / なぜ

能力マップ [[sgk-2026-0465]] の「エンジンが無いギャップ領域」の代表格 **XXE** を新設して ◎ 化。
コードベースに XXE のテスター・VulnType・specialist は**一切存在しなかった**（真の greenfield）。
DVGA/SKF と同じ posture で OWASP SKF ラボ `blabla1337/owasp-skf-lab:xxe`（Python/Flask）を制御
対象として起動（`127.0.0.1:5089`）。実測で `/home` が `request.form['xxe']` を
`xml.dom.pulldom.parseString` でパースし `<items>` を expandNode→toxml() で本文反映することを確認。
外部実体 `<!ENTITY x SYSTEM "file:///etc/passwd">` を含む XML で `/etc/passwd` の内容が応答に
反映される本物の in-band XXE を、機械フロア＋実再現＋実 poc_judge の完全3ゲートで ◎ に到達させた。
非破壊（ファイル読み取りのみ）。`/etc/passwd` はユーザー秘密ではなく標準的な XXE 実証用システム
ファイル（機微値なし・本文は署名中心スニペットで有界化）。

## 実装（新設・非凍結2＋承認済み凍結2）

- **finding.py（非凍結）**: `VulnType.XXE = "xxe"` を追加。
- **smart_xxe.py（非凍結・新規エンジン）**: `SmartXXEHunter`。汎用の外部実体ペイロード
  （`<!ENTITY <一意> SYSTEM "file:///etc/passwd">`）を、一般的な XML ラッパ要素名
  （items/data/root/xml/foo）× 汎用パラメータ名（task 由来＋xml/xxe/data/body/content）×
  モード（生 XML ボディ / form パラメータ）で試行し、応答に `/etc/passwd` 署名（`root:.*:0:0:`）が
  反映されたら確定（**製品固有のエンドポイント/パラメータ名はハードコードしない**）。`self._client`
  注入 seam・署名中心スニペット（`_snippet`）で証拠を有界化。構造化 `xxe_evidence`＋`xxe_replay`
  ＋生 `poc_request`/`poc_response`＋impact/repro を付与。broad catch は境界のみ noqa 付き。
- **payout_grade.py（凍結・承認）**: `_XXE_FILE_PATTERNS`（passwd `root:.*:0:0:`／PEM 秘密鍵署名）＋
  `_XXE_ENTITY_PATTERN`（`<!ENTITY ... SYSTEM`）を追加。`_MARKER_CATEGORIES["xxe"]="xxe_file_read"`。
  `_match_firing_marker` の `xxe` 分岐は①request_url 非空 ②response_status>0 ③payload に外部実体
  宣言 ④served_body にファイル署名一致が**全て揃ったときだけ**発火（1つでも欠ければ None＝
  fail-closed）。我々が外部実体を送った事実＋本来読めないファイル内容の反映が実害の証拠。既存
  マーカー経路は byte-identical で非回帰。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_xxe_replay` を追加。`xxe_replay` に従い
  外部実体ペイロードを封印スコープ内へ 1 回再送（form パラメータ／生 XML ボディ）→応答にファイル
  署名再出現で matched。外部実体を含まない payload は not_run（fail-closed）。dispatch 分岐を
  GET-only ガードより前に追加。ライブ再取得本文は照合のみで非永続。

## 結果（独立検証・Claude が実測）

- **実 SKF XXE ラボ**で実 `SmartXXEHunter.execute` が自走検出（form パラメータ `xxe`＋要素 `items`
  を汎用候補から発見）→外部実体で `/etc/passwd` を読み取り応答反映（`root:x:0:0:root:/root:/bin/ash`）
  →`payout_grade=True/xxe_file_read`→**実 `SealedReproductionChecker` が payload を封印スコープ内で
  再送しファイル署名を再観測→matched→CONFIRMED**。
- **本物の poc_judge（実 LLM）で 5/5 承認**（is_real=True・has_actual_impact=True・
  counter_evidence=False）。審査理由は「ペイロードは外部実体宣言のみで /etc/passwd の内容自体は
  含まないのに、応答本文に passwd の実内容が `<items>` 内へ展開されて出現＝本物の XXE ファイル
  読み取り」。**完全3ゲート達成＝◎**。
- テスト: 新規18テスト緑（payout_grade 発火/fail-closed5種/PEM署名・engine 変換確定/replay 記述子/
  非署名 None/外部実体保持/スニペット有界・sealed_reproduction matched/mismatched/not_run/スコープ外/
  外部実体なし）。非回帰: 失敗3件は本変更前（HEAD）でも失敗する既存（phase_b_readiness×2＝環境依存・
  t3_hybrid_wiring budget・本セッションで stash 比較確認済み・1133 passed＝+18 全緑）＝**0486 起因の
  回帰ゼロ**。
- 凍結3（poc_judge.md / task_queue.py / finding_validator.py）は各 `git diff --quiet HEAD` exit 0。
  承認済凍結2は承認範囲の追加のみ。製品非依存 token 0（追加コード・新規テストは target.example/
  evil.example のみ。SKF/5089 は scratchpad E2E のみ）。trailing whitespace 0。

## 確度の結論（正直な格付け）

- **XXE（外部実体によるローカルファイル読み取り）＝実害あり**（機密ファイル漏洩・SSRF 発展可）で、
  実 poc_judge も通り **◎（完全3ゲート）**。バーを下げて通す curve-fit はしていない（新マーカーは
  fail-closed の追加・証拠は「外部実体送出＋本来読めないファイル内容の反映」という決定的証拠・
  エンジンは製品固有ハードコードなし）。
- **対象の正当性**: SKF ラボは DVWA/Juice Shop/crAPI/DVGA と同じく意図的脆弱アプリ（本物の脆弱
  シンク）。「エンジンが無い」ギャップを、テスター新設＋実対象で埋めた。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を 5/5 で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16（エンジン配置）/§17/§19、`rules/lessons.md`（封印実行は実対象到達を証明）、
`rules/codingrules.md`（bare except 禁止・境界のみ noqa 付き broad catch）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- OOB/blind XXE（外部受信基盤が必要）は別タスク（`non_blocking_observation`）。
- CRLF は実務価値低・現代ランタイム遮断でユーザー判断により対象外（据え置き）。
- 台帳 `task_registry.yaml` の構造ずれ（0465 以降が `tasks:` 外・validator 0 エラー・運用影響なし）は
  既存慣習どおり同位置に登録。構造修正は §12 に基づき別途判断（`non_blocking_observation`）。
